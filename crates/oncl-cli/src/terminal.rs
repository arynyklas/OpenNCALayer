//! CLI-only terminal ownership; no global SDK prompter or secret reallocations.
use oncl_core::{OperationContext, OperationError};
use oncl_pki::resource::ProcessingError;
use std::io::{self, Read};
use zeroize::{Zeroize, Zeroizing};
const MAX: usize = 4096;
/// How often a secret read that waits for a key re-checks cancellation and the deadline.
const POLL_MS: u32 = 100;

pub fn finish(bytes: &[u8]) -> Result<Zeroizing<String>, OperationError> {
    let text = std::str::from_utf8(bytes).map_err(|_| OperationError::SecretRequired)?;
    let mut result = Zeroizing::new(String::new());
    result
        .try_reserve_exact(text.len())
        .map_err(|_| ProcessingError::MemoryLimit)?;
    // The only owned string allocation happens before copying any secret byte.
    // zeroize 1.9.1 String delegates to Vec::zeroize, including spare capacity.
    result.push_str(text);
    Ok(result)
}
fn pop(bytes: &mut [u8; MAX], len: &mut usize) {
    if *len == 0 {
        return;
    }
    let start = std::str::from_utf8(&bytes[..*len])
        .expect("editor retains UTF-8")
        .char_indices()
        .next_back()
        .map(|(i, _)| i)
        .unwrap_or(0);
    bytes[start..*len].zeroize();
    *len = start;
}
pub fn read_bounded(
    reader: &mut impl Read,
    ctx: &mut OperationContext,
) -> Result<Zeroizing<String>, OperationError> {
    let mut password = Zeroizing::new([0u8; MAX]);
    let mut scalar = Zeroizing::new([0u8; 4]);
    let mut len = 0;
    let mut scalar_len = 0;
    let mut raw = 0usize;
    loop {
        ctx.resources().checkpoint()?;
        if raw > MAX {
            return Err(OperationError::SecretRequired);
        }
        let read = reader.read(&mut scalar[scalar_len..scalar_len + 1]);
        ctx.resources().checkpoint()?;
        let count = match read {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result.map_err(ProcessingError::from)?,
        };
        if count == 0 {
            return Err(OperationError::SecretRequired);
        }
        raw = raw
            .checked_add(count)
            .ok_or(OperationError::SecretRequired)?;
        scalar_len += count;
        let character = match std::str::from_utf8(&scalar[..scalar_len]) {
            Ok(text) => text.chars().next().ok_or(OperationError::SecretRequired)?,
            Err(error) if error.error_len().is_none() && scalar_len < 4 => continue,
            Err(_) => return Err(OperationError::SecretRequired),
        };
        match character {
            '\n' | '\r' => return finish(&password[..len]),
            // The secret is read without signal processing: Ctrl-C and Ctrl-\ arrive here
            // in order with the typed keys instead of as a signal that can race the read.
            '\x03' | '\x1c' => return Err(ProcessingError::Cancelled.into()),
            '\x04' => return Err(OperationError::SecretRequired),
            '\x08' | '\x7f' => pop(&mut password, &mut len),
            '\x15' => {
                password[..len].zeroize();
                len = 0;
            }
            '\x17' => {
                while len > 0
                    && std::str::from_utf8(&password[..len])
                        .expect("UTF-8")
                        .chars()
                        .next_back()
                        .is_some_and(char::is_whitespace)
                {
                    pop(&mut password, &mut len);
                }
                while len > 0
                    && std::str::from_utf8(&password[..len])
                        .expect("UTF-8")
                        .chars()
                        .next_back()
                        .is_some_and(|c| !c.is_whitespace())
                {
                    pop(&mut password, &mut len);
                }
            }
            c if c.is_control() => return Err(OperationError::SecretRequired),
            _ => {
                let end = len
                    .checked_add(scalar_len)
                    .filter(|n| *n <= MAX)
                    .ok_or(OperationError::SecretRequired)?;
                password[len..end].copy_from_slice(&scalar[..scalar_len]);
                len = end;
            }
        }
        scalar.zeroize();
        scalar_len = 0;
    }
}
pub fn read(ctx: &mut OperationContext) -> Result<Zeroizing<String>, OperationError> {
    let mut terminal = platform::Terminal::open(ctx.resources()).map_err(ProcessingError::from)?;
    std::io::Write::write_all(
        &mut std::io::stderr().lock(),
        b"Key secret (input hidden): ",
    )
    .map_err(ProcessingError::from)?;
    let result = read_bounded(&mut terminal, ctx);
    let restore = terminal.restore();
    crate::diagnostic(format_args!(""));
    if restore.is_err() {
        crate::diagnostic(format_args!("oncl: TerminalRestoreFailed"));
    }
    match result {
        Err(error) => Err(error),
        Ok(secret) => {
            restore.map_err(ProcessingError::from)?;
            Ok(secret)
        }
    }
}
#[cfg(windows)]
mod platform {
    use super::*;
    use std::{fs::File, os::windows::io::AsRawHandle};
    use windows_sys::Win32::{
        Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::{
            Console::{
                ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
                ENABLE_VIRTUAL_TERMINAL_INPUT, FlushConsoleInputBuffer, GetConsoleMode,
                INPUT_RECORD, KEY_EVENT, ReadConsoleInputW, SetConsoleMode,
            },
            Threading::WaitForSingleObject,
        },
    };
    /// `VK_ESCAPE` and `VK_MENU` (Alt); local constants save the keyboard feature of
    /// `windows-sys`.
    const VK_ESCAPE: u16 = 0x1b;
    const VK_MENU: u16 = 0x12;
    pub struct Terminal {
        file: File,
        scope: oncl_pki::resource::ResourceScope,
        mode: u32,
        restored: bool,
        pending: Zeroizing<[u8; 4]>,
        start: usize,
        end: usize,
        /// A key record repeats its character `wRepeatCount` times: the unit and how
        /// many copies are still owed.
        repeated: Zeroizing<[u16; 1]>,
        repeats: u16,
    }
    /// The UTF-16 unit and repeat count a raw console stream read (conhost `GetChar`
    /// without virtual-terminal input) would return for this record, if any.
    fn character(record: &INPUT_RECORD) -> Option<(u16, u16)> {
        if u32::from(record.EventType) != KEY_EVENT {
            return None;
        }
        // SAFETY: a key record holds the key variant of the plain-data union.
        let key = unsafe { &record.Event.KeyEvent };
        // SAFETY: both union variants are a plain u16.
        let unit = unsafe { key.uChar.UnicodeChar };
        if unit == 0 {
            return None;
        }
        let repeats = key.wRepeatCount.max(1);
        if key.bKeyDown != 0 {
            // A stream read skips Esc and a bare line feed (Ctrl+J).
            (key.wVirtualKeyCode != VK_ESCAPE && unit != 0x0a).then_some((unit, repeats))
        } else {
            // A released Alt completes an Alt+numpad character.
            (key.wVirtualKeyCode == VK_MENU).then_some((unit, 1))
        }
    }
    impl Terminal {
        pub fn open(scope: &oncl_pki::resource::ResourceScope) -> io::Result<Self> {
            let file = File::options().read(true).write(true).open("CONIN$")?;
            let mut mode = 0;
            // SAFETY: the owned explicit console handle is live; output is valid.
            if unsafe { GetConsoleMode(file.as_raw_handle(), &mut mode) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let terminal = Self {
                file,
                scope: scope.shared_view(),
                mode,
                restored: false,
                pending: Zeroizing::new([0; 4]),
                start: 0,
                end: 0,
                repeated: Zeroizing::new([0; 1]),
                repeats: 0,
            };
            // SAFETY: affect only this console input handle, preserving all other bits.
            // Raw and unprocessed: no echo, `read_bounded` edits the line, and Ctrl-C is
            // queued as 0x03 in order with the typed keys. Processed input would drop it
            // and raise a control event that a read issued just after it never sees.
            // No virtual-terminal input: arrow keys stay keys, not escape sequences.
            if unsafe {
                SetConsoleMode(
                    terminal.file.as_raw_handle(),
                    mode & !(ENABLE_ECHO_INPUT
                        | ENABLE_LINE_INPUT
                        | ENABLE_PROCESSED_INPUT
                        | ENABLE_VIRTUAL_TERMINAL_INPUT),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(terminal)
        }
        /// The next typed UTF-16 unit. Only records already queued are read, so the
        /// wait is in `POLL_MS` slices that check cancellation and the deadline.
        fn unit(&mut self) -> io::Result<u16> {
            if self.repeats > 0 {
                self.repeats -= 1;
                let unit = self.repeated[0];
                if self.repeats == 0 {
                    self.repeated.zeroize();
                }
                return Ok(unit);
            }
            let handle = self.file.as_raw_handle();
            loop {
                self.scope.checkpoint().map_err(io::Error::other)?;
                // SAFETY: live owned console handle.
                match unsafe { WaitForSingleObject(handle, POLL_MS) } {
                    WAIT_OBJECT_0 => {}
                    WAIT_TIMEOUT => continue,
                    _ => return Err(io::Error::last_os_error()),
                }
                // SAFETY: an all-zero INPUT_RECORD is valid plain data.
                let mut record: INPUT_RECORD = unsafe { std::mem::zeroed() };
                let mut count = 0;
                // SAFETY: one record slot, exact declared count, live owned console
                // handle; the wait above saw a record queued, so this does not block.
                let read = unsafe { ReadConsoleInputW(handle, &mut record, 1, &mut count) };
                let decided = (read != 0 && count == 1)
                    .then(|| character(&record))
                    .flatten();
                // SAFETY: the record may hold a typed character; clear it in place.
                unsafe { std::ptr::write_volatile(&mut record, std::mem::zeroed()) };
                if read == 0 {
                    return Err(io::Error::last_os_error());
                }
                if let Some((unit, repeats)) = decided {
                    // A repeated surrogate would not pair; it is never repeated.
                    if repeats > 1 && !(0xd800..=0xdfff).contains(&unit) {
                        self.repeated[0] = unit;
                        self.repeats = repeats - 1;
                    }
                    return Ok(unit);
                }
            }
        }
        /// Discards unread input, so a remainder of the secret never reaches the next
        /// program, then puts the original mode back.
        pub fn restore(&mut self) -> io::Result<()> {
            if self.restored {
                return Ok(());
            }
            let handle = self.file.as_raw_handle();
            // SAFETY: handle remains owned and live through restoration.
            let flushed = unsafe { FlushConsoleInputBuffer(handle) } != 0;
            let flush_error = (!flushed).then(io::Error::last_os_error);
            // SAFETY: as above.
            if unsafe { SetConsoleMode(handle, self.mode) } == 0 {
                return Err(io::Error::last_os_error());
            }
            self.restored = true;
            flush_error.map_or(Ok(()), Err)
        }
    }
    impl Read for Terminal {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if output.is_empty() {
                return Ok(0);
            }
            if self.start == self.end {
                self.pending.zeroize();
                self.start = 0;
                let mut units = Zeroizing::new([0u16; 2]);
                units[0] = self.unit()?;
                let count = if (0xd800..=0xdbff).contains(&units[0]) {
                    units[1] = self.unit()?;
                    2
                } else {
                    1
                };
                let mut chars = char::decode_utf16(units[..count].iter().copied());
                let character = chars
                    .next()
                    .ok_or_else(|| io::Error::other("invalid terminal scalar"))?
                    .map_err(|_| io::Error::other("invalid terminal scalar"))?;
                self.end = character.encode_utf8(&mut *self.pending).len();
            }
            let count = output.len().min(self.end - self.start);
            output[..count].copy_from_slice(&self.pending[self.start..self.start + count]);
            self.pending[self.start..self.start + count].zeroize();
            self.start += count;
            Ok(count)
        }
    }
    impl Drop for Terminal {
        fn drop(&mut self) {
            if self.restore().is_err() {
                crate::diagnostic(format_args!("oncl: TerminalRestoreFailed"));
            }
        }
    }
}
#[cfg(unix)]
mod platform {
    use super::*;
    use std::{fs::File, os::fd::AsRawFd};
    /// Signals that would end or stop the process while the terminal is raw. The first
    /// three cancel the prompt (the terminal is then restored on the way out), the
    /// job-control stops are ignored until it is.
    const CANCELLING: [libc::c_int; 3] = [libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];
    const STOPPING: [libc::c_int; 3] = [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU];
    /// The dispositions in force while the prompt is open; the previous ones come back
    /// on drop, after the terminal is restored.
    struct PromptSignals {
        previous: Vec<(libc::c_int, libc::sigaction)>,
    }
    impl PromptSignals {
        fn install() -> io::Result<Self> {
            let mut signals = Self {
                previous: Vec::with_capacity(CANCELLING.len() + STOPPING.len()),
            };
            for (signal, handler) in CANCELLING
                .iter()
                .map(|s| {
                    (
                        *s,
                        crate::control::signal as *const () as libc::sighandler_t,
                    )
                })
                .chain(STOPPING.iter().map(|s| (*s, libc::SIG_IGN)))
            {
                // SAFETY: zero is a valid empty sigaction; sigemptyset initializes the
                // mask; sigaction copies both values before returning.
                let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
                action.sa_sigaction = handler;
                if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
                    || unsafe { libc::sigaction(signal, &action, &mut previous) } != 0
                {
                    return Err(io::Error::last_os_error());
                }
                signals.previous.push((signal, previous));
            }
            Ok(signals)
        }
    }
    impl Drop for PromptSignals {
        fn drop(&mut self) {
            for (signal, previous) in self.previous.iter().rev() {
                // SAFETY: restores exactly the disposition copied at install.
                unsafe { libc::sigaction(*signal, previous, std::ptr::null_mut()) };
            }
        }
    }
    /// Whether `fd` has input within `POLL_MS`. An interrupted wait reports none, so
    /// the caller re-checks cancellation.
    #[cfg(not(target_vendor = "apple"))]
    pub(super) fn readable(fd: libc::c_int) -> io::Result<bool> {
        let mut ready = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd for a live descriptor.
        match unsafe { libc::poll(&mut ready, 1, POLL_MS as libc::c_int) } {
            0 => Ok(false),
            n if n < 0 => interrupted(io::Error::last_os_error()),
            _ if ready.revents & libc::POLLNVAL != 0 => {
                Err(io::Error::from_raw_os_error(libc::EBADF))
            }
            _ => Ok(true),
        }
    }
    /// macOS `poll(2)` does not support devices (`/dev/tty` reports POLLNVAL), so the
    /// wait there is `select(2)`.
    #[cfg(target_vendor = "apple")]
    pub(super) fn readable(fd: libc::c_int) -> io::Result<bool> {
        if !(0..libc::FD_SETSIZE as libc::c_int).contains(&fd) {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        // SAFETY: zero is a valid fd_set; FD_ZERO/FD_SET stay within it for an fd
        // below FD_SETSIZE; select reads and writes only the passed set and timeout.
        let found = unsafe {
            let mut set: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut set);
            libc::FD_SET(fd, &mut set);
            let mut timeout = libc::timeval {
                tv_sec: 0,
                tv_usec: (POLL_MS * 1000) as libc::suseconds_t,
            };
            libc::select(
                fd + 1,
                &mut set,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut timeout,
            )
        };
        match found {
            0 => Ok(false),
            n if n < 0 => interrupted(io::Error::last_os_error()),
            _ => Ok(true),
        }
    }
    fn interrupted(error: io::Error) -> io::Result<bool> {
        if error.kind() == io::ErrorKind::Interrupted {
            Ok(false)
        } else {
            Err(error)
        }
    }
    pub struct Terminal {
        file: File,
        scope: oncl_pki::resource::ResourceScope,
        original: libc::termios,
        restored: bool,
        // Dropped after `Drop::drop` restored the terminal.
        _signals: PromptSignals,
    }
    impl Terminal {
        pub fn open(scope: &oncl_pki::resource::ResourceScope) -> io::Result<Self> {
            let file = File::options().read(true).write(true).open("/dev/tty")?;
            let fd = file.as_raw_fd();
            // SAFETY: zero is valid storage; tcgetattr initializes the complete structure.
            let mut original: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let signals = PromptSignals::install()?;
            let mut terminal = Self {
                file,
                scope: scope.shared_view(),
                original,
                restored: true,
                _signals: signals,
            };
            let mut mode = original;
            // Noncanonical, no signals, no flow control or input translation (as
            // cfmakeraw, output processing kept for the prompt): `read_bounded` edits the
            // line, and Ctrl-C/Ctrl-\ arrive as 0x03/0x1c in order with the typed keys
            // instead of a SIGINT that can land between the cancellation check and read(2).
            mode.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
            mode.c_iflag &= !(libc::IXON
                | libc::BRKINT
                | libc::ISTRIP
                | libc::INLCR
                | libc::IGNCR
                | libc::ICRNL
                | libc::PARMRK
                | libc::IGNBRK);
            mode.c_cc[libc::VMIN] = 1;
            mode.c_cc[libc::VTIME] = 0;
            // SAFETY: valid original-derived termios and live explicit terminal descriptor.
            if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &mode) } != 0 {
                return Err(io::Error::last_os_error());
            }
            terminal.restored = false;
            // tcsetattr succeeds if any of the changes applied: read the mode back.
            // SAFETY: zero is valid storage; tcgetattr initializes the complete structure.
            let mut applied: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(fd, &mut applied) } != 0 {
                return Err(io::Error::last_os_error());
            }
            if applied.c_lflag != mode.c_lflag
                || applied.c_iflag != mode.c_iflag
                || applied.c_cc[libc::VMIN] != 1
                || applied.c_cc[libc::VTIME] != 0
            {
                return Err(io::Error::other("terminal mode not applied"));
            }
            Ok(terminal)
        }
        /// Puts the original mode back, discarding unread input so a remainder of the
        /// secret never reaches the next program.
        pub fn restore(&mut self) -> io::Result<()> {
            if self.restored {
                return Ok(());
            }
            // SAFETY: restore exactly the saved structure while its descriptor lives.
            if unsafe { libc::tcsetattr(self.file.as_raw_fd(), libc::TCSAFLUSH, &self.original) }
                != 0
            {
                return Err(io::Error::last_os_error());
            }
            self.restored = true;
            Ok(())
        }
    }
    impl Read for Terminal {
        /// Waits for input in `POLL_MS` slices so cancellation and the deadline are
        /// checked while the user has not typed anything.
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            loop {
                self.scope.checkpoint().map_err(io::Error::other)?;
                if readable(self.file.as_raw_fd())? {
                    return self.file.read(output);
                }
            }
        }
    }
    impl Drop for Terminal {
        fn drop(&mut self) {
            if self.restore().is_err() {
                crate::diagnostic(format_args!("oncl: TerminalRestoreFailed"));
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use oncl_core::{Action, Engine, EngineServices, ExecutionGrant, OperationPolicy};
    use oncl_pki::resource::{OperationControl, Progress, ResourceLimits};
    use std::sync::Arc;
    struct Control;
    impl OperationControl for Control {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            Ok(())
        }
    }
    fn context() -> OperationContext {
        Engine::new(EngineServices::hash_only(ResourceLimits::default()))
            .unwrap()
            .begin(
                ExecutionGrant::new([Action::Hash]),
                OperationPolicy::strict_online(),
                Arc::new(Control),
            )
            .unwrap()
    }
    #[test]
    fn fixed_secret_editor_uses_utf8_byte_bound_and_never_truncates() {
        for input in ["a".repeat(4096), "\u{10348}".repeat(1024)] {
            let mut with_enter = input.as_bytes().to_vec();
            with_enter.push(b'\n');
            let secret = read_bounded(&mut with_enter.as_slice(), &mut context()).unwrap();
            assert_eq!(secret.as_bytes(), input.as_bytes());
            let mut too_long = input.as_bytes().to_vec();
            too_long.extend_from_slice(b"x\n");
            assert!(read_bounded(&mut too_long.as_slice(), &mut context()).is_err());
        }
        for mut input in [
            b"no enter".as_slice(),
            b"\xf0\x28\x8c\x28\n",
            b"\xed\xa0\x80\n",
        ] {
            assert!(read_bounded(&mut input, &mut context()).is_err());
        }
    }
    #[test]
    fn editing_removes_complete_scalars_and_clear_operations() {
        for (input, want) in [
            ("a\u{10348}\u{8}b\n", "ab"),
            ("discard\u{15}chosen\n", "chosen"),
            ("first second\u{17}last\n", "first last"),
        ] {
            let secret = read_bounded(&mut input.as_bytes(), &mut context()).unwrap();
            assert_eq!(secret.as_str(), want);
        }
        for cancel in [b"typed\x03".as_slice(), b"typed\x1c"] {
            assert_eq!(
                read_bounded(&mut &*cancel, &mut context())
                    .unwrap_err()
                    .code(),
                oncl_core::ErrorCode::Cancelled
            );
        }
    }
    /// The wait that slices a terminal read (`select` on macOS, where `poll` rejects
    /// devices) times out without input and reports input that is there.
    #[cfg(unix)]
    #[test]
    fn readable_times_out_and_then_sees_input() {
        use std::os::fd::AsRawFd;
        let (reader, mut writer) = std::io::pipe().unwrap();
        let started = std::time::Instant::now();
        assert!(!platform::readable(reader.as_raw_fd()).unwrap());
        assert!(started.elapsed() >= std::time::Duration::from_millis(u64::from(POLL_MS) / 2));
        std::io::Write::write_all(&mut writer, b"x").unwrap();
        assert!(platform::readable(reader.as_raw_fd()).unwrap());
    }
}
