//! `--secret-interactive` on a real Unix terminal: the actual `oncl` process runs with a
//! pseudo-terminal as its controlling terminal. Keystrokes are written to the master side;
//! the terminal mode is read from the slave side before and after.
use crate::support::*;
use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::process::{CommandExt, ExitStatusExt},
    },
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

struct Pty {
    master: File,
    slave: OwnedFd,
    screen: Arc<Mutex<Vec<u8>>>,
    child: Child,
    /// The terminal mode before `oncl` started.
    before: (
        libc::tcflag_t,
        libc::tcflag_t,
        libc::tcflag_t,
        Vec<libc::cc_t>,
    ),
}
/// The parts of a terminal mode the prompt changes.
fn mode(
    fd: &OwnedFd,
) -> (
    libc::tcflag_t,
    libc::tcflag_t,
    libc::tcflag_t,
    Vec<libc::cc_t>,
) {
    // SAFETY: zero is valid storage; tcgetattr initializes the complete structure.
    let mut mode: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: live descriptor, valid out-pointer.
    assert_eq!(unsafe { libc::tcgetattr(fd.as_raw_fd(), &mut mode) }, 0);
    (mode.c_iflag, mode.c_oflag, mode.c_lflag, mode.c_cc.to_vec())
}
impl Pty {
    /// Starts `oncl` with `args` in a new session whose controlling terminal is a fresh pty.
    fn start(args: &[String]) -> Pty {
        Self::start_program(env!("CARGO_BIN_EXE_oncl"), args)
    }
    fn start_program(program: &str, args: &[String]) -> Pty {
        let (mut master, mut slave) = (0, 0);
        // SAFETY: valid out-pointers; no name, default mode and size.
        let opened = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(opened, 0, "openpty: {}", std::io::Error::last_os_error());
        // SAFETY: both descriptors were just opened and are owned here only.
        let (master, slave) = unsafe { (File::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        let before = mode(&slave);
        let stdio = || Stdio::from(slave.try_clone().unwrap());
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(stdio())
            .stdout(stdio())
            .stderr(stdio());
        // SAFETY: async-signal-safe calls only, between fork and exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let screen = Arc::new(Mutex::new(Vec::new()));
        let (shown, mut output) = (screen.clone(), master.try_clone().unwrap());
        // Detached: the master reaches no EOF while the test holds the slave open.
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(n @ 1..) = output.read(&mut chunk) {
                shown.lock().unwrap().extend_from_slice(&chunk[..n]);
            }
        });
        Pty {
            master,
            slave,
            screen,
            child,
            before,
        }
    }
    fn screen(&self) -> String {
        String::from_utf8_lossy(&self.screen.lock().unwrap()).into_owned()
    }
    fn type_keys(&mut self, keys: &[u8]) {
        self.master.write_all(keys).unwrap();
    }
    fn wait_for(&self, needle: &str) {
        let start = Instant::now();
        while !self.screen().contains(needle) {
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "never displayed {needle:?}; screen: {:?}",
                self.screen()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    /// The exit code within `seconds`; a hung child is killed and fails the test.
    fn finish(&mut self, seconds: u64) -> i32 {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status
                    .code()
                    .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
            }
            if start.elapsed() > Duration::from_secs(seconds) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("child did not exit; screen: {:?}", self.screen());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    /// Whatever input the terminal still holds for the next reader.
    fn unread_input(&self) -> Vec<u8> {
        // SAFETY: live descriptor; only the status flags change.
        unsafe {
            let flags = libc::fcntl(self.slave.as_raw_fd(), libc::F_GETFL);
            libc::fcntl(
                self.slave.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            );
        }
        let mut left = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            // SAFETY: valid buffer of the declared length, live descriptor.
            let n = unsafe { libc::read(self.slave.as_raw_fd(), chunk.as_mut_ptr().cast(), 256) };
            if n <= 0 {
                return left;
            }
            left.extend_from_slice(&chunk[..n as usize]);
        }
    }
}
fn inspect(w: &World, extra: &[&str]) -> Vec<String> {
    let mut args: Vec<String> = extra.iter().map(|s| s.to_string()).collect();
    args.extend(
        [
            "inspect",
            "--profile",
            "container",
            "--input",
            w.rsa_key.to_str().unwrap(),
            "--alias",
            &w.pki.rsa.alias,
            "--secret-interactive",
            "--json",
        ]
        .map(String::from),
    );
    args
}
#[test]
fn edited_secret_opens_the_container_and_the_mode_is_restored() {
    let w = world();
    let mut pty = Pty::start(&inspect(&w, &[]));
    pty.wait_for("input hidden");
    pty.type_keys(format!("garbage\x15{PASSWORD}x\x7f\r").as_bytes());
    assert_eq!(pty.finish(60), 0, "{:?}", pty.screen());
    assert!(pty.screen().contains("\"entries\""), "{:?}", pty.screen());
    assert!(!pty.screen().contains(PASSWORD));
    assert_eq!(
        mode(&pty.slave),
        pty.before,
        "terminal mode restored exactly"
    );
}
#[test]
fn ctrl_c_and_ctrl_backslash_cancel_restore_the_mode_and_discard_the_rest() {
    let w = world();
    for cancel in [b"\x03", b"\x1c"] {
        let mut pty = Pty::start(&inspect(&w, &[]));
        pty.wait_for("input hidden");
        let mut keys = b"PARTIAL".to_vec();
        keys.extend_from_slice(cancel);
        keys.extend_from_slice(b"LEFTOVER\n");
        pty.type_keys(&keys);
        assert_eq!(pty.finish(60), 130, "{:?}", pty.screen());
        assert!(!pty.screen().contains("PARTIAL") && !pty.screen().contains("LEFTOVER"));
        assert_eq!(
            mode(&pty.slave),
            pty.before,
            "terminal mode restored exactly"
        );
        let left = pty.unread_input();
        assert!(
            !left.windows(8).any(|w| w == b"LEFTOVER"),
            "unread secret input reached the next reader: {left:?}"
        );
    }
}
#[test]
fn terminating_signals_during_the_prompt_restore_the_mode() {
    let w = world();
    for signal in [libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        let mut pty = Pty::start(&inspect(&w, &[]));
        pty.wait_for("input hidden");
        pty.type_keys(b"PARTIAL");
        // SAFETY: signals only the owned, still running child.
        assert_eq!(
            unsafe { libc::kill(pty.child.id() as libc::pid_t, signal) },
            0
        );
        assert_eq!(pty.finish(60), 130, "signal {signal}: {:?}", pty.screen());
        assert_eq!(
            mode(&pty.slave),
            pty.before,
            "signal {signal}: mode restored"
        );
    }
}
#[test]
fn an_idle_prompt_honours_the_deadline() {
    let w = world();
    let mut pty = Pty::start(&inspect(&w, &["--timeout-seconds", "2"]));
    pty.wait_for("input hidden");
    let start = Instant::now();
    assert_eq!(pty.finish(30), 1, "{:?}", pty.screen());
    assert!(start.elapsed() < Duration::from_secs(10));
    assert!(
        pty.screen().contains("DeadlineExceeded"),
        "{:?}",
        pty.screen()
    );
    assert_eq!(mode(&pty.slave), pty.before);
}
#[test]
fn a_background_job_is_refused_before_touching_the_terminal() {
    let w = world();
    // `set -m` gives the background job its own process group, not the terminal's.
    let quoted: Vec<String> = inspect(&w, &[]).iter().map(|a| format!("'{a}'")).collect();
    let script = format!(
        "set -m; '{}' {} & wait $!; echo EXIT=$?",
        env!("CARGO_BIN_EXE_oncl"),
        quoted.join(" ")
    );
    let mut pty = Pty::start_program("sh", &["-c".to_string(), script]);
    pty.wait_for("EXIT=");
    assert_eq!(pty.finish(30), 0, "{:?}", pty.screen());
    let screen = pty.screen();
    assert!(screen.contains("TerminalNotForeground"), "{screen:?}");
    assert!(!screen.contains("EXIT=0"), "{screen:?}");
    assert!(!screen.contains("input hidden"), "{screen:?}");
    assert_eq!(mode(&pty.slave), pty.before);
}
