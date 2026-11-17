//! Console output for the windowed Windows build.
//!
//! `openncalayer` is a GUI-subsystem program on Windows, so starting it from a shortcut, the
//! autostart entry or the updater creates no console window. A command-line use still needs
//! the parent's console: [`attach_for_cli`] connects to it for the std handles the parent did
//! not redirect.

use std::ffi::OsStr;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{
    ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE, SetStdHandle,
};

/// Whether the first argument starts the daemon (no argument or `run`): it never holds a console.
fn starts_daemon(first: Option<&OsStr>) -> bool {
    first.is_none_or(|a| a == "run")
}

fn missing(which: u32) -> bool {
    // SAFETY: GetStdHandle has no preconditions.
    let handle = unsafe { GetStdHandle(which) };
    handle.is_null() || handle == INVALID_HANDLE_VALUE
}

fn open(name: &str) -> Option<HANDLE> {
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: `wide` is a NUL-terminated string that outlives the call.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    (handle != INVALID_HANDLE_VALUE).then_some(handle)
}

/// Gives a command-line run the parent's console for the std handles the parent left unset.
/// Redirected handles stay as they are; without a parent console nothing changes.
pub fn attach_for_cli() {
    let first = std::env::args_os().nth(1);
    if starts_daemon(first.as_deref()) {
        return;
    }
    let (no_in, no_out, no_err) = (
        missing(STD_INPUT_HANDLE),
        missing(STD_OUTPUT_HANDLE),
        missing(STD_ERROR_HANDLE),
    );
    if !(no_in || no_out || no_err) {
        return;
    }
    // SAFETY: AttachConsole has no preconditions; failure means there is no parent console.
    if unsafe { AttachConsole(ATTACH_PARENT_PROCESS) } == 0 {
        return;
    }
    if (no_out || no_err)
        && let Some(out) = open("CONOUT$")
    {
        for (absent, which) in [(no_out, STD_OUTPUT_HANDLE), (no_err, STD_ERROR_HANDLE)] {
            if absent {
                // SAFETY: `out` is a valid console handle that stays open for the process's life.
                unsafe { SetStdHandle(which, out) };
            }
        }
    }
    if no_in && let Some(input) = open("CONIN$") {
        // SAFETY: as above.
        unsafe { SetStdHandle(STD_INPUT_HANDLE, input) };
    }
}
