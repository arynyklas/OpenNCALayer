//! Tests that need a real Windows console (Ctrl-Break delivery, a pseudoconsole) cannot run
//! where cargo has none: an IDE runner, a service, an agent shell. They skip there, with a
//! line saying why, unless `ONCL_REQUIRE_ORACLES=1` (set in CI) makes the missing console a
//! failure.

/// The variable that turns a skip into a failure.
pub const REQUIRE_VAR: &str = "ONCL_REQUIRE_ORACLES";

/// Whether the test may go on: `available` says whether `what` (a console feature) works
/// here. When it does not, the test skips (`false`, with a note on stderr) unless
/// `ONCL_REQUIRE_ORACLES=1`, which panics instead.
///
/// # Panics
///
/// Panics if `what` is missing and `ONCL_REQUIRE_ORACLES=1`.
pub fn proceed(what: &str, available: bool) -> bool {
    if available {
        return true;
    }
    assert!(
        std::env::var_os(REQUIRE_VAR).is_none_or(|v| v != "1"),
        "no {what}, and {REQUIRE_VAR}=1 requires it"
    );
    eprintln!("skipped: no {what}, see docs/dev/development.md «Что нужно для тестов»");
    false
}

/// Whether this process is attached to a console, which a Ctrl-Break sent to a child of its
/// own process group needs: without one `GenerateConsoleCtrlEvent` fails.
#[cfg(windows)]
pub fn attached() -> bool {
    use windows_sys::Win32::System::Console::GetConsoleProcessList;
    let mut pid = 0u32;
    // SAFETY: a one-element buffer of the stated size; the call only counts the processes
    // that share the console (0 when there is none).
    unsafe { GetConsoleProcessList(&raw mut pid, 1) != 0 }
}

/// Whether a test may deliver Ctrl-Break to its child; see [`proceed`].
#[cfg(windows)]
pub fn ctrl_break_possible() -> bool {
    proceed("console to deliver CTRL_BREAK through", attached())
}

#[cfg(test)]
mod tests {
    use super::proceed;

    #[test]
    fn an_available_feature_proceeds() {
        assert!(proceed("anything", true));
    }
}
