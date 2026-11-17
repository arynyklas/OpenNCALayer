//! The windowed Windows build still writes to redirected output.
#![cfg(windows)]

use std::process::Command;

#[test]
fn version_reaches_a_pipe() {
    let output = Command::new(env!("CARGO_BIN_EXE_openncalayer"))
        .arg("--version")
        .output()
        .expect("start openncalayer");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains(env!("CARGO_PKG_VERSION")), "stdout: {text:?}");
}
