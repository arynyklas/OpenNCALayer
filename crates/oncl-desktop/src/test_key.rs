//! The registry sandbox of this crate's tests.

/// A key `HKCU\Software\OpenNCALayer-test-<pid>-<n>-<time>` for a test (nothing is created
/// until a value is written), deleted with its subkeys when dropped, also when the test
/// fails.
pub(crate) struct TestKey(String);

impl TestKey {
    /// A key no other test uses.
    pub(crate) fn new() -> TestKey {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        TestKey(format!(
            r"Software\OpenNCALayer-test-{:x}-{}-{nanos:x}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// The key's path under `HKEY_CURRENT_USER`.
    pub(crate) fn path(&self) -> &str {
        &self.0
    }
}

impl Drop for TestKey {
    fn drop(&mut self) {
        let _ = oncl_winreg::delete_tree(&self.0);
    }
}
