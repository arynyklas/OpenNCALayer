//! Registry values for OpenNCALayer: string, DWORD and binary values read under
//! `HKEY_CURRENT_USER` or `HKEY_LOCAL_MACHINE`, written and deleted under
//! `HKEY_CURRENT_USER` only. The registry exists on Windows only: elsewhere every function
//! fails with [`std::io::ErrorKind::Unsupported`].
//!
//! `key` is a path under the hive; a `None` value name is the key's default value. A key or
//! value that does not exist reads as `None`. Values are read in the 64-bit registry view of
//! 64-bit Windows ([`View::Wow64`]), by a 32-bit build as by a 64-bit one; [`value_exists`]
//! reads in either view. Writes and deletes go to this process's view of `HKCU`, where the
//! two views share `Software` (except `Software\Classes`).
//!
//! A key path or value name that contains NUL fails with
//! [`std::io::ErrorKind::InvalidInput`] (Windows would read only the part before it), and so
//! does an empty key path given to a write or a delete (it would name `HKCU` itself).

/// A predefined root key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hive {
    /// `HKEY_CURRENT_USER`.
    CurrentUser,
    /// `HKEY_LOCAL_MACHINE`, read only here.
    LocalMachine,
}

/// A registry view of 64-bit Windows, the same keys for a 32-bit and a 64-bit process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    /// The 64-bit programs' view (`KEY_WOW64_64KEY`); on 32-bit Windows, its only one.
    Wow64,
    /// The 32-bit programs' view (`KEY_WOW64_32KEY`), where `HKLM\Software` is the 64-bit
    /// view's `HKLM\Software\WOW6432Node`. 32-bit Windows has none: nothing exists in it.
    Wow32,
}

#[cfg(windows)]
pub use windows::{
    delete_tree, delete_value, get_binary, get_dword, get_string, set_binary, set_dword,
    set_string, value_exists,
};

#[cfg(not(windows))]
pub use elsewhere::{
    delete_tree, delete_value, get_binary, get_dword, get_string, set_binary, set_dword,
    set_string, value_exists,
};

#[cfg(windows)]
mod windows {
    use super::{Hive, View};
    use std::io;
    use std::iter::once;
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE,
        KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_BINARY, REG_DWORD, REG_OPTION_NON_VOLATILE,
        REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE, RRF_RT_DWORD, RRF_RT_REG_BINARY, RRF_RT_REG_SZ,
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyValueW, RegDeleteTreeW, RegGetValueW,
        RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    };
    use windows_sys::Win32::System::SystemInformation::{
        GetNativeSystemInfo, PROCESSOR_ARCHITECTURE, PROCESSOR_ARCHITECTURE_INTEL, SYSTEM_INFO,
    };

    /// The key path or value name `s` as a NUL-terminated UTF-16 string. Fails if `s`
    /// contains NUL: Windows would read only the part before it.
    fn wide(s: &str) -> io::Result<Vec<u16>> {
        if s.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a registry key path or value name cannot contain NUL",
            ));
        }
        Ok(s.encode_utf16().chain(once(0)).collect())
    }

    /// [`wide`] of an optional value name: `None` is the default value.
    fn wide_name(name: Option<&str>) -> io::Result<Option<Vec<u16>>> {
        name.map(wide).transpose()
    }

    /// [`wide`] of the key path of a write or a delete, which must not be empty: an empty
    /// path names the hive itself.
    fn subkey(key: &str) -> io::Result<Vec<u16>> {
        if key.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "an empty registry key path names the hive itself",
            ));
        }
        wide(key)
    }

    fn check(status: u32) -> io::Result<()> {
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            // Win32 error codes fit in i32.
            Err(io::Error::from_raw_os_error(status as i32))
        }
    }

    fn root(hive: Hive) -> HKEY {
        match hive {
            Hive::CurrentUser => HKEY_CURRENT_USER,
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
        }
    }

    /// The access flag that opens a key in `view`, for a process that is 64-bit or not
    /// (`process_64bit`) on Windows whose processor is `native`; `None` if that Windows has
    /// no such view. Windows on an x86 processor is 32-bit and has one view, opened without
    /// a flag; 64-bit Windows has both, and the flags name them for either process.
    fn view_access(
        view: View,
        process_64bit: bool,
        native: PROCESSOR_ARCHITECTURE,
    ) -> Option<REG_SAM_FLAGS> {
        let windows_64bit = process_64bit || native != PROCESSOR_ARCHITECTURE_INTEL;
        match (view, windows_64bit) {
            (View::Wow64, true) => Some(KEY_WOW64_64KEY),
            (View::Wow32, true) => Some(KEY_WOW64_32KEY),
            (View::Wow64, false) => Some(0),
            (View::Wow32, false) => None,
        }
    }

    /// [`view_access`] for this process on this Windows.
    pub(super) fn access_of(view: View) -> Option<REG_SAM_FLAGS> {
        view_access(view, cfg!(target_pointer_width = "64"), native_processor())
    }

    /// The processor Windows runs on, not the one this process is built for: x86
    /// (`PROCESSOR_ARCHITECTURE_INTEL`) for 32-bit Windows only. `GetNativeSystemInfo` exists
    /// since Windows XP; `IsWow64Process2` would need Windows 10.
    fn native_processor() -> PROCESSOR_ARCHITECTURE {
        let mut info = SYSTEM_INFO::default();
        // SAFETY: `info` is a writable SYSTEM_INFO, which the call fills.
        unsafe { GetNativeSystemInfo(&mut info) };
        // SAFETY: both arms of the union are plain integers; the processor is the
        // documented one.
        unsafe { info.Anonymous.Anonymous.wProcessorArchitecture }
    }

    /// An open key, closed when dropped.
    struct Key(HKEY);

    impl Key {
        /// `<hive>\<key>` opened for `access` in `view`; `None` if the key does not exist,
        /// or the view does not on this Windows.
        fn open(
            hive: Hive,
            key: &str,
            access: REG_SAM_FLAGS,
            view: View,
        ) -> io::Result<Option<Key>> {
            let key = wide(key)?;
            let Some(view) = access_of(view) else {
                return Ok(None);
            };
            let mut hkey: HKEY = ptr::null_mut();
            // SAFETY: `key` is NUL-terminated and outlives the call; `hkey` receives the key.
            match unsafe { RegOpenKeyExW(root(hive), key.as_ptr(), 0, access | view, &mut hkey) } {
                ERROR_FILE_NOT_FOUND => Ok(None),
                status => check(status).map(|()| Some(Key(hkey))),
            }
        }
    }

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the key was opened by `RegOpenKeyExW` or `RegCreateKeyExW`, and is
            // closed once, here.
            unsafe { RegCloseKey(self.0) };
        }
    }

    /// The bytes of value `name` of `<hive>\<key>` in the 64-bit view, of a type `flags`
    /// allows.
    fn get_bytes(
        hive: Hive,
        key: &str,
        name: Option<&str>,
        flags: u32,
    ) -> io::Result<Option<Vec<u8>>> {
        let name = wide_name(name)?;
        let Some(key) = Key::open(hive, key, KEY_QUERY_VALUE, View::Wow64)? else {
            return Ok(None);
        };
        let name = name.as_ref().map_or(ptr::null(), |n| n.as_ptr());
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let mut size = u32::try_from(buf.len()).unwrap_or(u32::MAX);
            let data = if buf.is_empty() {
                ptr::null_mut()
            } else {
                buf.as_mut_ptr().cast()
            };
            // SAFETY: `key` is open with KEY_QUERY_VALUE and the subkey is null (the key
            // itself); `name` is null (the default value) or NUL-terminated; `data` is null
            // (size query) or `buf`, whose size in bytes `size` holds.
            let status = unsafe {
                RegGetValueW(
                    key.0,
                    ptr::null(),
                    name,
                    flags,
                    ptr::null_mut(),
                    data,
                    &mut size,
                )
            };
            match status {
                ERROR_FILE_NOT_FOUND => return Ok(None),
                ERROR_SUCCESS if !buf.is_empty() || size == 0 => {
                    // `size` counts the bytes written.
                    buf.truncate(size as usize);
                    return Ok(Some(buf));
                }
                // The size query, or the value grew since it.
                ERROR_SUCCESS | ERROR_MORE_DATA => buf = vec![0; size as usize],
                status => return check(status).map(|()| None),
            }
        }
    }

    /// The string (`REG_SZ`) value `name` of `<hive>\<key>`.
    pub fn get_string(hive: Hive, key: &str, name: Option<&str>) -> io::Result<Option<String>> {
        let Some(bytes) = get_bytes(hive, key, name, RRF_RT_REG_SZ)? else {
            return Ok(None);
        };
        let mut units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        while units.last() == Some(&0) {
            units.pop();
        }
        String::from_utf16(&units)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// The `REG_DWORD` value `name` of `<hive>\<key>`.
    pub fn get_dword(hive: Hive, key: &str, name: Option<&str>) -> io::Result<Option<u32>> {
        let Some(bytes) = get_bytes(hive, key, name, RRF_RT_DWORD)? else {
            return Ok(None);
        };
        let bytes = <[u8; 4]>::try_from(bytes.as_slice())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not a DWORD"))?;
        Ok(Some(u32::from_le_bytes(bytes)))
    }

    /// The `REG_BINARY` value `name` of `<hive>\<key>`.
    pub fn get_binary(hive: Hive, key: &str, name: Option<&str>) -> io::Result<Option<Vec<u8>>> {
        get_bytes(hive, key, name, RRF_RT_REG_BINARY)
    }

    /// Whether value `name` of `<hive>\<key>` in `view` exists, of any type.
    pub fn value_exists(hive: Hive, key: &str, name: Option<&str>, view: View) -> io::Result<bool> {
        let name = wide_name(name)?;
        let Some(key) = Key::open(hive, key, KEY_QUERY_VALUE, view)? else {
            return Ok(false);
        };
        // SAFETY: `key` is open with KEY_QUERY_VALUE; the name is null (the default value)
        // or NUL-terminated; type, data and size are not asked for.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                name.as_ref().map_or(ptr::null(), |n| n.as_ptr()),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        match status {
            ERROR_FILE_NOT_FOUND => Ok(false),
            status => check(status).map(|()| true),
        }
    }

    /// Sets value `name` of `HKCU\<key>` to `data` of type `kind`, creating the key and its
    /// missing parents.
    fn set_bytes(
        key: &str,
        name: Option<&str>,
        kind: REG_VALUE_TYPE,
        data: &[u8],
    ) -> io::Result<()> {
        let key = subkey(key)?;
        let name = wide_name(name)?;
        let len = u32::try_from(data.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "registry value too long"))?;
        let mut hkey: HKEY = ptr::null_mut();
        // SAFETY: `key` is NUL-terminated and outlives the call; the class, security
        // attributes and disposition may be null; `hkey` receives the opened key.
        check(unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                ptr::null(),
                &mut hkey,
                ptr::null_mut(),
            )
        })?;
        let key = Key(hkey);
        // SAFETY: `key` is open with KEY_SET_VALUE; the name is null (the default value)
        // or NUL-terminated; `data` holds `len` bytes.
        check(unsafe {
            RegSetValueExW(
                key.0,
                name.as_ref().map_or(ptr::null(), |n| n.as_ptr()),
                0,
                kind,
                data.as_ptr(),
                len,
            )
        })
    }

    /// Sets value `name` of `HKCU\<key>` to the string `value` (`REG_SZ`).
    pub fn set_string(key: &str, name: Option<&str>, value: &str) -> io::Result<()> {
        // A NUL-terminated UTF-16 string, as REG_SZ wants.
        let data: Vec<u8> = value
            .encode_utf16()
            .chain(once(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        set_bytes(key, name, REG_SZ, &data)
    }

    /// Sets value `name` of `HKCU\<key>` to `value` (`REG_DWORD`).
    pub fn set_dword(key: &str, name: Option<&str>, value: u32) -> io::Result<()> {
        set_bytes(key, name, REG_DWORD, &value.to_le_bytes())
    }

    /// Sets value `name` of `HKCU\<key>` to `value` (`REG_BINARY`).
    pub fn set_binary(key: &str, name: Option<&str>, value: &[u8]) -> io::Result<()> {
        set_bytes(key, name, REG_BINARY, value)
    }

    /// Deletes value `name` of `HKCU\<key>`; `false` if it or the key did not exist.
    pub fn delete_value(key: &str, name: &str) -> io::Result<bool> {
        let (key, name) = (subkey(key)?, wide(name)?);
        // SAFETY: `key` and `name` are NUL-terminated and outlive the call.
        match unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), name.as_ptr()) } {
            ERROR_FILE_NOT_FOUND => Ok(false),
            status => check(status).map(|()| true),
        }
    }

    /// Deletes `HKCU\<key>` with its subkeys and values; `false` if it did not exist.
    pub fn delete_tree(key: &str) -> io::Result<bool> {
        delete_tree_under(HKEY_CURRENT_USER, key)
    }

    /// [`delete_tree`] under `parent`: a test passes a key of its own, so that a path the
    /// check lets through cannot empty `HKCU`.
    fn delete_tree_under(parent: HKEY, key: &str) -> io::Result<bool> {
        let key = subkey(key)?;
        // SAFETY: `parent` is a predefined or open key; `key` is NUL-terminated and
        // outlives the call.
        match unsafe { RegDeleteTreeW(parent, key.as_ptr()) } {
            ERROR_FILE_NOT_FOUND => Ok(false),
            status => check(status).map(|()| true),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::TestKey;
        use windows_sys::Win32::System::SystemInformation::{
            PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_ARM64,
        };

        #[test]
        fn views_by_process_and_windows() {
            let both = (Some(KEY_WOW64_64KEY), Some(KEY_WOW64_32KEY));
            for (process_64bit, native, expected) in [
                // 64-bit Windows: the same flags for a 64-bit and a 32-bit process.
                (true, PROCESSOR_ARCHITECTURE_AMD64, both),
                (true, PROCESSOR_ARCHITECTURE_ARM64, both),
                (false, PROCESSOR_ARCHITECTURE_AMD64, both),
                (false, PROCESSOR_ARCHITECTURE_ARM64, both),
                // 32-bit Windows: one view, opened without a flag; no 32-bit view.
                (false, PROCESSOR_ARCHITECTURE_INTEL, (Some(0), None)),
            ] {
                let access = |view| view_access(view, process_64bit, native);
                assert_eq!(
                    (access(View::Wow64), access(View::Wow32)),
                    expected,
                    "64-bit process: {process_64bit}, processor {native}"
                );
            }
        }

        #[test]
        fn nul_and_empty_paths_are_refused() {
            let invalid = |e: io::Error| e.kind() == io::ErrorKind::InvalidInput;
            let base = TestKey::new();
            set_string(base.path(), Some("v"), "kept").unwrap();
            // Cut at the NUL, each would name the test key or its value.
            let nul = format!("{}\0x", base.path());
            let (key, hkcu) = (base.path(), Hive::CurrentUser);
            assert!(get_string(hkcu, &nul, Some("v")).is_err_and(invalid));
            assert!(get_string(hkcu, key, Some("v\0x")).is_err_and(invalid));
            assert!(get_dword(hkcu, &nul, None).is_err_and(invalid));
            assert!(get_binary(hkcu, key, Some("v\0")).is_err_and(invalid));
            for view in [View::Wow64, View::Wow32] {
                assert!(value_exists(hkcu, &nul, Some("v"), view).is_err_and(invalid));
                assert!(value_exists(hkcu, key, Some("v\0x"), view).is_err_and(invalid));
            }
            assert!(set_string(&nul, Some("v"), "x").is_err_and(invalid));
            assert!(set_dword(key, Some("v\0x"), 1).is_err_and(invalid));
            assert!(set_binary(&nul, None, b"x").is_err_and(invalid));
            assert!(delete_value(&nul, "v").is_err_and(invalid));
            assert!(delete_value(key, "v\0x").is_err_and(invalid));
            assert!(delete_tree(&nul).is_err_and(invalid));
            assert_eq!(
                get_string(hkcu, key, Some("v")).unwrap().as_deref(),
                Some("kept")
            );

            // An empty path names HKCU itself: the writes and deletes refuse it. The empty
            // `delete_tree` runs under the test key, opened read-only: if the check let it
            // through, it would fail to empty the test key, not empty HKCU.
            let absent = format!("OpenNCALayer-test-absent-{}", std::process::id());
            assert!(set_string("", Some(&absent), "x").is_err_and(invalid));
            assert!(set_dword("", Some(&absent), 1).is_err_and(invalid));
            assert!(set_binary("", Some(&absent), b"x").is_err_and(invalid));
            assert!(delete_value("", &absent).is_err_and(invalid));
            let parent = Key::open(hkcu, key, KEY_QUERY_VALUE, View::Wow64)
                .unwrap()
                .unwrap();
            assert!(delete_tree_under(parent.0, "").is_err_and(invalid));
            drop(parent);
            assert!(value_exists(hkcu, key, Some("v"), View::Wow64).unwrap());
        }
    }
}

#[cfg(not(windows))]
mod elsewhere {
    use super::{Hive, View};
    use std::io;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "the registry exists on Windows only",
        )
    }

    /// Fails: no registry.
    pub fn get_string(_hive: Hive, _key: &str, _name: Option<&str>) -> io::Result<Option<String>> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn get_dword(_hive: Hive, _key: &str, _name: Option<&str>) -> io::Result<Option<u32>> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn get_binary(_hive: Hive, _key: &str, _name: Option<&str>) -> io::Result<Option<Vec<u8>>> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn value_exists(
        _hive: Hive,
        _key: &str,
        _name: Option<&str>,
        _view: View,
    ) -> io::Result<bool> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn set_string(_key: &str, _name: Option<&str>, _value: &str) -> io::Result<()> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn set_dword(_key: &str, _name: Option<&str>, _value: u32) -> io::Result<()> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn set_binary(_key: &str, _name: Option<&str>, _value: &[u8]) -> io::Result<()> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn delete_value(_key: &str, _name: &str) -> io::Result<bool> {
        Err(unsupported())
    }

    /// Fails: no registry.
    pub fn delete_tree(_key: &str) -> io::Result<bool> {
        Err(unsupported())
    }
}

/// A key `HKCU\Software\OpenNCALayer-test-<pid>-<n>-<time>` for a test (nothing is created
/// until a value is written), deleted with its subkeys when dropped, also when the test
/// fails.
#[cfg(all(windows, any(test, feature = "testing")))]
pub struct TestKey(String);

#[cfg(all(windows, any(test, feature = "testing")))]
impl TestKey {
    /// A key no other test uses.
    pub fn new() -> TestKey {
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
    pub fn path(&self) -> &str {
        &self.0
    }
}

#[cfg(all(windows, any(test, feature = "testing")))]
impl Default for TestKey {
    fn default() -> Self {
        TestKey::new()
    }
}

#[cfg(all(windows, any(test, feature = "testing")))]
impl Drop for TestKey {
    fn drop(&mut self) {
        let _ = delete_tree(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn values_under_a_test_key() {
        let base = TestKey::new();
        let key = format!(r"{}\Sub", base.path());
        let hkcu = Hive::CurrentUser;
        assert_eq!(get_string(hkcu, &key, Some("v")).unwrap(), None);
        assert_eq!(get_dword(hkcu, &key, Some("d")).unwrap(), None);
        assert_eq!(get_binary(hkcu, &key, Some("b")).unwrap(), None);
        assert!(!delete_value(&key, "v").unwrap());

        set_string(&key, Some("v"), "named").unwrap();
        set_string(&key, None, &"д".repeat(300)).unwrap();
        set_string(&key, Some("empty"), "").unwrap();
        set_dword(&key, Some("d"), 0x0102_0304).unwrap();
        set_binary(&key, Some("b"), &[3, 0, 0, 0, 9]).unwrap();
        set_binary(&key, Some("b0"), &[]).unwrap();
        assert_eq!(
            get_string(hkcu, &key, Some("v")).unwrap().as_deref(),
            Some("named")
        );
        assert_eq!(get_string(hkcu, &key, None).unwrap(), Some("д".repeat(300)));
        assert_eq!(
            get_string(hkcu, &key, Some("empty")).unwrap().as_deref(),
            Some("")
        );
        assert_eq!(get_dword(hkcu, &key, Some("d")).unwrap(), Some(0x0102_0304));
        assert_eq!(
            get_binary(hkcu, &key, Some("b")).unwrap(),
            Some(vec![3, 0, 0, 0, 9])
        );
        assert_eq!(get_binary(hkcu, &key, Some("b0")).unwrap(), Some(vec![]));
        // A value of another type is an error, not a misread.
        assert!(get_dword(hkcu, &key, Some("v")).is_err());
        assert!(get_string(hkcu, &key, Some("d")).is_err());

        // Any type; `HKCU\Software` is the same in both views of 64-bit Windows, and
        // 32-bit Windows has no 32-bit view.
        for view in [View::Wow64, View::Wow32] {
            let in_view = windows::access_of(view).is_some();
            for name in [Some("v"), Some("d"), Some("b0"), None] {
                assert_eq!(
                    value_exists(hkcu, &key, name, view).unwrap(),
                    in_view,
                    "{name:?} {view:?}"
                );
            }
            assert!(!value_exists(hkcu, &key, Some("missing"), view).unwrap());
            assert!(!value_exists(hkcu, &format!(r"{key}\No"), Some("v"), view).unwrap());
        }
        assert!(delete_value(&key, "v").unwrap());
        assert_eq!(get_string(hkcu, &key, Some("v")).unwrap(), None);
        assert!(get_string(hkcu, &key, None).unwrap().is_some());

        assert!(delete_tree(base.path()).unwrap());
        assert!(!delete_tree(base.path()).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn local_machine_is_readable() {
        // Present on every Windows installation.
        let root = get_string(
            Hive::LocalMachine,
            r"Software\Microsoft\Windows NT\CurrentVersion",
            Some("SystemRoot"),
        )
        .unwrap();
        assert!(root.is_some_and(|r| !r.is_empty()));
    }

    /// 64-bit Windows keeps `ProgramFilesDir` in both views: `Program Files` in the 64-bit
    /// one, as `ProgramW6432Dir`, and `Program Files (x86)` in the 32-bit one. An x86 build
    /// reads the 64-bit one as an x64 build does.
    #[cfg(windows)]
    #[test]
    fn values_are_read_in_the_64bit_view() {
        if windows::access_of(View::Wow32).is_none() {
            return; // 32-bit Windows: one view.
        }
        let dir = |name| {
            get_string(
                Hive::LocalMachine,
                r"Software\Microsoft\Windows\CurrentVersion",
                Some(name),
            )
            .unwrap()
        };
        let program_files = dir("ProgramW6432Dir");
        assert!(program_files.as_deref().is_some_and(|d| !d.is_empty()));
        assert_eq!(dir("ProgramFilesDir"), program_files);
    }

    #[cfg(not(windows))]
    #[test]
    fn no_registry_elsewhere() {
        use std::io;

        let unsupported = |e: io::Error| e.kind() == io::ErrorKind::Unsupported;
        let hkcu = Hive::CurrentUser;
        assert!(get_string(hkcu, "k", None).is_err_and(unsupported));
        assert!(get_dword(hkcu, "k", None).is_err_and(unsupported));
        assert!(get_binary(hkcu, "k", None).is_err_and(unsupported));
        assert!(value_exists(hkcu, "k", None, View::Wow32).is_err_and(unsupported));
        assert!(set_string("k", None, "v").is_err_and(unsupported));
        assert!(set_dword("k", None, 1).is_err_and(unsupported));
        assert!(set_binary("k", None, b"").is_err_and(unsupported));
        assert!(delete_value("k", "v").is_err_and(unsupported));
        assert!(delete_tree("k").is_err_and(unsupported));
    }
}
