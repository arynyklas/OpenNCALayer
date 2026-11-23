//! The system's proxy of [`ProxySetting::System`](super::ProxySetting::System).

use ureq::Proxy;

/// The system's proxy for a request to `url`: the environment's (whose `NO_PROXY` the
/// caller applies), otherwise on Windows the manual proxy of the Internet Options unless
/// they bypass `url`'s host. `None`: connect directly.
pub(super) fn for_url(url: &str) -> Option<Proxy> {
    Proxy::try_from_env().or_else(|| os_proxy(url))
}

#[cfg(windows)]
fn os_proxy(url: &str) -> Option<Proxy> {
    let uri = url.parse::<ureq::http::Uri>().ok()?;
    let scheme = uri.scheme_str()?;
    let port = uri.port_u16().or(match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    })?;
    let options = windows::internet_options(&windows::Keys::system())?;
    let proxy = options.proxy_for(scheme, uri.host()?, port)?;
    Proxy::new(&proxy).ok()
}

#[cfg(not(windows))]
fn os_proxy(_url: &str) -> Option<Proxy> {
    None
}

/// The manual proxy of the Windows Internet Options, when it is on.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
struct InternetOptions {
    /// `ProxyServer`: `host:port` for every scheme, or `scheme=host:port` entries separated
    /// by `;`.
    server: String,
    /// `ProxyOverride`: patterns separated by `;` of a host, optionally with a scheme
    /// (`http://`) before and a port (`:8080`) after it, `*` matching any characters;
    /// `<local>` stands for every host name without a dot, `<-loopback>` sends loopback
    /// requests through the proxy too.
    bypass: Option<String>,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl InternetOptions {
    /// The proxy URL for a request with `scheme` to `host` and `port`; `None` if the request
    /// bypasses the proxy (loopback hosts do, as in Windows, unless `<-loopback>` is listed)
    /// or no entry covers `scheme`.
    fn proxy_for(&self, scheme: &str, host: &str, port: u16) -> Option<String> {
        let bypass = self.bypass.as_deref().unwrap_or_default();
        let proxied_loopback = bypass
            .split(';')
            .any(|p| p.trim().eq_ignore_ascii_case("<-loopback>"));
        if (loopback(host) && !proxied_loopback) || bypassed(bypass, scheme, host, port) {
            return None;
        }
        let mut common = None;
        let mut per_scheme = false;
        for entry in self.server.split(';').map(str::trim) {
            match entry.split_once('=') {
                Some((key, value)) => {
                    per_scheme = true;
                    let value = value.trim();
                    if key.trim().eq_ignore_ascii_case(scheme) && !value.is_empty() {
                        return Some(with_scheme(value));
                    }
                }
                None if !entry.is_empty() => common = common.or(Some(entry)),
                None => {}
            }
        }
        if per_scheme {
            None
        } else {
            common.map(with_scheme)
        }
    }
}

/// Whether `host` (as in a URL: IPv6 in brackets) is `localhost` or a loopback address.
#[cfg_attr(not(windows), allow(dead_code))]
fn loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// `proxy` as a URL: `http://` unless it names a scheme (the entries of `ProxyServer` are
/// HTTP proxies, `https=` included: HTTPS goes through them as a tunnel). A scheme other
/// than `http://` is refused by the caller.
#[cfg_attr(not(windows), allow(dead_code))]
fn with_scheme(proxy: &str) -> String {
    if proxy.contains("://") {
        proxy.to_owned()
    } else {
        format!("http://{proxy}")
    }
}

/// Whether a pattern of the `ProxyOverride` list `bypass` matches a request with `scheme`
/// to `host` and `port`, ignoring case.
#[cfg_attr(not(windows), allow(dead_code))]
fn bypassed(bypass: &str, scheme: &str, host: &str, port: u16) -> bool {
    let host = host.to_ascii_lowercase();
    bypass
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .any(|p| {
            if p.eq_ignore_ascii_case("<local>") {
                // A name without a dot; IPv6 addresses (with colons) are not local names.
                return !host.contains(['.', ':']);
            }
            let p = p.to_ascii_lowercase();
            let (p_scheme, rest) = match p.split_once("://") {
                Some((s, rest)) => (Some(s), rest),
                None => (None, p.as_str()),
            };
            // A port after the last colon, unless that colon is inside a bare IPv6 address.
            let (p_host, p_port) = match rest.rsplit_once(':') {
                Some((h, port))
                    if !port.is_empty()
                        && port.bytes().all(|b| b.is_ascii_digit())
                        && (!h.contains(':') || h.ends_with(']')) =>
                {
                    (h, port.parse::<u16>().ok())
                }
                _ => (rest, None),
            };
            p_scheme.is_none_or(|s| s.eq_ignore_ascii_case(scheme))
                && p_port.is_none_or(|p| p == port)
                && wildcard_match(p_host.as_bytes(), host.as_bytes())
        })
}

/// Whether `text` matches `pattern`, where `*` matches any run of bytes.
#[cfg_attr(not(windows), allow(dead_code))]
fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    // The last `*` seen and the text position its run of matched bytes ends at.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                // Let the last `*` take one more byte.
                Some((star_p, star_t)) => {
                    p = star_p + 1;
                    t = star_t + 1;
                    star = Some((star_p, star_t + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

/// The Internet Options in the registry, read only.
#[cfg(windows)]
mod windows {
    use super::InternetOptions;
    use std::ptr;
    use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, REG_ROUTINE_FLAGS, RRF_RT_DWORD,
        RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegGetValueW,
    };

    const SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const POLICY: &str = r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";

    /// Where the options are: the policy choosing per-user or per-machine settings, and
    /// those two.
    pub(super) struct Keys {
        policy: (HKEY, String),
        user: (HKEY, String),
        machine: (HKEY, String),
    }

    impl Keys {
        /// The real keys: the policy and the machine's settings in `HKLM`, the user's in
        /// `HKCU`.
        pub(super) fn system() -> Keys {
            Keys {
                policy: (HKEY_LOCAL_MACHINE, POLICY.to_owned()),
                user: (HKEY_CURRENT_USER, SETTINGS.to_owned()),
                machine: (HKEY_LOCAL_MACHINE, SETTINGS.to_owned()),
            }
        }

        /// All three under `HKCU\<root>\HKCU` and `HKCU\<root>\HKLM`, for tests.
        #[cfg(test)]
        pub(super) fn sandbox(root: &str) -> Keys {
            let hkcu = HKEY_CURRENT_USER;
            Keys {
                policy: (hkcu, format!(r"{root}\HKLM\{POLICY}")),
                user: (hkcu, format!(r"{root}\HKCU\{SETTINGS}")),
                machine: (hkcu, format!(r"{root}\HKLM\{SETTINGS}")),
            }
        }
    }

    /// The manual proxy, if `ProxyEnable` is set and `ProxyServer` names one: the
    /// machine's when the policy `ProxySettingsPerUser` is 0, otherwise the user's. A value
    /// that cannot be read counts as missing.
    pub(super) fn internet_options(keys: &Keys) -> Option<InternetOptions> {
        let (policy_root, policy) = &keys.policy;
        let per_user = get_dword(*policy_root, policy, "ProxySettingsPerUser") != Some(0);
        let (root, key) = if per_user { &keys.user } else { &keys.machine };
        if get_dword(*root, key, "ProxyEnable").unwrap_or(0) == 0 {
            return None;
        }
        Some(InternetOptions {
            server: get_string(*root, key, "ProxyServer")?,
            bypass: get_string(*root, key, "ProxyOverride"),
        })
    }

    /// The `REG_DWORD` value `name` of `<root>\<key>`.
    fn get_dword(root: HKEY, key: &str, name: &str) -> Option<u32> {
        let bytes = get_bytes(root, key, name, RRF_RT_DWORD)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    /// The string (`REG_SZ`) value `name` of `<root>\<key>`, without its terminating NULs.
    fn get_string(root: HKEY, key: &str, name: &str) -> Option<String> {
        let bytes = get_bytes(root, key, name, RRF_RT_REG_SZ)?;
        let mut units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        while units.last() == Some(&0) {
            units.pop();
        }
        String::from_utf16(&units).ok()
    }

    /// The bytes of value `name` of `<root>\<key>`, of a type `flags` allows, read in the
    /// 64-bit registry view of 64-bit Windows by a 32-bit build too (32-bit Windows ignores
    /// the flag). `None` if the key or the value does not exist, has another type or cannot
    /// be read, or a path contains NUL (Windows would read only the part before it).
    fn get_bytes(root: HKEY, key: &str, name: &str, flags: REG_ROUTINE_FLAGS) -> Option<Vec<u8>> {
        let wide = |s: &str| {
            (!s.contains('\0')).then(|| s.encode_utf16().chain([0]).collect::<Vec<u16>>())
        };
        let (key, name) = (wide(key)?, wide(name)?);
        let mut buf = vec![0_u8; 256];
        loop {
            let mut size = u32::try_from(buf.len()).ok()?;
            // SAFETY: `root` is a predefined key; `key` and `name` are NUL-terminated and
            // outlive the call; `buf` is writable for `size` bytes; the type is not asked for.
            let status = unsafe {
                RegGetValueW(
                    root,
                    key.as_ptr(),
                    name.as_ptr(),
                    flags | RRF_SUBKEY_WOW6464KEY,
                    ptr::null_mut(),
                    buf.as_mut_ptr().cast(),
                    &mut size,
                )
            };
            match status {
                // `size` counts the bytes written.
                ERROR_SUCCESS => {
                    buf.truncate(size as usize);
                    return Some(buf);
                }
                // The value is longer than `buf`: `size` is its length.
                ERROR_MORE_DATA if size as usize > buf.len() => buf.resize(size as usize, 0),
                _ => return None,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use oncl_winreg::{Hive, delete_tree, set_dword, set_string};

        /// A key `HKCU\Software\OpenNCALayer-test-<pid>-<n>-<time>` (nothing is created until
        /// a value is written), deleted with its subkeys when dropped, also when the test
        /// fails.
        struct TestKey(String);

        impl TestKey {
            fn new() -> TestKey {
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
        }

        impl Drop for TestKey {
            fn drop(&mut self) {
                let _ = delete_tree(&self.0);
            }
        }

        #[test]
        fn options_are_read_from_the_user_or_the_machine() {
            let root = TestKey::new();
            let keys = Keys::sandbox(&root.0);
            let (user, machine, policy) = (&keys.user.1, &keys.machine.1, &keys.policy.1);
            assert_eq!(internet_options(&keys), None);

            set_string(user, Some("ProxyServer"), "user:3128").unwrap();
            assert_eq!(internet_options(&keys), None, "ProxyEnable is not set");
            set_dword(user, Some("ProxyEnable"), 0).unwrap();
            assert_eq!(internet_options(&keys), None);
            set_dword(user, Some("ProxyEnable"), 1).unwrap();
            assert_eq!(
                internet_options(&keys),
                Some(InternetOptions {
                    server: "user:3128".to_owned(),
                    bypass: None
                })
            );
            set_string(user, Some("ProxyOverride"), "<local>").unwrap();
            assert_eq!(
                internet_options(&keys).unwrap().bypass.as_deref(),
                Some("<local>")
            );

            // The per-machine policy: the machine's settings, even if they are off.
            set_dword(policy, Some("ProxySettingsPerUser"), 0).unwrap();
            assert_eq!(internet_options(&keys), None);
            set_dword(machine, Some("ProxyEnable"), 1).unwrap();
            set_string(machine, Some("ProxyServer"), "http=machine:8080").unwrap();
            assert_eq!(
                internet_options(&keys),
                Some(InternetOptions {
                    server: "http=machine:8080".to_owned(),
                    bypass: None
                })
            );
            set_dword(policy, Some("ProxySettingsPerUser"), 1).unwrap();
            assert_eq!(internet_options(&keys).unwrap().server, "user:3128");
            // A value of the wrong type counts as missing.
            set_string(user, Some("ProxyEnable"), "1").unwrap();
            assert_eq!(internet_options(&keys), None);
        }

        /// The reader returns what the programs' registry crate reads, in the same view, for
        /// every value the proxy needs, and nothing where that crate reads nothing or fails.
        #[test]
        fn values_read_as_the_programs_registry_crate_reads_them() {
            let root = TestKey::new();
            let key = format!(r"{}\Values", root.0);
            set_string(&key, Some("s"), "proxy.corp:3128").unwrap();
            set_string(&key, Some("empty"), "").unwrap();
            set_string(&key, Some("long"), &"д".repeat(300)).unwrap();
            set_dword(&key, Some("d"), 0x0102_0304).unwrap();
            let shared_string = |hive, key: &str, name| {
                oncl_winreg::get_string(hive, key, Some(name))
                    .ok()
                    .flatten()
            };
            let shared_dword = |hive, key: &str, name| {
                oncl_winreg::get_dword(hive, key, Some(name)).ok().flatten()
            };
            let missing = format!(r"{key}\Missing");
            for (k, name) in [
                (key.as_str(), "s"),
                (&key, "empty"),
                (&key, "long"),
                (&key, "d"),
                (&key, "absent"),
                (&missing, "s"),
            ] {
                let hkcu = HKEY_CURRENT_USER;
                assert_eq!(
                    get_string(hkcu, k, name),
                    shared_string(Hive::CurrentUser, k, name),
                    "{k} {name}"
                );
                assert_eq!(
                    get_dword(hkcu, k, name),
                    shared_dword(Hive::CurrentUser, k, name),
                    "{k} {name}"
                );
            }
            assert_eq!(
                get_string(HKEY_CURRENT_USER, &key, "long"),
                Some("д".repeat(300))
            );
            assert_eq!(get_dword(HKEY_CURRENT_USER, &key, "d"), Some(0x0102_0304));

            // `HKLM`, in the 64-bit view of 64-bit Windows: there `ProgramFilesDir` is
            // `Program Files`, in the 32-bit view `Program Files (x86)`.
            let current = r"Software\Microsoft\Windows\CurrentVersion";
            let nt = r"Software\Microsoft\Windows NT\CurrentVersion";
            for (k, name) in [(nt, "SystemRoot"), (current, "ProgramFilesDir")] {
                let value = get_string(HKEY_LOCAL_MACHINE, k, name);
                assert!(
                    value.as_deref().is_some_and(|v| !v.is_empty()),
                    "{k} {name}"
                );
                assert_eq!(
                    value,
                    shared_string(Hive::LocalMachine, k, name),
                    "{k} {name}"
                );
            }
            // `Program Files (x86)` would mean the 32-bit view; 32-bit Windows has only
            // `Program Files`.
            let program_files = get_string(HKEY_LOCAL_MACHINE, current, "ProgramFilesDir");
            assert!(
                program_files
                    .as_deref()
                    .is_some_and(|v| !v.ends_with("(x86)")),
                "{program_files:?}"
            );
            assert_eq!(
                get_string(HKEY_CURRENT_USER, &format!("{key}\0x"), "s"),
                None
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(server: &str, bypass: Option<&str>) -> InternetOptions {
        InternetOptions {
            server: server.to_owned(),
            bypass: bypass.map(str::to_owned),
        }
    }

    #[test]
    fn one_proxy_serves_every_scheme() {
        let o = options("proxy.corp:3128", None);
        let proxy = Some("http://proxy.corp:3128".to_owned());
        assert_eq!(o.proxy_for("http", "tsp.pki.gov.kz", 80), proxy);
        assert_eq!(o.proxy_for("https", "tsp.pki.gov.kz", 443), proxy);
        assert_eq!(
            options("socks5://proxy.corp:1080", None).proxy_for("http", "x.kz", 80),
            Some("socks5://proxy.corp:1080".to_owned())
        );
        assert_eq!(options(" ; ", None).proxy_for("http", "x.kz", 80), None);
    }

    #[test]
    fn per_scheme_entries_pick_the_request_scheme() {
        let o = options("HTTP=web:80; https=secure:8443;ftp=f:21;socks=s:1080", None);
        assert_eq!(
            o.proxy_for("http", "x.kz", 80),
            Some("http://web:80".to_owned())
        );
        assert_eq!(
            o.proxy_for("https", "x.kz", 443),
            Some("http://secure:8443".to_owned())
        );
        // A scheme without an entry goes directly.
        let o = options("https=secure:8443", None);
        assert_eq!(o.proxy_for("http", "x.kz", 80), None);
        assert_eq!(options("http=", None).proxy_for("http", "x.kz", 80), None);
    }

    #[test]
    fn bypass_list_skips_the_proxy() {
        let o = options("p:1", Some("<local>;*.gov.kz; 10.0.*;EXACT.example"));
        assert_eq!(o.proxy_for("http", "intranet", 80), None);
        assert_eq!(o.proxy_for("http", "tsp.pki.gov.kz", 80), None);
        assert_eq!(o.proxy_for("http", "10.0.3.4", 80), None);
        assert_eq!(o.proxy_for("http", "exact.example", 80), None);
        let proxy = Some("http://p:1".to_owned());
        assert_eq!(o.proxy_for("http", "gov.kz.evil.com", 80), proxy);
        assert_eq!(o.proxy_for("http", "sub.exact.example", 80), proxy);
        assert_eq!(o.proxy_for("http", "10.1.0.4", 80), proxy);
        // `<local>` is about names: an IPv6 address has no dot but is not one.
        assert_eq!(o.proxy_for("http", "[2001:db8::1]", 80), proxy);
    }

    #[test]
    fn bypass_patterns_with_scheme_and_port() {
        let o = options(
            "p:1",
            Some("http://*.corp; *.svc:8080; [2001:db8::1]:81; 2001:db8::2"),
        );
        let proxy = Some("http://p:1".to_owned());
        assert_eq!(o.proxy_for("http", "a.corp", 80), None);
        assert_eq!(o.proxy_for("https", "a.corp", 443), proxy);
        assert_eq!(o.proxy_for("http", "a.svc", 8080), None);
        assert_eq!(o.proxy_for("http", "a.svc", 80), proxy);
        assert_eq!(o.proxy_for("http", "[2001:db8::1]", 81), None);
        assert_eq!(o.proxy_for("http", "[2001:db8::1]", 80), proxy);
        // A bare IPv6 address: its last group is not a port.
        assert_eq!(o.proxy_for("http", "2001:db8::2", 80), None);
    }

    #[test]
    fn loopback_bypasses_unless_listed() {
        let o = options("p:1", None);
        for host in ["localhost", "LocalHost", "127.0.0.1", "127.8.9.10", "[::1]"] {
            assert_eq!(o.proxy_for("http", host, 80), None, "{host}");
        }
        assert_eq!(
            o.proxy_for("http", "localhost.kz", 80),
            Some("http://p:1".to_owned())
        );
        let o = options("p:1", Some("*.kz; <-Loopback>"));
        assert_eq!(
            o.proxy_for("http", "127.0.0.1", 80),
            Some("http://p:1".to_owned())
        );
        assert_eq!(o.proxy_for("http", "x.kz", 80), None);
    }

    #[test]
    fn wildcards() {
        let m = |p: &str, t: &str| wildcard_match(p.as_bytes(), t.as_bytes());
        assert!(m("*", ""));
        assert!(m("a*c", "abbbc"));
        assert!(m("*.kz", "a.b.kz"));
        assert!(m("a**", "a"));
        assert!(m("*b*b", "abab"));
        assert!(!m("a*c", "abcd"));
        assert!(!m("", "a"));
        assert!(!m("*.kz", "kz"));
    }
}
