//! External programs the tests run (OpenSSL, Python, Java's `keytool`, Git): where to find
//! them and one message for their absence.
//!
//! A test that needs a program which is not installed fails; it is never skipped. The failure
//! says which executable names were tried, which environment variable overrides them, which
//! package provides the program and where the list of everything the tests need is kept, so a
//! contributor does not have to read test code to learn what to put on `PATH`.
//!
//! Lookup order, where a program has an override: the override variable, then the executable
//! names on `PATH` (on Windows the OpenSSL of Git for Windows last).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Where the dependencies of the tests are listed.
const DOCS: &str = "docs/dev/development.md, section «Что нужно для тестов»";

/// Environment variable naming the OpenSSL executable.
pub const OPENSSL_ENV: &str = "ONCL_OPENSSL";
/// Environment variable naming the Python interpreter of the independent checks.
pub const PYTHON_ENV: &str = "ONCL_PYHANKO_PYTHON";

/// What provides a Python with the modules of the independent checks.
const PYTHON_PROVIDES: &str = "Python 3 with the modules the check imports; the virtual \
    environment of CI comes from `pip install -r xtask/assets/oracle/requirements.txt` \
    (pyHanko, pyhanko-certvalidator, lxml, cryptography)";

/// Message for a program the tests need and cannot find: the executable names tried, the
/// override variable (with its current value), what provides the program and the document
/// listing the test dependencies.
#[must_use]
pub fn message(tried: &[String], env: Option<&str>, provides: &str) -> String {
    let names = tried
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut text =
        format!("a program the tests need is not installed. Executables tried: {names}.");
    if let Some(var) = env {
        match std::env::var_os(var) {
            Some(value) => {
                let _ = write!(
                    text,
                    " Override: {var} is set to `{}` (set it to a working executable).",
                    value.to_string_lossy()
                );
            }
            None => {
                let _ = write!(
                    text,
                    " Override: set {var} to the path of the executable (it is not set)."
                );
            }
        }
    }
    let _ = write!(text, " Provided by: {provides}. See {DOCS}.");
    text
}

/// Fails the running test with [`message`]. The test is not skipped.
///
/// # Panics
///
/// Always.
pub fn missing(tried: &[String], env: Option<&str>, provides: &str) -> ! {
    panic!("{}", message(tried, env, provides));
}

/// A program that is run by name.
#[derive(Clone, Copy, Debug)]
pub struct Tool {
    /// Executable names tried on `PATH`, in order.
    pub names: &'static [&'static str],
    /// Environment variable that names the executable, tried first.
    pub env: Option<&'static str>,
    /// What provides it.
    pub provides: &'static str,
}

/// OpenSSL 3 (with `cms`, `ts` and `dgst`).
pub const OPENSSL: Tool = Tool {
    names: &["openssl"],
    env: Some(OPENSSL_ENV),
    provides: "OpenSSL 3 (Linux: the `openssl` package; macOS: `brew install openssl@3`; \
        Windows: Git for Windows, whose `usr/bin/openssl.exe` is found by itself, or any \
        OpenSSL 3 build)",
};

/// Java's `keytool`.
pub const KEYTOOL: Tool = Tool {
    names: &["keytool"],
    env: None,
    provides: "a JDK: keytool is in its bin/ directory, which must be on PATH",
};

/// Git.
pub const GIT: Tool = Tool {
    names: &["git"],
    env: None,
    provides: "Git (https://git-scm.com/)",
};

/// NSS's `certutil` (the Linux trust-store tests).
pub const CERTUTIL: Tool = Tool {
    names: &["certutil"],
    env: None,
    provides: "the NSS tools (Debian/Ubuntu: `libnss3-tools`; Fedora: `nss-tools`)",
};

/// A Python 3 whose standard library is all a script needs; any interpreter will do.
pub const PYTHON_STDLIB: Tool = Tool {
    names: &["python", "python3", "py"],
    env: Some(PYTHON_ENV),
    provides: "Python 3 (any interpreter; the standard library is enough for this check)",
};

/// A Python 3 that has to import extra modules; see [`python_with`].
const PYTHON: Tool = Tool {
    names: &["python", "python3", "py"],
    env: Some(PYTHON_ENV),
    provides: PYTHON_PROVIDES,
};

impl Tool {
    /// The candidates in lookup order: the override variable's value, the names, and for
    /// OpenSSL on Windows the copy inside Git for Windows.
    #[must_use]
    pub fn candidates(&self) -> Vec<String> {
        let mut found = Vec::new();
        if let Some(value) = self.env.and_then(|var| std::env::var(var).ok()) {
            found.push(value);
        }
        found.extend(self.names.iter().map(|name| (*name).to_owned()));
        if cfg!(windows) && self.names == ["openssl"] {
            for var in ["ProgramFiles", "ProgramW6432"] {
                if let Some(base) = std::env::var_os(var) {
                    found.push(
                        Path::new(&base)
                            .join("Git/usr/bin/openssl.exe")
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
            }
        }
        let mut unique: Vec<String> = Vec::with_capacity(found.len());
        for candidate in found {
            if !unique.contains(&candidate) {
                unique.push(candidate);
            }
        }
        unique
    }

    /// The first candidate for which `<candidate> <probe args>` exits successfully.
    #[must_use]
    pub fn find(&self, probe: &[&str]) -> Option<String> {
        self.candidates().into_iter().find(|candidate| {
            Command::new(candidate)
                .args(probe)
                .stdin(Stdio::null())
                .output()
                .is_ok_and(|output| output.status.success())
        })
    }

    /// Like [`Tool::find`], failing the test with [`message`] when nothing works.
    ///
    /// # Panics
    ///
    /// If no candidate runs.
    #[must_use]
    pub fn require(&self, probe: &[&str]) -> String {
        self.find(probe)
            .unwrap_or_else(|| missing(&self.candidates(), self.env, self.provides))
    }

    /// The result of running the tool by its first name (`Command::new(name)….output()`),
    /// failing the test with [`message`] when the program cannot be started because it is not
    /// there. Any other I/O error is reported as it is.
    ///
    /// # Panics
    ///
    /// If the program is not installed or could not be run.
    pub fn spawned<T>(&self, result: std::io::Result<T>) -> T {
        match result {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing(&self.candidates(), self.env, self.provides)
            }
            Err(error) => panic!("cannot run `{}`: {error}", self.names[0]),
        }
    }
}

/// The OpenSSL executable: [`OPENSSL_ENV`], `openssl` on `PATH`, then (Windows) the copy in
/// Git for Windows.
///
/// # Panics
///
/// If none of them runs `openssl version`.
#[must_use]
pub fn openssl() -> String {
    OPENSSL.require(&["version"])
}

/// A Python that imports `modules` (for example `"lxml, cryptography"`): [`PYTHON_ENV`]
/// first (the virtual environment of CI and of `xtask`), then `python`, `python3` and `py`
/// on `PATH`, which on a CI runner have no lxml.
#[must_use]
pub fn python_with(modules: &str) -> Option<String> {
    PYTHON.find(&["-c", &format!("import {modules}")])
}

/// Message for the absence of a Python that imports `modules`; see [`message`].
#[must_use]
pub fn python_missing_message(modules: &str) -> String {
    message(
        &PYTHON.candidates(),
        PYTHON.env,
        &format!("{PYTHON_PROVIDES}. This check imports: {modules}"),
    )
}

/// [`python_with`], failing the test with [`python_missing_message`] when there is none.
///
/// # Panics
///
/// If no Python imports `modules`.
#[must_use]
pub fn require_python(modules: &str) -> String {
    python_with(modules).unwrap_or_else(|| panic!("{}", python_missing_message(modules)))
}

/// Any working Python 3, for scripts that use only the standard library.
///
/// # Panics
///
/// If no Python runs.
#[must_use]
pub fn python() -> String {
    PYTHON_STDLIB.require(&["--version"])
}

/// The interpreter [`PYTHON_ENV`] names, for the checks that need pyHanko and must not run
/// with whichever `python` is first on `PATH` (it has no pyHanko or lxml on a CI runner).
///
/// # Panics
///
/// If the variable is unset or does not name an existing file.
#[must_use]
pub fn pyhanko_python() -> PathBuf {
    std::env::var_os(PYTHON_ENV)
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .unwrap_or_else(|| {
            missing(
                &[std::env::var(PYTHON_ENV)
                    .unwrap_or_else(|_| format!("<{PYTHON_ENV} is not set>"))],
                Some(PYTHON_ENV),
                &format!(
                    "{PYTHON_PROVIDES}. There is no PATH fallback: {PYTHON_ENV} must name \
                     that environment's python executable"
                ),
            )
        })
}

/// The `keytool` executable of a JDK.
///
/// # Panics
///
/// If `keytool` does not run.
#[must_use]
pub fn keytool() -> String {
    KEYTOOL.require(&["-help"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_names_executables_variable_package_and_document() {
        let text = message(
            &[
                "openssl".to_owned(),
                "/opt/git/usr/bin/openssl".to_owned(),
            ],
            Some("ONCL_TOOL_THAT_IS_NEVER_SET"),
            "OpenSSL 3",
        );
        assert!(
            text.contains("`openssl`, `/opt/git/usr/bin/openssl`"),
            "{text}"
        );
        assert!(text.contains("ONCL_TOOL_THAT_IS_NEVER_SET"), "{text}");
        assert!(text.contains("OpenSSL 3"), "{text}");
        assert!(text.contains("Что нужно для тестов"), "{text}");
        assert!(!text.to_lowercase().contains("oracle"), "{text}");
    }

    #[test]
    #[should_panic(expected = "`oncl-no-such-program`")]
    fn spawn_of_a_missing_program_reports_it() {
        let tool = Tool {
            names: &["oncl-no-such-program"],
            env: None,
            provides: "nothing",
        };
        let _ = tool.spawned(Command::new("oncl-no-such-program").output());
    }
}
