//! `cargo xtask tuf`: the operator's side of the TUF repository that authenticates the update
//! indexes (`docs/design/tuf.md`, `docs/dev/release.md`). The verifier and the builder are
//! `oncl_update::tuf`: this module only decides what to sign, when, and with which key, and
//! checks the result with the client's own code. Nothing here has a second implementation of
//! canonical JSON, signatures or the client workflow.
//!
//! - [`init`]: the keys and root version 1 (the ceremony, once);
//! - [`update`]: targets and snapshot over the update indexes, signed with the owner's keys;
//! - [`timestamp`]: the one file CI signs, with the online key, when Pages is published;
//! - [`root`]: the next root: a renewal, or a rotation of any role's key;
//! - [`check`]: offline verification of a repository with the client over a directory;
//! - [`published`]: the client over HTTPS against the published site.
//!
//! The repository is a directory ([`repo`]): `metadata/<N>.root.json`, `<N>.targets.json`,
//! `<N>.snapshot.json` (every version is kept for good), `metadata/timestamp.json` (never
//! committed) and `targets/indexes/<sha256>.<channel>.json`. Secret keys are in [`keystore`].

pub mod check;
pub mod cli;
pub mod init;
pub mod keystore;
pub mod published;
pub mod repo;
pub mod root;
pub mod timestamp;
pub mod update;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

/// Where the repository is committed, from the workspace root.
pub const REPO_DIR: &str = "tuf/v1";

/// The root of trust the client embeds (a copy of root version 1), from the workspace root.
pub const ANCHOR: &str = "crates/oncl-update/keys/root.json";

/// How long each role's metadata is valid, in days, from the moment it is signed
/// (`docs/design/tuf.md`).
pub const ROOT_DAYS: i64 = 365;
/// See [`ROOT_DAYS`].
pub const TARGETS_DAYS: i64 = 30;
/// See [`ROOT_DAYS`].
pub const SNAPSHOT_DAYS: i64 = 30;
/// See [`ROOT_DAYS`].
pub const TIMESTAMP_DAYS: i64 = 7;

/// The largest index (and so target) the tools read: the client's own limit.
pub const MAX_TARGET: u64 = oncl_update::MAX_INDEX_LEN;

/// `now` in whole seconds (the metadata has no sub-seconds).
pub fn whole_seconds(now: OffsetDateTime) -> OffsetDateTime {
    now.replace_nanosecond(0).expect("0 is a valid nanosecond")
}

/// The moment `days` days after `now`, in whole seconds.
pub fn expiry(now: OffsetDateTime, days: i64) -> OffsetDateTime {
    whole_seconds(now) + Duration::days(days)
}

/// A time given on the command line: RFC 3339 (`2026-12-01T10:00:00Z`) or Unix seconds.
///
/// # Errors
///
/// If it is neither.
pub fn parse_time(text: &str) -> anyhow::Result<OffsetDateTime> {
    if let Ok(seconds) = text.parse::<i64>() {
        return OffsetDateTime::from_unix_timestamp(seconds)
            .with_context(|| format!("{text} is not a Unix time"));
    }
    OffsetDateTime::parse(text, &Rfc3339)
        .with_context(|| format!("{text:?} is neither RFC 3339 nor Unix seconds"))
}

/// `expires` as the metadata spells it (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn show_time(time: OffsetDateTime) -> String {
    oncl_update::tuf::model::format_expires(time).unwrap_or_else(|_| time.to_string())
}

/// Where the passphrase of the encrypted key files comes from.
#[derive(Clone, Debug)]
pub enum PassphraseSource {
    /// Asked on the terminal, without echo.
    Prompt,
    /// The first line of this file (for automation and tests; the file is as secret as the
    /// keys).
    File(PathBuf),
}

impl PassphraseSource {
    /// The passphrase of existing keys.
    ///
    /// # Errors
    ///
    /// If it cannot be read, or is empty.
    pub fn get(&self, prompt: &str) -> anyhow::Result<Zeroizing<String>> {
        let text = match self {
            PassphraseSource::Prompt => Zeroizing::new(
                rpassword::prompt_password(prompt).context("reading the passphrase")?,
            ),
            PassphraseSource::File(path) => read_passphrase_file(path)?,
        };
        if text.is_empty() {
            bail!("the passphrase must not be empty");
        }
        Ok(text)
    }

    /// The passphrase of new keys: asked twice.
    ///
    /// # Errors
    ///
    /// If it cannot be read, is empty, or the two entries differ.
    pub fn get_new(&self, prompt: &str) -> anyhow::Result<Zeroizing<String>> {
        let first = self.get(prompt)?;
        if matches!(self, PassphraseSource::Prompt) {
            let again = self.get("The passphrase again: ")?;
            if again != first {
                bail!("the passphrases differ");
            }
        }
        Ok(first)
    }
}

fn read_passphrase_file(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let text = Zeroizing::new(
        fs::read_to_string(path)
            .with_context(|| format!("reading the passphrase file {}", path.display()))?,
    );
    let line = text.lines().next().unwrap_or("");
    Ok(Zeroizing::new(line.to_owned()))
}

/// One thing a check found wrong or worth a warning: a stable `code` (documented in
/// `docs/dev/release.md`) and a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// The stable code.
    pub code: &'static str,
    /// The message for the operator.
    pub message: String,
}

impl Problem {
    /// A problem.
    pub fn new(code: &'static str, message: impl Into<String>) -> Problem {
        Problem {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}
