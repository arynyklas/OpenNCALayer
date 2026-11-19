//! Check 25 (`docs/design/publishers.md`, «Проверки PR издателя»): the git revision a
//! publisher names in `source.vcs`, fetched alone into a bare repository (no work tree is
//! checked out, nothing of it runs) and made into the canonical archive by the same code as
//! `oncl-pack source`. The same bytes as the signed archive: confirmed; the host or the
//! revision unreachable: unverified, which does not stop the pull request; other bytes: the
//! pull request is refused.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use oncl_pack::source::Tree;
use serde::{Deserialize, Serialize};

use super::fetch::host_policy;

/// What check 25 found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "result", content = "detail")]
pub enum Provenance {
    /// The revision gives the signed archive byte for byte.
    Confirmed,
    /// The revision could not be had (the host, the network, the revision): why.
    Unverified(String),
    /// The revision gives another archive: the sha256 it gives.
    Mismatch(String),
}

impl Provenance {
    /// The word of `BUILDINFO.json` and the site: `confirmed`, `unverified`, `mismatch`.
    pub fn word(&self) -> &'static str {
        match self {
            Provenance::Confirmed => "confirmed",
            Provenance::Unverified(_) => "unverified",
            Provenance::Mismatch(_) => "mismatch",
        }
    }
}

/// Compares the archive `tree` of the fetched revision gives with the signed `archive`.
pub fn compare(tree: &Tree, archive: &[u8]) -> Provenance {
    match tree.to_archive() {
        Ok(bytes) if bytes == archive => Provenance::Confirmed,
        Ok(bytes) => Provenance::Mismatch(oncl_pack::sha256_hex(&bytes)),
        Err(e) => Provenance::Mismatch(format!("the revision makes no archive: {e}")),
    }
}

fn git(dir: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "protocol.allow=never",
            "-c",
            "protocol.https.allow=always",
            "-c",
            "http.followRedirects=false",
            "-c",
            "credential.helper=",
            "-c",
            "core.askPass=",
        ])
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .stdin(Stdio::null());
    command
}

/// Fetches `rev` of `url` into the new bare repository `dir` within `timeout`.
///
/// # Errors
///
/// The policy refuses `url`, or git fails or runs out of time.
pub fn fetch(url: &str, rev: &str, dir: &Path, timeout: Duration) -> anyhow::Result<()> {
    host_policy(url).map_err(|e| anyhow::anyhow!(e))?;
    let format = if rev.len() == 64 { "sha256" } else { "sha1" };
    std::fs::create_dir_all(dir)?;
    let init = git(dir)
        .args(["init", "-q", "--bare", &format!("--object-format={format}")])
        .output()
        .context("running git init")?;
    if !init.status.success() {
        bail!("git init: {}", String::from_utf8_lossy(&init.stderr).trim());
    }
    let mut child = git(dir)
        .args(["fetch", "-q", "--no-tags", "--depth=1", url, rev])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("running git fetch")?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return Ok(());
            }
            let mut err = String::new();
            if let Some(mut stderr) = child.stderr.take() {
                use std::io::Read as _;
                let _ = stderr.read_to_string(&mut err);
            }
            bail!("git fetch {url} {rev}: {}", err.trim());
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "git fetch {url} {rev} took more than {} s",
                timeout.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Check 25: `rev` of `url` against the signed `archive`, the repository fetched into a new
/// directory under `work`.
pub fn check(url: &str, rev: &str, archive: &[u8], work: &Path, timeout: Duration) -> Provenance {
    let dir = work.join("vcs.git");
    if let Err(e) = fetch(url, rev, &dir, timeout) {
        return Provenance::Unverified(format!("{e:#}"));
    }
    match Tree::from_git(&dir, rev) {
        Ok(tree) => compare(&tree, archive),
        Err(e) => Provenance::Unverified(format!("reading {rev}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use oncl_pack::source::File;

    use super::*;

    #[test]
    fn the_same_files_confirm_and_other_files_refuse() {
        let mut tree = Tree::new();
        tree.insert(
            "Cargo.toml",
            File {
                executable: false,
                data: b"[package]\n".to_vec(),
            },
        )
        .unwrap();
        let archive = tree.to_archive().unwrap();
        assert_eq!(compare(&tree, &archive), Provenance::Confirmed);
        let mut other = tree.clone();
        other
            .insert(
                "build.rs",
                File {
                    executable: false,
                    data: b"fn main() {}\n".to_vec(),
                },
            )
            .unwrap();
        assert_eq!(compare(&other, &archive).word(), "mismatch");
    }

    #[test]
    fn a_host_the_policy_refuses_is_unverified_without_a_connection() {
        let dir = tempfile::tempdir().unwrap();
        let found = check(
            "https://127.0.0.1/repo.git",
            &"a".repeat(40),
            b"",
            dir.path(),
            Duration::from_secs(5),
        );
        assert!(
            matches!(&found, Provenance::Unverified(why) if why.contains("IP address")),
            "{found:?}"
        );
    }
}
