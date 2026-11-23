//! `cargo xtask check-release-features`: test code must not reach the **normal** dependency
//! tree of any release program: neither a test-only crate ([`TEST_ONLY`], e.g. the NCA service
//! doubles of `oncl-pki-testing`) nor a feature named `testing` on any package.
//!
//! A release is built with `-p <crate>`, whose normal tree has no dev-dependencies; but
//! `cargo build --workspace --all-targets` or `cargo test` unify the dev-dependencies into the
//! same binaries. This check reads the exact resolution a release gets:
//! `cargo tree -p <crate> -e normal -f "{p} [{f}]"` prints every package with the features
//! enabled on it, and a test-only crate or any `testing` there fails.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail};

/// The release programs: the desktop, the CLI, the server and the UI.
pub const RELEASE_CRATES: [&str; 4] = ["openncalayer", "oncl-cli", "oncl-server", "oncl-ui"];

/// Crates that exist only for tests: never in a release program.
pub const TEST_ONLY: [&str; 2] = ["oncl-pki-testing", "oncl-testkit"];

/// The packages of one `cargo tree -f "{p} [{f}]"` output that are test code: a
/// [`TEST_ONLY`] crate, or one with the `testing` feature enabled.
///
/// A line is `name vX.Y.Z (path) [feature,feature]`; the features are the last bracket group
/// (a package name never contains `[`).
pub fn test_packages(tree: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in tree.lines() {
        let Some((head, rest)) = line.rsplit_once('[') else {
            continue;
        };
        let Some(features) = rest.trim_end().strip_suffix(']') else {
            continue;
        };
        let name = head.split_whitespace().next().unwrap_or(head).to_owned();
        let test_code = TEST_ONLY.contains(&name.as_str())
            || features.split(',').any(|f| f.trim() == "testing");
        if test_code && !found.contains(&name) {
            found.push(name);
        }
    }
    found
}

/// Runs the check for every [`RELEASE_CRATES`] at the workspace `root`.
///
/// # Errors
///
/// `cargo tree` fails, or some release program's normal tree has test code.
pub fn run(root: &Path) -> anyhow::Result<()> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut offending = Vec::new();
    for krate in RELEASE_CRATES {
        let out = Command::new(&cargo)
            .args([
                "tree",
                "--locked",
                "--offline",
                "-p",
                krate,
                "-e",
                "normal",
                "--prefix",
                "none",
                "-f",
                "{p} [{f}]",
            ])
            .current_dir(root)
            .output()
            .with_context(|| format!("running cargo tree -p {krate}"))?;
        if !out.status.success() {
            bail!(
                "cargo tree -p {krate} failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let tree = String::from_utf8(out.stdout).context("cargo tree output is not UTF-8")?;
        let found = test_packages(&tree);
        if tree.lines().next().is_none() {
            bail!("cargo tree -p {krate} printed nothing");
        }
        if !found.is_empty() {
            offending.push(format!("{krate}: test code {}", found.join(", ")));
        }
    }
    if !offending.is_empty() {
        bail!(
            "test code leaks into a release program's normal dependencies:\n{}",
            offending.join("\n")
        );
    }
    println!(
        "no test code in the normal tree of {}",
        RELEASE_CRATES.join(", ")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_test_crates_and_testing_only_as_a_whole_feature_name() {
        let tree = "\
openncalayer v0.1.0 (/w/crates/openncalayer) [default]
oncl-core v0.1.0 (/w/crates/oncl-core) [default,jose,plugins,testing,xml]
oncl-pki v0.1.0 (/w/crates/oncl-pki) [testing]
oncl-xml v0.1.0 (/w/crates/oncl-xml) [default,testing-extra]
oncl-flows v0.1.0 (/w/crates/oncl-flows) []
oncl-pki-testing v0.1.0 (/w/crates/oncl-pki-testing) []
oncl-pki-testing-extra v0.1.0 (/w/crates/oncl-pki-testing-extra) []
serde v1.0.0 [default,std]
";
        assert_eq!(
            test_packages(tree),
            ["oncl-core", "oncl-pki", "oncl-pki-testing"]
        );
        assert!(test_packages("oncl-core v0.1.0 (/w) [default,xml]\n").is_empty());
    }
}
