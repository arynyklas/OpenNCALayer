//! Licences of a publisher's release (Р31): its own `source.license` (check 12) and the
//! licence of every crate that ends up in its WebAssembly module (check 20) must be on the
//! OSI's list, as SPDX publishes it (`isOsiApproved`): `xtask/assets/spdx/`. Also the
//! `THIRD-PARTY.txt` of the copy in the project's Releases, from the crates `cargo metadata`
//! resolves for `wasm32-unknown-unknown`.
//!
//! An SPDX expression is on the list when it leaves a choice of OSI licences only: `A OR B`
//! needs one of them, `A AND B` both, `A WITH E` an OSI `A` and an exception SPDX lists; a
//! `LicenseRef-` is no OSI licence. The crates of the module are read leniently, as Cargo
//! once allowed: `/` is `OR` and the operators may be lower case.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::LazyLock;

use anyhow::Context;
use serde_json::Value;

/// The OSI-approved SPDX licence ids.
static OSI: LazyLock<BTreeSet<&'static str>> =
    LazyLock::new(|| ids(include_str!("../../assets/spdx/osi-licenses.txt")));

/// The SPDX licence exception ids.
static EXCEPTIONS: LazyLock<BTreeSet<&'static str>> =
    LazyLock::new(|| ids(include_str!("../../assets/spdx/exceptions.txt")));

fn ids(text: &'static str) -> BTreeSet<&'static str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Whether `id` is an OSI-approved SPDX licence id.
pub fn is_osi(id: &str) -> bool {
    OSI.contains(id)
}

/// How an expression is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reading {
    /// SPDX 2.3: upper-case operators only (a publisher's `source.license`).
    Strict,
    /// A crate's `license` as Cargo once allowed: `/` is `OR`, operators in any case.
    Lenient,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Open,
    Close,
    And,
    Or,
    With,
    Word(String),
}

fn tokens(expression: &str, reading: Reading) -> Vec<Token> {
    let spaced = expression.replace('(', " ( ").replace(')', " ) ").replace(
        '/',
        if reading == Reading::Lenient {
            " OR "
        } else {
            "/"
        },
    );
    spaced
        .split_whitespace()
        .map(|word| {
            let op = |name: &str| match reading {
                Reading::Strict => word == name,
                Reading::Lenient => word.eq_ignore_ascii_case(name),
            };
            match word {
                "(" => Token::Open,
                ")" => Token::Close,
                _ if op("AND") => Token::And,
                _ if op("OR") => Token::Or,
                _ if op("WITH") => Token::With,
                _ => Token::Word(word.to_owned()),
            }
        })
        .collect()
}

/// A reader of the tokens that says whether the expression is OSI, and what is not.
struct Eval<'t> {
    tokens: &'t [Token],
    at: usize,
    depth: usize,
    not_osi: BTreeSet<String>,
}

impl Eval<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn next(&mut self) -> Option<&Token> {
        let token = self.tokens.get(self.at);
        self.at += 1;
        token
    }

    fn or(&mut self) -> Result<bool, String> {
        let mut any = self.and()?;
        while self.peek() == Some(&Token::Or) {
            self.at += 1;
            any |= self.and()?;
        }
        Ok(any)
    }

    fn and(&mut self) -> Result<bool, String> {
        let mut all = self.atom()?;
        while self.peek() == Some(&Token::And) {
            self.at += 1;
            all &= self.atom()?;
        }
        Ok(all)
    }

    fn atom(&mut self) -> Result<bool, String> {
        self.depth += 1;
        if self.depth > 32 {
            return Err("nested too deep".to_owned());
        }
        let result = match self.next().cloned() {
            Some(Token::Open) => {
                let inner = self.or()?;
                if self.next() != Some(&Token::Close) {
                    return Err("a bracket is not closed".to_owned());
                }
                inner
            }
            Some(Token::Word(word)) => {
                let base = word.strip_suffix('+').unwrap_or(&word);
                let mut osi = is_osi(base);
                if !osi {
                    self.not_osi.insert(word.clone());
                }
                if self.peek() == Some(&Token::With) {
                    self.at += 1;
                    match self.next().cloned() {
                        Some(Token::Word(exception)) if EXCEPTIONS.contains(exception.as_str()) => {
                        }
                        Some(Token::Word(exception)) => {
                            self.not_osi.insert(format!("WITH {exception}"));
                            osi = false;
                        }
                        _ => return Err("WITH names no exception".to_owned()),
                    }
                }
                osi
            }
            Some(token) => return Err(format!("{token:?} where a licence was expected")),
            None => return Err("the expression ends where a licence was expected".to_owned()),
        };
        self.depth -= 1;
        Ok(result)
    }
}

/// Checks that `expression` leaves a choice of OSI licences only.
///
/// # Errors
///
/// It is no expression, or what it allows is not OSI; the message names the ids.
pub fn check_osi(expression: &str, reading: Reading) -> Result<(), String> {
    let tokens = tokens(expression, reading);
    if tokens.is_empty() {
        return Err("no licence".to_owned());
    }
    let mut eval = Eval {
        tokens: &tokens,
        at: 0,
        depth: 0,
        not_osi: BTreeSet::new(),
    };
    let osi = eval
        .or()
        .map_err(|e| format!("{expression:?} is not an SPDX expression: {e}"))?;
    if eval.at != tokens.len() {
        return Err(format!(
            "{expression:?} is not an SPDX expression: more after the end"
        ));
    }
    if osi {
        Ok(())
    } else {
        let names: Vec<String> = eval.not_osi.into_iter().collect();
        Err(format!(
            "{expression:?} is not an OSI licence (not on the OSI's list: {})",
            names.join(", ")
        ))
    }
}

/// A crate in a plugin's WebAssembly module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmCrate {
    /// Its name.
    pub name: String,
    /// Its version.
    pub version: String,
    /// Its `license`, if it has one.
    pub license: Option<String>,
    /// Where it comes from (`registry+…`, `git+…#<commit>`); `None` for a path inside the
    /// sources.
    pub source: Option<String>,
    /// Its repository, if it says.
    pub repository: Option<String>,
}

/// The crates of the module of the crate at `manifest_path` (as `cargo metadata` was given
/// it), from the output of `cargo metadata --format-version 1 --filter-platform
/// wasm32-unknown-unknown`: the crate and its normal dependencies, transitively; build and
/// development dependencies and procedural macros (with what only they use) run on the build
/// machine and are not in the module.
///
/// # Errors
///
/// The metadata is not of that form, or has no package of `manifest_path`.
pub fn wasm_crates(metadata: &Value, manifest_path: &str) -> anyhow::Result<Vec<WasmCrate>> {
    let packages = metadata["packages"]
        .as_array()
        .context("cargo metadata has no packages")?;
    let by_id: BTreeMap<&str, &Value> = packages
        .iter()
        .filter_map(|p| Some((p["id"].as_str()?, p)))
        .collect();
    let wanted = manifest_path.replace('\\', "/");
    let root = packages
        .iter()
        .find(|p| {
            p["manifest_path"]
                .as_str()
                .is_some_and(|m| m.replace('\\', "/") == wanted)
        })
        .and_then(|p| p["id"].as_str())
        .with_context(|| format!("cargo metadata has no package of {manifest_path}"))?;
    let nodes: BTreeMap<&str, &Value> = metadata["resolve"]["nodes"]
        .as_array()
        .context("cargo metadata has no resolve graph")?
        .iter()
        .filter_map(|n| Some((n["id"].as_str()?, n)))
        .collect();
    let proc_macro = |id: &str| {
        by_id.get(id).is_some_and(|p| {
            p["targets"].as_array().is_some_and(|targets| {
                targets.iter().any(|t| {
                    t["kind"]
                        .as_array()
                        .is_some_and(|k| k.iter().any(|k| k == "proc-macro"))
                })
            })
        })
    };
    let mut seen = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = nodes
            .get(id)
            .with_context(|| format!("the resolve graph has no node {id}"))?;
        for dep in node["deps"].as_array().into_iter().flatten() {
            let normal = dep["dep_kinds"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|k| k["kind"].is_null()));
            let Some(pkg) = dep["pkg"].as_str() else {
                continue;
            };
            if normal && !proc_macro(pkg) {
                stack.push(pkg);
            }
        }
    }
    let text = |p: &Value, key: &str| p[key].as_str().map(str::to_owned);
    let mut crates: Vec<WasmCrate> = seen
        .into_iter()
        .filter_map(|id| by_id.get(id))
        .map(|p| WasmCrate {
            name: text(p, "name").unwrap_or_default(),
            version: text(p, "version").unwrap_or_default(),
            license: text(p, "license"),
            source: text(p, "source"),
            repository: text(p, "repository"),
        })
        .collect();
    crates.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    Ok(crates)
}

/// Check 20: every crate of the module has an OSI licence.
///
/// # Errors
///
/// A line per crate without one.
pub fn check_crates(crates: &[WasmCrate]) -> Result<(), Vec<String>> {
    let problems: Vec<String> = crates
        .iter()
        .filter_map(|c| match &c.license {
            None => Some(format!(
                "{} {} has no SPDX licence in its Cargo.toml (license-file is not checkable)",
                c.name, c.version
            )),
            Some(license) => check_osi(license, Reading::Lenient)
                .err()
                .map(|e| format!("{} {}: {e}", c.name, c.version)),
        })
        .collect();
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// `THIRD-PARTY.txt` of a release: the crates of its module, their licences and sources.
pub fn third_party(id: &str, version: &str, crates: &[WasmCrate]) -> String {
    let mut text = format!(
        "The crates in the WebAssembly module of {id} {version}, as `cargo metadata` resolves\n\
         them for wasm32-unknown-unknown from its source archive, with their SPDX licences.\n\
         The licence texts are in the crates' own sources (the source archive and the crates\n\
         its Cargo.lock names).\n\n"
    );
    for c in crates {
        let source = c.source.as_deref().unwrap_or("path, in the source archive");
        let _ = writeln!(
            text,
            "{} {} | {} | {}{}",
            c.name,
            c.version,
            c.license.as_deref().unwrap_or("-"),
            source,
            c.repository
                .as_deref()
                .map(|r| format!(" | {r}"))
                .unwrap_or_default()
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn an_expression_is_osi_when_every_choice_it_leaves_is() {
        for good in [
            "MIT",
            "Apache-2.0 OR MIT",
            "(MIT OR Apache-2.0) AND Unicode-3.0",
            "Apache-2.0 WITH LLVM-exception",
            "GPL-2.0-or-later",
            "MIT OR LicenseRef-Proprietary",
        ] {
            check_osi(good, Reading::Strict).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
        for (bad, why) in [
            ("LicenseRef-Proprietary", "LicenseRef-Proprietary"),
            ("MIT AND BUSL-1.1", "BUSL-1.1"),
            ("CC-BY-4.0", "CC-BY-4.0"),
            ("MIT/Apache-2.0", "MIT/Apache-2.0"),
            ("mit or apache-2.0", "not an SPDX expression"),
            ("MIT WITH Not-An-Exception", "WITH Not-An-Exception"),
            ("(MIT", "not an SPDX expression"),
            ("", "no licence"),
        ] {
            let err = check_osi(bad, Reading::Strict).unwrap_err();
            assert!(err.contains(why), "{bad}: {err}");
        }
        check_osi("MIT/Apache-2.0", Reading::Lenient).unwrap();
        check_osi("MIT or Apache-2.0", Reading::Lenient).unwrap();
    }

    fn metadata() -> Value {
        let pkg = |name: &str, license: Value, macro_: bool| {
            json!({
                "id": format!("{name} 1.0.0"),
                "name": name,
                "version": "1.0.0",
                "license": license,
                "source": if name == "plugin" { Value::Null } else { json!("registry+https://github.com/rust-lang/crates.io-index") },
                "manifest_path": format!("/build/src/{name}/Cargo.toml"),
                "targets": [{"kind": [if macro_ { "proc-macro" } else { "lib" }]}],
            })
        };
        let dep = |name: &str, kind: Value| json!({"pkg": format!("{name} 1.0.0"), "dep_kinds": [{"kind": kind, "target": null}]});
        json!({
            "packages": [
                pkg("plugin", json!("MIT"), false),
                pkg("serde", json!("MIT OR Apache-2.0"), false),
                pkg("derive", json!("LicenseRef-X"), true),
                pkg("cc", json!("BUSL-1.1"), false),
                pkg("syn", json!("LicenseRef-X"), false),
            ],
            "resolve": {"root": null, "nodes": [
                {"id": "plugin 1.0.0", "deps": [dep("serde", Value::Null), dep("derive", Value::Null), dep("cc", json!("build"))]},
                {"id": "serde 1.0.0", "deps": []},
                {"id": "derive 1.0.0", "deps": [dep("syn", Value::Null)]},
                {"id": "cc 1.0.0", "deps": []},
                {"id": "syn 1.0.0", "deps": []},
            ]},
        })
    }

    #[test]
    fn the_module_holds_normal_dependencies_but_no_macros_or_build_tools() {
        let crates = wasm_crates(&metadata(), "/build/src/plugin/Cargo.toml").unwrap();
        let names: Vec<&str> = crates.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["plugin", "serde"]);
        check_crates(&crates).unwrap();
        let text = third_party("kz.a.b", "1.0.0", &crates);
        assert!(
            text.contains("serde 1.0.0 | MIT OR Apache-2.0 | registry+"),
            "{text}"
        );
        assert!(text.contains("plugin 1.0.0 | MIT | path"), "{text}");
    }

    #[test]
    fn a_crate_of_the_module_without_an_osi_licence_fails_check_20() {
        let mut m = metadata();
        m["packages"][1]["license"] = json!("BUSL-1.1");
        let crates = wasm_crates(&m, "/build/src/plugin/Cargo.toml").unwrap();
        let err = check_crates(&crates).unwrap_err();
        assert!(
            err[0].contains("serde 1.0.0") && err[0].contains("BUSL-1.1"),
            "{err:?}"
        );
        m["packages"][1]["license"] = Value::Null;
        let crates = wasm_crates(&m, "/build/src/plugin/Cargo.toml").unwrap();
        assert!(check_crates(&crates).unwrap_err()[0].contains("no SPDX licence"));
    }
}
