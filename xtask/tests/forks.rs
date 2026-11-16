//! The forks named in `[patch.crates-io]` are the ones the lock file uses.
//!
//! An upgrade of a patched crate leaves its `[patch.crates-io]` entry unused (cargo only
//! warns) and brings the crates.io package back: Slint's winit backend would import
//! `SystemParametersInfoForDpi` again, which Windows 7 does not have, Velopack would use an
//! Update.exe taken from a package rebuilt from a delta before anything checks it, and the
//! secret-input variants of `streebog`/`hmac` and the framing observer of `multer` would
//! be missing.

use oncl_testkit::workspace_root;

fn read_table(path: &str) -> toml::Table {
    std::fs::read_to_string(workspace_root().join(path))
        .unwrap()
        .parse()
        .unwrap()
}

/// `(version, source)` of every locked package `name`.
fn locked(lock: &toml::Table, name: &str) -> Vec<(String, Option<String>)> {
    lock["package"]
        .as_array()
        .expect("[[package]] in Cargo.lock")
        .iter()
        .filter(|p| p["name"].as_str() == Some(name))
        .map(|p| {
            (
                p["version"].as_str().unwrap().to_owned(),
                p.get("source").and_then(|s| s.as_str()).map(str::to_owned),
            )
        })
        .collect()
}

/// The git source Cargo.lock records for a dependency pinned by `rev` in the manifest.
fn pinned_source(spec: &toml::Value) -> String {
    let git = spec["git"].as_str().expect("a git dependency");
    let rev = spec["rev"].as_str().expect("pinned by rev");
    assert_eq!(rev.len(), 40, "rev must be a full commit hash: {rev}");
    format!("git+{git}?rev={rev}#{rev}")
}

#[test]
fn every_patched_crate_is_locked_from_its_pinned_fork() {
    let manifest = read_table("Cargo.toml");
    let lock = read_table("Cargo.lock");
    let patches = manifest["patch"]["crates-io"]
        .as_table()
        .expect("[patch.crates-io]");
    assert_eq!(
        patches.keys().map(String::as_str).collect::<Vec<_>>(),
        ["hmac", "i-slint-backend-winit", "streebog", "velopack"]
    );
    for (name, spec) in patches {
        let source = pinned_source(spec);
        let packages = locked(&lock, name);
        let forked: Vec<_> = packages
            .iter()
            .filter(|(_, s)| s.as_deref() == Some(&source))
            .collect();
        assert_eq!(
            forked.len(),
            1,
            "{name} is not locked from {source}: {packages:?}"
        );
        for (version, source) in &packages {
            assert!(
                !(source
                    .as_deref()
                    .is_some_and(|s| s.starts_with("registry+"))
                    && *version == forked[0].0),
                "{name} {version} also comes from a registry: update the fork"
            );
        }
    }
}

#[test]
fn direct_git_dependencies_name_the_same_fork_and_rev_as_the_patches() {
    let manifest = read_table("Cargo.toml");
    let lock = read_table("Cargo.lock");
    let patches = &manifest["patch"]["crates-io"];
    let dependencies = &manifest["workspace"]["dependencies"];
    for name in ["hmac", "streebog"] {
        assert_eq!(
            pinned_source(&dependencies[name]),
            pinned_source(&patches[name]),
            "{name}: [workspace.dependencies] and [patch.crates-io] name different forks"
        );
    }
    let source = pinned_source(&dependencies["multer"]);
    assert!(
        locked(&lock, "multer")
            .iter()
            .any(|(_, s)| s.as_deref() == Some(&source)),
        "multer is not locked from {source}"
    );
}

#[test]
fn locked_winit_backend_is_slints_version() {
    let lock = read_table("Cargo.lock");
    let backend = locked(&lock, "i-slint-backend-winit");
    let core = locked(&lock, "i-slint-core");
    assert_eq!(backend.len(), 1);
    assert_eq!(core.len(), 1);
    assert_eq!(
        backend[0].0, core[0].0,
        "the patched backend is not Slint's version"
    );
}

#[test]
fn locked_velopack_is_the_version_the_workspace_asks_for() {
    let manifest = read_table("Cargo.toml");
    let lock = read_table("Cargo.lock");
    let wanted = manifest["workspace"]["dependencies"]["velopack"]["version"]
        .as_str()
        .unwrap();
    let velopack = locked(&lock, "velopack");
    assert_eq!(velopack.len(), 1, "{velopack:?}");
    assert_eq!(velopack[0].0, wanted);
}

#[test]
fn sdk_docs_name_the_pinned_revs_of_the_rustcrypto_forks() {
    let manifest = read_table("Cargo.toml");
    let patches = &manifest["patch"]["crates-io"];
    for doc in [
        "crates/oncl-core/README.md",
        "docs/dev/sdk.md",
        "docs/dev/sdk-overview.md",
    ] {
        let text = std::fs::read_to_string(workspace_root().join(doc)).unwrap();
        for name in ["hmac", "streebog"] {
            let git = patches[name]["git"].as_str().unwrap();
            let rev = patches[name]["rev"].as_str().unwrap();
            assert!(
                text.contains(&format!("{{ git = \"{git}\", rev = \"{rev}\" }}")),
                "{doc} does not name {git} at {rev}: update the example [patch.crates-io]"
            );
        }
    }
}
