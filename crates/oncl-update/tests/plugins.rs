use std::collections::{BTreeMap, BTreeSet};

use oncl_update::{Catalog, Index, PluginChoice, Version, choose_plugin, offer, plugin_bucket};
use serde_json::{Value, json};

fn version(s: &str) -> Version {
    Version::parse(s).unwrap()
}

fn release(id: &str, v: &str) -> Value {
    json!({
        "id": id, "version": v,
        "url": format!("https://example.invalid/{id}-{v}.onclp"),
        "sha256": "00".repeat(32), "size": 120,
        "min_core": "0.1.0",
        "modules": [format!("{id}.Module")],
        "replaces": {"symname": id, "version": "1.2.1"},
        "name": {"ru": "Модуль", "kk": "Модуль", "en": "Module"},
        "rollout": 100
    })
}

fn document(plugins: Vec<Value>) -> Value {
    json!({
        "schema": 1, "channel": "beta", "seq": 1,
        "generated": "2026-10-01T00:00:00Z", "expires": "2026-10-31T00:00:00Z",
        "core": [], "plugins": plugins
    })
}

fn index(plugins: Vec<Value>) -> Index {
    Index::from_json(&serde_json::to_vec(&document(plugins)).unwrap()).unwrap()
}

/// The catalog of the owner's index of `plugins` alone.
fn catalog(plugins: Vec<Value>) -> Catalog {
    Catalog::owner(index(plugins))
}

fn reject(plugins: Vec<Value>, reason: &str) {
    let err = Index::from_json(&serde_json::to_vec(&document(plugins)).unwrap())
        .expect_err("invalid plugin release was accepted");
    assert!(err.to_string().contains(reason), "{err}");
}

#[test]
fn duplicate_plugin_versions_are_rejected_but_other_ids_may_share_a_version() {
    let a = release("kz.example.one", "1.0.0");
    reject(vec![a.clone(), a.clone()], "listed twice");
    let accepted = index(vec![a, release("kz.example.two", "1.0.0")]);
    assert_eq!(accepted.plugins[1].id, "kz.example.two");
}

#[test]
fn plugin_release_shape_and_https_and_rollout_are_enforced() {
    let mut entry = release("kz.example.one", "1.0.0");
    entry["url"] = json!("http://example.invalid/a.onclp");
    reject(vec![entry], "https");
    let mut entry = release("kz.example.one", "1.0.0");
    entry["rollout"] = json!(101);
    reject(vec![entry], "rollout");
    let mut entry = release("kz.example.one", "1.0.0");
    entry["modules"] = json!([]);
    reject(vec![entry], "modules");
}

#[test]
fn plugin_details_the_installer_checks_do_not_reject_the_core_index() {
    // The package's own manifest is compared with the entry before installing; the index
    // parser keeps only the rules a client needs to read it, so a stricter or newer manifest
    // grammar never stops a core from updating itself.
    let mut entry = release("kz.example.one", "1.0.0");
    entry["name"]["ru"] = json!("");
    entry["modules"] = json!(["any name the plugin format allows later"]);
    entry["replaces"] = json!({"symname": "x", "version": ""});
    let mut doc = document(vec![entry]);
    doc["core"] = json!([{
        "version": "0.2.0", "rollout": 100,
        "flavors": {"win-x64": {"url": "https://example.invalid/full.nupkg", "sha256": "00".repeat(32), "size": 1}}
    }]);
    let parsed = Index::from_json(&serde_json::to_vec(&doc).unwrap()).unwrap();
    assert_eq!(parsed.core[0].version, version("0.2.0"));
    assert_eq!(parsed.plugins.len(), 1);
}

#[test]
fn plugin_entries_parse_and_roundtrip() {
    let mut revoked = release("kz.example.one", "1.0.0");
    revoked["revoked"] = json!(true);
    let mut bare = release("kz.example.two", "2.0.0-beta.1");
    bare.as_object_mut().unwrap().remove("replaces");
    let parsed = index(vec![revoked, bare]);
    let text = serde_json::to_vec(&parsed).unwrap();
    let again = Index::from_json(&text).unwrap();
    assert_eq!(again, parsed);
    assert!(again.plugins[0].revoked);
    assert_eq!(again.plugins[0].package.size, 120);
    assert_eq!(again.plugins[0].replaces.as_ref().unwrap().version, "1.2.1");
    assert!(again.plugins[1].replaces.is_none());
    // Optional members are not written when absent, as in the core entries.
    assert!(
        !String::from_utf8(text)
            .unwrap()
            .contains("\"replaces\":null")
    );
}

#[test]
fn no_plugin_entries_remains_compatible_with_previous_indexes() {
    let parsed = catalog(Vec::new());
    assert!(matches!(
        choose_plugin(
            &parsed,
            "kz.example.one",
            &version("1.0.0"),
            &version("0.1.0"),
            &[7; 16],
            &BTreeSet::new()
        ),
        PluginChoice::Keep
    ));
}

#[test]
fn updates_skip_bad_incompatible_and_not_rolled_out_versions() {
    let id = "kz.example.one";
    let mut newer_core = release(id, "5.0.0");
    newer_core["min_core"] = json!("2.0.0");
    let mut staged = release(id, "4.0.0");
    staged["rollout"] = json!(0);
    let parsed = catalog(vec![
        newer_core,
        staged,
        release(id, "3.0.0"),
        release(id, "2.0.0"),
    ]);
    let bad = BTreeSet::from([version("3.0.0")]);
    let PluginChoice::Update(target) = choose_plugin(
        &parsed,
        id,
        &version("1.0.0"),
        &version("1.0.0"),
        &[7; 16],
        &bad,
    ) else {
        panic!("eligible update was not selected");
    };
    assert_eq!(target.version, version("2.0.0"));
    assert!(matches!(
        choose_plugin(
            &parsed,
            id,
            &version("6.0.0"),
            &version("1.0.0"),
            &[7; 16],
            &bad
        ),
        PluginChoice::Keep
    ));
}

/// The choice for the installed `current` in `catalog`.
fn choose<'a>(catalog: &'a Catalog, id: &str, current: &str) -> PluginChoice<'a> {
    choose_plugin(
        catalog,
        id,
        &version(current),
        &version("1.0.0"),
        &[7; 16],
        &BTreeSet::new(),
    )
}

/// A release of `id` `v` rolled out to the installation `[7; 16]` (`in_rollout`) or held
/// back from it at the edge of its bucket.
fn rolled_out(id: &str, v: &str, in_rollout: bool) -> Value {
    let bucket = plugin_bucket(&[7; 16], id, &version(v));
    let mut release = release(id, v);
    release["rollout"] = json!(if in_rollout { bucket + 1 } else { bucket });
    release
}

#[test]
fn revoked_current_moves_back_only_within_its_rollout() {
    let id = "kz.example.one";
    let mut current = release(id, "3.0.0");
    current["revoked"] = json!(true);
    let parsed = catalog(vec![current.clone(), release(id, "2.0.0")]);
    let PluginChoice::Downgrade(target) = choose(&parsed, id, "3.0.0") else {
        panic!("revoked version did not fall back");
    };
    assert_eq!(target.version, version("2.0.0"));
    // 2.0.0 not rolled out here: back to the newest older one that is.
    let parsed = catalog(vec![
        current.clone(),
        rolled_out(id, "2.0.0", false),
        rolled_out(id, "1.5.0", true),
    ]);
    let PluginChoice::Downgrade(target) = choose(&parsed, id, "3.0.0") else {
        panic!("revoked version did not fall back");
    };
    assert_eq!(target.version, version("1.5.0"));
    // None rolled out here: off until one is.
    let mut fallback = release(id, "2.0.0");
    fallback["rollout"] = json!(0);
    let parsed = catalog(vec![current.clone(), fallback]);
    assert_eq!(choose(&parsed, id, "3.0.0"), PluginChoice::Withdrawn);
    let parsed = catalog(vec![current]);
    assert_eq!(choose(&parsed, id, "3.0.0"), PluginChoice::Withdrawn);
}

#[test]
fn revoked_current_takes_a_newer_version_only_once_rolled_out_to_it() {
    let id = "kz.example.one";
    let mut current = release(id, "1.1.0");
    current["revoked"] = json!(true);
    // The fix at rollout 0: not offered, the revoked version is off.
    let mut fix = release(id, "1.2.0");
    fix["rollout"] = json!(0);
    let parsed = catalog(vec![current.clone(), fix]);
    assert_eq!(choose(&parsed, id, "1.1.0"), PluginChoice::Withdrawn);
    // Rolled out, but not to this installation: still off.
    let parsed = catalog(vec![current.clone(), rolled_out(id, "1.2.0", false)]);
    assert_eq!(choose(&parsed, id, "1.1.0"), PluginChoice::Withdrawn);
    // Rolled out to it: the update, even over an older version in its rollout.
    let parsed = catalog(vec![
        current,
        rolled_out(id, "1.2.0", true),
        release(id, "1.0.0"),
    ]);
    let PluginChoice::Update(target) = choose(&parsed, id, "1.1.0") else {
        panic!("the fix was not chosen");
    };
    assert_eq!(target.version, version("1.2.0"));
}

#[test]
fn offer_finds_a_plugin_by_module_and_skips_bad_and_revoked_ones() {
    let mut revoked = release("kz.example.one", "3.0.0");
    revoked["revoked"] = json!(true);
    let parsed = catalog(vec![
        revoked,
        release("kz.example.one", "2.0.0"),
        release("kz.example.one", "1.0.0"),
        release("kz.example.two", "9.0.0"),
    ]);
    let bad = BTreeMap::from([(
        "kz.example.one".to_owned(),
        BTreeSet::from([version("2.0.0")]),
    )]);
    let selected = offer(&parsed, &version("1.0.0"), &[7; 16], &bad, |r| {
        r.modules.iter().any(|m| m == "kz.example.one.Module")
    })
    .unwrap();
    assert_eq!(selected.version, version("1.0.0"));
    assert!(
        offer(&parsed, &version("1.0.0"), &[7; 16], &bad, |r| r
            .modules
            .iter()
            .any(|m| m == "absent"))
        .is_none()
    );
}

/// `min_core` compares in semver order, where a prerelease precedes its release: a publisher
/// names `0.1.3-beta.1` to reach the betas of `0.1.3`, and `0.1.3` to reach stable only.
#[test]
fn min_core_of_a_prerelease_reaches_its_betas_and_of_a_release_only_stable() {
    let offered = |min_core: &str, core: &str| {
        let mut entry = release("kz.example.one", "1.0.0");
        entry["min_core"] = json!(min_core);
        offer(
            &catalog(vec![entry]),
            &version(core),
            &[7; 16],
            &BTreeMap::new(),
            |_| true,
        )
        .is_some()
    };
    assert!(offered("0.1.3-beta.1", "0.1.3-beta.1"));
    assert!(offered("0.1.3-beta.1", "0.1.3"));
    assert!(offered("0.1.3", "0.1.3"));
    assert!(!offered("0.1.3", "0.1.3-beta.1"));
}

#[test]
fn rollout_cutoff_is_exact_and_offers_match_the_requested_original_bundle() {
    let id = "kz.example.one";
    let v = version("2.0.0");
    let bucket = plugin_bucket(&[7; 16], id, &v);
    let mut entry = release(id, "2.0.0");
    entry["rollout"] = json!(bucket);
    let parsed = catalog(vec![entry.clone()]);
    assert!(matches!(
        choose_plugin(
            &parsed,
            id,
            &version("1.0.0"),
            &version("1.0.0"),
            &[7; 16],
            &BTreeSet::new()
        ),
        PluginChoice::Keep
    ));
    entry["rollout"] = json!(bucket + 1);
    let parsed = catalog(vec![release("kz.example.other", "9.0.0"), entry]);
    let selected = offer(
        &parsed,
        &version("1.0.0"),
        &[7; 16],
        &BTreeMap::new(),
        |r| r.replaces.as_ref().is_some_and(|r| r.symname == id),
    )
    .unwrap();
    assert_eq!(selected.id, id);
    assert_eq!(selected.version, v);
}
