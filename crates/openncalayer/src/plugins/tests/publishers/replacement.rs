//! Р11: acme replaces the owner's port (the example, `supersedes`). With updates on the
//! installed port is offered acme's plugin in the replacement window: agreed, the plugin
//! takes the port's place with its publisher recorded; declined, the port runs on, the offer
//! is not repeated (across a restart too) and stays in the port's row. A publisher no longer
//! active replaces nothing: the port is an ordinary port again. With updates off nothing is
//! offered.

use super::*;

const PORT_BUNDLE: &str = "kz.example.echo";

/// acme in `state`, replacing the example port by its plugin, which serves the port's module
/// and stands for its bundle.
fn superseding(state: &str) -> Value {
    let mut entry = entry(state);
    entry["modules"] = json!([ACME_MODULE, MODULE]);
    entry["bundles"] = json!([ACME_BUNDLE, PORT_BUNDLE]);
    entry["supersedes"] = json!({ ID: ACME_ID });
    entry
}

/// acme's plugin replacing the port: the example under acme's id, with the port's module
/// and bundle.
fn replacing_package(version: &str) -> Vec<u8> {
    example_at(version, |m| m.replace(ID, ACME_ID))
}

/// acme's release `version` of the plugin replacing the port; `edit` changes its
/// `custom.oncl`.
fn replacing(sandbox: &Sandbox, version: &str, edit: impl FnOnce(&mut Value)) -> (String, Value) {
    release(sandbox, version, &replacing_package(version), |oncl| {
        oncl["modules"] = json!([MODULE]);
        oncl["replaces"] = json!({"symname": PORT_BUNDLE, "version": "1.0.0"});
        edit(oncl);
    })
}

/// What the windows say of acme's plugin `version` replacing the port.
fn acme_origin(version: &str) -> ReleaseOrigin {
    let sha256 = Sha256::of(&replacing_package(version)).to_string();
    ReleaseOrigin::Publisher {
        display: acme_display(),
        source: Some(SourceArchive {
            name: format!("{ACME_ID}-{version}.src.tar.gz"),
            url: format!("{MIRROR_BASE}pub-acme-{sha256}/{ACME_ID}-{version}.src.tar.gz"),
            license: "Apache-2.0".to_owned(),
        }),
    }
}

fn set_updates(sandbox: &Sandbox, on: bool) {
    std::fs::write(
        sandbox.dir.path().join("settings.json"),
        format!(r#"{{"updates": {{"enabled": {on}, "channel": "stable"}}}}"#),
    )
    .unwrap();
}

/// The port 1.0.0 installed from the catalog 1; then the catalog 2 lists it still, and acme,
/// active, replaces it by its plugin 2.0.0 (role version 1).
fn port_then_replacement(sandbox: &Sandbox, service: &Arc<PluginService>) {
    sandbox.installed_from_catalog(service, 1, "1.0.0");
    publish_with(
        sandbox,
        2,
        vec![sandbox.release("1.0.0", &example("1.0.0"))],
        Some(&policy(vec![superseding("active")])),
        Some((1, role(&[replacing(sandbox, "2.0.0", |_| {})]))),
    );
}

/// The port runs as it did: 1.0.0 from the catalog, loaded.
fn port_runs(sandbox: &Sandbox) {
    let state = sandbox.store().state();
    let port = &state.plugins[ID];
    assert_eq!(port.version, v("1.0.0"));
    assert!(port.enabled && !port.withdrawn && port.publisher.is_none());
    assert!(!state.plugins.contains_key(ACME_ID));
    assert_eq!(sandbox.modules.names(), [MODULE]);
}

#[test]
fn an_installed_port_is_offered_its_replacement_and_replaced_once_agreed() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    port_then_replacement(&sandbox, &service);
    service.check_now();
    // The window names the port, acme with its source, and what acme's plugin may do.
    let requests = sandbox.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    let request = &requests[0];
    assert_eq!(request.replaces_port, Some((name(), v("1.0.0"))));
    assert_eq!(request.origin_kind, acme_origin("2.0.0"));
    assert_eq!(request.version, v("2.0.0"));
    assert_eq!(request.replacing, None);
    assert!(request.capabilities.keys && request.capabilities.files);
    assert_eq!(request.origin, None);
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Installed { name: name() }]
    );
    // Agreed: acme's plugin serves the module, its publisher recorded; the port is gone.
    let state = sandbox.store().state();
    assert!(!state.plugins.contains_key(ID));
    let plugin = &state.plugins[ACME_ID];
    assert_eq!(plugin.version, v("2.0.0"));
    assert_eq!(plugin.source, Source::Catalog);
    assert_eq!(plugin.publisher, Some(acme()));
    assert!(plugin.enabled && !plugin.withdrawn);
    assert!(state.declined_replacements.is_empty());
    assert_eq!(sandbox.modules.names(), [MODULE]);
    assert_eq!(sandbox.count(), 1);
    let view = service.view();
    assert_eq!(view.installed.len(), 1);
    assert_eq!(view.installed[0].origin, acme_origin("2.0.0"));
    assert_eq!(view.installed[0].replacement, None);
    assert!(view.available.is_empty(), "{:?}", view.available);
    // Nothing more to offer.
    service.check_now();
    assert!(sandbox.requests().is_empty() && sandbox.notices().is_empty());
}

#[test]
fn a_declined_replacement_is_not_offered_again_but_from_the_ports_row() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    port_then_replacement(&sandbox, &service);
    *lock(&sandbox.ui.answer) = Some(false);
    service.check_now();
    assert_eq!(sandbox.requests().len(), 1);
    assert!(sandbox.notices().is_empty());
    port_runs(&sandbox);
    assert_eq!(sandbox.store().state().declined_replacements[ID], ACME_ID);
    // The port's row says so; acme's plugin is not listed apart.
    let view = service.view();
    assert_eq!(view.installed[0].id, ID);
    assert_eq!(view.installed[0].replacement, Some(acme_display()));
    assert!(view.available.is_empty(), "{:?}", view.available);
    service.check_now();
    assert!(sandbox.requests().is_empty() && sandbox.notices().is_empty());

    // After a restart: still declined, still in the row.
    drop(service);
    let service = sandbox.service();
    service.check_now();
    assert!(sandbox.requests().is_empty() && sandbox.notices().is_empty());
    port_runs(&sandbox);
    assert_eq!(
        service.view().installed[0].replacement,
        Some(acme_display())
    );

    // With updates off the row offers nothing, nor does its button.
    set_updates(&sandbox, false);
    assert_eq!(service.view().installed[0].replacement, None);
    assert_eq!(service.replace_port(ID), Err(PluginActionError::UpdatesOff));
    set_updates(&sandbox, true);
    assert_eq!(
        service.replace_port("kz.none"),
        Err(PluginActionError::NotInstalled)
    );

    // From the row: asked again, and replaced once agreed.
    *lock(&sandbox.ui.answer) = Some(true);
    service.replace_port(ID).unwrap();
    let requests = sandbox.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].replaces_port, Some((name(), v("1.0.0"))));
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::Installed { name: name() }]
    );
    let state = sandbox.store().state();
    assert!(!state.plugins.contains_key(ID) && state.declined_replacements.is_empty());
    assert_eq!(state.plugins[ACME_ID].publisher, Some(acme()));
    assert_eq!(
        service.replace_port(ID),
        Err(PluginActionError::NotInstalled)
    );
}

/// A publisher retired, revoked, of a `state` this version does not know, or unavailable
/// (active without its role) replaces nothing: the port declined before is an ordinary port
/// again, updated by the owner's index.
#[test]
fn a_publisher_no_longer_active_leaves_the_port_an_ordinary_port() {
    for state in ["retired", "revoked", "paused", "active"] {
        let sandbox = Sandbox::new(true);
        let service = sandbox.service();
        port_then_replacement(&sandbox, &service);
        *lock(&sandbox.ui.answer) = Some(false);
        service.check_now();
        assert_eq!(sandbox.requests().len(), 1);
        publish_with(
            &sandbox,
            3,
            vec![sandbox.release("1.1.0", &example("1.1.0"))],
            Some(&policy(vec![superseding(state)])),
            None,
        );
        service.check_now();
        assert!(sandbox.requests().is_empty(), "{state}");
        assert_eq!(
            sandbox.notices(),
            [PluginNotice::Updated {
                name: name(),
                version: v("1.1.0"),
            }],
            "{state}"
        );
        assert_eq!(sandbox.installed_version(), Some(v("1.1.0")), "{state}");
        assert_eq!(service.view().installed[0].replacement, None, "{state}");
    }
}

/// Replaced, then acme revoked: its plugin is turned off as any of a revoked publisher's,
/// and the port is offered for installation again.
#[test]
fn a_replacement_of_a_revoked_publisher_is_turned_off_and_the_port_offered_again() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    port_then_replacement(&sandbox, &service);
    service.check_now();
    sandbox.requests();
    sandbox.notices();
    publish_with(
        &sandbox,
        3,
        vec![sandbox.release("1.0.0", &example("1.0.0"))],
        Some(&policy(vec![superseding("revoked")])),
        None,
    );
    service.check_now();
    assert_eq!(
        sandbox.notices(),
        [PluginNotice::PublisherRevoked {
            name: name(),
            publisher: acme_display(),
        }]
    );
    assert!(sandbox.store().state().plugins[ACME_ID].withdrawn);
    assert!(sandbox.modules.names().is_empty());
    let view = service.view();
    assert_eq!(
        view.available
            .iter()
            .map(|a| (a.id.as_str(), a.origin.clone()))
            .collect::<Vec<_>>(),
        [(ID, ReleaseOrigin::Project)]
    );
}

/// With updates off only revocations apply: the replacement is neither downloaded nor
/// offered; once they are on it is.
#[test]
fn with_updates_off_no_replacement_is_offered() {
    let sandbox = Sandbox::new(false);
    let service = sandbox.service();
    port_then_replacement(&sandbox, &service);
    let url = format!(
        "{MIRROR_BASE}pub-acme-{}/{ACME_ID}-2.0.0.onclp",
        Sha256::of(&replacing_package("2.0.0"))
    );
    service.check_now();
    assert!(sandbox.requests().is_empty() && sandbox.notices().is_empty());
    assert!(
        !sandbox
            .transport
            .asked()
            .iter()
            .any(|(asked, ..)| *asked == url),
        "the replacement is not downloaded"
    );
    port_runs(&sandbox);
    assert_eq!(service.view().installed[0].replacement, None);
    assert!(sandbox.store().state().declined_replacements.is_empty());

    set_updates(&sandbox, true);
    *lock(&sandbox.ui.answer) = Some(false);
    service.check_now();
    assert_eq!(sandbox.requests().len(), 1);
}

/// A port the user turned off is replaced by a plugin turned off: nothing starts serving.
#[test]
fn a_port_turned_off_is_replaced_by_a_plugin_turned_off() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    port_then_replacement(&sandbox, &service);
    service.set_enabled(ID, false).unwrap();
    service.check_now();
    assert_eq!(sandbox.requests().len(), 1);
    let state = sandbox.store().state();
    assert!(!state.plugins.contains_key(ID));
    assert!(!state.plugins[ACME_ID].enabled);
    assert!(sandbox.modules.names().is_empty());
}

/// A replacement whose package is not what its entry says is marked bad and not offered; the
/// port runs on, and with no other version of acme's it is an ordinary port again.
#[test]
fn a_bad_replacement_is_not_offered_and_the_port_runs_on() {
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    sandbox.installed_from_catalog(&service, 1, "1.0.0");
    let narrower = replacing(&sandbox, "2.0.0", |oncl| {
        oncl["capabilities"] = json!({"keys": true});
    });
    publish_with(
        &sandbox,
        2,
        vec![sandbox.release("1.0.0", &example("1.0.0"))],
        Some(&policy(vec![superseding("active")])),
        Some((1, role(&[narrower]))),
    );
    service.check_now();
    assert!(sandbox.requests().is_empty(), "the user is not asked");
    assert!(
        matches!(&sandbox.notices()[..], [PluginNotice::Failed { error, .. }] if error.contains("capabilities"))
    );
    assert!(sandbox.store().state().bad[ACME_ID].contains(&v("2.0.0")));
    port_runs(&sandbox);
    service.check_now();
    assert!(sandbox.requests().is_empty() && sandbox.notices().is_empty());
    assert_eq!(service.view().installed[0].replacement, None);
}

/// A replacement that cannot load (a module of its is served by a plugin from a file): the
/// port runs again, the user is told, and it is not offered again while that plugin serves
/// the module.
#[test]
fn a_replacement_that_does_not_load_gives_the_port_back() {
    const OTHER: &str = "kz.local.Other";
    let sandbox = Sandbox::new(true);
    let service = sandbox.service();
    sandbox.installed_from_catalog(&service, 1, "1.0.0");
    let local = sandbox.dir.path().join("other.onclp");
    std::fs::write(
        &local,
        example_at("0.1.0", |m| {
            m.replace(ID, "kz.local.other")
                .replace(MODULE, OTHER)
                .replace(PORT_BUNDLE, "kz.local.echo")
        }),
    )
    .unwrap();
    service.install_from_file(local).unwrap();
    sandbox.requests();
    sandbox.notices();
    let modules = format!(r#"modules = ["{MODULE}"]"#);
    let wider = example_at("2.0.0", |m| {
        m.replace(ID, ACME_ID)
            .replace(&modules, &format!(r#"modules = ["{MODULE}", "{OTHER}"]"#))
    });
    let mut acme = superseding("active");
    acme["modules"] = json!([ACME_MODULE, MODULE, OTHER]);
    publish_with(
        &sandbox,
        2,
        vec![sandbox.release("1.0.0", &example("1.0.0"))],
        Some(&policy(vec![acme])),
        Some((
            1,
            role(&[release(&sandbox, "2.0.0", &wider, |oncl| {
                oncl["modules"] = json!([MODULE, OTHER]);
                oncl["replaces"] = json!({"symname": PORT_BUNDLE, "version": "1.0.0"});
            })]),
        )),
    );
    service.check_now();
    assert_eq!(sandbox.requests().len(), 1);
    assert!(
        matches!(&sandbox.notices()[..], [PluginNotice::Failed { error, .. }] if error.contains(OTHER)),
    );
    let state = sandbox.store().state();
    assert_eq!(state.plugins[ID].version, v("1.0.0"));
    assert!(!state.plugins.contains_key(ACME_ID));
    assert!(
        !state.bad.contains_key(ACME_ID),
        "the package is not at fault"
    );
    assert_eq!(sandbox.modules.names().len(), 2);
    assert!(sandbox.modules.names().contains(&MODULE.to_owned()));
    service.check_now();
    assert!(sandbox.requests().is_empty() && sandbox.notices().is_empty());
}
