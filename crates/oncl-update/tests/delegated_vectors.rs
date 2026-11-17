//! The delegated repositories python-tuf read (`tests/fixtures/tuf/delegated-*` and
//! `cross-repo`, see the README): a `tuf/v2` repository of two publishers, `pub-alpha` and
//! `pub-beta`, and one mutation of it per vector. These tests read the files with the model
//! alone: the top-level targets in the delegating profile, and each role's file against the
//! keys its delegation names.

use std::path::{Path, PathBuf};

use oncl_update::tuf::ed25519::{count_valid, verify_role};
use oncl_update::tuf::{
    DelegatedRole, DelegationError, Delegations, Envelope, Limits, Profile, RefusedRole, Role,
    RoleName, Root, Snapshot, Targets, Timestamp, TufError, layout,
};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tuf")
}

fn file(vector: &str, path: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(vector).join(path)).unwrap()
}

fn envelope(vector: &str, path: &str) -> Envelope {
    Envelope::parse(&file(vector, path), Limits::default().targets, path).unwrap()
}

fn role(name: &str) -> RoleName {
    RoleName::parse(name).unwrap()
}

/// The root every delegated vector is anchored at.
fn root() -> Root {
    Root::from_signed(&envelope("delegated-valid", "metadata/1.root.json").signed).unwrap()
}

/// The snapshot the vector's timestamp names.
fn snapshot(vector: &str) -> Snapshot {
    let timestamp =
        Timestamp::from_signed(&envelope(vector, layout::TIMESTAMP_PATH).signed).unwrap();
    let path = layout::snapshot_path(timestamp.snapshot.version);
    Snapshot::from_signed(&envelope(vector, &path).signed).unwrap()
}

/// The vector's top-level targets, the version its snapshot lists, read in `profile`.
fn targets(vector: &str, profile: Profile) -> Result<Targets, TufError> {
    let path = layout::targets_path(snapshot(vector).targets().version);
    Targets::from_signed(&envelope(vector, &path).signed, profile)
}

fn delegations(vector: &str) -> Delegations {
    targets(vector, Profile::Delegating)
        .unwrap()
        .delegations
        .unwrap()
}

fn accepted<'a>(delegations: &'a Delegations, name: &str) -> &'a DelegatedRole {
    match delegations.role(&role(name)) {
        Some(Ok(role)) => role,
        other => panic!("{name}: {other:?}"),
    }
}

/// Whether the file the snapshot lists for `name` is signed by a threshold of the keys of
/// its delegation.
fn signed_by_its_delegation(vector: &str, name: &str) -> bool {
    let delegations = delegations(vector);
    let delegated = accepted(&delegations, name);
    let listed = &snapshot(vector).meta[&delegated.name().meta_name()];
    let file = envelope(
        vector,
        &layout::delegated_path(listed.version, delegated.name()),
    );
    let message = file.canonical_signed().unwrap();
    let valid = count_valid(
        &message,
        &file.signatures,
        delegated.keys(),
        delegations.keys(),
    );
    valid >= delegated.keys().threshold as usize
}

const VECTORS_OF_TWO_ROLES: [&str; 11] = [
    "delegated-valid",
    "delegated-bad-signature",
    "delegated-threshold-not-met",
    "delegated-version-mismatch",
    "delegated-hash-mismatch",
    "delegated-expired",
    "delegated-not-in-snapshot",
    "delegated-path-outside",
    "delegated-nested",
    "delegated-key-reuse",
    "delegated-glob-depth",
];

#[test]
fn the_legacy_profile_refuses_the_top_level_targets_of_every_delegated_vector() {
    for vector in VECTORS_OF_TWO_ROLES {
        assert!(
            matches!(
                targets(vector, Profile::Legacy),
                Err(TufError::Unsupported(_))
            ),
            "{vector}"
        );
    }
}

#[test]
fn both_roles_keep_the_profile_where_the_attack_is_not_in_the_delegation() {
    for vector in VECTORS_OF_TWO_ROLES {
        let delegations = delegations(vector);
        let names: Vec<&str> = delegations
            .roles()
            .iter()
            .map(|role| role.as_ref().map(|r| r.name().as_str()).unwrap())
            .collect();
        assert_eq!(names, ["pub-alpha", "pub-beta"], "{vector}");
    }
}

#[test]
fn a_removed_delegation_leaves_only_the_other_role() {
    let delegations = delegations("delegated-removed");
    assert_eq!(delegations.roles().len(), 1);
    accepted(&delegations, "pub-alpha");
    assert!(delegations.role(&role("pub-beta")).is_none());
    // The snapshot still lists the role.
    assert!(
        snapshot("delegated-removed")
            .meta
            .contains_key("pub-beta.json")
    );
}

#[test]
fn a_delegation_by_path_hash_prefixes_refuses_that_role_alone() {
    let delegations = delegations("delegated-path-hash-prefixes");
    accepted(&delegations, "pub-alpha");
    assert_eq!(
        delegations.role(&role("pub-beta")),
        Some(Err(&RefusedRole {
            name: role("pub-beta"),
            error: DelegationError::HashPrefixes,
        }))
    );
}

#[test]
fn a_role_listed_twice_refuses_the_top_level_targets_as_python_tuf_does() {
    let e = targets("delegated-duplicate-role", Profile::Delegating).unwrap_err();
    assert!(
        matches!(&e, TufError::Malformed { why, .. } if why.contains("twice")),
        "{e:?}"
    );
}

#[test]
fn a_top_level_role_name_refuses_the_top_level_targets_as_python_tuf_does() {
    let e = targets("delegated-top-level-name", Profile::Delegating).unwrap_err();
    assert!(matches!(e, TufError::Malformed { .. }), "{e:?}");
}

#[test]
fn the_threshold_of_two_is_read_from_the_delegation() {
    let delegations = delegations("delegated-threshold-not-met");
    let beta = accepted(&delegations, "pub-beta");
    assert_eq!((beta.keys().threshold, beta.keys().keyids.len()), (2, 2));
}

#[test]
fn the_reused_key_is_the_roots_targets_key() {
    // The delegations alone cannot tell: the client refuses the role against the root.
    let delegations = delegations("delegated-key-reuse");
    let beta = accepted(&delegations, "pub-beta");
    assert_eq!(beta.keys().keyids, root().targets.keyids);
}

#[test]
fn the_role_files_are_signed_by_their_delegations_keys() {
    for vector in VECTORS_OF_TWO_ROLES {
        assert!(signed_by_its_delegation(vector, "pub-alpha"), "{vector}");
    }
    for vector in [
        "delegated-valid",
        "delegated-version-mismatch",
        "delegated-expired",
        "delegated-path-outside",
        "delegated-nested",
        "delegated-key-reuse",
        "delegated-glob-depth",
    ] {
        assert!(signed_by_its_delegation(vector, "pub-beta"), "{vector}");
    }
}

#[test]
fn a_flipped_signature_or_one_key_of_two_is_below_the_threshold() {
    for vector in [
        "delegated-bad-signature",
        "delegated-threshold-not-met",
        "delegated-hash-mismatch",
    ] {
        assert!(!signed_by_its_delegation(vector, "pub-beta"), "{vector}");
    }
}

#[test]
fn the_top_level_metadata_of_the_delegated_vectors_is_signed_by_their_root() {
    let root = root();
    for vector in VECTORS_OF_TWO_ROLES {
        let timestamp = envelope(vector, layout::TIMESTAMP_PATH);
        verify_role(&timestamp, &root, Role::Timestamp, vector).unwrap();
    }
}

#[test]
fn the_v1_timestamp_is_not_signed_by_the_v2_root() {
    let e = verify_role(
        &envelope("cross-repo", layout::TIMESTAMP_PATH),
        &root(),
        Role::Timestamp,
        "cross-repo",
    )
    .unwrap_err();
    assert!(matches!(e, TufError::Signature { valid: 0, .. }), "{e:?}");
}
