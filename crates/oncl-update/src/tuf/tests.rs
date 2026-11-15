//! The client against repositories made by [`super::build`], in memory: every attack of
//! the specification's "Security" section, and the steps of its client workflow. The keys are
//! made here (from fixed seeds), the repository is a [`MemoryFetcher`].

use serde_json::{Value, json};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

use super::build::{self, RoleDef, RootDef};
use super::layout;
use super::model::{Digest, Envelope};
use super::store::{SnapshotState, TimestampState};
use super::*;

const T0: OffsetDateTime = datetime!(2026-11-15 12:00 UTC);
const STABLE: &[u8] = b"{\"channel\":\"stable\",\"seq\":7}\n";
const BETA: &[u8] = b"{\"channel\":\"beta\",\"seq\":9}\n";
const BIG: u64 = 1 << 20;

fn days(n: i64) -> Duration {
    Duration::days(n)
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&[seed; 32]).unwrap()
}

/// The four keys of a root.
struct Keys {
    root: SigningKey,
    timestamp: SigningKey,
    snapshot: SigningKey,
    targets: SigningKey,
}

fn keys(base: u8) -> Keys {
    Keys {
        root: key(base),
        timestamp: key(base + 1),
        snapshot: key(base + 2),
        targets: key(base + 3),
    }
}

fn role(key: &SigningKey) -> RoleDef {
    RoleDef {
        keys: vec![key.public()],
        threshold: 1,
    }
}

fn def(k: &Keys) -> RootDef {
    RootDef {
        root: role(&k.root),
        timestamp: role(&k.timestamp),
        snapshot: role(&k.snapshot),
        targets: role(&k.targets),
    }
}

/// A root file of `version` for `def`, signed by `signers`.
fn root_file(
    version: u64,
    expires: OffsetDateTime,
    def: &RootDef,
    signers: &[&SigningKey],
) -> Vec<u8> {
    build::sign(&build::root(version, expires, def).unwrap(), signers).unwrap()
}

/// What one publication contains.
#[derive(Clone)]
struct Release {
    files: Vec<(String, Vec<u8>)>,
    targets_version: u64,
    snapshot_version: u64,
    timestamp_version: u64,
    targets_expires: OffsetDateTime,
    snapshot_expires: OffsetDateTime,
    timestamp_expires: OffsetDateTime,
    /// Members added to the signed part of the targets and the timestamp.
    targets_extra: Vec<(&'static str, Value)>,
    timestamp_extra: Vec<(&'static str, Value)>,
}

fn release() -> Release {
    Release {
        files: vec![
            ("indexes/stable.json".to_owned(), STABLE.to_vec()),
            ("indexes/beta.json".to_owned(), BETA.to_vec()),
        ],
        targets_version: 1,
        snapshot_version: 1,
        timestamp_version: 1000,
        targets_expires: T0 + days(30),
        snapshot_expires: T0 + days(30),
        timestamp_expires: T0 + days(7),
        targets_extra: vec![],
        timestamp_extra: vec![],
    }
}

struct Signers<'a> {
    targets: Vec<&'a SigningKey>,
    snapshot: Vec<&'a SigningKey>,
    timestamp: Vec<&'a SigningKey>,
}

fn signers(k: &Keys) -> Signers<'_> {
    Signers {
        targets: vec![&k.targets],
        snapshot: vec![&k.snapshot],
        timestamp: vec![&k.timestamp],
    }
}

/// The signed files of a publication.
struct Published {
    targets: Vec<u8>,
    snapshot: Vec<u8>,
    timestamp: Vec<u8>,
}

fn with_extra(mut signed: Value, extra: &[(&'static str, Value)]) -> Value {
    for (name, value) in extra {
        signed[*name] = value.clone();
    }
    signed
}

fn publish_with(repo: &MemoryFetcher, r: &Release, s: &Signers<'_>) -> Published {
    let files: Vec<(&str, &[u8])> = r
        .files
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_slice()))
        .collect();
    let targets_signed = with_extra(
        build::targets(r.targets_version, r.targets_expires, &files).unwrap(),
        &r.targets_extra,
    );
    let targets = build::sign(&targets_signed, &s.targets).unwrap();
    repo.put(layout::targets_path(r.targets_version), targets.clone());
    for (path, content) in build::target_files(&files).unwrap() {
        repo.put(path, content);
    }
    let snapshot_signed = build::snapshot(
        r.snapshot_version,
        r.snapshot_expires,
        r.targets_version,
        &targets,
    )
    .unwrap();
    let snapshot = build::sign(&snapshot_signed, &s.snapshot).unwrap();
    repo.put(layout::snapshot_path(r.snapshot_version), snapshot.clone());
    let timestamp_signed = with_extra(
        build::timestamp(
            r.timestamp_version,
            r.timestamp_expires,
            r.snapshot_version,
            &snapshot,
        )
        .unwrap(),
        &r.timestamp_extra,
    );
    let timestamp = build::sign(&timestamp_signed, &s.timestamp).unwrap();
    repo.put(layout::TIMESTAMP_PATH, timestamp.clone());
    Published {
        targets,
        snapshot,
        timestamp,
    }
}

fn publish(repo: &MemoryFetcher, k: &Keys, r: &Release) -> Published {
    publish_with(repo, r, &signers(k))
}

/// A repository with root 1 of `k` and the standard release; and root 1's file.
fn standard(k: &Keys) -> (MemoryFetcher, Vec<u8>) {
    let repo = MemoryFetcher::new();
    let anchor = root_file(1, T0 + days(365), &def(k), &[&k.root]);
    repo.put(layout::root_path(1), anchor.clone());
    publish(&repo, k, &release());
    (repo, anchor)
}

type Client<'a> = TufClient<&'a MemoryFetcher, &'a mut MemoryStore>;

fn client<'a>(anchor: &[u8], repo: &'a MemoryFetcher, store: &'a mut MemoryStore) -> Client<'a> {
    TufClient::new(anchor, repo, store, Limits::default()).unwrap()
}

fn refresh(
    anchor: &[u8],
    repo: &MemoryFetcher,
    store: &mut MemoryStore,
) -> Result<Trusted, TufError> {
    client(anchor, repo, store).refresh(T0)
}

/// Rotates to `new` keys in root `version`, signed by `old` root key and `new` root key; the
/// file is put in the repository.
fn rotate(repo: &MemoryFetcher, version: u64, old: &Keys, new: &Keys) -> Vec<u8> {
    let file = root_file(version, T0 + days(365), &def(new), &[&old.root, &new.root]);
    repo.put(layout::root_path(version), file.clone());
    file
}

/// A fetcher that does not honour `max_len`, like a transport that does not enforce it.
struct Lying<'a>(&'a MemoryFetcher);

impl Fetcher for Lying<'_> {
    fn fetch(&self, path: &str, _max_len: u64) -> Result<Response, TufError> {
        Ok(self.0.get(path).map_or(Response::NotFound, Response::Body))
    }
}

fn signature_error(e: TufError) -> (String, usize, u32) {
    match e {
        TufError::Signature {
            what,
            valid,
            threshold,
        } => (what, valid, threshold),
        other => panic!("not a signature error: {other:?}"),
    }
}

// --- the workflow from scratch ---

#[test]
fn refresh_from_scratch_trusts_the_index_and_downloads_it() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let mut store = MemoryStore::default();
    let mut c = client(&anchor, &repo, &mut store);

    let trusted = c.refresh(T0).unwrap();
    assert_eq!(trusted.root().version, 1);
    assert_eq!(trusted.timestamp().version, 1000);
    assert_eq!(trusted.snapshot().version, 1);
    assert_eq!(trusted.targets().version, 1);
    assert_eq!(trusted.targets().targets.len(), 2);
    assert_eq!(
        trusted.expires(),
        T0 + days(7),
        "the timestamp expires first"
    );

    let stable = c
        .download_target(&trusted, "indexes/stable.json", BIG)
        .unwrap();
    assert_eq!(stable, STABLE);
    assert_eq!(
        c.download_target(&trusted, "indexes/beta.json", BIG)
            .unwrap(),
        BETA
    );

    // Steps 5.3 to 5.7, in order; the chain ended at the 404 of root 2.
    let hex = Digest::of(STABLE).to_hex();
    assert_eq!(
        repo.requests()[..5],
        [
            "metadata/2.root.json".to_owned(),
            "metadata/timestamp.json".to_owned(),
            "metadata/1.snapshot.json".to_owned(),
            "metadata/1.targets.json".to_owned(),
            format!("targets/indexes/{hex}.stable.json"),
        ]
    );
    let state = &store.state;
    assert_eq!(state.timestamp.as_ref().unwrap().version, 1000);
    assert_eq!(state.snapshot.as_ref().unwrap().version, 1);
    assert_eq!(state.targets, Some(1));
    assert_eq!(
        state.accepted["indexes/stable.json"].length,
        STABLE.len() as u64
    );
    assert_eq!(
        state.accepted["indexes/stable.json"].sha256,
        Digest::of(STABLE)
    );
}

#[test]
fn a_repository_that_is_re_signed_is_refreshed_again() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let mut store = MemoryStore::default();
    let mut c = client(&anchor, &repo, &mut store);
    c.refresh(T0).unwrap();
    // The same timestamp again (nothing changed): trusted.
    c.refresh(T0 + Duration::hours(1)).unwrap();
    // A daily re-signing: a new timestamp version over the same snapshot and targets.
    let mut r = release();
    r.timestamp_version = 1001;
    publish(&repo, &k, &r);
    let t = c.refresh(T0 + days(1)).unwrap();
    assert_eq!(t.timestamp().version, 1001);
    assert_eq!(t.snapshot().version, 1);
}

#[test]
fn a_404_for_the_next_root_ends_the_chain_and_a_404_elsewhere_is_an_error() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let mut store = MemoryStore::default();
    refresh(&anchor, &repo, &mut store).unwrap();
    assert_eq!(repo.requests()[0], "metadata/2.root.json");
    for path in [
        layout::TIMESTAMP_PATH.to_owned(),
        layout::snapshot_path(1),
        layout::targets_path(1),
    ] {
        let kept = repo.remove(&path).unwrap();
        assert!(
            matches!(refresh(&anchor, &repo, &mut store), Err(TufError::NotFound(p)) if p == path),
            "{path}"
        );
        repo.put(path, kept);
    }
    refresh(&anchor, &repo, &mut store).unwrap();
}

#[test]
fn a_missing_embedded_root_means_the_updater_is_off() {
    // No root built in: no client, nothing asked of the repository.
    let repo = MemoryFetcher::new();
    let off = TufClient::with_root(None, &repo, MemoryStore::default(), Limits::default()).unwrap();
    assert!(off.is_none());
    assert!(repo.requests().is_empty());
    // The real build agrees with whether it has a root.
    let real = TufClient::with_embedded_root(&repo, MemoryStore::default(), Limits::default());
    assert_eq!(real.unwrap().is_some(), crate::embedded_root().is_some());
    // A root that is there but is not one is an error, not "off".
    assert!(
        TufClient::with_root(
            Some(b"{}"),
            &repo,
            MemoryStore::default(),
            Limits::default()
        )
        .is_err()
    );
}

#[test]
fn the_trust_anchor_must_be_a_root_signed_by_its_own_keys() {
    let k = keys(1);
    let new = |bytes: &[u8]| {
        TufClient::new(
            bytes,
            MemoryFetcher::new(),
            MemoryStore::default(),
            Limits::default(),
        )
    };
    new(&root_file(1, T0 + days(365), &def(&k), &[&k.root])).unwrap();
    // Not signed by a root key.
    let (what, valid, threshold) = signature_error(
        new(&root_file(1, T0, &def(&k), &[&k.targets]))
            .err()
            .unwrap(),
    );
    assert_eq!((valid, threshold), (0, 1), "{what}");
    // consistent_snapshot false.
    let mut signed = build::root(1, T0 + days(365), &def(&k)).unwrap();
    signed["consistent_snapshot"] = json!(false);
    let file = build::sign(&signed, &[&k.root]).unwrap();
    assert!(matches!(new(&file), Err(TufError::Unsupported(_))));
    for bad in [&b"not json"[..], b"{\"signed\":{},\"signatures\":[]}", b""] {
        assert!(new(bad).is_err());
    }
    // An expired anchor is fine: the first refresh looks for a newer one.
    new(&root_file(1, T0 - days(1), &def(&k), &[&k.root])).unwrap();
}

// --- 5.3: the root chain ---

#[test]
fn the_root_chain_is_followed_through_rotations() {
    let (k1, k2, k3) = (keys(1), keys(11), keys(21));
    let (repo, anchor) = standard(&k1);
    // v2 moves every role to k2; v3 moves only the root key to k3's.
    rotate(&repo, 2, &k1, &k2);
    let mut v3 = def(&k2);
    v3.root = role(&k3.root);
    repo.put(
        layout::root_path(3),
        root_file(3, T0 + days(365), &v3, &[&k2.root, &k3.root]),
    );
    publish(&repo, &k2, &release());

    let mut store = MemoryStore::default();
    let trusted = refresh(&anchor, &repo, &mut store).unwrap();
    assert_eq!(trusted.root().version, 3);
    assert_eq!(trusted.root().root.keyids, [k3.root.key_id()]);
    let state_root = Root::from_signed(&store.state.root.as_ref().unwrap().signed).unwrap();
    assert_eq!(state_root.version, 3, "the chain was saved");

    // The next run starts from root 3, not from the built-in root 1.
    repo.clear_requests();
    refresh(&anchor, &repo, &mut store).unwrap();
    assert_eq!(repo.requests()[0], "metadata/4.root.json");
}

#[test]
fn rotating_timestamp_and_snapshot_keys_forgets_their_versions_so_a_fast_forward_recovers() {
    let (k1, k2) = (keys(1), keys(11));
    let (repo, anchor) = standard(&k1);
    // The repository was driven to timestamp 9000, snapshot 9000: the next legitimate
    // publication would look like a rollback.
    let mut high = release();
    high.timestamp_version = 9000;
    high.snapshot_version = 9000;
    publish(&repo, &k1, &high);
    let mut store = MemoryStore::default();
    refresh(&anchor, &repo, &mut store).unwrap();
    assert_eq!(store.state.snapshot.as_ref().unwrap().version, 9000);

    // Without a rotation, the repository back at low versions is refused: a rollback.
    publish(&repo, &k1, &release());
    let e = refresh(&anchor, &repo, &mut store).unwrap_err();
    assert!(
        matches!(&e, TufError::Rollback { what, .. } if what == "timestamp"),
        "{e:?}"
    );

    // A new root rotating the timestamp and snapshot keys: the stored versions are dropped
    // (5.3.11), and the low versions signed by the new keys are accepted.
    let mut rotated = def(&k1);
    rotated.timestamp = role(&k2.timestamp);
    rotated.snapshot = role(&k2.snapshot);
    repo.put(
        layout::root_path(2),
        root_file(2, T0 + days(365), &rotated, &[&k1.root]),
    );
    let mut s = signers(&k1);
    s.timestamp = vec![&k2.timestamp];
    s.snapshot = vec![&k2.snapshot];
    publish_with(&repo, &release(), &s);
    let trusted = refresh(&anchor, &repo, &mut store).unwrap();
    assert_eq!(
        (trusted.timestamp().version, trusted.snapshot().version),
        (1000, 1)
    );
    assert_eq!(store.state.timestamp.as_ref().unwrap().version, 1000);
}

#[test]
fn a_root_that_does_not_rotate_those_keys_keeps_their_versions() {
    let k1 = keys(1);
    let (repo, anchor) = standard(&k1);
    let mut high = release();
    high.timestamp_version = 9000;
    publish(&repo, &k1, &high);
    let mut store = MemoryStore::default();
    refresh(&anchor, &repo, &mut store).unwrap();
    // Root 2 changes only the root key.
    let k2 = keys(11);
    let mut same = def(&k1);
    same.root = role(&k2.root);
    repo.put(
        layout::root_path(2),
        root_file(2, T0 + days(365), &same, &[&k1.root, &k2.root]),
    );
    publish(&repo, &k1, &release());
    let e = refresh(&anchor, &repo, &mut store).unwrap_err();
    assert!(matches!(e, TufError::Rollback { .. }), "{e:?}");
    assert_eq!(store.state.timestamp.as_ref().unwrap().version, 9000);
    assert_eq!(
        Root::from_signed(&store.state.root.as_ref().unwrap().signed)
            .unwrap()
            .version,
        2,
        "the new root was kept all the same"
    );
}

#[test]
fn a_targets_fast_forward_recovers_by_rotating_the_targets_key() {
    let (k1, k2) = (keys(1), keys(11));
    let (repo, anchor) = standard(&k1);
    let mut high = release();
    high.targets_version = 500;
    publish(&repo, &k1, &high);
    let mut store = MemoryStore::default();
    refresh(&anchor, &repo, &mut store).unwrap();
    assert_eq!(store.state.targets, Some(500));
    // The targets key alone is replaced and the targets start again at 1.
    let mut rotated = def(&k1);
    rotated.targets = role(&k2.targets);
    repo.put(
        layout::root_path(2),
        root_file(2, T0 + days(365), &rotated, &[&k1.root]),
    );
    let mut s = signers(&k1);
    s.targets = vec![&k2.targets];
    publish_with(&repo, &release(), &s);
    let trusted = refresh(&anchor, &repo, &mut store).unwrap();
    assert_eq!(trusted.targets().version, 1);
    assert_eq!(store.state.targets, Some(1));
}

#[test]
fn a_new_root_signed_only_by_the_old_keys_is_refused() {
    let (k1, k2) = (keys(1), keys(11));
    let (repo, anchor) = standard(&k1);
    repo.put(
        layout::root_path(2),
        root_file(2, T0 + days(365), &def(&k2), &[&k1.root]),
    );
    let mut store = MemoryStore::default();
    let (what, valid, threshold) =
        signature_error(refresh(&anchor, &repo, &mut store).unwrap_err());
    assert!(what.contains("its own keys"), "{what}");
    assert_eq!((valid, threshold), (0, 1));
    assert_eq!(store.saves, 0, "nothing was kept");
}

#[test]
fn a_new_root_signed_only_by_the_new_keys_is_refused() {
    let (k1, k2) = (keys(1), keys(11));
    let (repo, anchor) = standard(&k1);
    repo.put(
        layout::root_path(2),
        root_file(2, T0 + days(365), &def(&k2), &[&k2.root]),
    );
    let mut store = MemoryStore::default();
    let (what, valid, threshold) =
        signature_error(refresh(&anchor, &repo, &mut store).unwrap_err());
    assert!(what.contains("keys of root 1"), "{what}");
    assert_eq!((valid, threshold), (0, 1));
    assert_eq!(store.saves, 0);
}

#[test]
fn the_old_roots_threshold_is_needed_for_the_new_root() {
    let (r1, r2, k2) = (key(1), key(2), keys(11));
    let mut d = def(&keys(5));
    d.root = RoleDef {
        keys: vec![r1.public(), r2.public()],
        threshold: 2,
    };
    let repo = MemoryFetcher::new();
    let anchor = root_file(1, T0 + days(365), &d, &[&r1, &r2]);
    // One of the two old root keys, and the new key: not enough of the old ones.
    repo.put(
        layout::root_path(2),
        root_file(2, T0 + days(365), &def(&k2), &[&r1, &k2.root]),
    );
    let mut store = MemoryStore::default();
    let (what, valid, threshold) =
        signature_error(refresh(&anchor, &repo, &mut store).unwrap_err());
    assert!(what.contains("keys of root 1"), "{what}");
    assert_eq!((valid, threshold), (1, 2));
    // Both old keys and the new one.
    repo.put(
        layout::root_path(2),
        root_file(2, T0 + days(365), &def(&k2), &[&r1, &r2, &k2.root]),
    );
    publish(&repo, &k2, &release());
    refresh(&anchor, &repo, &mut store).unwrap();
}

#[test]
fn a_root_whose_version_is_not_exactly_one_more_is_refused() {
    let (k1, k2) = (keys(1), keys(11));
    let (repo, anchor) = standard(&k1);
    let signers = [&k1.root, &k2.root];
    let mut store = MemoryStore::default();
    // A gap: root 2 is a file of version 3.
    repo.put(
        layout::root_path(2),
        root_file(3, T0 + days(365), &def(&k2), &signers),
    );
    let e = refresh(&anchor, &repo, &mut store).unwrap_err();
    assert!(
        matches!(
            e,
            TufError::RootVersion {
                expected: 2,
                found: 3
            }
        ),
        "{e:?}"
    );
    // A repeat of the trusted version.
    repo.put(
        layout::root_path(2),
        root_file(1, T0 + days(365), &def(&k2), &signers),
    );
    let e = refresh(&anchor, &repo, &mut store).unwrap_err();
    assert!(
        matches!(
            e,
            TufError::RootVersion {
                expected: 2,
                found: 1
            }
        ),
        "{e:?}"
    );
    // After a good root 2, a root 3 that is version 2 again.
    repo.put(
        layout::root_path(2),
        root_file(2, T0 + days(365), &def(&k2), &signers),
    );
    repo.put(
        layout::root_path(3),
        root_file(2, T0 + days(365), &def(&k2), &[&k2.root]),
    );
    let e = refresh(&anchor, &repo, &mut store).unwrap_err();
    assert!(
        matches!(
            e,
            TufError::RootVersion {
                expected: 3,
                found: 2
            }
        ),
        "{e:?}"
    );
}

#[test]
fn an_expired_intermediate_root_is_accepted_and_an_expired_final_root_is_not() {
    let (k1, k2, k3) = (keys(1), keys(11), keys(21));
    let (repo, anchor) = standard(&k1);
    // Root 2 expired a day ago; root 3 is current: the chain passes through the old one.
    repo.put(
        layout::root_path(2),
        root_file(2, T0 - days(1), &def(&k2), &[&k1.root, &k2.root]),
    );
    repo.put(
        layout::root_path(3),
        root_file(3, T0 + days(300), &def(&k3), &[&k2.root, &k3.root]),
    );
    publish(&repo, &k3, &release());
    let mut store = MemoryStore::default();
    assert_eq!(
        refresh(&anchor, &repo, &mut store).unwrap().root().version,
        3
    );

    // Without root 3, root 2 is the final one, and expired (5.3.10).
    repo.remove(&layout::root_path(3));
    repo.clear_requests();
    let mut fresh = MemoryStore::default();
    let e = refresh(&anchor, &repo, &mut fresh).unwrap_err();
    assert!(
        matches!(
            e,
            TufError::Expired {
                role: Role::Root,
                ..
            }
        ),
        "{e:?}"
    );
    // Nothing past the root was fetched, and the root that was followed is remembered.
    assert!(!repo.requests().iter().any(|p| p == layout::TIMESTAMP_PATH));
    assert_eq!(
        Root::from_signed(&fresh.state.root.as_ref().unwrap().signed)
            .unwrap()
            .version,
        2
    );

    // The built-in root alone, expired.
    let old = root_file(1, T0 - days(1), &def(&k1), &[&k1.root]);
    let e = refresh(&old, &MemoryFetcher::new(), &mut MemoryStore::default()).unwrap_err();
    assert!(
        matches!(
            e,
            TufError::Expired {
                role: Role::Root,
                ..
            }
        ),
        "{e:?}"
    );
}

#[test]
fn only_so_many_roots_are_followed_in_one_refresh() {
    let keys_: Vec<Keys> = (0..5).map(|i| keys(1 + 10 * i)).collect();
    let (repo, anchor) = standard(&keys_[0]);
    for v in 2..=5u64 {
        rotate(&repo, v, &keys_[v as usize - 2], &keys_[v as usize - 1]);
    }
    publish(&repo, &keys_[4], &release());
    let limits = Limits {
        max_roots: 2,
        ..Limits::default()
    };
    let mut store = MemoryStore::default();
    let mut c = TufClient::new(&anchor, &repo, &mut store, limits).unwrap();
    // Two roots per refresh, and the publication is by the last keys: the first refresh
    // stops at root 3 and cannot verify the timestamp, the second reaches root 5.
    assert!(c.refresh(T0).is_err());
    assert_eq!(c.refresh(T0).unwrap().root().version, 5);
    assert_eq!(
        repo.requests()
            .iter()
            .filter(|p| p.ends_with(".root.json"))
            .count(),
        4
    );
}

#[test]
fn a_root_naming_a_key_under_a_wrong_id_is_refused() {
    let (k1, k2) = (keys(1), keys(11));
    let (repo, anchor) = standard(&k1);
    let mut signed = build::root(2, T0 + days(365), &def(&k2)).unwrap();
    // The key of the targets role listed under the id of the timestamp key.
    let (a, b) = (k2.timestamp.key_id().to_hex(), k2.targets.key_id().to_hex());
    let swapped = signed["keys"][&b].clone();
    signed["keys"][&a] = swapped;
    repo.put(
        layout::root_path(2),
        build::sign(&signed, &[&k1.root, &k2.root]).unwrap(),
    );
    let e = refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err();
    assert!(
        matches!(&e, TufError::BadKeyId { claimed, actual } if *claimed == a && *actual == b),
        "{e:?}"
    );
    // The same in the built-in root.
    let file = build::sign(&signed, &[&k2.root]).unwrap();
    let e = TufClient::new(
        &file,
        MemoryFetcher::new(),
        MemoryStore::default(),
        Limits::default(),
    )
    .err();
    assert!(matches!(e, Some(TufError::BadKeyId { .. })));
}

// --- 5.4: the timestamp ---

#[test]
fn a_timestamp_must_be_signed_by_the_timestamp_key() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let mut s = signers(&k);
    s.timestamp = vec![&k.targets];
    publish_with(&repo, &release(), &s);
    let (what, valid, threshold) =
        signature_error(refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err());
    assert_eq!((what.as_str(), valid, threshold), ("the timestamp", 0, 1));
}

#[test]
fn a_timestamp_older_than_the_trusted_one_is_a_rollback() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let mut store = MemoryStore::default();
    refresh(&anchor, &repo, &mut store).unwrap();
    let mut r = release();
    r.timestamp_version = 999;
    publish(&repo, &k, &r);
    let e = refresh(&anchor, &repo, &mut store).unwrap_err();
    assert!(
        matches!(&e, TufError::Rollback { what, found: 999, trusted: 1000 } if what == "timestamp"),
        "{e:?}"
    );
    assert_eq!(
        store.state.timestamp.as_ref().unwrap().version,
        1000,
        "nothing moved back"
    );
}

#[test]
fn a_timestamp_of_the_trusted_version_must_list_the_same_snapshot() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let mut store = MemoryStore::default();
    refresh(&anchor, &repo, &mut store).unwrap();
    // The same version, another snapshot.
    let mut r = release();
    r.snapshot_version = 2;
    publish(&repo, &k, &r);
    let e = refresh(&anchor, &repo, &mut store).unwrap_err();
    assert!(matches!(e, TufError::TimestampChanged(1000)), "{e:?}");
}

#[test]
fn a_timestamp_may_not_list_an_older_snapshot_than_before() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let mut high = release();
    high.snapshot_version = 5;
    publish(&repo, &k, &high);
    let mut store = MemoryStore::default();
    refresh(&anchor, &repo, &mut store).unwrap();
    let mut r = release();
    r.timestamp_version = 1001;
    r.snapshot_version = 4;
    publish(&repo, &k, &r);
    let e = refresh(&anchor, &repo, &mut store).unwrap_err();
    assert!(
        matches!(
            e,
            TufError::Rollback {
                found: 4,
                trusted: 5,
                ..
            }
        ),
        "{e:?}"
    );
}

#[test]
fn expired_timestamp_snapshot_and_targets_are_refused() {
    let k = keys(1);
    for (role, edit) in [
        (
            Role::Timestamp,
            (|r: &mut Release| r.timestamp_expires = T0) as fn(&mut Release),
        ),
        (Role::Snapshot, |r| r.snapshot_expires = T0 - days(1)),
        (Role::Targets, |r| r.targets_expires = T0),
    ] {
        let (repo, anchor) = standard(&k);
        let mut r = release();
        edit(&mut r);
        publish(&repo, &k, &r);
        let e = refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err();
        assert!(
            matches!(e, TufError::Expired { role: found, .. } if found == role),
            "{role}: {e:?}"
        );
    }
    // One second before the expiry is still good.
    let (repo, anchor) = standard(&k);
    let mut r = release();
    r.timestamp_expires = T0 + Duration::seconds(1);
    publish(&repo, &k, &r);
    refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap();
}

// --- 5.5 and 5.6: snapshot and targets ---

#[test]
fn a_snapshot_must_be_the_version_the_timestamp_lists() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    // The timestamp lists snapshot 2, whose file is the (validly signed) snapshot 1.
    let old = repo.get(&layout::snapshot_path(1)).unwrap();
    repo.put(layout::snapshot_path(2), old.clone());
    let timestamp = build::timestamp(2000, T0 + days(7), 2, &old).unwrap();
    repo.put(
        layout::TIMESTAMP_PATH,
        build::sign(&timestamp, &[&k.timestamp]).unwrap(),
    );
    let e = refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err();
    assert!(
        matches!(
            e,
            TufError::VersionMismatch {
                role: Role::Snapshot,
                above: Role::Timestamp,
                expected: 2,
                found: 1
            }
        ),
        "{e:?}"
    );
}

#[test]
fn a_snapshot_may_not_roll_back_a_targets_version_or_drop_it() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let mut r = release();
    r.targets_version = 3;
    publish(&repo, &k, &r);
    let mut store = MemoryStore::default();
    refresh(&anchor, &repo, &mut store).unwrap();

    // A new snapshot listing the older, validly signed targets 2.
    let mut old = release();
    old.targets_version = 2;
    old.snapshot_version = 2;
    old.timestamp_version = 1001;
    publish(&repo, &k, &old);
    let e = refresh(&anchor, &repo, &mut store).unwrap_err();
    assert!(
        matches!(&e, TufError::Rollback { what, found: 2, trusted: 3 } if what.contains("targets.json")),
        "{e:?}"
    );

    // A snapshot that lists no targets file is not a snapshot.
    let snapshot = json!({
        "_type": "snapshot", "spec_version": "1.0.31", "version": 2,
        "expires": "2027-01-01T00:00:00Z", "meta": {},
    });
    let file = build::sign(&snapshot, &[&k.snapshot]).unwrap();
    repo.put(layout::snapshot_path(2), file.clone());
    let timestamp = build::timestamp(1002, T0 + days(7), 2, &file).unwrap();
    repo.put(
        layout::TIMESTAMP_PATH,
        build::sign(&timestamp, &[&k.timestamp]).unwrap(),
    );
    assert!(matches!(
        refresh(&anchor, &repo, &mut store).unwrap_err(),
        TufError::Malformed { .. }
    ));
}

#[test]
fn a_dropped_meta_entry_of_the_trusted_snapshot_is_a_rollback() {
    // A snapshot that no longer lists a file the trusted one listed (a delegated role's, in
    // a repository that had one): 5.5.5.
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let mut store = MemoryStore::default();
    refresh(&anchor, &repo, &mut store).unwrap();
    store
        .state
        .snapshot
        .as_mut()
        .unwrap()
        .meta
        .insert("vendor.json".to_owned(), 1);
    let mut r = release();
    r.snapshot_version = 2;
    r.timestamp_version = 1001;
    publish(&repo, &k, &r);
    let e = refresh(&anchor, &repo, &mut store).unwrap_err();
    assert!(
        matches!(&e, TufError::Malformed { why, .. } if why.contains("vendor.json")),
        "{e:?}"
    );
}

#[test]
fn targets_may_not_go_back_below_the_saved_version() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let mut store = MemoryStore::default();
    refresh(&anchor, &repo, &mut store).unwrap();
    // Only the saved targets version remembers 5 (as if the snapshot's record was lost).
    store.state.snapshot = None;
    store.state.targets = Some(5);
    let e = refresh(&anchor, &repo, &mut store).unwrap_err();
    assert!(
        matches!(&e, TufError::Rollback { what, found: 1, trusted: 5 } if what == "targets"),
        "{e:?}"
    );
}

#[test]
fn targets_must_be_the_version_the_snapshot_lists() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    // The snapshot lists targets 2; the file served as 2.targets.json is targets 1.
    let old = repo.get(&layout::targets_path(1)).unwrap();
    repo.put(layout::targets_path(2), old.clone());
    let snapshot = build::snapshot(2, T0 + days(30), 2, &old).unwrap();
    let file = build::sign(&snapshot, &[&k.snapshot]).unwrap();
    repo.put(layout::snapshot_path(2), file.clone());
    let timestamp = build::timestamp(2000, T0 + days(7), 2, &file).unwrap();
    repo.put(
        layout::TIMESTAMP_PATH,
        build::sign(&timestamp, &[&k.timestamp]).unwrap(),
    );
    let e = refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err();
    assert!(
        matches!(
            e,
            TufError::VersionMismatch {
                role: Role::Targets,
                above: Role::Snapshot,
                expected: 2,
                found: 1
            }
        ),
        "{e:?}"
    );
}

#[test]
fn mix_and_match_is_refused_by_the_hashes() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let one = publish(&repo, &k, &release());
    let mut two = release();
    two.targets_version = 2;
    two.snapshot_version = 2;
    two.timestamp_version = 1001;
    two.files = vec![("indexes/stable.json".to_owned(), b"{\"seq\":8}\n".to_vec())];
    let new = publish(&repo, &k, &two);

    // The new snapshot with the old targets (properly signed, but not what it lists).
    repo.put(layout::targets_path(2), one.targets.clone());
    let e = refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err();
    assert!(
        matches!(
            e,
            TufError::Length { .. } | TufError::Hash { .. } | TufError::Fetch(_)
        ),
        "{e:?}"
    );
    repo.put(layout::targets_path(2), new.targets.clone());
    // The new timestamp with the old snapshot.
    repo.put(layout::snapshot_path(2), one.snapshot.clone());
    let e = refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err();
    assert!(
        matches!(
            e,
            TufError::Length { .. } | TufError::Hash { .. } | TufError::Fetch(_)
        ),
        "{e:?}"
    );
    repo.put(layout::snapshot_path(2), new.snapshot.clone());
    refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap();
    let _ = new.timestamp;
}

#[test]
fn a_changed_snapshot_or_targets_file_fails_its_hash_before_its_signature() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    for path in [layout::snapshot_path(1), layout::targets_path(1)] {
        let good = repo.get(&path).unwrap();
        // The same length, one byte different: a hash mismatch, not a bad signature.
        let mut bad = good.clone();
        let at = bad.iter().position(|b| *b == b'1').unwrap();
        bad[at] = b'2';
        repo.put(path.clone(), bad);
        let e = refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err();
        assert!(matches!(e, TufError::Hash { .. }), "{path}: {e:?}");
        repo.put(path, good);
    }
}

#[test]
fn a_threshold_of_distinct_keys_is_needed_and_a_duplicate_counts_once() {
    let (s1, s2) = (key(31), key(32));
    let k = keys(1);
    let mut d = def(&k);
    d.snapshot = RoleDef {
        keys: vec![s1.public(), s2.public()],
        threshold: 2,
    };
    let repo = MemoryFetcher::new();
    let anchor = root_file(1, T0 + days(365), &d, &[&k.root]);
    let mut s = signers(&k);

    s.snapshot = vec![&s1];
    publish_with(&repo, &release(), &s);
    let (what, valid, threshold) =
        signature_error(refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err());
    assert_eq!((what.as_str(), valid, threshold), ("the snapshot", 1, 2));

    // The same key's signature twice in the file.
    let published = publish_with(&repo, &release(), &s);
    let mut env = Envelope::parse(&published.snapshot, 10_000, "snapshot").unwrap();
    env.signatures.push(env.signatures[0].clone());
    repo.put(layout::snapshot_path(1), env.to_file().unwrap());
    // (The file changed, so the timestamp is made again over it.)
    let timestamp = build::timestamp(1000, T0 + days(7), 1, &env.to_file().unwrap()).unwrap();
    repo.put(
        layout::TIMESTAMP_PATH,
        build::sign(&timestamp, &[&k.timestamp]).unwrap(),
    );
    let (_, valid, threshold) =
        signature_error(refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err());
    assert_eq!((valid, threshold), (1, 2));

    // Two different keys: enough.
    s.snapshot = vec![&s1, &s2];
    publish_with(&repo, &release(), &s);
    refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap();
}

// --- what the signature covers, and the shape of the JSON ---

#[test]
fn an_unknown_field_is_covered_by_the_signature() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let mut r = release();
    r.timestamp_extra = vec![("x-future", json!({"allowed": [1, 2]}))];
    let published = publish(&repo, &k, &r);
    refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap();

    // The same file with the unknown field changed: no longer what was signed.
    let text = String::from_utf8(published.timestamp).unwrap();
    assert!(text.contains(r#""x-future":{"allowed":[1,2]}"#), "{text}");
    repo.put(
        layout::TIMESTAMP_PATH,
        text.replace(r#""allowed":[1,2]"#, r#""allowed":[1,3]"#)
            .into_bytes(),
    );
    let (what, valid, _) =
        signature_error(refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err());
    assert_eq!((what.as_str(), valid), ("the timestamp", 0));
}

#[test]
fn a_file_need_not_be_canonical_but_its_signed_part_is_signed_canonically() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    // The timestamp pretty-printed, keys in another order: the same signed value.
    let published = publish(&repo, &k, &release());
    let value: Value = serde_json::from_slice(&published.timestamp).unwrap();
    repo.put(
        layout::TIMESTAMP_PATH,
        serde_json::to_vec_pretty(&value).unwrap(),
    );
    refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap();
}

#[test]
fn duplicate_keys_and_floats_are_refused() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let good = String::from_utf8(publish(&repo, &k, &release()).timestamp).unwrap();
    let dup = good.replacen(
        r#""_type":"timestamp""#,
        r#""_type":"timestamp","_type":"timestamp""#,
        1,
    );
    repo.put(layout::TIMESTAMP_PATH, dup.into_bytes());
    let e = refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err();
    assert!(
        matches!(&e, TufError::DuplicateKey(k) if k == "_type"),
        "{e:?}"
    );

    // A key twice at the top: which `signed` signs?
    let dup = good.replacen(r#"{"signatures""#, r#"{"signed":{},"signatures""#, 1);
    repo.put(layout::TIMESTAMP_PATH, dup.into_bytes());
    let e = refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err();
    assert!(
        matches!(&e, TufError::DuplicateKey(k) if k == "signed"),
        "{e:?}"
    );

    let float = good.replacen(r#""version":1000"#, r#""version":1000.0"#, 1);
    repo.put(layout::TIMESTAMP_PATH, float.into_bytes());
    let e = refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err();
    assert!(matches!(e, TufError::Float), "{e:?}");

    // A float in a member nobody reads is as bad: it has no canonical form.
    let mut r = release();
    r.timestamp_extra = vec![("x", json!({"a": 1}))];
    let extra = String::from_utf8(publish(&repo, &k, &r).timestamp).unwrap();
    repo.put(
        layout::TIMESTAMP_PATH,
        extra
            .replace(r#""x":{"a":1}"#, r#""x":{"a":1.5}"#)
            .into_bytes(),
    );
    let e = refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err();
    assert!(matches!(e, TufError::Float), "{e:?}");
}

#[test]
fn delegations_are_refused() {
    let k = keys(1);
    for delegations in [
        json!({"keys": {}, "roles": [{"name": "vendor", "keyids": [], "threshold": 1, "paths": ["plugins/*"]}]}),
        json!({}),
    ] {
        let (repo, anchor) = standard(&k);
        let mut r = release();
        r.targets_extra = vec![("delegations", delegations)];
        publish(&repo, &k, &r);
        let e = refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err();
        assert!(
            matches!(&e, TufError::Unsupported(m) if m.contains("delegations")),
            "{e:?}"
        );
    }
}

// --- endless data, and the target file ---

#[test]
fn metadata_over_its_limit_is_refused_even_from_a_fetcher_that_does_not_stop() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let limits = |f: &dyn Fn(&mut Limits)| {
        let mut l = Limits::default();
        f(&mut l);
        l
    };
    let timestamp_len = repo.get(layout::TIMESTAMP_PATH).unwrap().len() as u64;
    for small in [
        limits(&|l| l.timestamp = timestamp_len - 1),
        limits(&|l| l.snapshot = 10),
        limits(&|l| l.targets = 10),
    ] {
        // An honest fetcher stops at the limit; the client does not rely on that.
        let honest = TufClient::new(&anchor, &repo, MemoryStore::default(), small)
            .unwrap()
            .refresh(T0);
        assert!(
            matches!(honest, Err(TufError::Fetch(_) | TufError::TooLarge { .. })),
            "{honest:?}"
        );
        let lying = TufClient::new(&anchor, Lying(&repo), MemoryStore::default(), small)
            .unwrap()
            .refresh(T0);
        assert!(matches!(lying, Err(TufError::TooLarge { .. })), "{lying:?}");
    }
    // Exactly the limit is fine.
    let exact = limits(&|l| l.timestamp = timestamp_len);
    TufClient::new(&anchor, &repo, MemoryStore::default(), exact)
        .unwrap()
        .refresh(T0)
        .unwrap();

    // Endless data in place of a root.
    repo.put(layout::root_path(2), vec![b' '; 10 << 20]);
    let e = TufClient::new(
        &anchor,
        Lying(&repo),
        MemoryStore::default(),
        Limits::default(),
    )
    .unwrap()
    .refresh(T0)
    .unwrap_err();
    assert!(
        matches!(e, TufError::TooLarge { limit, .. } if limit == Limits::default().root),
        "{e:?}"
    );
}

#[test]
fn a_listed_length_over_the_limit_is_refused_before_the_request() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let snapshot = repo.get(&layout::snapshot_path(1)).unwrap();
    let mut signed = build::timestamp(2000, T0 + days(7), 1, &snapshot).unwrap();
    signed["meta"]["snapshot.json"]["length"] = json!(1u64 << 40);
    repo.put(
        layout::TIMESTAMP_PATH,
        build::sign(&signed, &[&k.timestamp]).unwrap(),
    );
    repo.clear_requests();
    let e = refresh(&anchor, &repo, &mut MemoryStore::default()).unwrap_err();
    assert!(matches!(e, TufError::TooLarge { .. }), "{e:?}");
    assert!(!repo.requests().contains(&layout::snapshot_path(1)));
}

#[test]
fn a_target_of_another_hash_or_length_is_refused() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let mut store = MemoryStore::default();
    let mut c = client(&anchor, &repo, &mut store);
    let trusted = c.refresh(T0).unwrap();
    let path = format!(
        "targets/indexes/{}.stable.json",
        Digest::of(STABLE).to_hex()
    );

    // Another content of the same length.
    let mut same_len = STABLE.to_vec();
    same_len[3] ^= 1;
    repo.put(path.clone(), same_len);
    let e = c
        .download_target(&trusted, "indexes/stable.json", BIG)
        .unwrap_err();
    assert!(matches!(e, TufError::Hash { .. }), "{e:?}");
    // A byte fewer.
    repo.put(path.clone(), STABLE[1..].to_vec());
    let e = c
        .download_target(&trusted, "indexes/stable.json", BIG)
        .unwrap_err();
    assert!(
        matches!(e, TufError::Length { expected, actual, .. } if expected == STABLE.len() as u64 && actual == expected - 1),
        "{e:?}"
    );
    // Nothing was accepted by any of those.
    assert!(c.store().state.accepted.is_empty());
}

#[test]
fn a_target_of_exactly_its_length_is_read_and_one_byte_more_is_refused() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let mut c = TufClient::new(&anchor, &repo, MemoryStore::default(), Limits::default()).unwrap();
    let trusted = c.refresh(T0).unwrap();
    let path = format!(
        "targets/indexes/{}.stable.json",
        Digest::of(STABLE).to_hex()
    );

    // Exactly the listed length: the fetcher was asked for that many and gave them all.
    let exact = c.download_target(&trusted, "indexes/stable.json", STABLE.len() as u64);
    assert_eq!(exact.unwrap(), STABLE);

    let mut longer = STABLE.to_vec();
    longer.push(b'\n');
    repo.put(path.clone(), longer.clone());
    // A fetcher that honours its limit refuses the extra byte ...
    let e = c
        .download_target(&trusted, "indexes/stable.json", BIG)
        .unwrap_err();
    assert!(matches!(e, TufError::Fetch(_)), "{e:?}");
    // ... and the client does not rely on that.
    let mut lying = TufClient::new(
        &anchor,
        Lying(&repo),
        MemoryStore::default(),
        Limits::default(),
    )
    .unwrap();
    let trusted = lying.refresh(T0).unwrap();
    let e = lying
        .download_target(&trusted, "indexes/stable.json", BIG)
        .unwrap_err();
    assert!(
        matches!(e, TufError::TooLarge { limit, .. } if limit == STABLE.len() as u64),
        "{e:?}"
    );
}

#[test]
fn only_listed_targets_within_the_callers_limit_are_downloaded() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let mut store = MemoryStore::default();
    let mut c = client(&anchor, &repo, &mut store);
    let trusted = c.refresh(T0).unwrap();
    repo.clear_requests();
    let e = c
        .download_target(&trusted, "indexes/nightly.json", BIG)
        .unwrap_err();
    assert!(
        matches!(&e, TufError::NoSuchTarget(p) if p == "indexes/nightly.json"),
        "{e:?}"
    );
    let e = c
        .download_target(&trusted, "../indexes/stable.json", BIG)
        .unwrap_err();
    assert!(matches!(e, TufError::NoSuchTarget(_)), "{e:?}");
    let e = c
        .download_target(&trusted, "indexes/stable.json", STABLE.len() as u64 - 1)
        .unwrap_err();
    assert!(matches!(e, TufError::TargetTooLarge { .. }), "{e:?}");
    assert!(repo.requests().is_empty(), "no request for any of those");

    // A listed target the repository lacks.
    let path = format!(
        "targets/indexes/{}.stable.json",
        Digest::of(STABLE).to_hex()
    );
    repo.remove(&path);
    let e = c
        .download_target(&trusted, "indexes/stable.json", BIG)
        .unwrap_err();
    assert!(matches!(&e, TufError::NotFound(p) if *p == path), "{e:?}");
}

// --- state across runs ---

#[test]
fn the_state_in_a_directory_keeps_rollback_protection_between_runs() {
    let k = keys(1);
    let (repo, anchor) = standard(&k);
    let dir = tempfile::tempdir().unwrap();
    let run = |store: FileStore| {
        TufClient::new(&anchor, &repo, store, Limits::default())
            .unwrap()
            .refresh(T0)
    };
    run(FileStore::in_data_dir(dir.path())).unwrap();

    let mut r = release();
    r.timestamp_version = 999;
    publish(&repo, &k, &r);
    // A new process, the same data directory.
    let e = run(FileStore::in_data_dir(dir.path())).unwrap_err();
    assert!(matches!(e, TufError::Rollback { .. }), "{e:?}");
    // Without the state, the old timestamp is accepted (a fresh install has no memory).
    run(FileStore::in_data_dir(tempfile::tempdir().unwrap().path())).unwrap();
}

#[test]
fn a_newer_built_in_root_replaces_the_saved_one_and_drops_versions_it_rotates() {
    let (k1, k2) = (keys(1), keys(11));
    let (repo, anchor1) = standard(&k1);
    let mut high = release();
    high.timestamp_version = 9000;
    publish(&repo, &k1, &high);
    let mut store = MemoryStore::default();
    refresh(&anchor1, &repo, &mut store).unwrap();
    assert_eq!(store.state.timestamp.as_ref().unwrap().version, 9000);

    // The program is updated and now carries root 2, which rotates the timestamp key.
    let mut v2 = def(&k1);
    v2.timestamp = role(&k2.timestamp);
    let anchor2 = root_file(2, T0 + days(365), &v2, &[&k1.root]);
    let mut s = signers(&k1);
    s.timestamp = vec![&k2.timestamp];
    publish_with(&repo, &release(), &s);
    let trusted = refresh(&anchor2, &repo, &mut store).unwrap();
    assert_eq!(trusted.root().version, 2);
    assert_eq!(trusted.timestamp().version, 1000);

    // A saved root newer than the built-in one wins: root 1 again does not undo root 2.
    let mut store = MemoryStore::default();
    store.state.root = Some(Envelope::parse(&anchor2, 10_000, "root").unwrap());
    let trusted = refresh(&anchor1, &repo, &mut store).unwrap();
    assert_eq!(trusted.root().version, 2);
    // A saved root that is not valid is dropped, with what was saved beside it.
    publish(&repo, &k1, &release());
    let mut store = MemoryStore::default();
    let mut broken = Envelope::parse(&anchor2, 10_000, "root").unwrap();
    broken.signatures.clear();
    store.state.root = Some(broken);
    store.state.timestamp = Some(TimestampState {
        version: 99_999,
        snapshot: model::MetaFile {
            version: 1,
            length: None,
            sha256: None,
        },
    });
    store.state.snapshot = Some(SnapshotState {
        version: 1,
        meta: Default::default(),
    });
    let trusted = refresh(&anchor1, &repo, &mut store).unwrap();
    assert_eq!(trusted.timestamp().version, 1000);
}
