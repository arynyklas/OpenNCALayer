//! A TUF repository of synthetic keys for the updater's and the catalog's tests, made with
//! `oncl_update`'s public builder ([`build`]) as the maintainer's tools make one.
//!
//! The keys are derived from fixed seeds: they sign nothing real. Root 1 first, then one
//! publication per [`Repo::publish`]: targets, snapshot and timestamp each with their own
//! version and expiry, under consistent-snapshot names ([`layout`]). Besides the indexes the
//! top-level targets may list other files ([`Repo::set_target`]: `publishers.json`), delegate
//! ([`Repo::delegations`], [`delegations`]) and the snapshot list the delegated roles' files
//! ([`Repo::set_role`]).

use std::collections::BTreeMap;

use oncl_update::Channel;
use oncl_update::tuf::build::{self, RoleDef, RootDef};
use oncl_update::tuf::layout;
use oncl_update::tuf::model::{SPEC_VERSION, format_expires};
use oncl_update::tuf::{Digest, RoleName, SigningKey, TargetPath};
use serde_json::{Map, Value, json};
use time::{Duration, OffsetDateTime};

/// How long each role stays valid from the moment of signing, the design's values by
/// default (`docs/design/tuf.md`).
#[derive(Clone, Copy)]
pub(crate) struct Lifetimes {
    /// 365 days.
    pub(crate) root: Duration,
    /// 7 days.
    pub(crate) timestamp: Duration,
    /// 30 days.
    pub(crate) snapshot: Duration,
    /// 30 days.
    pub(crate) targets: Duration,
}

impl Default for Lifetimes {
    fn default() -> Lifetimes {
        Lifetimes {
            root: Duration::days(365),
            timestamp: Duration::days(7),
            snapshot: Duration::days(30),
            targets: Duration::days(30),
        }
    }
}

/// A repository with root 1 of synthetic keys, and what has been published into it.
pub(crate) struct Repo {
    timestamp: SigningKey,
    snapshot: SigningKey,
    targets: SigningKey,
    anchor: Vec<u8>,
    files: BTreeMap<String, Vec<u8>>,
    /// The top-level targets published next (the indexes among them), by path.
    top_level: BTreeMap<String, Vec<u8>>,
    /// The delegated roles' files the snapshot lists next, by role: their version and bytes.
    roles: BTreeMap<RoleName, (u64, Vec<u8>)>,
    /// The version of the targets and snapshot published next.
    next_version: u64,
    /// The version of the timestamp published next (it grows by one with each publication,
    /// as a timestamp signed later has a higher version).
    next_timestamp: u64,
    /// The moment of the next signature: the roles expire [`Repo::lifetimes`] after it. The
    /// clock of the repository's creation until a test sets another.
    pub(crate) signed_at: OffsetDateTime,
    /// How long each role signed next stays valid.
    pub(crate) lifetimes: Lifetimes,
    /// The `delegations` member of the top-level targets published next, as it is signed
    /// (`None`: no member). Anything, also what no client can read as delegations.
    pub(crate) delegations: Option<Value>,
}

impl Repo {
    /// A repository of the keys of `seed` (a different seed, different keys), root 1 valid
    /// for [`Lifetimes::root`] from now. Nothing is published yet. `seed` is at most 252:
    /// the four keys are derived from it.
    pub(crate) fn with_seed(seed: u8) -> Repo {
        let key = |n: u8| SigningKey::from_seed(&[seed + n; 32]).expect("a 32-byte seed");
        let (root, timestamp, snapshot, targets) = (key(0), key(1), key(2), key(3));
        let signed_at = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let lifetimes = Lifetimes::default();
        let role = |key: &SigningKey| RoleDef {
            keys: vec![key.public()],
            threshold: 1,
        };
        let def = RootDef {
            root: role(&root),
            timestamp: role(&timestamp),
            snapshot: role(&snapshot),
            targets: role(&targets),
        };
        let signed =
            build::root(1, signed_at + lifetimes.root, &def).expect("a root of four roles");
        let anchor = build::sign(&signed, &[&root]).expect("a root file");
        let mut files = BTreeMap::new();
        files.insert(layout::root_path(1), anchor.clone());
        Repo {
            timestamp,
            snapshot,
            targets,
            anchor,
            files,
            top_level: BTreeMap::new(),
            roles: BTreeMap::new(),
            next_version: 1,
            next_timestamp: 1_000_000,
            signed_at,
            lifetimes,
            delegations: None,
        }
    }

    /// [`Repo::with_seed`] 1.
    pub(crate) fn new() -> Repo {
        Repo::with_seed(1)
    }

    /// The trust anchor: root 1, what the client is built with.
    pub(crate) fn anchor(&self) -> &[u8] {
        &self.anchor
    }

    /// Publishes the index `bytes` of `channel` (the others stay as they were published):
    /// signs new targets, snapshot and timestamp at [`Repo::signed_at`] and puts them and the
    /// index under their consistent-snapshot names.
    pub(crate) fn publish(&mut self, channel: Channel, bytes: &[u8]) {
        self.top_level.insert(channel.target_path(), bytes.to_vec());
        self.republish();
    }

    /// Lists `bytes` as the top-level target `path` from the next publication on.
    pub(crate) fn set_target(&mut self, path: &str, bytes: &[u8]) {
        self.top_level.insert(path.to_owned(), bytes.to_vec());
    }

    /// Lists no top-level target `path` from the next publication on.
    pub(crate) fn remove_target(&mut self, path: &str) {
        self.top_level.remove(path);
    }

    /// Serves `file` as version `version` of the delegated role `role` from the next
    /// publication on, listed in the snapshot by its version, length and sha256 (whatever
    /// the delegations say of the role: [`Repo::delegations`]).
    pub(crate) fn set_role(&mut self, role: &RoleName, version: u64, file: Vec<u8>) {
        self.roles.insert(role.clone(), (version, file));
    }

    /// The file of version `version` (above 0) of a delegated role listing `targets` (by
    /// target path: `length`, `hashes`, `custom`), expiring [`Lifetimes::targets`] after
    /// [`Repo::signed_at`], signed by `keys`.
    pub(crate) fn role_file(
        &self,
        version: u64,
        targets: Map<String, Value>,
        keys: &[&SigningKey],
    ) -> Vec<u8> {
        let signed = json!({
            "_type": "targets",
            "spec_version": SPEC_VERSION,
            "version": version,
            "expires": format_expires(self.signed_at + self.lifetimes.targets).expect("an expiry"),
            "targets": targets,
        });
        build::sign(&signed, keys).expect("a role file")
    }

    /// Signs new targets, snapshot and timestamp at [`Repo::signed_at`] over what is set now
    /// and puts them, the top-level targets and the roles' files under their
    /// consistent-snapshot names.
    fn republish(&mut self) {
        let version = self.next_version;
        let timestamp_version = self.next_timestamp;
        self.next_version += 1;
        self.next_timestamp += 1;
        let at = self.signed_at;
        let listed: Vec<(&str, &[u8])> = self
            .top_level
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
            .collect();
        let mut targets_signed = build::targets(version, at + self.lifetimes.targets, &listed)
            .expect("targets of valid paths");
        if let (Some(delegations), Some(members)) =
            (&self.delegations, targets_signed.as_object_mut())
        {
            members.insert("delegations".to_owned(), delegations.clone());
        }
        let targets = build::sign(&targets_signed, &[&self.targets]).expect("a targets file");
        let mut snapshot_signed =
            build::snapshot(version, at + self.lifetimes.snapshot, version, &targets)
                .expect("a snapshot");
        if let Some(meta) = snapshot_signed
            .get_mut("meta")
            .and_then(Value::as_object_mut)
        {
            for (role, (role_version, file)) in &self.roles {
                meta.insert(
                    role.meta_name(),
                    json!({
                        "version": role_version,
                        "length": file.len(),
                        "hashes": {"sha256": Digest::of(file).to_hex()},
                    }),
                );
            }
        }
        let snapshot = build::sign(&snapshot_signed, &[&self.snapshot]).expect("a snapshot file");
        let timestamp_signed = build::timestamp(
            timestamp_version,
            at + self.lifetimes.timestamp,
            version,
            &snapshot,
        )
        .expect("a timestamp");
        let timestamp = build::sign(&timestamp_signed, &[&self.timestamp]).expect("a file");
        for (path, content) in build::target_files(&listed).expect("target files") {
            self.files.insert(path, content);
        }
        for (role, (role_version, file)) in &self.roles {
            self.files
                .insert(layout::delegated_path(*role_version, role), file.clone());
        }
        self.files.insert(layout::targets_path(version), targets);
        self.files.insert(layout::snapshot_path(version), snapshot);
        self.files
            .insert(layout::TIMESTAMP_PATH.to_owned(), timestamp);
    }

    /// Every file of the repository, by its path under the base.
    pub(crate) fn files(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.files
    }

    /// The file at `path`.
    pub(crate) fn get(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).map(Vec::as_slice)
    }

    /// The path of the index file of `channel` as published last, under its hash name.
    ///
    /// # Panics
    ///
    /// If nothing was published for the channel.
    pub(crate) fn index_file_path(&self, channel: Channel) -> String {
        let target = channel.target_path();
        let bytes = self.top_level.get(&target).expect("a published channel");
        let target = TargetPath::parse(&target).expect("a valid path");
        layout::target_file_path(&target, &Digest::of(bytes))
    }
}

/// A `delegations` member delegating to each of `roles` with its one key, threshold 1, the
/// paths `plugins/<publisher>/*/*`, terminating: what the maintainer's tools write for a
/// publisher.
pub(crate) fn delegations(roles: &[(&RoleName, &SigningKey)]) -> Value {
    let keys: Map<String, Value> = roles
        .iter()
        .map(|(_, key)| (key.public().key_id().to_hex(), key.public().to_value()))
        .collect();
    let roles: Vec<Value> = roles
        .iter()
        .map(|(role, key)| {
            json!({
                "name": role.as_str(),
                "keyids": [key.public().key_id().to_hex()],
                "threshold": 1,
                "paths": [format!("plugins/{}/*/*", role.publisher())],
                "terminating": true,
            })
        })
        .collect();
    json!({"keys": keys, "roles": roles})
}
