//! The TUF client: the "detailed client workflow" of the specification (version 1.0.37,
//! section 5), step by step, over a [`Fetcher`] and a [`Store`]. Step numbers in the
//! comments are that section's.
//!
//! Nothing here touches the network or the disk except through those two traits, and the
//! verification itself (the model, canonical JSON, signatures) is in modules that touch
//! neither.
//!
//! What differs from the specification, all of it stricter or a recovery the specification
//! leaves open:
//!
//! - hashes and lengths a role lists are enforced exactly (a file of another length is
//!   refused, not just a file over it);
//! - a timestamp of the version already trusted is not a reason to stop (the snapshot and
//!   targets are fetched anyway, from names that carry their version) but it must list the
//!   same snapshot;
//! - when a new root changes the keys or threshold of the timestamp, snapshot **or targets**
//!   role, the stored versions of all three are forgotten (step 5.3.11 names the first two;
//!   without the third, a targets key rotated after a fast-forward could never recover);
//! - the root files are saved with that deletion in one atomic write, before the expiry of
//!   the final root is checked (step 5.3.10), so a root that is too old to use is still
//!   remembered and the keys it rotated are still forgotten;
//! - there are no delegations: step 5.6.7 is only the top-level targets.

use time::OffsetDateTime;

use super::ed25519::verify_role;
use super::error::{Role, TufError};
use super::fetch::{Fetcher, Response};
use super::layout;
use super::model::{
    Digest, Envelope, MetaFile, Root, Snapshot, TARGETS_META, Target, Targets, Timestamp,
    ensure_fresh,
};
use super::store::{AcceptedTarget, SnapshotState, Store, TimestampState, TrustState};

/// The most each kind of file may be, when its size is not listed by the role above (and the
/// most a listed size may be).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// A root file (the size is unknown: the specification's W).
    pub root: u64,
    /// The timestamp (X).
    pub timestamp: u64,
    /// The snapshot (Y).
    pub snapshot: u64,
    /// The targets (Z).
    pub targets: u64,
    /// How many new roots one refresh follows (the specification's Y of step 5.3.3).
    pub max_roots: u32,
}

impl Default for Limits {
    /// 64 KiB per root, 16 KiB for the timestamp, 128 KiB for the snapshot, 256 KiB for the
    /// targets, 128 roots.
    fn default() -> Self {
        Limits {
            root: 64 << 10,
            timestamp: 16 << 10,
            snapshot: 128 << 10,
            targets: 256 << 10,
            max_roots: 128,
        }
    }
}

/// The verified metadata of one [`TufClient::refresh`]: only what passed every check, and
/// the only way to name a target to [`TufClient::download_target`].
#[derive(Clone, Debug)]
pub struct Trusted {
    root: Root,
    timestamp: Timestamp,
    snapshot: Snapshot,
    targets: Targets,
}

impl Trusted {
    /// The root in force.
    pub fn root(&self) -> &Root {
        &self.root
    }

    /// The timestamp.
    pub fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }

    /// The snapshot.
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// The targets metadata.
    pub fn targets(&self) -> &Targets {
        &self.targets
    }

    /// What the targets metadata says of the target `path`.
    pub fn target(&self, path: &str) -> Option<&Target> {
        self.targets.targets.get(path)
    }

    /// The earliest moment one of the four files stops being trusted.
    pub fn expires(&self) -> OffsetDateTime {
        self.root
            .expires
            .min(self.timestamp.expires)
            .min(self.snapshot.expires)
            .min(self.targets.expires)
    }
}

/// A TUF repository's client.
pub struct TufClient<F, S> {
    fetcher: F,
    store: S,
    anchor: Anchor,
    limits: Limits,
}

/// The root built into the program.
struct Anchor {
    envelope: Envelope,
    root: Root,
}

impl<F: Fetcher, S: Store> TufClient<F, S> {
    /// A client of the repository `fetcher` reads, trusting `trust_anchor`: the bytes of a
    /// root file (`keys/root.json`, [`crate::embedded_root`]), signed by its own keys. Its
    /// expiry does not matter: the first refresh looks for a newer one.
    ///
    /// # Errors
    ///
    /// The errors of [`Envelope::parse`] and [`Root::from_signed`], and
    /// [`TufError::Signature`] if the root is not signed by a threshold of its own root keys.
    pub fn new(
        trust_anchor: &[u8],
        fetcher: F,
        store: S,
        limits: Limits,
    ) -> Result<TufClient<F, S>, TufError> {
        let envelope = Envelope::parse(trust_anchor, limits.root, "the built-in root")?;
        let root = Root::from_signed(&envelope.signed)?;
        verify_role(&envelope, &root, Role::Root, "the built-in root")?;
        Ok(TufClient {
            fetcher,
            store,
            anchor: Anchor { envelope, root },
            limits,
        })
    }

    /// A client trusting the root built into this program, or `None` if the build has none:
    /// then there is no way to trust a repository, and the updater is off, as it is without
    /// a minisign key.
    ///
    /// # Errors
    ///
    /// As [`TufClient::new`] (which the build already checked structurally).
    pub fn with_embedded_root(
        fetcher: F,
        store: S,
        limits: Limits,
    ) -> Result<Option<TufClient<F, S>>, TufError> {
        TufClient::with_root(crate::embedded_root(), fetcher, store, limits)
    }

    /// [`TufClient::with_embedded_root`] for the root `trust_anchor`, if there is one.
    pub(crate) fn with_root(
        trust_anchor: Option<&[u8]>,
        fetcher: F,
        store: S,
        limits: Limits,
    ) -> Result<Option<TufClient<F, S>>, TufError> {
        trust_anchor
            .map(|root| TufClient::new(root, fetcher, store, limits))
            .transpose()
    }

    /// The store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The fetcher.
    pub fn fetcher(&self) -> &F {
        &self.fetcher
    }

    /// Updates the metadata (steps 5.1 to 5.6): the chain of roots, then the timestamp,
    /// snapshot and targets, each checked against the trusted one above it, and saves what
    /// it accepted. `now` is the fixed update start time of 5.1: every expiry is checked
    /// against it.
    ///
    /// On an error nothing from the failing file onward is trusted; what was accepted
    /// before it (a newer root, say) stays saved, as the specification says.
    ///
    /// # Errors
    ///
    /// A [`TufError`] naming the check that failed: a signature below its threshold, a
    /// version that went back or is not the one listed, a hash or length that does not
    /// match, an expired file, a file that is not there, or a store that cannot be written.
    pub fn refresh(&mut self, now: OffsetDateTime) -> Result<Trusted, TufError> {
        // 5.1: `now` is the fixed update start time.
        let mut state = self.store.load()?;
        let loaded_root = state.root.clone();
        // 5.2: the trusted root: the built-in one, or the newer one saved by an earlier run.
        let (mut root_file, mut root) = self.trusted_root(&mut state);

        // 5.3: the root chain.
        let mut changed = loaded_root.as_ref() != Some(&root_file);
        let mut rotated = false;
        let mut downloaded = 0u32;
        // 5.3.2-5.3.3: N is the trusted version; try N+1.
        while let Some(next) = root.version.checked_add(1) {
            if downloaded >= self.limits.max_roots {
                break; // 5.3.3: more than Y roots, go to 5.3.10.
            }
            let path = layout::root_path(next);
            let Some(body) = self.get(&path, self.limits.root)? else {
                break; // 5.3.3: not available, go to 5.3.10.
            };
            downloaded += 1;
            let new_file = Envelope::parse(&body, self.limits.root, &path)?;
            // 5.3.4: signed by a threshold of the keys of the trusted root (N) ...
            verify_role(
                &new_file,
                &root,
                Role::Root,
                &format!("root {next} by the keys of root {}", root.version),
            )?;
            let new_root = Root::from_signed(&new_file.signed)?;
            // ... and by a threshold of the keys of the new root (N+1).
            verify_role(
                &new_file,
                &new_root,
                Role::Root,
                &format!("root {next} by its own keys"),
            )?;
            // 5.3.5: exactly N+1.
            if new_root.version != next {
                return Err(TufError::RootVersion {
                    expected: next,
                    found: new_root.version,
                });
            }
            // 5.3.6: the expiry of an intermediate root does not matter yet.
            // 5.3.7: the new root is the trusted root.
            rotated |= root.rotates(&new_root);
            root_file = new_file;
            root = new_root;
            changed = true;
            // 5.3.8: persisted below, in one write with 5.3.11.
            // 5.3.9: repeat.
        }

        // 5.3.11: if the timestamp, snapshot (or targets) keys were rotated, the versions
        // trusted before are forgotten. It is done, and saved with the root, before the
        // expiry check below: a root too old to use would otherwise be saved without it.
        if rotated {
            state.timestamp = None;
            state.snapshot = None;
            state.targets = None;
        }
        state.root = Some(root_file);
        if changed {
            self.store.save(&state)?;
        }
        // 5.3.10: a freeze attack, or a repository nobody re-signed.
        ensure_fresh(Role::Root, root.expires, now)?;
        // 5.3.12: consistent snapshots: `Root::from_signed` refuses a root without them.

        // 5.4: the timestamp.
        let timestamp = self.update_timestamp(&mut state, &root, now)?;
        // 5.5: the snapshot.
        let snapshot = self.update_snapshot(&mut state, &root, &timestamp, now)?;
        // 5.6: the targets.
        let targets = self.update_targets(&mut state, &root, &snapshot, now)?;
        Ok(Trusted {
            root,
            timestamp,
            snapshot,
            targets,
        })
    }

    /// 5.2: the root to start from. The saved one if it is newer than the built-in one;
    /// otherwise the built-in one, and then, if a saved root is there whose timestamp,
    /// snapshot or targets keys differ, what was saved of those roles is dropped (the
    /// built-in root is a later root). A saved root that cannot be read, or is not signed by
    /// its own keys, is dropped with everything saved with it.
    fn trusted_root(&self, state: &mut TrustState) -> (Envelope, Root) {
        let saved = state.root.take().and_then(|file| {
            let root = Root::from_signed(&file.signed).ok()?;
            verify_role(&file, &root, Role::Root, "the saved root").ok()?;
            Some((file, root))
        });
        let anchor = &self.anchor;
        match saved {
            Some((file, root)) if root.version > anchor.root.version => (file, root),
            Some((_, root)) => {
                if root.rotates(&anchor.root) {
                    state.timestamp = None;
                    state.snapshot = None;
                    state.targets = None;
                }
                (anchor.envelope.clone(), anchor.root.clone())
            }
            None => {
                *state = TrustState::default();
                (anchor.envelope.clone(), anchor.root.clone())
            }
        }
    }

    fn update_timestamp(
        &mut self,
        state: &mut TrustState,
        root: &Root,
        now: OffsetDateTime,
    ) -> Result<Timestamp, TufError> {
        // 5.4.1: download it, up to X bytes.
        let body = self.get_required(layout::TIMESTAMP_PATH, self.limits.timestamp)?;
        let file = Envelope::parse(&body, self.limits.timestamp, "timestamp.json")?;
        // 5.4.2: signed by a threshold of the timestamp keys of the trusted root.
        verify_role(&file, root, Role::Timestamp, "the timestamp")?;
        let timestamp = Timestamp::from_signed(&file.signed)?;
        // 5.4.3: a rollback attack.
        if let Some(trusted) = &state.timestamp {
            // 5.4.3.1: the version must not be below the trusted one. An equal one is the
            // same timestamp (and then the rest of the update goes on, see the module's
            // description), unless it lists another snapshot.
            if timestamp.version < trusted.version {
                return Err(TufError::Rollback {
                    what: "timestamp".to_owned(),
                    found: timestamp.version,
                    trusted: trusted.version,
                });
            }
            if timestamp.version == trusted.version && timestamp.snapshot != trusted.snapshot {
                return Err(TufError::TimestampChanged(timestamp.version));
            }
            // 5.4.3.2: the snapshot it lists is not older than the trusted one's.
            if timestamp.snapshot.version < trusted.snapshot.version {
                return Err(TufError::Rollback {
                    what: "snapshot listed by the timestamp".to_owned(),
                    found: timestamp.snapshot.version,
                    trusted: trusted.snapshot.version,
                });
            }
        }
        // 5.4.4: a freeze attack.
        ensure_fresh(Role::Timestamp, timestamp.expires, now)?;
        // 5.4.5: persist.
        state.timestamp = Some(TimestampState {
            version: timestamp.version,
            snapshot: timestamp.snapshot.clone(),
        });
        self.store.save(state)?;
        Ok(timestamp)
    }

    fn update_snapshot(
        &mut self,
        state: &mut TrustState,
        root: &Root,
        timestamp: &Timestamp,
        now: OffsetDateTime,
    ) -> Result<Snapshot, TufError> {
        let listed = &timestamp.snapshot;
        // 5.5.1: download it, up to the length the timestamp lists (or Y), from the name
        // with its version.
        let body = self.get_listed(
            &layout::snapshot_path(listed.version),
            "snapshot.json",
            listed,
            self.limits.snapshot,
        )?;
        // 5.5.2: the hash the timestamp lists (checked in `get_listed`, before the
        // signature).
        let file = Envelope::parse(&body, self.limits.snapshot, "snapshot.json")?;
        // 5.5.3: signed by a threshold of the snapshot keys of the trusted root.
        verify_role(&file, root, Role::Snapshot, "the snapshot")?;
        let snapshot = Snapshot::from_signed(&file.signed)?;
        // 5.5.4: the version the timestamp lists.
        if snapshot.version != listed.version {
            return Err(TufError::VersionMismatch {
                role: Role::Snapshot,
                above: Role::Timestamp,
                expected: listed.version,
                found: snapshot.version,
            });
        }
        // 5.5.5: a rollback attack: no file's version goes back, no file listed is dropped.
        if let Some(trusted) = &state.snapshot {
            for (name, trusted_version) in &trusted.meta {
                match snapshot.meta.get(name) {
                    None => {
                        return Err(TufError::malformed(
                            "snapshot",
                            format!("{name} was listed by the snapshot trusted before"),
                        ));
                    }
                    Some(now_listed) if now_listed.version < *trusted_version => {
                        return Err(TufError::Rollback {
                            what: format!("{name} listed by the snapshot"),
                            found: now_listed.version,
                            trusted: *trusted_version,
                        });
                    }
                    Some(_) => {}
                }
            }
        }
        // 5.5.6: a freeze attack.
        ensure_fresh(Role::Snapshot, snapshot.expires, now)?;
        // 5.5.7: persist.
        state.snapshot = Some(SnapshotState {
            version: snapshot.version,
            meta: snapshot
                .meta
                .iter()
                .map(|(name, meta)| (name.clone(), meta.version))
                .collect(),
        });
        self.store.save(state)?;
        Ok(snapshot)
    }

    fn update_targets(
        &mut self,
        state: &mut TrustState,
        root: &Root,
        snapshot: &Snapshot,
        now: OffsetDateTime,
    ) -> Result<Targets, TufError> {
        let listed = snapshot.targets();
        // 5.6.1: download it, up to the length the snapshot lists (or Z), from the name with
        // its version.
        let body = self.get_listed(
            &layout::targets_path(listed.version),
            TARGETS_META,
            listed,
            self.limits.targets,
        )?;
        // 5.6.2: the hash the snapshot lists (checked in `get_listed`).
        let file = Envelope::parse(&body, self.limits.targets, TARGETS_META)?;
        // 5.6.3: signed by a threshold of the targets keys of the trusted root.
        verify_role(&file, root, Role::Targets, "the targets")?;
        let targets = Targets::from_signed(&file.signed)?;
        // 5.6.4: the version the snapshot lists.
        if targets.version != listed.version {
            return Err(TufError::VersionMismatch {
                role: Role::Targets,
                above: Role::Snapshot,
                expected: listed.version,
                found: targets.version,
            });
        }
        // The targets trusted before are not newer than these (5.5.5 holds the snapshot to
        // this too; the saved version is kept apart so that it outlives a snapshot's).
        if let Some(trusted) = state.targets
            && targets.version < trusted
        {
            return Err(TufError::Rollback {
                what: "targets".to_owned(),
                found: targets.version,
                trusted,
            });
        }
        // 5.6.5: a freeze attack.
        ensure_fresh(Role::Targets, targets.expires, now)?;
        // 5.6.6: persist.
        state.targets = Some(targets.version);
        self.store.save(state)?;
        // 5.6.7: the search for a target is in the top-level targets only: delegations are
        // refused when the targets are read.
        Ok(targets)
    }

    /// 5.7: the target `path` of `trusted`, as the repository has it: downloaded from its
    /// hash name, and handed over only if it is exactly the length and sha256 the targets
    /// metadata lists. `max_len` is the most the caller takes; a target the metadata lists
    /// as larger is refused without a request.
    ///
    /// The target is recorded as accepted ([`TrustState::accepted`]) in the store.
    ///
    /// # Errors
    ///
    /// [`TufError::NoSuchTarget`] (5.7.2), [`TufError::TargetTooLarge`],
    /// [`TufError::NotFound`] if the file is not there, [`TufError::Fetch`] if it is longer
    /// than listed, [`TufError::Length`] or [`TufError::Hash`] if it does not match, or the
    /// store's error.
    pub fn download_target(
        &mut self,
        trusted: &Trusted,
        path: &str,
        max_len: u64,
    ) -> Result<Vec<u8>, TufError> {
        // 5.7.1-5.7.2: the metadata of the target.
        let target = trusted
            .target(path)
            .ok_or_else(|| TufError::NoSuchTarget(path.to_owned()))?;
        if target.length > max_len {
            return Err(TufError::TargetTooLarge {
                path: path.to_owned(),
                len: target.length,
                max: max_len,
            });
        }
        // 5.7.3: download up to the listed length, from the name with the hash ...
        let stored = layout::target_file_path(path, &target.sha256)
            .ok_or_else(|| TufError::NoSuchTarget(path.to_owned()))?;
        let body = self.get_required(&stored, target.length)?;
        // ... and verify its length and hash.
        if body.len() as u64 != target.length {
            return Err(TufError::Length {
                what: path.to_owned(),
                expected: target.length,
                actual: body.len() as u64,
            });
        }
        if Digest::of(&body) != target.sha256 {
            return Err(TufError::Hash {
                what: path.to_owned(),
            });
        }
        let mut state = self.store.load()?;
        state.accepted.insert(
            path.to_owned(),
            AcceptedTarget {
                sha256: target.sha256,
                length: target.length,
                targets_version: trusted.targets.version,
            },
        );
        self.store.save(&state)?;
        Ok(body)
    }

    /// The file at `path`, or `None` for a 404; never more than `max_len` bytes, whatever
    /// the fetcher hands over.
    fn get(&self, path: &str, max_len: u64) -> Result<Option<Vec<u8>>, TufError> {
        match self.fetcher.fetch(path, max_len)? {
            Response::NotFound => Ok(None),
            Response::Body(body) if body.len() as u64 > max_len => Err(TufError::TooLarge {
                what: path.to_owned(),
                limit: max_len,
            }),
            Response::Body(body) => Ok(Some(body)),
        }
    }

    fn get_required(&self, path: &str, max_len: u64) -> Result<Vec<u8>, TufError> {
        self.get(path, max_len)?
            .ok_or_else(|| TufError::NotFound(path.to_owned()))
    }

    /// A metadata file a role above lists: at most `listed.length` bytes (or `limit`, which
    /// is also the most a listed length may be), then exactly that length and the listed
    /// sha256, if they are listed.
    fn get_listed(
        &self,
        path: &str,
        name: &str,
        listed: &MetaFile,
        limit: u64,
    ) -> Result<Vec<u8>, TufError> {
        let max_len = match listed.length {
            Some(length) if length > limit => {
                return Err(TufError::TooLarge {
                    what: name.to_owned(),
                    limit,
                });
            }
            Some(length) => length,
            None => limit,
        };
        let body = self.get_required(path, max_len)?;
        if let Some(length) = listed.length
            && body.len() as u64 != length
        {
            return Err(TufError::Length {
                what: name.to_owned(),
                expected: length,
                actual: body.len() as u64,
            });
        }
        if let Some(sum) = listed.sha256
            && Digest::of(&body) != sum
        {
            return Err(TufError::Hash {
                what: name.to_owned(),
            });
        }
        Ok(body)
    }
}
