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
//! - the roots followed are saved with that deletion in one atomic write, before the expiry
//!   of the final root is checked (step 5.3.10), and also when a root further on is refused:
//!   a root that is too old to use is still remembered, the keys it rotated are still
//!   forgotten, and a chain too long for one refresh is followed in several;
//! - what is saved is the whole chain of roots from the built-in one; a later run checks it
//!   again from the built-in root, both thresholds at every step, before it trusts any of it
//!   (a saved root alone, signed by its own keys, would be whatever whoever writes the
//!   state says). A state that is not a state, or whose chain does not hold, is dropped and
//!   the run starts from the built-in root ([`Trusted::state_was_reset`]);
//! - a built-in root newer than the saved state drops the versions saved before it (its keys
//!   cannot be compared with those of roots it does not chain from);
//! - the targets file accepted is saved beside its version, so that a target kept from an
//!   earlier download can be checked again offline ([`TufClient::verify_cached_target`]);
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
use super::store::{SnapshotState, Store, TimestampState, TrustState};

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
    reset: Option<String>,
}

impl Trusted {
    /// Why this refresh started from the built-in root, ignoring the saved state: it was
    /// not readable, or did not hold up. The caller logs it; the state was replaced.
    pub fn state_was_reset(&self) -> Option<&str> {
        self.reset.as_deref()
    }

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

    /// `Ok` if none of the four files has expired at `now`: metadata that was fresh when it
    /// was refreshed is not fresh for ever.
    ///
    /// # Errors
    ///
    /// [`TufError::Expired`] for the first of root, timestamp, snapshot, targets that has.
    pub fn ensure_fresh(&self, now: OffsetDateTime) -> Result<(), TufError> {
        ensure_fresh(Role::Root, self.root.expires, now)?;
        ensure_fresh(Role::Timestamp, self.timestamp.expires, now)?;
        ensure_fresh(Role::Snapshot, self.snapshot.expires, now)?;
        ensure_fresh(Role::Targets, self.targets.expires, now)
    }
}

/// A TUF repository's client.
pub struct TufClient<F, S> {
    fetcher: F,
    store: S,
    /// The root built into the program.
    anchor: Root,
    limits: Limits,
    /// Why the last refresh that reset the saved state did (also when it then failed).
    last_reset: Option<String>,
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
            anchor: root,
            limits,
            last_reset: None,
        })
    }

    /// A client trusting the root built into this program, or `None` if the build has none:
    /// then there is no way to trust a repository, and updates are off.
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

    /// Why the last refresh that reset the saved state did so, if one did, whether or not it
    /// went on to succeed (it is logged as a warning when it happens).
    pub fn last_reset(&self) -> Option<&str> {
        self.last_reset.as_deref()
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
    /// before it stays saved, as the specification says: the roots followed before a root
    /// that is refused (or before the limit of roots one refresh follows), the timestamp
    /// before a snapshot that is refused, and so on.
    ///
    /// # Errors
    ///
    /// A [`TufError`] naming the check that failed: a signature below its threshold, a
    /// version that went back or is not the one listed, a hash or length that does not
    /// match, an expired file, a file that is not there, a chain of roots longer than
    /// [`Limits::max_roots`], or a store that cannot be written.
    pub fn refresh(&mut self, now: OffsetDateTime) -> Result<Trusted, TufError> {
        // 5.1: `now` is the fixed update start time.
        let (mut state, mut reset) = match self.store.load() {
            Ok(state) => (state, None),
            Err(TufError::Store(e)) if e.kind() == std::io::ErrorKind::InvalidData => (
                TrustState::default(),
                Some(format!("the saved state is not readable: {e}")),
            ),
            Err(e) => return Err(e),
        };
        // 5.2: the trusted root: the built-in one, and the saved chain after it if it holds.
        let loaded = state.clone();
        let mut root = match self.replay(&mut state) {
            Ok(root) => root,
            Err(why) => {
                state = TrustState::default();
                reset.get_or_insert(why);
                self.anchor.clone()
            }
        };
        if let Some(why) = &reset {
            tracing::warn!(reason = %why, "the saved TUF state was reset to the built-in root");
            self.last_reset = Some(why.clone());
        }
        if reset.is_some() {
            state.root_version = root.version;
            self.store.overwrite(&state)?;
        }

        // 5.3: the root chain.
        let mut downloaded = 0u32;
        let mut chain_error = None;
        // 5.3.2-5.3.3: N is the trusted version; try N+1.
        while let Some(next) = root.version.checked_add(1) {
            let path = layout::root_path(next);
            let body = match self.get(&path, self.limits.root) {
                Ok(Some(body)) => body,
                // 5.3.3: not available, go to 5.3.10.
                Ok(None) => break,
                Err(e) => {
                    chain_error = Some(e);
                    break;
                }
            };
            if downloaded >= self.limits.max_roots {
                // 5.3.3: more than Y roots: the chain ends here only if there is no more.
                chain_error = Some(TufError::RootChainTooLong(self.limits.max_roots));
                break;
            }
            downloaded += 1;
            match self.follow_root(&root, next, &body, &path) {
                Ok((file, new_root)) => {
                    // 5.3.6: the expiry of an intermediate root does not matter yet.
                    // 5.3.11: if the timestamp, snapshot (or targets) keys were rotated, the
                    // versions trusted before are forgotten.
                    if root.rotates(&new_root) {
                        state.timestamp = None;
                        state.snapshot = None;
                        state.targets = None;
                        state.targets_file = None;
                        state.keys_epoch = new_root.version;
                    }
                    // 5.3.7: the new root is the trusted root.
                    state.roots.push(file);
                    state.root_version = new_root.version;
                    root = new_root;
                    // 5.3.9: repeat.
                }
                Err(e) => {
                    chain_error = Some(e);
                    break;
                }
            }
        }
        // 5.3.8: persist the roots followed, and what 5.3.11 dropped, in one write, also if
        // a root further on was refused (and before the expiry check below: a root too old
        // to use would otherwise be saved without the deletion).
        if state != loaded {
            state = self.store.save(&state)?;
        }
        if let Some(e) = chain_error {
            return Err(e);
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
            reset,
        })
    }

    /// 5.3.4-5.3.5: the root file `body` as version `next` after `root`, the trusted one.
    fn follow_root(
        &self,
        root: &Root,
        next: u64,
        body: &[u8],
        path: &str,
    ) -> Result<(Envelope, Root), TufError> {
        let file = Envelope::parse(body, self.limits.root, path)?;
        accept_root(root, next, file)
    }

    /// 5.2: checks the saved chain of roots again from the built-in one, drops the entries
    /// the built-in root has overtaken, and returns the root in force. `Err` says why the
    /// state does not hold. If the built-in root is newer than the state, what was saved of
    /// the timestamp, snapshot and targets goes too.
    fn replay(&self, state: &mut TrustState) -> Result<Root, String> {
        let anchor = &self.anchor;
        let mut trusted = anchor.clone();
        let mut kept = Vec::new();
        for (i, file) in state.roots.iter().enumerate() {
            let root = Root::from_signed(&file.signed)
                .map_err(|e| format!("saved root #{} is not a root: {e}", i + 1))?;
            if root.version <= anchor.version {
                continue; // The built-in root has overtaken it.
            }
            let (file, root) =
                accept_root(&trusted, trusted.version + 1, file.clone()).map_err(|e| {
                    format!(
                        "saved root {} does not follow the built-in root: {e}",
                        root.version
                    )
                })?;
            kept.push(file);
            trusted = root;
        }
        if state.root_version > trusted.version {
            return Err(format!(
                "the saved state is of root {}, its chain ends at {}",
                state.root_version, trusted.version
            ));
        }
        if state.root_version != 0 && state.root_version < anchor.version {
            // A built-in root newer than anything saved: the keys of the roles in between
            // are not known, so the versions saved under them are not kept.
            state.timestamp = None;
            state.snapshot = None;
            state.targets = None;
            state.targets_file = None;
            state.keys_epoch = anchor.version;
        }
        state.roots = kept;
        state.root_version = trusted.version;
        Ok(trusted)
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
        *state = self.store.save(state)?;
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
        *state = self.store.save(state)?;
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
        state.targets_file = Some(file);
        *state = self.store.save(state)?;
        // 5.6.7: the search for a target is in the top-level targets only: delegations are
        // refused when the targets are read.
        Ok(targets)
    }

    /// 5.7: the target `path` of `trusted`, as the repository has it: downloaded from its
    /// hash name, and handed over only if it is exactly the length and sha256 the targets
    /// metadata lists. `max_len` is the most the caller takes; a target the metadata lists
    /// as larger is refused without a request. `now` is the time of this call: `trusted` is
    /// not used once any of its files has expired.
    ///
    /// # Errors
    ///
    /// [`TufError::Expired`], [`TufError::NoSuchTarget`] (5.7.2), [`TufError::TargetTooLarge`],
    /// [`TufError::NotFound`] if the file is not there, [`TufError::Fetch`] if it is longer
    /// than listed, [`TufError::Length`] or [`TufError::Hash`] if it does not match.
    pub fn download_target(
        &self,
        trusted: &Trusted,
        path: &str,
        max_len: u64,
        now: OffsetDateTime,
    ) -> Result<Vec<u8>, TufError> {
        trusted.ensure_fresh(now)?;
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
        Ok(body)
    }

    /// The target `path` as a file kept from an earlier [`TufClient::download_target`]
    /// (`bytes`), checked again without the network: the saved targets file must still be
    /// signed by the targets keys of the root chain, which is replayed from the built-in
    /// root, be the version saved, and not have expired at `now`; the root in force must not
    /// have expired either; `bytes` must be exactly the length and sha256 it lists. Nothing
    /// is read from the repository and nothing is written.
    ///
    /// The timestamp and snapshot are not asked: they expire in days and say that the
    /// targets are *current*, which only a refresh can tell; this says that `bytes` are what
    /// the targets the client accepted last list. On success the moment this stops holding:
    /// the earlier of the expiry of the root and of the targets.
    ///
    /// # Errors
    ///
    /// [`TufError::Store`] if the state cannot be read, [`TufError::Malformed`] if it does
    /// not hold up from the built-in root or its targets are not the version saved,
    /// [`TufError::NoSuchTarget`] if no targets are saved or they do not list `path`,
    /// [`TufError::Signature`], [`TufError::Expired`], [`TufError::Length`] or
    /// [`TufError::Hash`].
    pub fn verify_cached_target(
        &self,
        path: &str,
        bytes: &[u8],
        now: OffsetDateTime,
    ) -> Result<OffsetDateTime, TufError> {
        let mut state = self.store.load()?;
        let root = self
            .replay(&mut state)
            .map_err(|why| TufError::malformed("the saved TUF state", why))?;
        ensure_fresh(Role::Root, root.expires, now)?;
        let (Some(version), Some(file)) = (state.targets, &state.targets_file) else {
            return Err(TufError::NoSuchTarget(path.to_owned()));
        };
        verify_role(file, &root, Role::Targets, "the saved targets")?;
        let targets = Targets::from_signed(&file.signed)?;
        if targets.version != version {
            return Err(TufError::malformed(
                "the saved targets",
                format!("version {} is not the {version} saved", targets.version),
            ));
        }
        ensure_fresh(Role::Targets, targets.expires, now)?;
        let target = targets
            .targets
            .get(path)
            .ok_or_else(|| TufError::NoSuchTarget(path.to_owned()))?;
        if bytes.len() as u64 != target.length {
            return Err(TufError::Length {
                what: path.to_owned(),
                expected: target.length,
                actual: bytes.len() as u64,
            });
        }
        if Digest::of(bytes) != target.sha256 {
            return Err(TufError::Hash {
                what: path.to_owned(),
            });
        }
        Ok(root.expires.min(targets.expires))
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

/// 5.3.4-5.3.5: `file` as root version `next` after `trusted`: signed by a threshold of the
/// keys of the trusted root and by a threshold of its own, and exactly that version.
fn accept_root(trusted: &Root, next: u64, file: Envelope) -> Result<(Envelope, Root), TufError> {
    // 5.3.4: signed by a threshold of the keys of the trusted root (N) ...
    verify_role(
        &file,
        trusted,
        Role::Root,
        &format!("root {next} by the keys of root {}", trusted.version),
    )?;
    let new_root = Root::from_signed(&file.signed)?;
    // ... and by a threshold of the keys of the new root (N+1).
    verify_role(
        &file,
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
    Ok((file, new_root))
}
