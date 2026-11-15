//! `cargo xtask tuf update`: new targets and snapshot over the update indexes, signed with the
//! owner's keys.
//!
//! The indexes (`updates/v1/{stable,beta}.json`) are copied byte for byte to
//! `targets/indexes/<sha256>.<channel>.json` and listed by `metadata/<N+1>.targets.json`,
//! which `metadata/<N+1>.snapshot.json` lists. Versions only grow, by one over the highest
//! committed. The timestamp is not touched: CI signs it when Pages is published.
//!
//! A run with nothing to change writes nothing (so the owner is not asked for a passphrase
//! either): the indexes are the committed targets, and the committed targets and snapshot
//! are signed by the keys of the root in force. `refresh` signs new versions anyway, with
//! the same targets: the monthly job that pushes the expiry forward. After a rotation of the
//! targets or snapshot key the committed files are not signed by the keys in force, which is
//! "something to change" too.
//!
//! The result is verified before the run ends, with the client's code ([`super::check`]);
//! if it does not hold, what was written is removed again.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use oncl_update::tuf::build;
use oncl_update::tuf::ed25519::verify_role;
use oncl_update::tuf::{Digest, Envelope, Limits, Role, Snapshot, Targets, layout};
use oncl_update::{Channel, Index, MAX_INDEX_LEN};
use time::OffsetDateTime;

use super::check::{self, Expiry, TimestampMode};
use super::keystore::{self, Unlock};
use super::repo::{self, Listing};
use super::{PassphraseSource, SNAPSHOT_DAYS, TARGETS_DAYS, expiry};

/// What [`update`] does.
pub struct Options<'a> {
    /// The directory of the secret keys.
    pub keys: &'a Path,
    /// The directory of the indexes (`updates/v1`).
    pub index: &'a Path,
    /// The repository directory (`tuf/v1`).
    pub out: &'a Path,
    /// Sign new versions even if nothing changed.
    pub refresh: bool,
    /// The signing time.
    pub now: OffsetDateTime,
    /// Where the passphrase of the keys comes from.
    pub passphrase: &'a PassphraseSource,
}

/// What [`update`] did.
#[derive(Debug)]
pub enum Outcome {
    /// Nothing to change: the committed targets and snapshot already are the indexes.
    UpToDate {
        /// The targets version in force.
        targets: u64,
        /// The snapshot version in force.
        snapshot: u64,
    },
    /// New versions were written.
    Written(Written),
}

/// The new versions.
#[derive(Debug)]
pub struct Written {
    /// Why.
    pub reason: String,
    /// The new targets version.
    pub targets: u64,
    /// The new snapshot version.
    pub snapshot: u64,
    /// When both expire.
    pub expires: OffsetDateTime,
    /// The files made, with the metadata last.
    pub files: Vec<PathBuf>,
}

/// The indexes in `dir` as targets: `(target path, bytes)`, valid indexes of the channel
/// their file name says.
///
/// # Errors
///
/// If one is not readable, too large or not a valid index of its channel.
pub fn read_indexes(dir: &Path) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::new();
    for channel in Channel::ALL {
        let path = dir.join(format!("{}.json", channel.as_str()));
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        if bytes.len() as u64 > MAX_INDEX_LEN {
            bail!("{} is larger than {MAX_INDEX_LEN} bytes", path.display());
        }
        let index =
            Index::from_json(&bytes).with_context(|| format!("reading {}", path.display()))?;
        if index.channel != channel {
            bail!(
                "{} is an index of the {} channel",
                path.display(),
                index.channel
            );
        }
        files.push((format!("indexes/{}.json", channel.as_str()), bytes));
    }
    Ok(files)
}

fn read_targets(dir: &Path, version: u64) -> anyhow::Result<(Envelope, Targets)> {
    let path = layout::targets_path(version);
    let bytes = repo::read(dir, &path)?;
    let env = Envelope::parse(&bytes, Limits::default().targets, &path)
        .map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
    let targets = Targets::from_signed(&env.signed).map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
    Ok((env, targets))
}

fn read_snapshot(dir: &Path, version: u64) -> anyhow::Result<(Envelope, Snapshot)> {
    let path = layout::snapshot_path(version);
    let bytes = repo::read(dir, &path)?;
    let env = Envelope::parse(&bytes, Limits::default().snapshot, &path)
        .map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
    let snapshot =
        Snapshot::from_signed(&env.signed).map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
    Ok((env, snapshot))
}

/// Signs new targets and snapshot over the indexes (see the module's description).
///
/// # Errors
///
/// If the repository or the indexes are not usable, the keys cannot be opened, or the result
/// does not verify (then nothing stays written).
pub fn update(options: &Options) -> anyhow::Result<Outcome> {
    let anchor = repo::read(options.out, &layout::root_path(1))
        .context("the repository has no root version 1: run `cargo xtask tuf init` first")?;
    let root = check::final_root(options.out, &anchor, options.now)?;
    let listing = Listing::read(options.out)?;
    let (_, last_targets, last_snapshot) = listing.highest();

    let indexes = read_indexes(options.index)?;
    if indexes.is_empty() {
        bail!("there is no update index in {}", options.index.display());
    }
    let wanted: BTreeMap<&str, (u64, Digest)> = indexes
        .iter()
        .map(|(path, bytes)| (path.as_str(), (bytes.len() as u64, Digest::of(bytes))))
        .collect();

    // What there is to do.
    let mut reasons: Vec<String> = Vec::new();
    if last_targets == 0 || last_snapshot == 0 {
        reasons.push("the repository has no targets and snapshot yet".to_owned());
    } else {
        let (targets_env, targets) = read_targets(options.out, last_targets)?;
        for path in targets.targets.keys() {
            if !wanted.contains_key(path.as_str()) {
                bail!(
                    "the targets list {path}, but its index file is not in {}: clients of that \
                     channel would be left without updates",
                    options.index.display()
                );
            }
        }
        let listed: BTreeMap<&str, (u64, Digest)> = targets
            .targets
            .iter()
            .map(|(path, t)| (path.as_str(), (t.length, t.sha256)))
            .collect();
        if listed != wanted {
            let changed: Vec<&str> = wanted
                .iter()
                .filter(|(path, entry)| listed.get(*path) != Some(entry))
                .map(|(path, _)| *path)
                .collect();
            reasons.push(format!("the indexes changed: {}", changed.join(", ")));
        }
        let (snapshot_env, snapshot) = read_snapshot(options.out, last_snapshot)?;
        let keys_ok = verify_role(&targets_env, &root, Role::Targets, "the targets").is_ok()
            && verify_role(&snapshot_env, &root, Role::Snapshot, "the snapshot").is_ok();
        if !keys_ok {
            reasons.push(format!(
                "targets {last_targets} and snapshot {last_snapshot} are not signed by the keys \
                 of root {} (a key was rotated)",
                root.version
            ));
        }
        if snapshot.targets().version != last_targets {
            reasons.push(format!(
                "snapshot {last_snapshot} lists targets {}, not {last_targets}",
                snapshot.targets().version
            ));
        }
    }
    if reasons.is_empty() && options.refresh {
        reasons.push("refresh: new expiry, same targets".to_owned());
    }
    if reasons.is_empty() {
        return Ok(Outcome::UpToDate {
            targets: last_targets,
            snapshot: last_snapshot,
        });
    }

    // The keys of the roles in force.
    let mut unlock = Unlock::new(options.passphrase.clone(), "Passphrase of the TUF keys: ");
    let mut signers = |role: Role| -> anyhow::Result<Vec<_>> {
        let keys = keystore::find_keys(options.keys, role, &root.role(role).keyids, &mut unlock)?;
        if keys.len() < root.role(role).threshold as usize {
            bail!(
                "root {} needs {} {role} keys to sign, {} are in {}",
                root.version,
                root.role(role).threshold,
                keys.len(),
                options.keys.display()
            );
        }
        Ok(keys)
    };
    let targets_keys = signers(Role::Targets)?;
    let snapshot_keys = signers(Role::Snapshot)?;

    let targets_version = last_targets + 1;
    let snapshot_version = last_snapshot + 1;
    let expires = expiry(options.now, TARGETS_DAYS.min(SNAPSHOT_DAYS));
    let refs: Vec<(&str, &[u8])> = indexes
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect();
    let signed = build::targets(targets_version, expiry(options.now, TARGETS_DAYS), &refs)
        .map_err(|e| anyhow::anyhow!("making the targets: {e}"))?;
    let targets_file = build::sign(&signed, &targets_keys.iter().collect::<Vec<_>>())
        .map_err(|e| anyhow::anyhow!("signing the targets: {e}"))?;
    let signed = build::snapshot(
        snapshot_version,
        expiry(options.now, SNAPSHOT_DAYS),
        targets_version,
        &targets_file,
    )
    .map_err(|e| anyhow::anyhow!("making the snapshot: {e}"))?;
    let snapshot_file = build::sign(&signed, &snapshot_keys.iter().collect::<Vec<_>>())
        .map_err(|e| anyhow::anyhow!("signing the snapshot: {e}"))?;
    let stored =
        build::target_files(&refs).map_err(|e| anyhow::anyhow!("laying out the targets: {e}"))?;

    // Write: the targets files (content-addressed: one that is there already must be the
    // same bytes), then the metadata. A failure removes what this run made.
    let mut created: Vec<PathBuf> = Vec::new();
    let written = (|| -> anyhow::Result<()> {
        for (path, content) in &stored {
            let full = options.out.join(path);
            if full.exists() {
                if fs::read(&full).with_context(|| format!("reading {}", full.display()))?
                    != *content
                {
                    bail!(
                        "{} exists and is not the file its name says",
                        full.display()
                    );
                }
                continue;
            }
            created.push(repo::write_new(options.out, path, content)?);
        }
        created.push(repo::write_new(
            options.out,
            &layout::targets_path(targets_version),
            &targets_file,
        )?);
        created.push(repo::write_new(
            options.out,
            &layout::snapshot_path(snapshot_version),
            &snapshot_file,
        )?);
        Ok(())
    })();
    let verdict = written.and_then(|()| {
        let report = check::check(&check::Options {
            dir: options.out,
            index: Some(options.index),
            anchor: None,
            now: options.now,
            timestamp: TimestampMode::Absent,
            expiry: Expiry {
                min_days: 0,
                min_root_days: 0,
                fail: false,
            },
            base: None,
        })?;
        match report {
            check::Outcome::Checked(report) if report.problems.is_empty() => Ok(()),
            check::Outcome::Checked(report) => bail!(
                "the repository does not verify after the update:\n{}",
                report
                    .problems
                    .iter()
                    .map(|p| format!("  {p}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            check::Outcome::NoRepository => bail!("the repository vanished"),
        }
    });
    if let Err(e) = verdict {
        for path in &created {
            let _ = fs::remove_file(path);
        }
        return Err(e.context("nothing was left written"));
    }
    Ok(Outcome::Written(Written {
        reason: reasons.join("; "),
        targets: targets_version,
        snapshot: snapshot_version,
        expires,
        files: created,
    }))
}
