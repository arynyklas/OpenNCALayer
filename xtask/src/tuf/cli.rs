//! The command line of `cargo xtask tuf` (`docs/dev/release.md` says when each is run).
//!
//! Exit codes: 0 when the command did what it says (`tuf check` also when it found only
//! warnings, or no repository yet); 1 when it refused, failed, or `tuf check` found
//! problems; 2 for a command line that does not parse.

use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::Subcommand;
use oncl_update::tuf::HttpFetcher;
use time::OffsetDateTime;

use super::check::{self, Expiry, TimestampMode};
use super::published::{self, Published};
use super::timestamp::KeySource;
use super::{
    ANCHOR, PassphraseSource, REPO_DIR, init, parse_time, root, show_time, timestamp, update,
};

/// `cargo xtask tuf …`: the operator's side of the TUF repository of the update indexes.
#[derive(Subcommand)]
pub enum TufCommand {
    /// The owner's ceremony: make the root, targets, snapshot and timestamp keys, root
    /// version 1 in the repository, and a copy of it as the client's trust anchor. The
    /// root, targets and snapshot keys are written encrypted with one passphrase (asked
    /// twice); the timestamp key is one unencrypted line, for the GitHub secret
    /// `TUF_TIMESTAMP_KEY`. Nothing existing is overwritten.
    Init {
        /// The directory of the secret keys: outside the repository, or git-ignored.
        #[arg(long)]
        keys: PathBuf,
        /// The repository directory [default: `tuf/v1` of the workspace].
        #[arg(long)]
        out: Option<PathBuf>,
        /// The trust anchor file [default: `crates/oncl-update/keys/root.json`].
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// Also make a second root key (the threshold stays 1), to keep in another safe
        /// place: either signs the next root.
        #[arg(long)]
        spare_root: bool,
        /// The signing time, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
        /// Read the passphrase from the first line of this file instead of asking
        /// (automation and tests).
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Sign new targets and snapshot over `updates/v1/{stable,beta}.json` (those that
    /// exist): copies the indexes under their hashes and writes `metadata/<N+1>.targets.json`
    /// and `<N+1>.snapshot.json`, valid for 30 days. With nothing changed it says "up to
    /// date" and writes nothing; `--refresh` signs new versions anyway, to push the expiry
    /// forward. Never touches the timestamp.
    Update {
        /// The directory of the secret keys.
        #[arg(long)]
        keys: PathBuf,
        /// The directory of the indexes [default: `updates/v1` of the workspace].
        #[arg(long)]
        index: Option<PathBuf>,
        /// The repository directory [default: `tuf/v1` of the workspace].
        #[arg(long)]
        out: Option<PathBuf>,
        /// Sign new versions even if the indexes did not change (the monthly job).
        #[arg(long)]
        refresh: bool,
        /// The signing time, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
        /// Read the passphrase from the first line of this file instead of asking.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Sign `metadata/timestamp.json` for the newest committed snapshot in `--out`, with the
    /// online key (version: Unix seconds, valid for 7 days). Verifies the repository first
    /// and refuses a snapshot, targets or root that has expired or expires within a day. Run
    /// by Pages on the copy that is published: the file is never committed. The key is
    /// never printed.
    Timestamp {
        /// The repository directory (a copy for publication).
        #[arg(long)]
        out: PathBuf,
        /// The trust anchor the repository is verified from [default:
        /// `crates/oncl-update/keys/root.json`].
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// The indexes the targets must be [default: `updates/v1` of the workspace].
        #[arg(long)]
        index: Option<PathBuf>,
        /// The environment variable that holds the key line.
        #[arg(long, default_value = "TUF_TIMESTAMP_KEY", conflicts_with = "key_file")]
        key_env: String,
        /// A key file instead of the environment.
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// The signing time, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
    },
    /// The next root (version N+1, valid for 365 days), signed by the keys of the root in
    /// force: a renewal when no `--rotate-*` is given, else a rotation of those roles'
    /// keys (the new root key signs too). New keys are written next to the old as
    /// `<role>.v<N>.key`.
    Root {
        /// The directory of the secret keys.
        #[arg(long)]
        keys: PathBuf,
        /// The repository directory [default: `tuf/v1` of the workspace].
        #[arg(long)]
        out: Option<PathBuf>,
        /// Replace the root key.
        #[arg(long)]
        rotate_root: bool,
        /// Replace the targets key (then `tuf update` signs new versions).
        #[arg(long)]
        rotate_targets: bool,
        /// Replace the snapshot key (then `tuf update` signs new versions).
        #[arg(long)]
        rotate_snapshot: bool,
        /// Replace the timestamp key (then replace the GitHub secret).
        #[arg(long)]
        rotate_timestamp: bool,
        /// The signing time, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
        /// Read the passphrase from the first line of this file instead of asking.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Verify a repository offline with the client's code over the directory: the chain of
    /// roots from the trust anchor, the newest snapshot and targets, every file listed, no
    /// stray file, the targets equal to the indexes in the tree, history unchanged against
    /// `--base`, expiry. With neither the directory nor the anchor it says "no TUF
    /// repository yet" and succeeds. Findings are `error[<code>]` (exit 1) and
    /// `warning[<code>]`; the codes are in `docs/dev/release.md`.
    Check {
        /// The repository directory [default: `tuf/v1` of the workspace].
        #[arg(long)]
        dir: Option<PathBuf>,
        /// The directory of the indexes [default: `updates/v1` of the workspace].
        #[arg(long)]
        index: Option<PathBuf>,
        /// The trust anchor [default: `crates/oncl-update/keys/root.json`].
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// The time to judge expiry at, RFC 3339 or Unix seconds [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
        /// Targets and snapshot with fewer days left are expiring.
        #[arg(long, default_value_t = 10)]
        min_days: i64,
        /// The root with fewer days left is expiring.
        #[arg(long, default_value_t = 45)]
        min_root_days: i64,
        /// Expired and expiring metadata is an error, not a warning.
        #[arg(long)]
        fail_on_expiring: bool,
        /// The git revision whose repository this one extends: published files may not
        /// change or go, no version may go back.
        #[arg(long)]
        base: Option<String>,
        /// The directory is the committed tree: there must be no timestamp (the default
        /// requires one, as in a repository about to be published).
        #[arg(long)]
        no_timestamp: bool,
    },
    /// The client over HTTPS against the published site (the smoke check after a
    /// deployment): the whole chain, and every index target.
    VerifyPublished {
        /// The base URL of the repository, `https://…/tuf/v1/`.
        #[arg(long)]
        url: String,
        /// The trust anchor [default: `crates/oncl-update/keys/root.json`].
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// A repository that is not published yet (no timestamp) is not a failure.
        #[arg(long)]
        allow_missing: bool,
        /// The time to judge expiry at [default: now].
        #[arg(long, value_parser = parse_time)]
        now: Option<OffsetDateTime>,
    },
}

fn workspace(path: Option<PathBuf>, default: &str) -> PathBuf {
    path.unwrap_or_else(|| oncl_testkit::workspace_root().join(default))
}

fn passphrase(file: Option<PathBuf>) -> PassphraseSource {
    file.map_or(PassphraseSource::Prompt, PassphraseSource::File)
}

fn now_or(now: Option<OffsetDateTime>) -> OffsetDateTime {
    now.unwrap_or_else(OffsetDateTime::now_utc)
}

/// Runs `command`.
///
/// # Errors
///
/// Whatever the command refuses or fails with; for `check`, any problem found.
pub fn run(command: TufCommand) -> anyhow::Result<()> {
    match command {
        TufCommand::Init {
            keys,
            out,
            anchor,
            spare_root,
            now,
            passphrase_file: file,
        } => {
            let out = workspace(out, REPO_DIR);
            let anchor = workspace(anchor, ANCHOR);
            let source = passphrase(file);
            let made = init::init(&init::Options {
                keys: &keys,
                out: &out,
                anchor: &anchor,
                spare_root,
                now: now_or(now),
                passphrase: &source,
            })?;
            println!("tuf init: key ids");
            for (name, id) in &made.key_ids {
                println!("  {name}: {id}");
            }
            println!("tuf init: secret keys (keep them offline, never in the repository)");
            for file in &made.key_files {
                println!("  {}", file.display());
            }
            println!("tuf init: wrote {}", made.root.display());
            println!("tuf init: wrote the trust anchor {}", made.anchor.display());
            println!(
                "tuf init: the timestamp key is the single line of timestamp.key: put it in the \
                 GitHub secret TUF_TIMESTAMP_KEY of the environment tuf-timestamp, then keep \
                 no other copy"
            );
            Ok(())
        }
        TufCommand::Update {
            keys,
            index,
            out,
            refresh,
            now,
            passphrase_file: file,
        } => {
            let source = passphrase(file);
            let done = update::update(&update::Options {
                keys: &keys,
                index: &workspace(index, crate::index::INDEX_DIR),
                out: &workspace(out, REPO_DIR),
                refresh,
                now: now_or(now),
                passphrase: &source,
            })?;
            match done {
                update::Outcome::UpToDate { targets, snapshot } => println!(
                    "tuf update: up to date (targets {targets}, snapshot {snapshot} list the \
                     indexes); nothing written"
                ),
                update::Outcome::Written(w) => {
                    println!("tuf update: {}", w.reason);
                    for file in &w.files {
                        println!("tuf update: wrote {}", file.display());
                    }
                    println!(
                        "tuf update: targets {}, snapshot {}, valid until {}",
                        w.targets,
                        w.snapshot,
                        show_time(w.expires)
                    );
                }
            }
            Ok(())
        }
        TufCommand::Timestamp {
            out,
            anchor,
            index,
            key_env,
            key_file,
            now,
        } => {
            let source = key_file.map_or(KeySource::Env(key_env), KeySource::File);
            let signed = timestamp::timestamp(&timestamp::Options {
                out: &out,
                anchor: &workspace(anchor, ANCHOR),
                index: &workspace(index, crate::index::INDEX_DIR),
                key: &source,
                now: now_or(now),
            })?;
            println!(
                "tuf timestamp: wrote {} (version {}, snapshot {}, valid until {})",
                signed.path.display(),
                signed.version,
                signed.snapshot,
                show_time(signed.expires)
            );
            Ok(())
        }
        TufCommand::Root {
            keys,
            out,
            rotate_root,
            rotate_targets,
            rotate_snapshot,
            rotate_timestamp,
            now,
            passphrase_file: file,
        } => {
            let source = passphrase(file);
            let made = root::root(&root::Options {
                keys: &keys,
                out: &workspace(out, REPO_DIR),
                rotate_root,
                rotate_targets,
                rotate_snapshot,
                rotate_timestamp,
                now: now_or(now),
                passphrase: &source,
            })?;
            println!(
                "tuf root: wrote {} (root {}, valid until {})",
                made.root.display(),
                made.version,
                show_time(made.expires)
            );
            for (role, id, path) in &made.new_keys {
                println!("tuf root: new {role} key {id}: {}", path.display());
            }
            if rotate_targets || rotate_snapshot {
                println!(
                    "tuf root: the committed targets and snapshot are signed by the old keys: \
                     run `cargo xtask tuf update` now"
                );
            }
            if rotate_timestamp {
                println!(
                    "tuf root: put the new timestamp key in the GitHub secret TUF_TIMESTAMP_KEY \
                     (`gh secret set --env tuf-timestamp TUF_TIMESTAMP_KEY < <file>`) before \
                     the root is merged"
                );
            }
            Ok(())
        }
        TufCommand::Check {
            dir,
            index,
            anchor,
            now,
            min_days,
            min_root_days,
            fail_on_expiring,
            base,
            no_timestamp,
        } => {
            let dir = workspace(dir, REPO_DIR);
            let index = workspace(index, crate::index::INDEX_DIR);
            let anchor = workspace(anchor, ANCHOR);
            let outcome = check::check(&check::Options {
                dir: &dir,
                index: Some(&index),
                anchor: Some(&anchor),
                now: now_or(now),
                timestamp: if no_timestamp {
                    TimestampMode::Absent
                } else {
                    TimestampMode::Required
                },
                expiry: Expiry {
                    min_days,
                    min_root_days,
                    fail: fail_on_expiring,
                },
                base: base.as_deref(),
            })?;
            match outcome {
                check::Outcome::NoRepository => println!(
                    "tuf check: no TUF repository yet (no {}, no trust anchor {})",
                    dir.display(),
                    anchor.display()
                ),
                check::Outcome::Checked(report) => {
                    for note in &report.notes {
                        println!("tuf check: {note}");
                    }
                    for w in &report.warnings {
                        println!("tuf check: warning[{}]: {}", w.code, w.message);
                    }
                    for p in &report.problems {
                        eprintln!("tuf check: error[{}]: {}", p.code, p.message);
                    }
                    if !report.problems.is_empty() {
                        bail!(
                            "tuf check: failed with {} problem(s)",
                            report.problems.len()
                        );
                    }
                    println!("tuf check: ok");
                }
            }
            Ok(())
        }
        TufCommand::VerifyPublished {
            url,
            anchor,
            allow_missing,
            now,
        } => {
            let anchor = workspace(anchor, ANCHOR);
            let anchor = std::fs::read(&anchor)
                .with_context(|| format!("reading the trust anchor {}", anchor.display()))?;
            let transport = oncl_pki::http::UreqTransport::default();
            let fetcher =
                HttpFetcher::new(&transport, &url).map_err(|e| anyhow::anyhow!("{url}: {e}"))?;
            match published::verify_published(fetcher, &anchor, now_or(now), allow_missing)? {
                Published::NotPublished => println!(
                    "tuf verify-published: {url} has no timestamp yet (allowed): nothing verified"
                ),
                Published::Verified { lines } => {
                    for line in lines {
                        println!("tuf verify-published: {line}");
                    }
                    println!("tuf verify-published: ok");
                }
            }
            Ok(())
        }
    }
}
