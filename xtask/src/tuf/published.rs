//! `cargo xtask tuf verify-published`: the real client over HTTPS against the published site,
//! the smoke check after a deployment. It starts at the trust anchor, follows the roots,
//! verifies the timestamp, snapshot and targets, and downloads every target (the update
//! indexes), each of which must be a valid index of its channel.
//!
//! A repository that is not published yet is a failure unless `allow_missing` says it may be
//! (the first deployments, before the owner's timestamp secret exists).

use oncl_update::tuf::{Fetcher, Limits, MemoryStore, TufClient, TufError, layout};
use oncl_update::{Channel, Index};
use time::OffsetDateTime;

use super::{MAX_TARGET, show_time};

/// What was found.
#[derive(Debug, PartialEq, Eq)]
pub enum Published {
    /// The repository answers and verifies.
    Verified {
        /// A line per file the client trusts.
        lines: Vec<String>,
    },
    /// There is no timestamp (and `allow_missing` was set).
    NotPublished,
}

/// Runs the client over `fetcher` from `anchor` at `now`.
///
/// # Errors
///
/// If the repository does not verify, a target is not a valid index of its channel, or the
/// repository is not published and `allow_missing` is off.
pub fn verify_published<F: Fetcher>(
    fetcher: F,
    anchor: &[u8],
    now: OffsetDateTime,
    allow_missing: bool,
) -> anyhow::Result<Published> {
    let mut client = TufClient::new(anchor, fetcher, MemoryStore::default(), Limits::default())
        .map_err(|e| anyhow::anyhow!("the trust anchor is not usable: {e}"))?;
    let trusted = match client.refresh(now) {
        Ok(trusted) => trusted,
        Err(TufError::NotFound(path)) if allow_missing && path == layout::TIMESTAMP_PATH => {
            return Ok(Published::NotPublished);
        }
        Err(e) => anyhow::bail!("the published repository does not verify: {e}"),
    };
    let mut lines = vec![
        format!(
            "root {} (expires {})",
            trusted.root().version,
            show_time(trusted.root().expires)
        ),
        format!(
            "timestamp {} (expires {})",
            trusted.timestamp().version,
            show_time(trusted.timestamp().expires)
        ),
        format!(
            "snapshot {} (expires {})",
            trusted.snapshot().version,
            show_time(trusted.snapshot().expires)
        ),
        format!(
            "targets {} (expires {})",
            trusted.targets().version,
            show_time(trusted.targets().expires)
        ),
    ];
    for path in trusted.targets().targets.keys() {
        let bytes = client
            .download_target(&trusted, path, MAX_TARGET, now)
            .map_err(|e| anyhow::anyhow!("the target {path}: {e}"))?;
        let name = path
            .strip_prefix("indexes/")
            .and_then(|n| n.strip_suffix(".json"))
            .ok_or_else(|| anyhow::anyhow!("{path} is not an update index"))?;
        let channel = Channel::ALL
            .into_iter()
            .find(|c| c.as_str() == name)
            .ok_or_else(|| anyhow::anyhow!("{path} is not an index of a known channel"))?;
        let index = Index::from_json(&bytes)
            .map_err(|e| anyhow::anyhow!("the target {path} is not a valid index: {e}"))?;
        if index.channel != channel {
            anyhow::bail!(
                "the target {path} is an index of the {} channel",
                index.channel
            );
        }
        lines.push(format!("{path}: {} bytes, seq {}", bytes.len(), index.seq));
    }
    Ok(Published::Verified { lines })
}
