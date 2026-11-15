//! The update repository: the one TUF client, over one state directory
//! (`<data>/update/tuf/`), through which the updater ([`crate::update`]) and the plugin
//! catalog ([`crate::plugins`]) read the update index of a channel.
//!
//! The index is the target `indexes/<channel>.json` of the repository
//! ([`Channel::target_path`]); the client verifies the chain from the root built in
//! (`keys/root.json`, [`oncl_update::embedded_root`]) to the bytes, and what is kept of that
//! (the roots followed, the versions accepted, the targets file) is the state both consumers
//! share, saved under a lock of the directory and merged so that neither loses the other's
//! versions. A build without a root has no [`Repository`]: updates are off for both.
//!
//! What the consumers get is the index (its `seq` and channel checked by [`Index::accept`]
//! against the `last_seq` they pass), its bytes, and until when the metadata that vouches for
//! it holds. Every failure is an [`UpdateError`] ([`UpdateError::from_tuf`]) and is logged
//! here, once: a repository that is not published or cannot be read at `info`, one that is
//! refused (an expired or rolled-back role, a signature, a hash) at `warn`.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use oncl_pki::http::HttpTransport;
use oncl_update::tuf::{Fetcher, FileStore, HttpFetcher, Limits, Response, TufClient, TufError};
use oncl_update::{Channel, Index, MAX_INDEX_LEN, UpdateError};
use time::OffsetDateTime;
use tracing::{info, warn};

/// An index the repository vouches for.
#[derive(Clone, Debug)]
pub struct VerifiedIndex {
    /// The index, read from `bytes`.
    pub index: Index,
    /// The bytes as the repository has them (what the plugin store keeps and checks again).
    pub bytes: Vec<u8>,
    /// When the root or the targets metadata that vouches for the index expires: the index is
    /// not used after it without a new refresh.
    pub valid_until: OffsetDateTime,
}

/// The repository's files over HTTPS, all of one call within one deadline.
struct DeadlineFetcher {
    transport: Arc<dyn HttpTransport>,
    base: String,
    deadline: Mutex<Instant>,
}

impl Fetcher for DeadlineFetcher {
    fn fetch(&self, path: &str, max_len: u64) -> Result<Response, TufError> {
        let deadline = *self.deadline.lock().unwrap_or_else(PoisonError::into_inner);
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(TufError::Fetch(format!("{path}: no time left")));
        }
        HttpFetcher::new(&*self.transport, &self.base)?
            .with_timeout(left)
            .fetch(path, max_len)
    }
}

/// What the offline checks read the repository with: nothing.
struct Offline;

impl Fetcher for Offline {
    fn fetch(&self, path: &str, _max_len: u64) -> Result<Response, TufError> {
        Err(TufError::Fetch(format!("{path}: offline")))
    }
}

/// The shared TUF client; see the [module](self).
///
/// One state directory and one trust anchor, two handles on them: the client that refreshes
/// (one refresh at a time, for as long as its requests take) and one that checks kept bytes
/// from the saved state alone, so that a page asking for the catalog never waits for a
/// download in progress.
pub struct Repository {
    client: Mutex<TufClient<DeadlineFetcher, FileStore>>,
    offline: TufClient<Offline, FileStore>,
}

impl Repository {
    /// The repository at `base` (`https://…/tuf/v1`) read through `transport` (the proxy of
    /// the settings), with its state in `<data_dir>/update/tuf/`, trusting the root built in.
    /// `None`, logged, if the build has no root or it is unusable: updates are off.
    pub fn open(
        data_dir: &Path,
        base: &str,
        transport: Arc<dyn HttpTransport>,
    ) -> Option<Arc<Repository>> {
        let Some(anchor) = oncl_update::embedded_root() else {
            info!("the update trust root is not built into this build: updates are off");
            return None;
        };
        match Repository::with_anchor(anchor, data_dir, base, transport) {
            Ok(repository) => Some(Arc::new(repository)),
            Err(e) => {
                tracing::error!(error = %e, "the built-in update trust root is unusable: updates are off");
                None
            }
        }
    }

    /// [`Repository::open`] trusting `anchor`, the bytes of a root file, instead of the root
    /// built in.
    ///
    /// # Errors
    ///
    /// [`UpdateError::Tuf`] if `anchor` is not a root signed by its own keys, or `base` is
    /// not an `https://` URL.
    pub fn with_anchor(
        anchor: &[u8],
        data_dir: &Path,
        base: &str,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Repository, UpdateError> {
        // The URL is checked once, here.
        HttpFetcher::new(&*transport, base).map_err(UpdateError::Tuf)?;
        let fetcher = DeadlineFetcher {
            transport,
            base: base.to_owned(),
            deadline: Mutex::new(Instant::now()),
        };
        let store = FileStore::in_data_dir(data_dir);
        let client = TufClient::new(anchor, fetcher, store.clone(), Limits::default())
            .map_err(UpdateError::Tuf)?;
        let offline =
            TufClient::new(anchor, Offline, store, Limits::default()).map_err(UpdateError::Tuf)?;
        Ok(Repository {
            client: Mutex::new(client),
            offline,
        })
    }

    /// The index of `channel`, refreshed and downloaded within `timeout` (all the requests
    /// of the call together): the metadata chain is verified, the target downloaded, checked
    /// against the targets metadata, and read ([`Index::accept`]: of this channel, `seq` not
    /// below `last_seq`).
    ///
    /// # Errors
    ///
    /// [`UpdateError::NotPublished`] for a repository or a channel that is not there,
    /// otherwise [`UpdateError::Tuf`] for the client's refusals and failures, and the errors
    /// of [`Index::accept`]. [`UpdateError::retry_soon`] says which are worth trying again
    /// soon.
    pub fn index(
        &self,
        channel: Channel,
        last_seq: Option<u64>,
        timeout: Duration,
    ) -> Result<VerifiedIndex, UpdateError> {
        let result = self.download(channel, last_seq, timeout);
        match &result {
            Ok(_) => {}
            Err(UpdateError::NotPublished(_)) => {
                info!(%channel, "the update repository has no index of the channel yet");
            }
            Err(e) if e.retry_soon() => {
                info!(error = %e, %channel, "cannot read the update repository; trying again later");
            }
            Err(e) => warn!(error = %e, %channel, "the update index is refused"),
        }
        result
    }

    fn download(
        &self,
        channel: Channel,
        last_seq: Option<u64>,
        timeout: Duration,
    ) -> Result<VerifiedIndex, UpdateError> {
        let now = OffsetDateTime::now_utc();
        let mut client = self.client.lock().unwrap_or_else(PoisonError::into_inner);
        *client
            .fetcher()
            .deadline
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Instant::now() + timeout;
        let of_channel = |e| UpdateError::from_tuf(e, channel);
        let trusted = client.refresh(now).map_err(of_channel)?;
        if let Some(why) = trusted.state_was_reset() {
            warn!(
                reason = why,
                "the saved update trust state was reset to the built-in root"
            );
        }
        let bytes = client
            .download_target(&trusted, &channel.target_path(), MAX_INDEX_LEN, now)
            .map_err(of_channel)?;
        let index = Index::accept(&bytes, channel, last_seq)?;
        Ok(VerifiedIndex {
            index,
            bytes,
            valid_until: trusted.root().expires.min(trusted.targets().expires),
        })
    }

    /// Whether `bytes`, an index of `channel` kept from an earlier download, are what the
    /// targets metadata saved by the last refresh lists, still signed by the chain from the
    /// root built in and not expired at `now`, without the network
    /// ([`TufClient::verify_cached_target`]); and until when.
    ///
    /// # Errors
    ///
    /// Why not, in words.
    pub fn verify_kept(
        &self,
        channel: Channel,
        bytes: &[u8],
        now: OffsetDateTime,
    ) -> Result<OffsetDateTime, String> {
        self.offline
            .verify_cached_target(&channel.target_path(), bytes, now)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
pub(crate) mod tests;
