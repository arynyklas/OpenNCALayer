//! OpenNCALayer's self-update logic, without windows or a network stack of its own:
//!
//! - [`index`]: the update index of a channel (`updates/v1/<channel>.json`), its model and
//!   structural checks ([`Index::accept`]), and the sha256 check of a downloaded package;
//! - [`contents_sha256()`]: the sum of the files in a package, which a full package rebuilt
//!   from a delta is checked against;
//! - [`tuf`]: the TUF client that authenticates the index (it is the target
//!   `indexes/<channel>.json` of the repository), and the builder the maintainer's tools
//!   publish it with; the root it trusts is built in ([`embedded_root()`],
//!   `keys/root.json`), and without one the updater is off;
//! - [`choose()`]: the version to move to, with the staged rollout, revoked versions and
//!   versions that failed locally;
//! - [`state`]: `<data>/update/state.json`, what the updater keeps between runs.
//!
//! The format is described in `docs/design/update-index.md`, the authentication in
//! `docs/design/tuf.md`.

pub mod choose;
mod contents;
mod hex;
pub mod index;
mod keys;
pub mod plugins;
pub mod state;
pub mod tuf;

pub use choose::{Choice, Target, choose, rollout_bucket};
pub use contents::contents_sha256;
pub use index::{
    Asset, Channel, CoreRelease, Extension, Flavor, FlavorPackage, Index, MAX_INDEX_LEN, Package,
    Sha256,
};
pub use keys::embedded_root;
pub use plugins::{
    PluginChoice, PluginName, PluginRelease, PluginReplaces, choose_plugin, offer, plugin_bucket,
};
pub use semver::Version;
pub use state::{PendingHealth, State};

use tuf::TufError;

/// Why an index or a package is refused, or the repository that holds the index.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// The index is bigger than [`MAX_INDEX_LEN`].
    #[error("the update index is larger than {MAX_INDEX_LEN} bytes")]
    TooLarge,
    /// The index is not valid JSON of the expected shape, or breaks a rule of the format.
    #[error("the update index is malformed: {0}")]
    Malformed(String),
    /// The index uses a `schema` this version does not read.
    #[error("the update index schema {0} is not supported")]
    UnsupportedSchema(u32),
    /// The index is of another channel than the one asked for.
    #[error("the update index is for the {found} channel, not {expected}")]
    WrongChannel {
        /// The channel asked for.
        expected: Channel,
        /// The channel of the index.
        found: Channel,
    },
    /// The index is older than one already seen: `seq` went back.
    #[error("the update index seq {seq} is older than the last seen {last}")]
    Rollback {
        /// `seq` of the index.
        seq: u64,
        /// The last `seq` seen.
        last: u64,
    },
    /// A downloaded package has another size than the index says.
    #[error("the package is {actual} bytes, the update index says {expected}")]
    PackageSize {
        /// The size in the index.
        expected: u64,
        /// The size of the file.
        actual: u64,
    },
    /// A downloaded package has another sha256 than the index says.
    #[error("the package's sha256 does not match the update index")]
    PackageHash,
    /// A package rebuilt from a delta holds other files than the index's full package
    /// ([`contents_sha256()`]), or is not a package.
    #[error("the package's contents do not match the update index: {0}")]
    PackageContents(String),
    /// The TUF repository refused the index, or could not be read: an expired or rolled-back
    /// role, a signature or a hash that does not match, a network error, a state that cannot
    /// be saved ([`UpdateError::retry_soon`] tells which of these is worth trying again).
    #[error("the update repository: {0}")]
    Tuf(#[source] TufError),
    /// The channel has no index in the repository (404, or no entry for it in the targets
    /// metadata): nothing has been released into it yet.
    #[error("the {0} channel has no update index yet")]
    NotPublished(Channel),
    /// A file could not be read.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl UpdateError {
    /// `error`, which the TUF client gave for the index of `channel`, as this crate's error:
    /// a repository (or targets entry) that is not there is [`UpdateError::NotPublished`],
    /// everything else is [`UpdateError::Tuf`].
    pub fn from_tuf(error: TufError, channel: Channel) -> UpdateError {
        match error {
            TufError::NotFound(_) | TufError::NoSuchTarget(_) => UpdateError::NotPublished(channel),
            other => UpdateError::Tuf(other),
        }
    }

    /// Whether the check is worth trying again soon: the repository could not be read (no
    /// answer, a bad status) or the state could not be read or saved, or a long chain of
    /// roots is yet to be followed. What the repository answered and the client refused (an
    /// expired or rolled-back role, a signature, a hash, a length) stays refused until the
    /// next ordinary check, and a channel not published is not tried again soon either.
    pub fn retry_soon(&self) -> bool {
        matches!(
            self,
            UpdateError::Io(_)
                | UpdateError::Tuf(
                    TufError::Fetch(_) | TufError::Store(_) | TufError::RootChainTooLong(_)
                )
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;
    use tuf::Role;

    #[test]
    fn a_missing_repository_is_not_published_and_the_rest_is_a_refusal_or_a_retry() {
        let not_published = |e| {
            matches!(
                UpdateError::from_tuf(e, Channel::Beta),
                UpdateError::NotPublished(Channel::Beta)
            )
        };
        assert!(not_published(TufError::NotFound(
            "metadata/timestamp.json".into()
        )));
        assert!(not_published(TufError::NoSuchTarget(
            "indexes/beta.json".into()
        )));

        let retry = |e| UpdateError::from_tuf(e, Channel::Beta).retry_soon();
        // Could not be read, or the state could not be: soon.
        assert!(retry(TufError::Fetch("no answer".into())));
        assert!(retry(TufError::Store(std::io::Error::other("disk"))));
        assert!(retry(TufError::RootChainTooLong(128)));
        // Answered and refused: not soon.
        let at = datetime!(2026-11-15 12:00 UTC);
        for refused in [
            TufError::Expired {
                role: Role::Timestamp,
                expires: at,
            },
            TufError::Rollback {
                what: "timestamp".into(),
                found: 1,
                trusted: 2,
            },
            TufError::Signature {
                what: "the timestamp".into(),
                valid: 0,
                threshold: 1,
            },
            TufError::Hash {
                what: "indexes/beta.json".into(),
            },
            TufError::Length {
                what: "indexes/beta.json".into(),
                expected: 1,
                actual: 2,
            },
        ] {
            assert!(!retry(refused));
        }
        assert!(!UpdateError::NotPublished(Channel::Beta).retry_soon());
        assert!(!UpdateError::Rollback { seq: 1, last: 2 }.retry_soon());
        assert!(UpdateError::Io(std::io::Error::other("disk")).retry_soon());
    }
}
