//! The roles and the one error type of the `tuf` module.

use std::fmt;
use std::io;

use time::OffsetDateTime;

/// A top-level TUF role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// The trust anchor: names the keys of every role, itself included.
    Root,
    /// The short-lived pointer to the snapshot.
    Timestamp,
    /// The versions (and hashes) of the targets metadata.
    Snapshot,
    /// The files of the repository (here: the update indexes).
    Targets,
}

impl Role {
    /// `root`, `timestamp`, `snapshot` or `targets`: the role's name in `roles` and in
    /// `_type`.
    pub fn name(self) -> &'static str {
        match self {
            Role::Root => "root",
            Role::Timestamp => "timestamp",
            Role::Snapshot => "snapshot",
            Role::Targets => "targets",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Why metadata, a target or a key is refused.
#[derive(Debug, thiserror::Error)]
pub enum TufError {
    /// Not JSON, or JSON the strict parser refuses.
    #[error("malformed JSON: {0}")]
    Json(String),
    /// An object with the same key twice: which one signs is ambiguous.
    #[error("a JSON object has the key {0:?} twice")]
    DuplicateKey(String),
    /// A JSON number that is not an integer: the canonical form has no floats.
    #[error("a JSON number is not an integer")]
    Float,
    /// JSON nested deeper than the limit.
    #[error("JSON is nested deeper than {0} levels")]
    TooDeep(usize),
    /// More data than the limit allows (endless data).
    #[error("{what} is larger than {limit} bytes")]
    TooLarge {
        /// What was too large.
        what: String,
        /// The limit it broke.
        limit: u64,
    },
    /// Valid JSON that breaks a rule of the format.
    #[error("{what} is malformed: {why}")]
    Malformed {
        /// The file or field.
        what: String,
        /// The rule broken.
        why: String,
    },
    /// Something TUF allows that this client does not: another key type or scheme or hash
    /// algorithm, delegations, a spec version other than 1.x, no consistent snapshots.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// A key of a root under another id than its hash says.
    #[error("the key {claimed} of the root hashes to {actual}")]
    BadKeyId {
        /// The id the root gives the key.
        claimed: String,
        /// The id the key's own canonical form hashes to.
        actual: String,
    },
    /// Not a key, or a key file the signer cannot use.
    #[error("bad key: {0}")]
    Key(String),
    /// Fewer distinct keys signed than the threshold needs.
    #[error("{what}: {valid} valid signatures from distinct trusted keys, {threshold} needed")]
    Signature {
        /// The file, and whose keys were asked.
        what: String,
        /// How many distinct trusted keys made a valid signature.
        valid: usize,
        /// The threshold.
        threshold: u32,
    },
    /// A root that is not exactly the trusted one plus one.
    #[error("the root asked for as version {expected} is version {found}")]
    RootVersion {
        /// The version the file name asks for: the trusted one plus one.
        expected: u64,
        /// The version inside the file.
        found: u64,
    },
    /// More new roots than one refresh follows, and another one is there: the chain is too
    /// long to follow in one go (the roots followed so far are kept; refresh again).
    #[error("the root chain is longer than the {0} roots one refresh follows")]
    RootChainTooLong(u32),
    /// Metadata past its `expires` (a freeze attack, or a repository nobody re-signed).
    #[error("the {role} metadata expired at {expires}")]
    Expired {
        /// The role.
        role: Role,
        /// Its `expires`.
        expires: OffsetDateTime,
    },
    /// A version below one already trusted (a rollback attack).
    #[error("the {what} is version {found}, version {trusted} was trusted before")]
    Rollback {
        /// What went back: a role, or the snapshot or targets a role lists.
        what: String,
        /// The version offered.
        found: u64,
        /// The version trusted before.
        trusted: u64,
    },
    /// Metadata whose version is not the one the role above lists for it.
    #[error("the {role} metadata is version {found}, the {above} metadata says {expected}")]
    VersionMismatch {
        /// The role fetched.
        role: Role,
        /// The role that lists it.
        above: Role,
        /// The version listed.
        expected: u64,
        /// The version of the file.
        found: u64,
    },
    /// A file whose size is not the one the metadata lists.
    #[error("{what} is {actual} bytes, the metadata says {expected}")]
    Length {
        /// The file.
        what: String,
        /// The size listed.
        expected: u64,
        /// The size of the file.
        actual: u64,
    },
    /// A file whose sha256 is not the one the metadata lists.
    #[error("the sha256 of {what} does not match the metadata")]
    Hash {
        /// The file.
        what: String,
    },
    /// The same timestamp version with other content than the one trusted.
    #[error("a second, different timestamp of version {0}")]
    TimestampChanged(u64),
    /// A file of the repository that must be there answers 404.
    #[error("{0} is not published")]
    NotFound(String),
    /// The repository could not be read: no response, a bad status, a redirect off-host.
    #[error("fetching {0}")]
    Fetch(String),
    /// A target the targets metadata does not list.
    #[error("{0} is not a target of the repository")]
    NoSuchTarget(String),
    /// A target bigger than the caller allows.
    #[error("the target {path} is {len} bytes, more than the {max} allowed")]
    TargetTooLarge {
        /// The target.
        path: String,
        /// Its size in the metadata.
        len: u64,
        /// What the caller allows.
        max: u64,
    },
    /// The state directory could not be read or written.
    #[error("TUF state: {0}")]
    Store(#[from] io::Error),
}

impl TufError {
    pub(crate) fn malformed(what: impl Into<String>, why: impl Into<String>) -> TufError {
        TufError::Malformed {
            what: what.into(),
            why: why.into(),
        }
    }
}
