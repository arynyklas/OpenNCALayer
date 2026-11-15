//! What the client keeps between runs: the trusted root, and the versions of the other roles
//! it has accepted, so that no later run takes a step back.
//!
//! All of it is one [`TrustState`], loaded and saved whole, so that a crash can never leave a
//! new root with the old timestamp (which would hide that the keys changed: step 5.3.11 of
//! the specification). [`FileStore`] writes it as `<dir>/state.json`, atomically.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use oncl_pki::fsutil::{Access, write_atomically};
use serde::{Deserialize, Serialize};

use super::canonical;
use super::error::TufError;
use super::model::{Digest, Envelope, MetaFile};

/// The only `schema` of the state file this version reads.
pub const SCHEMA: u32 = 1;

/// The largest state file read.
const MAX_STATE_LEN: u64 = 1 << 20;

/// What the client trusts, apart from its built-in root.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustState {
    /// The newest root accepted: the built-in one, or the last of the chain. Its signature
    /// is checked again by its own keys when it is loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<Envelope>,
    /// The newest timestamp accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<TimestampState>,
    /// The newest snapshot accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SnapshotState>,
    /// The version of the newest targets accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<u64>,
    /// The targets downloaded and verified, by path: the last of each.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub accepted: BTreeMap<String, AcceptedTarget>,
}

/// An accepted timestamp.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampState {
    /// Its version.
    pub version: u64,
    /// What it listed for the snapshot.
    pub snapshot: MetaFile,
}

/// An accepted snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotState {
    /// Its version.
    pub version: u64,
    /// The version of every file it listed, by file name (`targets.json`).
    pub meta: BTreeMap<String, u64>,
}

/// A target downloaded and verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedTarget {
    /// Its sha256.
    pub sha256: Digest,
    /// Its size.
    pub length: u64,
    /// The version of the targets metadata that listed it.
    pub targets_version: u64,
}

/// Where a [`TrustState`] is kept.
pub trait Store {
    /// The state saved last; an empty one ([`TrustState::default`]) if nothing was saved.
    ///
    /// # Errors
    ///
    /// [`TufError::Store`] if it cannot be read, or is not a state.
    fn load(&self) -> Result<TrustState, TufError>;

    /// Saves `state` in place of the one before, all or nothing.
    ///
    /// # Errors
    ///
    /// [`TufError::Store`] if it cannot be written.
    fn save(&mut self, state: &TrustState) -> Result<(), TufError>;
}

impl<S: Store + ?Sized> Store for &mut S {
    fn load(&self) -> Result<TrustState, TufError> {
        (**self).load()
    }

    fn save(&mut self, state: &TrustState) -> Result<(), TufError> {
        (**self).save(state)
    }
}

/// A state kept in memory: for tests, and for a run that keeps nothing.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MemoryStore {
    /// The state.
    pub state: TrustState,
    /// How many times it was saved.
    pub saves: usize,
}

impl Store for MemoryStore {
    fn load(&self) -> Result<TrustState, TufError> {
        Ok(self.state.clone())
    }

    fn save(&mut self, state: &TrustState) -> Result<(), TufError> {
        self.state = state.clone();
        self.saves += 1;
        Ok(())
    }
}

/// A state kept in a directory, `<dir>/state.json`.
#[derive(Clone, Debug)]
pub struct FileStore {
    dir: PathBuf,
}

/// The file `FileStore` writes, in its directory.
pub const STATE_FILE: &str = "state.json";

impl FileStore {
    /// A store in `dir`; the directory is created by the first save.
    pub fn new(dir: impl Into<PathBuf>) -> FileStore {
        FileStore { dir: dir.into() }
    }

    /// The store of an installation: `<data_dir>/update/tuf`, beside the updater's
    /// `state.json` ([`crate::State::path`]).
    pub fn in_data_dir(data_dir: &Path) -> FileStore {
        FileStore::new(data_dir.join("update").join("tuf"))
    }

    /// `<dir>/state.json`.
    pub fn path(&self) -> PathBuf {
        self.dir.join(STATE_FILE)
    }
}

fn invalid(why: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.to_string())
}

impl Store for FileStore {
    fn load(&self) -> Result<TrustState, TufError> {
        let path = self.path();
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(TrustState::default()),
            Err(e) => return Err(e.into()),
        };
        let bad = |why: String| invalid(format!("{}: {why}", path.display()));
        let mut value = canonical::parse(&bytes, MAX_STATE_LEN, "the TUF state")
            .map_err(|e| bad(e.to_string()))?;
        let schema = value
            .as_object_mut()
            .and_then(|members| members.remove("schema"))
            .and_then(|schema| schema.as_u64())
            .ok_or_else(|| bad("no schema".to_owned()))?;
        if schema != u64::from(SCHEMA) {
            return Err(bad(format!("schema {schema} is not supported")).into());
        }
        serde_json::from_value(value).map_err(|e| bad(e.to_string()).into())
    }

    fn save(&mut self, state: &TrustState) -> Result<(), TufError> {
        std::fs::create_dir_all(&self.dir)?;
        let mut file = serde_json::to_value(state).map_err(io::Error::other)?;
        if let Some(members) = file.as_object_mut() {
            members.insert("schema".to_owned(), SCHEMA.into());
        }
        let mut body = serde_json::to_vec_pretty(&file).map_err(io::Error::other)?;
        body.push(b'\n');
        write_atomically(&self.path(), &body, Access::Default)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn state() -> TrustState {
        TrustState {
            root: Some(Envelope {
                signed: json!({"_type": "root", "version": 2}),
                signatures: vec![],
            }),
            timestamp: Some(TimestampState {
                version: 1_800_000_000,
                snapshot: MetaFile {
                    version: 7,
                    length: Some(500),
                    sha256: Some(Digest([9; 32])),
                },
            }),
            snapshot: Some(SnapshotState {
                version: 7,
                meta: BTreeMap::from([("targets.json".to_owned(), 3)]),
            }),
            targets: Some(3),
            accepted: BTreeMap::from([(
                "indexes/beta.json".to_owned(),
                AcceptedTarget {
                    sha256: Digest([4; 32]),
                    length: 1234,
                    targets_version: 3,
                },
            )]),
        }
    }

    #[test]
    fn a_saved_state_loads_back_and_replaces_the_file_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileStore::in_data_dir(dir.path());
        assert_eq!(
            store.load().unwrap(),
            TrustState::default(),
            "nothing saved yet"
        );
        assert!(
            !dir.path().join("update").exists(),
            "loading writes nothing"
        );

        store.save(&state()).unwrap();
        assert_eq!(store.load().unwrap(), state());
        assert_eq!(
            store.path(),
            dir.path().join("update").join("tuf").join("state.json")
        );

        let mut newer = state();
        newer.targets = Some(4);
        newer.accepted.clear();
        store.save(&newer).unwrap();
        assert_eq!(FileStore::in_data_dir(dir.path()).load().unwrap(), newer);
        let names: Vec<_> = std::fs::read_dir(dir.path().join("update").join("tuf"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["state.json"], "no temporary file stays");
    }

    #[test]
    fn a_corrupt_state_is_an_error_not_an_empty_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileStore::new(dir.path());
        store.save(&state()).unwrap();
        let good = std::fs::read_to_string(store.path()).unwrap();
        for (name, body) in [
            ("not json", "nope".to_owned()),
            (
                "other schema",
                good.replace("\"schema\": 1", "\"schema\": 2"),
            ),
            ("no schema", r#"{"targets": 1}"#.to_owned()),
            ("unknown member", good.replacen('{', "{\"later\": 1,", 1)),
            ("duplicate key", r#"{"schema": 1, "schema": 1}"#.to_owned()),
            ("bad version", r#"{"schema": 1, "targets": "x"}"#.to_owned()),
        ] {
            std::fs::write(store.path(), body).unwrap();
            match store.load() {
                Err(TufError::Store(e)) => {
                    assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{name}")
                }
                other => panic!("{name}: {other:?}"),
            }
        }
    }

    #[test]
    fn the_memory_store_keeps_and_counts() {
        let mut store = MemoryStore::default();
        assert_eq!(store.load().unwrap(), TrustState::default());
        store.save(&state()).unwrap();
        assert_eq!((store.load().unwrap(), store.saves), (state(), 1));
        let by_ref: &mut MemoryStore = &mut store;
        by_ref.save(&TrustState::default()).unwrap();
        assert_eq!(store.saves, 2);
    }
}
