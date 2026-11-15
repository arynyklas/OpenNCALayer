//! The whole client against the repositories python-tuf built (`tests/fixtures/tuf/`, see its
//! README): `valid/` is accepted, byte for byte, and every `<attack>/` is refused at the step
//! its `expected.json` names, with the error class it names. Each directory is a served root;
//! the files are read from disk into a `MemoryFetcher`, the clock is the `now` of the vector.

use std::path::{Path, PathBuf};

use oncl_update::tuf::{Limits, MemoryFetcher, MemoryStore, Role, Store, TufClient, TufError};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const MAX_TARGET: u64 = 1 << 20;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tuf")
}

fn read_tree(base: &Path, dir: &Path, out: &MemoryFetcher) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            read_tree(base, &path, out);
        } else if path.file_name().unwrap() != "expected.json" {
            let relative = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.put(relative, std::fs::read(&path).unwrap());
        }
    }
}

/// The repository served from the directory `name`.
fn repository(name: &str) -> MemoryFetcher {
    let dir = fixtures().join(name);
    let repo = MemoryFetcher::new();
    read_tree(&dir, &dir, &repo);
    repo
}

fn expected(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(fixtures().join(name).join("expected.json")).unwrap())
        .unwrap()
}

fn anchor() -> Vec<u8> {
    std::fs::read(fixtures().join("valid/metadata/1.root.json")).unwrap()
}

fn now(vector: &Value) -> OffsetDateTime {
    OffsetDateTime::parse(vector["now"].as_str().unwrap(), &Rfc3339).unwrap()
}

/// How far into the workflow a path is: the step that asks for it.
fn rank(path: &str) -> u8 {
    if path.ends_with(".root.json") {
        0
    } else if path == "metadata/timestamp.json" {
        1
    } else if path.ends_with(".snapshot.json") {
        2
    } else if path.ends_with(".targets.json") {
        3
    } else {
        4
    }
}

fn step_rank(step: &str) -> u8 {
    match step {
        "root" => 0,
        "timestamp" => 1,
        "snapshot" => 2,
        "targets" | "snapshot or targets" => 3,
        "target" => 4,
        other => panic!("unknown step {other}"),
    }
}

/// Whether `error` is what the vector `name` is refused as.
fn refused_as(name: &str, error: &TufError) -> bool {
    match (name, error) {
        ("expired-timestamp", TufError::Expired { role, .. }) => *role == Role::Timestamp,
        ("expired-snapshot", TufError::Expired { role, .. }) => *role == Role::Snapshot,
        ("expired-targets", TufError::Expired { role, .. }) => *role == Role::Targets,
        ("rollback-timestamp", TufError::Rollback { what, .. }) => what == "timestamp",
        ("rollback-snapshot", TufError::Rollback { what, .. }) => what.contains("snapshot"),
        ("rollback-targets", TufError::Rollback { what, .. }) => what.contains("targets"),
        (
            "bad-signature-targets" | "tampered-unknown-field",
            TufError::Signature { what, valid, .. },
        ) => what == "the targets" && *valid == 0,
        (
            "threshold-not-met",
            TufError::Signature {
                what,
                valid,
                threshold,
            },
        ) => what.contains("its own keys") && (*valid, *threshold) == (1, 2),
        ("new-root-signed-only-by-new-keys", TufError::Signature { what, valid, .. }) => {
            what.contains("keys of root") && *valid == 0
        }
        ("root-version-gap", TufError::RootVersion { .. }) => true,
        ("wrong-keyid-in-root", TufError::BadKeyId { .. }) => true,
        ("target-hash-mismatch", TufError::Hash { .. }) => true,
        // A body longer than listed is stopped by the fetcher or the client, a shorter one
        // is a length mismatch.
        (
            "target-length-mismatch",
            TufError::Length { .. } | TufError::TooLarge { .. } | TufError::Fetch(_),
        ) => true,
        _ => false,
    }
}

fn client<'a>(
    repo: &'a MemoryFetcher,
    store: &'a mut MemoryStore,
) -> TufClient<&'a MemoryFetcher, &'a mut MemoryStore> {
    TufClient::new(&anchor(), repo, store, Limits::default()).unwrap()
}

#[test]
fn the_valid_repository_is_accepted_and_both_indexes_come_out_byte_for_byte() {
    let vector = expected("valid");
    let repo = repository("valid");
    let mut store = MemoryStore::default();
    let mut c = client(&repo, &mut store);
    let trusted = c.refresh(now(&vector)).unwrap();

    // Root 1 -> 2 -> 3 (a timestamp key rotation, then a root key rotation), snapshot and
    // targets 2, the timestamp at the time of signing.
    assert_eq!(trusted.root().version, 3);
    assert_eq!(trusted.timestamp().version, 1_794_700_800);
    assert_eq!(
        (trusted.snapshot().version, trusted.targets().version),
        (2, 2)
    );
    assert!(
        trusted.snapshot().targets().length.is_none(),
        "python-tuf lists no length or hashes"
    );

    let targets = vector["targets"].as_object().unwrap();
    assert_eq!(targets.len(), 2);
    for (target, stored) in targets {
        let fixture =
            std::fs::read(fixtures().join("valid").join(stored.as_str().unwrap())).unwrap();
        let downloaded = c.download_target(&trusted, target, MAX_TARGET).unwrap();
        assert_eq!(downloaded, fixture, "{target}");
    }
    let state = &store.load().unwrap();
    assert_eq!(state.accepted.len(), 2);
    assert_eq!(state.targets, Some(2));
}

#[test]
fn every_attack_is_refused_at_its_step_as_its_class() {
    let mut names: Vec<String> = std::fs::read_dir(fixtures())
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.path().is_dir() && e.file_name() != "valid")
        .map(|e| e.file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names.len(), 14, "{names:?}");

    for name in names {
        let vector = expected(&name);
        let step = vector["must_fail_at"].as_str().unwrap();
        let mut store = MemoryStore::default();
        if !vector["prior_state"].is_null() {
            // A client that has already accepted the valid repository on the same clock.
            let valid = repository("valid");
            client(&valid, &mut store).refresh(now(&vector)).unwrap();
        }
        let repo = repository(&name);
        let mut c = client(&repo, &mut store);
        let error = match c.refresh(now(&vector)) {
            Err(error) => error,
            Ok(trusted) => {
                assert_eq!(
                    step, "target",
                    "{name}: refresh accepted what must fail at {step}"
                );
                // Metadata is fine: the target is what is wrong.
                let valid = expected("valid");
                let failures: Vec<_> = valid["targets"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .filter_map(|target| c.download_target(&trusted, target, MAX_TARGET).err())
                    .collect();
                assert!(!failures.is_empty(), "{name}: every target was accepted");
                failures.into_iter().next().unwrap()
            }
        };
        assert!(
            refused_as(&name, &error),
            "{name}: refused as {error:?}, expected {}",
            vector["error_class"]
        );

        // Nothing past the failing step was asked for.
        let deepest = repo.requests().iter().map(|p| rank(p)).max().unwrap();
        assert!(
            deepest <= step_rank(step),
            "{name}: asked for a file of step {deepest} past {step}"
        );
    }
}

#[test]
fn the_only_vector_python_tuf_accepts_is_the_one_the_contract_refuses() {
    let name = "wrong-keyid-in-root";
    let vector = expected(name);
    assert_eq!(vector["python_tuf"]["diverges_from_contract"], true);
    assert_eq!(vector["python_tuf"]["verdict"], "ACCEPT");
    let repo = repository(name);
    let error = client(&repo, &mut MemoryStore::default())
        .refresh(now(&vector))
        .unwrap_err();
    assert!(matches!(error, TufError::BadKeyId { .. }), "{error:?}");
    // No other vector diverges.
    for entry in std::fs::read_dir(fixtures()).unwrap() {
        let path = entry.unwrap().path();
        if path.join("expected.json").is_file() {
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            let vector = expected(&name);
            let diverges = vector["python_tuf"]["diverges_from_contract"] == true;
            assert_eq!(diverges, name == "wrong-keyid-in-root", "{name}");
        }
    }
}
