//! Where the files of a repository are, relative to its base URL (or directory): the layout
//! of consistent snapshots (TUF specification section 6.2), which the client and the
//! repository builder both take from here.
//!
//! ```text
//! metadata/<N>.root.json          every version of the root, kept for good
//! metadata/timestamp.json         the one entry point, with no version in its name
//! metadata/<N>.snapshot.json
//! metadata/<N>.targets.json
//! targets/<dir>/<sha256>.<name>   the target <dir>/<name>, by the hash of its content
//! ```

use super::model::{Digest, valid_target_path};

/// The timestamp, the only file whose name has no version or hash.
pub const TIMESTAMP_PATH: &str = "metadata/timestamp.json";

/// Version `version` of the root.
pub fn root_path(version: u64) -> String {
    format!("metadata/{version}.root.json")
}

/// Version `version` of the snapshot.
pub fn snapshot_path(version: u64) -> String {
    format!("metadata/{version}.snapshot.json")
}

/// Version `version` of the top-level targets.
pub fn targets_path(version: u64) -> String {
    format!("metadata/{version}.targets.json")
}

/// The file holding the target `target` whose content has the sha256 `sha256`:
/// `targets/<dir>/<sha256>.<name>`. `None` if `target` is not a valid target path
/// ([`valid_target_path`]).
pub fn target_file_path(target: &str, sha256: &Digest) -> Option<String> {
    if !valid_target_path(target) {
        return None;
    }
    let (dir, name) = match target.rsplit_once('/') {
        Some((dir, name)) => (format!("{dir}/"), name),
        None => (String::new(), target),
    };
    Some(format!("targets/{dir}{sha256}.{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_follow_the_consistent_snapshot_layout() {
        assert_eq!(root_path(12), "metadata/12.root.json");
        assert_eq!(snapshot_path(3), "metadata/3.snapshot.json");
        assert_eq!(targets_path(4), "metadata/4.targets.json");
        let sum = Digest([0xab; 32]);
        let hex = "ab".repeat(32);
        assert_eq!(
            target_file_path("indexes/stable.json", &sum).unwrap(),
            format!("targets/indexes/{hex}.stable.json")
        );
        assert_eq!(
            target_file_path("top.bin", &sum).unwrap(),
            format!("targets/{hex}.top.bin")
        );
        assert_eq!(target_file_path("../x", &sum), None);
        assert_eq!(target_file_path("a//b", &sum), None);
    }
}
