#!/usr/bin/env python3
# Independent TUF test vectors for OpenNCALayer, built and checked with python-tuf.
#
# Pinned: tuf==7.0.1 (python-tuf; pulls securesystemslib==1.6.0), cryptography==50.0.2.
#   python3 -m venv /mnt/d/oncl-tuf-venv
#   /mnt/d/oncl-tuf-venv/bin/pip install tuf==7.0.1 cryptography==50.0.2
#   /mnt/d/oncl-tuf-venv/bin/python xtask/assets/tuf-oracle/gen.py
#
# Writes crates/oncl-update/tests/fixtures/tuf/{valid,<attack>}/ (+ keys.json), then runs
# python-tuf's ngclient.Updater over a local http.server against every repository and prints a
# verdict table. Everything is deterministic: the keys are SYNTHETIC test keys derived from fixed
# seeds, Ed25519 signatures are deterministic, and the clock of the check is fixed (NOW below).
# Re-running must leave `git status` clean.
#
# The binding contract this follows is documented in fixtures/tuf/README.md.

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import http.server
import json
import shutil
import sys
import tempfile
import threading
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import (
    Key,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer
from tuf.ngclient import Updater, UpdaterConfig

UTC = dt.timezone.utc
# Signing time of every file of the valid repository.
T0 = dt.datetime(2026, 11, 15, 0, 0, 0, tzinfo=UTC)
# The clock every check runs at (python-tuf here, the Rust verifier in its tests).
NOW = T0 + dt.timedelta(days=1)
ROOT_EXPIRES = T0 + dt.timedelta(days=365)
TARGETS_EXPIRES = T0 + dt.timedelta(days=30)
SNAPSHOT_EXPIRES = T0 + dt.timedelta(days=30)
TIMESTAMP_EXPIRES = T0 + dt.timedelta(days=7)
# The timestamp `version` is the Unix time in seconds at signing.
TS_VERSION = int(T0.timestamp())
EXPIRED = T0 + dt.timedelta(hours=12)  # before NOW

SEED_PREFIX = "oncl-tuf-oracle-v1/"
KEY_NAMES = ["root-a", "root-b", "targets", "snapshot", "timestamp-1", "timestamp-2"]

OUT_DEFAULT = Path(__file__).resolve().parents[3] / "crates/oncl-update/tests/fixtures/tuf"


# --------------------------------------------------------------------------- keys


def make_signer(name: str) -> tuple[CryptoSigner, bytes]:
    seed = hashlib.sha256((SEED_PREFIX + name).encode()).digest()
    signer = CryptoSigner(Ed25519PrivateKey.from_private_bytes(seed))
    return signer, seed


def olpc(obj) -> bytes:
    """OLPC canonical JSON, enough for the ASCII key objects hashed here."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


SIGNERS: dict[str, CryptoSigner] = {}
SEEDS: dict[str, bytes] = {}
for _n in KEY_NAMES:
    SIGNERS[_n], SEEDS[_n] = make_signer(_n)


def key_of(name: str) -> Key:
    return SIGNERS[name].public_key


def keyid_of(name: str) -> str:
    return key_of(name).keyid


# The contract: keyid = lowercase hex sha256 of the OLPC canonical JSON of the key object.
for _n in KEY_NAMES:
    _k = key_of(_n)
    _obj = {"keytype": _k.keytype, "scheme": _k.scheme, "keyval": {"public": _k.keyval["public"]}}
    assert _k.keytype == "ed25519" and _k.scheme == "ed25519", _n
    assert hashlib.sha256(olpc(_obj)).hexdigest() == _k.keyid, f"keyid of {_n} differs from contract"


# ----------------------------------------------------------------------- metadata


def ser(md: Metadata) -> bytes:
    return md.to_bytes(JSONSerializer(compact=False))


def sign_with(md: Metadata, *names: str) -> bytes:
    md.signatures.clear()
    for n in names:
        md.sign(SIGNERS[n], append=True)
    return ser(md)


def index_body(channel: str, seq: int) -> bytes:
    """A small synthetic update index (the shape of crates/oncl-update/src/index.rs tests)."""
    sums = lambda n: bytes([n] * 32).hex()  # noqa: E731
    doc = {
        "schema": 1,
        "channel": channel,
        "seq": seq,
        "generated": "2026-11-14T00:00:00Z",
        "expires": "2026-12-14T00:00:00Z",
        "core": [
            {
                "version": "0.1.0",
                "flavors": {
                    "win-x64": {
                        "url": "https://example.invalid/releases/v0.1.0/full.nupkg",
                        "sha256": sums(1),
                        "size": 123,
                        "contents_sha256": sums(2),
                    }
                },
                "rollout": 100,
                "revoked": False,
                "notes_url": "https://example.invalid/releases/v0.1.0",
            }
        ],
        "extension": {
            "version": "0.1.0",
            "chromium_zip": {"url": "https://example.invalid/e.zip", "sha256": sums(3)},
            "firefox_xpi": {"url": "https://example.invalid/e.xpi", "sha256": sums(4)},
        },
        "plugins": [],
    }
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()


TARGET_PATHS = ["indexes/stable.json", "indexes/beta.json"]
BODIES = {"indexes/stable.json": index_body("stable", 7), "indexes/beta.json": index_body("beta", 9)}


def target_file_name(path: str, body: bytes) -> str:
    d, _, base = path.rpartition("/")
    return f"targets/{d}/{hashlib.sha256(body).hexdigest()}.{base}"


def build_root(version: int, roles: dict[str, list[str]], threshold: dict[str, int] | None = None) -> Metadata:
    root = Root(version=version, expires=ROOT_EXPIRES, consistent_snapshot=True)
    for role, names in roles.items():
        for n in names:
            root.add_key(key_of(n), role)
        root.roles[role].threshold = (threshold or {}).get(role, 1)
    return Metadata(root)


def build_targets(version: int) -> Metadata:
    t = Targets(version=version, expires=TARGETS_EXPIRES)
    for p in TARGET_PATHS:
        t.targets[p] = TargetFile.from_data(p, BODIES[p], ["sha256"])
    return Metadata(t)


def build_snapshot(version: int, targets_version: int) -> Metadata:
    return Metadata(
        Snapshot(version=version, expires=SNAPSHOT_EXPIRES, meta={"targets.json": MetaFile(targets_version)})
    )


def build_timestamp(version: int, snapshot_version: int) -> Metadata:
    return Metadata(Timestamp(version=version, expires=TIMESTAMP_EXPIRES, snapshot_meta=MetaFile(snapshot_version)))


def build_valid() -> dict[str, bytes]:
    """The valid repository: root v1 -> v2 (timestamp key rotated) -> v3 (root key rotated)."""
    files: dict[str, bytes] = {}
    role_keys_1 = {"root": ["root-a"], "targets": ["targets"], "snapshot": ["snapshot"], "timestamp": ["timestamp-1"]}
    files["metadata/1.root.json"] = sign_with(build_root(1, role_keys_1), "root-a")
    role_keys_2 = {**role_keys_1, "timestamp": ["timestamp-2"]}
    files["metadata/2.root.json"] = sign_with(build_root(2, role_keys_2), "root-a")
    role_keys_3 = {**role_keys_2, "root": ["root-b"]}
    # The root key rotates in v3: signed by the old threshold (root-a) and the new one (root-b).
    files["metadata/3.root.json"] = sign_with(build_root(3, role_keys_3), "root-a", "root-b")
    files["metadata/2.targets.json"] = sign_with(build_targets(2), "targets")
    files["metadata/2.snapshot.json"] = sign_with(build_snapshot(2, 2), "snapshot")
    files["metadata/timestamp.json"] = sign_with(build_timestamp(TS_VERSION, 2), "timestamp-2")
    for p in TARGET_PATHS:
        files[target_file_name(p, BODIES[p])] = BODIES[p]
    return files


def load(files: dict[str, bytes], path: str) -> Metadata:
    return Metadata.from_bytes(files[path])


# ------------------------------------------------------------------------ attacks


class Attack:
    def __init__(self, name, attack, fails_at, error, build, prior_state=None):
        self.name, self.attack, self.fails_at, self.error = name, attack, fails_at, error
        self.build, self.prior_state = build, prior_state


def flip_hex_char(h: str) -> str:
    return h[:-1] + ("0" if h[-1] != "0" else "1")


def a_expired(path, signer, expires=EXPIRED):
    def build(f):
        md = load(f, path)
        md.signed.expires = expires
        f[path] = sign_with(md, signer)

    return build


def a_rollback_timestamp(f):
    f["metadata/timestamp.json"] = sign_with(build_timestamp(TS_VERSION - 3600, 2), "timestamp-2")


def a_rollback_snapshot(f):
    # A newer timestamp pointing at snapshot v1, after snapshot v2 was already accepted.
    f["metadata/timestamp.json"] = sign_with(build_timestamp(TS_VERSION + 3600, 1), "timestamp-2")
    f["metadata/1.snapshot.json"] = sign_with(build_snapshot(1, 1), "snapshot")
    f["metadata/1.targets.json"] = sign_with(build_targets(1), "targets")


def a_rollback_targets(f):
    # A newer timestamp and snapshot v3, whose `targets.json` entry is v1 after v2 was accepted.
    f["metadata/timestamp.json"] = sign_with(build_timestamp(TS_VERSION + 7200, 3), "timestamp-2")
    f["metadata/3.snapshot.json"] = sign_with(build_snapshot(3, 1), "snapshot")
    f["metadata/1.targets.json"] = sign_with(build_targets(1), "targets")


def a_bad_signature_targets(f):
    md = load(f, "metadata/2.targets.json")
    sig = md.signatures[next(iter(md.signatures))]
    sig.signature = flip_hex_char(sig.signature)
    f["metadata/2.targets.json"] = ser(md)


def a_threshold(f):
    # Root v2 demands 2 of {root-a, root-b} for the root role but carries one signature.
    md = build_root(
        2,
        {"root": ["root-a", "root-b"], "targets": ["targets"], "snapshot": ["snapshot"], "timestamp": ["timestamp-2"]},
        {"root": 2},
    )
    f["metadata/2.root.json"] = sign_with(md, "root-a")


def a_wrong_keyid(f):
    # Root v2 names the new timestamp key by an id that is not sha256 of its canonical form.
    d = json.loads(f["metadata/2.root.json"])
    real = keyid_of("timestamp-2")
    bogus = "00" * 32
    d["signed"]["keys"][bogus] = d["signed"]["keys"].pop(real)
    d["signed"]["roles"]["timestamp"]["keyids"] = [bogus]
    md = Metadata.from_dict(d)
    f["metadata/2.root.json"] = sign_with(md, "root-a")


def a_unknown_field(f):
    # A field the signer never saw, added after signing: it is part of the signed object.
    d = json.loads(f["metadata/2.targets.json"])
    d["signed"]["x-tampered"] = {"note": "unknown field"}
    f["metadata/2.targets.json"] = (json.dumps(d, indent=1, sort_keys=True)).encode()


def a_hash_mismatch(f):
    p = "indexes/stable.json"
    name = target_file_name(p, BODIES[p])
    body = f[name]
    assert b"0.1.0" in body
    f[name] = body.replace(b'"seq": 7', b'"seq": 8')  # same length, other content
    assert len(f[name]) == len(body) and f[name] != body


def a_length_mismatch(f):
    p = "indexes/stable.json"
    name = target_file_name(p, BODIES[p])
    f[name] = f[name] + b"\n"


def a_root_gap(f):
    # File 2.root.json holds root version 3 (signed by both root keys): the chain skips v2.
    d = json.loads(f["metadata/3.root.json"])
    md = Metadata.from_dict(d)
    f["metadata/2.root.json"] = sign_with(md, "root-a", "root-b")
    del f["metadata/3.root.json"]


def a_new_root_new_keys_only(f):
    md = load(f, "metadata/3.root.json")
    f["metadata/3.root.json"] = sign_with(md, "root-b")


ATTACKS = [
    Attack("expired-timestamp", "timestamp.json is past its expires", "timestamp",
           "ExpiredMetadataError: timestamp expires 2026-11-15T12:00:00Z is before the clock",
           a_expired("metadata/timestamp.json", "timestamp-2")),
    Attack("expired-snapshot", "2.snapshot.json is past its expires", "snapshot",
           "ExpiredMetadataError: snapshot expires 2026-11-15T12:00:00Z is before the clock",
           a_expired("metadata/2.snapshot.json", "snapshot")),
    Attack("expired-targets", "2.targets.json is past its expires", "targets",
           "ExpiredMetadataError: targets expires 2026-11-15T12:00:00Z is before the clock",
           a_expired("metadata/2.targets.json", "targets")),
    Attack("rollback-timestamp",
           "an older timestamp (version = TS_VERSION-3600) is served after TS_VERSION was accepted",
           "timestamp", "Rollback: timestamp version lower than the trusted one (BadVersionNumberError)",
           a_rollback_timestamp, "valid"),
    Attack("rollback-snapshot",
           "a newer timestamp (TS_VERSION+3600) names snapshot v1 after snapshot v2 was accepted; "
           "the pair metadata/timestamp.json + metadata/1.snapshot.json replaces timestamp.json/2.snapshot.json",
           "snapshot", "Rollback: snapshot version lower than the trusted one (BadVersionNumberError)",
           a_rollback_snapshot, "valid"),
    Attack("rollback-targets",
           "a newer timestamp (TS_VERSION+7200) and snapshot v3 whose `targets.json` entry is v1 after targets v2 "
           "was accepted; the pair metadata/3.snapshot.json + metadata/1.targets.json",
           "snapshot or targets", "Rollback: the targets version in the new snapshot (v1) is lower than the trusted one "
           "(python-tuf refuses at the targets step with BadVersionNumberError; a client MAY equally refuse at the "
           "snapshot step, but must never accept)",
           a_rollback_targets, "valid"),
    Attack("bad-signature-targets", "the only signature of 2.targets.json has its last hex digit flipped",
           "targets", "UnsignedMetadataError: signature threshold not met for targets", a_bad_signature_targets),
    Attack("threshold-not-met", "2.root.json sets the root role to threshold 2 over {root-a, root-b} and has one signature",
           "root", "UnsignedMetadataError: the new root does not meet its own root threshold (1 of 2)", a_threshold),
    Attack("wrong-keyid-in-root", "2.root.json lists the timestamp key under a keyid that is not sha256 of its OLPC form",
           "root", "Malformed root: keyid does not match the key (contract rule; python-tuf does not check it)",
           a_wrong_keyid),
    Attack("tampered-unknown-field", "an unknown field was added to the signed part of 2.targets.json without re-signing",
           "targets", "UnsignedMetadataError: signature invalid (unknown fields are part of the signed bytes)",
           a_unknown_field),
    Attack("target-hash-mismatch", "the stable index target has the same length, other content (sha256 differs)",
           "target", "Target hash mismatch (LengthOrHashMismatchError)", a_hash_mismatch),
    Attack("target-length-mismatch", "the stable index target is one byte longer than targets metadata says",
           "target", "Target length mismatch (LengthOrHashMismatchError / DownloadLengthMismatchError)",
           a_length_mismatch),
    Attack("root-version-gap", "2.root.json contains root version 3 (signed by root-a and root-b): v2 is skipped",
           "root", "BadVersionNumberError: root file N+1 must have version N+1", a_root_gap),
    Attack("new-root-signed-only-by-new-keys", "3.root.json (root key rotated) is signed only by the new root key root-b",
           "root", "UnsignedMetadataError: the new root is not signed by the threshold of the OLD root keys",
           a_new_root_new_keys_only),
]


# ------------------------------------------------------------------ python-tuf run


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def serve(root: Path):
    handler = lambda *a, **k: Quiet(*a, directory=str(root), **k)  # noqa: E731
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run_client(repo: Path, cache: Path, dl: Path):
    """One ngclient update against `repo`. Returns (verdict, step, error)."""
    srv = serve(repo)
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    step = "bootstrap"
    try:
        bootstrap = (repo.parent / "valid" / "metadata" / "1.root.json").read_bytes()
        up = Updater(
            metadata_dir=str(cache),
            metadata_base_url=base + "/metadata/",
            target_dir=str(dl),
            target_base_url=base + "/targets/",
            bootstrap=bootstrap,
            config=UpdaterConfig(),
        )
        up._trusted_set.reference_time = NOW  # the fixed clock
        step = "refresh"
        up.refresh()
        for p in TARGET_PATHS:
            step = "target-info"
            info = up.get_targetinfo(p)
            if info is None:
                return "REJECT", step, f"no target {p}"
            step = "target"
            got = Path(up.download_target(info)).read_bytes()
            if got != BODIES[p]:
                return "REJECT", step, f"{p}: downloaded bytes differ"
        return "ACCEPT", "-", ""
    except Exception as e:  # noqa: BLE001
        return "REJECT", step, f"{type(e).__name__}: {e}"[:150]
    finally:
        srv.shutdown()


def check(repo: Path, prior: str | None):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        cache, dl = tmp / "meta", tmp / "dl"
        cache.mkdir()
        dl.mkdir()
        if prior:
            v, s, e = run_client(repo.parent / prior, cache, tmp / "dl0")
            assert v == "ACCEPT", f"prior state {prior} was not accepted: {e}"
        return run_client(repo, cache, dl)


# --------------------------------------------------------------------------- main

# Where python-tuf is KNOWN to disagree with the contract (verdict it gives, and why).
PYTHON_TUF_DIVERGENCE = {
    "wrong-keyid-in-root": "ACCEPT",
}


def write_repo(root: Path, files: dict[str, bytes]):
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=OUT_DEFAULT)
    args = ap.parse_args()
    out: Path = args.out
    for child in out.iterdir() if out.exists() else []:
        if child.is_dir():
            shutil.rmtree(child)
    out.mkdir(parents=True, exist_ok=True)

    valid = build_valid()
    write_repo(out / "valid", valid)
    (out / "valid" / "expected.json").write_text(
        json.dumps(
            {
                "name": "valid",
                "now": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "trust_anchor": "metadata/1.root.json",
                "result": "accepted: root 1 -> 2 -> 3, timestamp, snapshot 2, targets 2, "
                "both targets download and match",
                "targets": {p: target_file_name(p, BODIES[p]) for p in TARGET_PATHS},
            },
            indent=2,
        )
        + "\n"
    )

    keys = {
        "seed_prefix": SEED_PREFIX,
        "note": "SYNTHETIC test keys. seed = sha256(seed_prefix + name); Ed25519 private key from the 32-byte seed.",
        "keys": {
            n: {
                "seed_hex": SEEDS[n].hex(),
                "public_hex": key_of(n).keyval["public"],
                "keyid": keyid_of(n),
            }
            for n in KEY_NAMES
        },
        "roles": {
            "root-v1": {"root": "root-a", "targets": "targets", "snapshot": "snapshot", "timestamp": "timestamp-1"},
            "root-v2": {"root": "root-a", "targets": "targets", "snapshot": "snapshot", "timestamp": "timestamp-2"},
            "root-v3": {"root": "root-b", "targets": "targets", "snapshot": "snapshot", "timestamp": "timestamp-2"},
        },
        "times": {
            "signed_at": T0.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "now": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "timestamp_version": TS_VERSION,
        },
    }
    (out / "keys.json").write_text(json.dumps(keys, indent=2) + "\n")

    results = [("valid", "ACCEPT", *check(out / "valid", None))]
    ok = results[0][2] == "ACCEPT"
    for a in ATTACKS:
        files = copy.deepcopy(valid)
        a.build(files)
        changed = sorted(k for k in set(files) | set(valid) if files.get(k) != valid.get(k))
        write_repo(out / a.name, {k: v for k, v in files.items()})
        verdict, step, err = check(out / a.name, a.prior_state)
        divergence = PYTHON_TUF_DIVERGENCE.get(a.name)
        (out / a.name / "expected.json").write_text(
            json.dumps(
                {
                    "name": a.name,
                    "attack": a.attack,
                    "now": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "trust_anchor": "valid/metadata/1.root.json",
                    "prior_state": ("client already accepted the 'valid' repository at the same clock"
                                    if a.prior_state else None),
                    "must_fail_at": a.fails_at,
                    "error_class": a.error,
                    "changed_files_vs_valid": changed,
                    "python_tuf": {"verdict": verdict, "step": step, "error": err,
                                   "diverges_from_contract": divergence is not None},
                },
                indent=2,
            )
            + "\n"
        )
        results.append((a.name, divergence or "REJECT", verdict, step, err))
        if verdict != (divergence or "REJECT"):
            ok = False

    w = max(len(r[0]) for r in results)
    print(f"{'repository'.ljust(w)}  python-tuf  step         error")
    for name, want, verdict, step, err in results:
        flag = "" if verdict == want else "  <-- UNEXPECTED"
        if want == "ACCEPT" and name != "valid":
            flag = "  (known divergence from the contract)"
        print(f"{name.ljust(w)}  {verdict:<10}  {step:<11}  {err}{flag}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
