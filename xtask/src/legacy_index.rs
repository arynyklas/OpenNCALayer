//! The minisign signature of an update index, the way the clients of `0.1.0-rc.1` and before
//! read it: Ed25519 over the BLAKE2b-512 hash of the file (the "prehashed" mode), in
//! `<channel>.json.minisig` beside the index. The signed trusted comment is
//! `channel=<channel>;seq=<seq>` ([`trusted_comment`]) and must name the index's own channel
//! and `seq`.
//!
//! Only the maintainer's tools verify this now (`cargo xtask sign`, `cargo xtask index
//! check`): the committed indexes stay signed with it as long as the legacy path
//! (`updates/v1/*.json` + `.minisig`) is served to the clients that read it. The clients of
//! this version read the indexes through TUF and contain no minisign code.

use std::fmt;

use minisign_verify::{PublicKey, Signature};
use oncl_update::{Channel, Index, MAX_INDEX_LEN, UpdateError};
use time::{Duration, OffsetDateTime};

/// The oldest an index may be, from its `generated`, whatever its `expires` says: the length
/// of the index's validity, and what the legacy clients refuse an older one by.
pub const MAX_AGE: Duration = Duration::days(30);

/// The trusted comment a signature of an index of `channel` and `seq` carries.
pub fn trusted_comment(channel: Channel, seq: u64) -> String {
    format!("channel={channel};seq={seq}")
}

/// Why a legacy client would refuse an index.
#[derive(Debug)]
pub enum Refused {
    /// The index is bigger than [`MAX_INDEX_LEN`].
    TooLarge,
    /// The signature file is not a minisign signature.
    MalformedSignature,
    /// No trusted key made the signature, or the index or its trusted comment were changed
    /// after signing; also a signature in minisign's legacy (not prehashed) mode.
    BadSignature,
    /// The signed trusted comment is not `channel=…;seq=…`.
    BadTrustedComment(String),
    /// The signed trusted comment names another channel or `seq` than the index.
    CommentMismatch { comment: String, index: String },
    /// The index is not valid.
    Index(UpdateError),
    /// The index is of another channel than the one asked for.
    WrongChannel { expected: Channel, found: Channel },
    /// The index is older than one already seen: `seq` went back.
    Rollback { seq: u64, last: u64 },
    /// The index is past its `expires`, or older than [`MAX_AGE`].
    Expired(OffsetDateTime),
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refused::TooLarge => write!(f, "the update index is larger than {MAX_INDEX_LEN} bytes"),
            Refused::MalformedSignature => f.write_str("the update index signature is malformed"),
            Refused::BadSignature => {
                f.write_str("the update index signature does not match any trusted key")
            }
            Refused::BadTrustedComment(why) => {
                write!(f, "the signature's trusted comment is malformed: {why}")
            }
            Refused::CommentMismatch { comment, index } => {
                write!(f, "the signature is for {comment}, the index is {index}")
            }
            Refused::Index(e) => e.fmt(f),
            Refused::WrongChannel { expected, found } => {
                write!(f, "the index is for the {found} channel, not {expected}")
            }
            Refused::Rollback { seq, last } => {
                write!(f, "the index seq {seq} is older than the last seen {last}")
            }
            Refused::Expired(at) => write!(f, "the index expired at {at}"),
        }
    }
}

impl std::error::Error for Refused {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Refused::Index(e) => Some(e),
            _ => None,
        }
    }
}

impl From<UpdateError> for Refused {
    fn from(e: UpdateError) -> Refused {
        Refused::Index(e)
    }
}

/// Verifies an index of `channel` the way the legacy clients did, and reads it.
///
/// The index is accepted only if all of these hold:
/// - it is at most [`MAX_INDEX_LEN`] bytes;
/// - `sig_bytes` is a prehashed minisign signature of `index_bytes` by one of `keys`, its
///   trusted comment included;
/// - the trusted comment names the channel and `seq` of the index, and the index is of
///   `channel`;
/// - the index is valid ([`Index::from_json`]);
/// - its `seq` is not below `last_seq`;
/// - `now` is before its `expires` and less than [`MAX_AGE`] after its `generated`.
///
/// The JSON is parsed only after the signature holds.
///
/// # Errors
///
/// The first rule broken.
pub fn verify(
    index_bytes: &[u8],
    sig_bytes: &[u8],
    keys: &[PublicKey],
    channel: Channel,
    last_seq: Option<u64>,
    now: OffsetDateTime,
) -> Result<Index, Refused> {
    if index_bytes.len() as u64 > MAX_INDEX_LEN {
        return Err(Refused::TooLarge);
    }
    let signature = std::str::from_utf8(sig_bytes)
        .ok()
        .and_then(|text| Signature::decode(text).ok())
        .ok_or(Refused::MalformedSignature)?;
    // `allow_legacy = false`: a signature of the raw file (minisign's legacy mode) fails.
    if !keys
        .iter()
        .any(|key| key.verify(index_bytes, &signature, false).is_ok())
    {
        return Err(Refused::BadSignature);
    }
    let (signed_channel, signed_seq) = parse_trusted_comment(signature.trusted_comment())?;
    let index = Index::from_json(index_bytes)?;
    if (signed_channel, signed_seq) != (index.channel, index.seq) {
        return Err(Refused::CommentMismatch {
            comment: trusted_comment(signed_channel, signed_seq),
            index: trusted_comment(index.channel, index.seq),
        });
    }
    if index.channel != channel {
        return Err(Refused::WrongChannel {
            expected: channel,
            found: index.channel,
        });
    }
    if let Some(last) = last_seq
        && index.seq < last
    {
        return Err(Refused::Rollback {
            seq: index.seq,
            last,
        });
    }
    let deadline = match index.generated.checked_add(MAX_AGE) {
        Some(aged) => aged.min(index.expires),
        None => index.expires,
    };
    if now >= deadline {
        return Err(Refused::Expired(deadline));
    }
    Ok(index)
}

/// `channel=<channel>;seq=<seq>`, in any order; other `key=value` pairs are ignored, a key
/// given twice is refused.
fn parse_trusted_comment(comment: &str) -> Result<(Channel, u64), Refused> {
    let bad = |why: &str| Refused::BadTrustedComment(format!("{why} in {comment:?}"));
    let mut channel = None;
    let mut seq = None;
    for pair in comment.split(';') {
        let (key, value) = pair.split_once('=').ok_or_else(|| bad("no key=value"))?;
        match key {
            "channel" => {
                let c = Channel::ALL
                    .into_iter()
                    .find(|c| c.as_str() == value)
                    .ok_or_else(|| bad("unknown channel"))?;
                if channel.replace(c).is_some() {
                    return Err(bad("channel given twice"));
                }
            }
            "seq" => {
                let s = Some(value)
                    .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|v| v.parse::<u64>().ok())
                    .ok_or_else(|| bad("bad seq"))?;
                if seq.replace(s).is_some() {
                    return Err(bad("seq given twice"));
                }
            }
            _ => {}
        }
    }
    Ok((
        channel.ok_or_else(|| bad("no channel"))?,
        seq.ok_or_else(|| bad("no seq"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use minisign::KeyPair;
    use serde_json::{Value, json};
    use std::io::Cursor;
    use time::macros::datetime;

    /// A key pair made for the test, and its public key as the legacy client read it.
    struct TestKey {
        pair: KeyPair,
        public: PublicKey,
    }

    impl TestKey {
        fn new() -> TestKey {
            let pair = KeyPair::generate_unencrypted_keypair().unwrap();
            let public = PublicKey::decode(&pair.pk.to_box().unwrap().into_string()).unwrap();
            TestKey { pair, public }
        }

        /// A `.minisig` of `data` with `comment` as its trusted comment.
        fn sign(&self, data: &[u8], comment: &str) -> Vec<u8> {
            minisign::sign(None, &self.pair.sk, Cursor::new(data), Some(comment), None)
                .unwrap()
                .into_string()
                .into_bytes()
        }
    }

    const NOW: OffsetDateTime = datetime!(2026-10-10 12:00 UTC);

    /// A valid index of `channel` and `seq`, generated 2026-10-01, expiring 2026-10-31.
    fn index_json(channel: &str, seq: u64) -> Value {
        let sum = |n: u8| hex(&[n; 32]);
        json!({
            "schema": 1,
            "channel": channel,
            "seq": seq,
            "generated": "2026-10-01T00:00:00Z",
            "expires": "2026-10-31T00:00:00Z",
            "core": [{
                "version": "0.1.0-alpha.2",
                "flavors": {"win-x64": {
                    "url": "https://github.com/o/r/releases/download/v0.1.0-alpha.2/full.nupkg",
                    "sha256": sum(1),
                    "size": 123
                }},
                "rollout": 100,
                "revoked": false
            }],
            "plugins": []
        })
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn body(channel: &str, seq: u64) -> Vec<u8> {
        serde_json::to_vec_pretty(&index_json(channel, seq)).unwrap()
    }

    fn signed(key: &TestKey, channel: &str, seq: u64) -> (Vec<u8>, Vec<u8>) {
        let index = body(channel, seq);
        let sig = key.sign(&index, &format!("channel={channel};seq={seq}"));
        (index, sig)
    }

    fn check(index: &[u8], sig: &[u8], keys: &[&TestKey]) -> Result<Index, Refused> {
        let keys: Vec<_> = keys.iter().map(|k| k.public.clone()).collect();
        verify(index, sig, &keys, Channel::Beta, Some(40), NOW)
    }

    #[test]
    fn either_trusted_key_verifies() {
        let (current, next) = (TestKey::new(), TestKey::new());
        let (index, sig) = signed(&current, "beta", 42);
        let read = check(&index, &sig, &[&current, &next]).unwrap();
        assert_eq!((read.channel, read.seq), (Channel::Beta, 42));
        let (index, sig) = signed(&next, "beta", 42);
        check(&index, &sig, &[&current, &next]).unwrap();
    }

    #[test]
    fn another_key_is_refused() {
        let (trusted, other) = (TestKey::new(), TestKey::new());
        let (index, sig) = signed(&other, "beta", 42);
        assert!(matches!(
            check(&index, &sig, &[&trusted]),
            Err(Refused::BadSignature)
        ));
        assert!(matches!(
            check(&index, &sig, &[]),
            Err(Refused::BadSignature)
        ));
    }

    #[test]
    fn changed_index_or_signature_is_refused() {
        let key = TestKey::new();
        let (index, sig) = signed(&key, "beta", 42);

        let mut changed = index.clone();
        let at = changed.len() / 2;
        changed[at] ^= 1;
        assert!(matches!(
            check(&changed, &sig, &[&key]),
            Err(Refused::BadSignature)
        ));

        // The trusted comment is covered by the global signature.
        let text = String::from_utf8(sig.clone()).unwrap();
        let forged = text.replace("seq=42", "seq=99");
        assert_ne!(forged, text);
        assert!(matches!(
            check(&index, forged.as_bytes(), &[&key]),
            Err(Refused::BadSignature)
        ));
    }

    /// A minisign signature in the legacy mode (`Ed`: Ed25519 over the raw file, not its
    /// BLAKE2b-512 hash), built apart from minisign, which only makes prehashed ones; and
    /// the public key that verifies it.
    fn legacy_signature(data: &[u8], comment: &str) -> (PublicKey, Vec<u8>) {
        use ring::signature::{Ed25519KeyPair, KeyPair as _};
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let key_id = *b"legacy01";
        let public = [&b"Ed"[..], &key_id, pair.public_key().as_ref()].concat();
        let public = PublicKey::from_base64(&STANDARD.encode(public)).unwrap();
        let signature = pair.sign(data);
        let global = pair.sign(&[signature.as_ref(), comment.as_bytes()].concat());
        let line = [&b"Ed"[..], &key_id, signature.as_ref()].concat();
        let text = format!(
            "untrusted comment: legacy\n{}\ntrusted comment: {comment}\n{}\n",
            STANDARD.encode(line),
            STANDARD.encode(global.as_ref())
        );
        (public, text.into_bytes())
    }

    #[test]
    fn legacy_unhashed_signatures_are_refused() {
        let index = body("beta", 42);
        let (public, sig) = legacy_signature(&index, "channel=beta;seq=42");
        // The signature is genuine: minisign-verify accepts it when legacy mode is allowed.
        let decoded = Signature::decode(std::str::from_utf8(&sig).unwrap()).unwrap();
        public.verify(&index, &decoded, true).unwrap();
        assert!(matches!(
            verify(&index, &sig, &[public], Channel::Beta, None, NOW),
            Err(Refused::BadSignature)
        ));
    }

    #[test]
    fn malformed_signature_files() {
        let key = TestKey::new();
        let index = body("beta", 42);
        for sig in [&b""[..], b"untrusted comment: x\nnot base64\n", b"\xff\xfe"] {
            assert!(
                matches!(
                    check(&index, sig, &[&key]),
                    Err(Refused::MalformedSignature)
                ),
                "{sig:?}"
            );
        }
    }

    #[test]
    fn trusted_comment_must_match_the_index() {
        let key = TestKey::new();
        let index = body("beta", 42);
        for comment in ["channel=beta;seq=41", "channel=stable;seq=42"] {
            let sig = key.sign(&index, comment);
            assert!(
                matches!(
                    check(&index, &sig, &[&key]),
                    Err(Refused::CommentMismatch { .. })
                ),
                "{comment}"
            );
        }
        for comment in [
            "timestamp:1700000000\tfile:beta.json",
            "channel=beta",
            "seq=42",
            "channel=beta;seq=42;seq=42",
            "channel=beta;channel=beta;seq=42",
            "channel=nightly;seq=42",
            "channel=beta;seq=+42",
            "channel=beta;seq=",
            "channel=beta;seq=18446744073709551616",
        ] {
            let sig = key.sign(&index, comment);
            assert!(
                matches!(
                    check(&index, &sig, &[&key]),
                    Err(Refused::BadTrustedComment(_))
                ),
                "{comment}"
            );
        }
        // Order and other pairs do not matter.
        let sig = key.sign(&index, "seq=42;timestamp=1700000000;channel=beta");
        check(&index, &sig, &[&key]).unwrap();
        assert_eq!(trusted_comment(Channel::Beta, 42), "channel=beta;seq=42");
    }

    #[test]
    fn index_of_another_channel_and_a_seq_that_went_back_are_refused() {
        let key = TestKey::new();
        let (index, sig) = signed(&key, "stable", 42);
        assert!(matches!(
            check(&index, &sig, &[&key]),
            Err(Refused::WrongChannel {
                expected: Channel::Beta,
                found: Channel::Stable
            })
        ));
        let (index, sig) = signed(&key, "beta", 39);
        assert!(matches!(
            check(&index, &sig, &[&key]),
            Err(Refused::Rollback { seq: 39, last: 40 })
        ));
        let keys = [key.public.clone()];
        verify(&index, &sig, &keys, Channel::Beta, Some(39), NOW).unwrap();
    }

    #[test]
    fn stale_index_is_refused() {
        let key = TestKey::new();
        let keys = [key.public.clone()];
        let at = |value: Value| {
            let index = serde_json::to_vec(&value).unwrap();
            let sig = key.sign(&index, "channel=beta;seq=42");
            (index, sig)
        };

        // Past `expires` (2026-10-31, also generated + 30 days).
        let (index, sig) = at(index_json("beta", 42));
        let expires = datetime!(2026-10-31 0:00 UTC);
        verify(
            &index,
            &sig,
            &keys,
            Channel::Beta,
            None,
            expires - Duration::SECOND,
        )
        .unwrap();
        assert!(matches!(
            verify(&index, &sig, &keys, Channel::Beta, None, expires),
            Err(Refused::Expired(t)) if t == expires
        ));

        // A far `expires` does not stretch the index past 30 days from `generated`.
        let mut far = index_json("beta", 42);
        far["expires"] = json!("2027-12-31T00:00:00Z");
        let (index, sig) = at(far);
        assert!(matches!(
            verify(&index, &sig, &keys, Channel::Beta, None, expires + Duration::days(60)),
            Err(Refused::Expired(t)) if t == expires
        ));
    }

    #[test]
    fn oversized_and_invalid_indexes_are_refused() {
        let index = vec![b' '; MAX_INDEX_LEN as usize + 1];
        assert!(matches!(
            verify(&index, b"", &[], Channel::Beta, None, NOW),
            Err(Refused::TooLarge)
        ));
        let key = TestKey::new();
        let mut v = index_json("beta", 42);
        v["core"][0]["rollout"] = json!(200);
        let index = serde_json::to_vec(&v).unwrap();
        let sig = key.sign(&index, "channel=beta;seq=42");
        assert!(matches!(
            check(&index, &sig, &[&key]),
            Err(Refused::Index(UpdateError::Malformed(_)))
        ));
    }
}
