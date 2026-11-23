//! The DER the doubles read and write: the request and answer structures of RFC 3161 and
//! RFC 6960, re-declared here (`oncl-pki` keeps its own private), and small helpers.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use der::asn1::{AnyRef, BitStringRef, IntRef, ObjectIdentifier, OctetStringRef, UintRef};
use der::{
    Decode, DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag, TagNumber,
    Writer,
};
use oncl_pki::http::HttpReply;
use oncl_pki::key::{KeyAlg, SigAlg};
use spki::AlgorithmIdentifierRef;
use time::OffsetDateTime;
use x509_cert::Certificate;

/// A value of a fixed tag kept as its raw contents.
macro_rules! raw_value {
    ($(#[$doc:meta])* $name:ident, $tag:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) struct $name<'a>(pub &'a [u8]);

        impl<'a> DecodeValue<'a> for $name<'a> {
            type Error = der::Error;

            fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
                reader.read_slice(header.length()).map($name)
            }
        }

        impl EncodeValue for $name<'_> {
            fn value_len(&self) -> der::Result<Length> {
                Length::try_from(self.0.len())
            }

            fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
                writer.write(self.0)
            }
        }

        impl FixedTag for $name<'_> {
            const TAG: Tag = $tag;
        }
    };
}

raw_value!(
    /// Contents of a `SEQUENCE` (or of an `IMPLICIT` tagged one), raw.
    RawSequence,
    Tag::Sequence
);
raw_value!(
    /// Contents of a `GeneralizedTime`, raw.
    RawGeneralizedTime,
    Tag::GeneralizedTime
);

/// An `ENUMERATED` of 0 to 127.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Enumerated(pub u8);

impl<'a> DecodeValue<'a> for Enumerated {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        match reader.read_slice(header.length())? {
            &[value] if value < 0x80 => Ok(Enumerated(value)),
            _ => Err(reader.error(der::ErrorKind::Value {
                tag: Tag::Enumerated,
            })),
        }
    }
}

impl EncodeValue for Enumerated {
    fn value_len(&self) -> der::Result<Length> {
        Ok(Length::ONE)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        writer.write_byte(self.0)
    }
}

impl FixedTag for Enumerated {
    const TAG: Tag = Tag::Enumerated;
}

/// `MessageImprint` (RFC 3161).
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct MessageImprint<'a> {
    pub hash_algorithm: AlgorithmIdentifierRef<'a>,
    pub hashed_message: &'a OctetStringRef,
}

/// `TimeStampReq` (RFC 3161).
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct TimeStampReq<'a> {
    pub version: u8,
    pub message_imprint: MessageImprint<'a>,
    pub req_policy: Option<ObjectIdentifier>,
    pub nonce: Option<UintRef<'a>>,
    pub cert_req: Option<bool>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<RawSequence<'a>>,
}

/// `TimeStampResp` (RFC 3161); the token is a `ContentInfo`.
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct TimeStampResp<'a> {
    pub status: PkiStatusInfo<'a>,
    pub time_stamp_token: Option<AnyRef<'a>>,
}

/// `PKIStatusInfo` (RFC 3161).
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct PkiStatusInfo<'a> {
    pub status: i64,
    pub status_string: Option<RawSequence<'a>>,
    pub fail_info: Option<BitStringRef<'a>>,
}

/// `TSTInfo` (RFC 3161).
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct TstInfo<'a> {
    pub version: u8,
    pub policy: ObjectIdentifier,
    pub message_imprint: MessageImprint<'a>,
    pub serial_number: IntRef<'a>,
    pub gen_time: RawGeneralizedTime<'a>,
    pub accuracy: Option<RawSequence<'a>>,
    pub ordering: Option<bool>,
    pub nonce: Option<IntRef<'a>>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub tsa: Option<AnyRef<'a>>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<RawSequence<'a>>,
}

/// `CertID` (RFC 6960).
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct CertId<'a> {
    pub hash_algorithm: AlgorithmIdentifierRef<'a>,
    pub issuer_name_hash: &'a OctetStringRef,
    pub issuer_key_hash: &'a OctetStringRef,
    pub serial_number: IntRef<'a>,
}

/// `Request` (RFC 6960).
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct Request<'a> {
    pub req_cert: CertId<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub single_request_extensions: Option<RawSequence<'a>>,
}

/// `TBSRequest` (RFC 6960).
#[derive(Clone, Debug, Sequence)]
pub(crate) struct TbsRequest<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub version: Option<u8>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub requestor_name: Option<AnyRef<'a>>,
    pub request_list: Vec<Request<'a>>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pub request_extensions: Option<RawSequence<'a>>,
}

/// `OCSPRequest` (RFC 6960).
#[derive(Clone, Debug, Sequence)]
pub(crate) struct OcspRequest<'a> {
    pub tbs_request: TbsRequest<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub optional_signature: Option<RawSequence<'a>>,
}

/// `OCSPResponse` (RFC 6960).
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct OcspResponse<'a> {
    pub response_status: Enumerated,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub response_bytes: Option<ResponseBytes<'a>>,
}

/// `ResponseBytes` (RFC 6960).
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct ResponseBytes<'a> {
    pub response_type: ObjectIdentifier,
    pub response: &'a OctetStringRef,
}

/// `BasicOCSPResponse` (RFC 6960).
#[derive(Clone, Debug, Sequence)]
pub(crate) struct BasicOcspResponse<'a> {
    pub tbs_response_data: AnyRef<'a>,
    pub signature_algorithm: AlgorithmIdentifierRef<'a>,
    pub signature: BitStringRef<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub certs: Option<Vec<Certificate>>,
}

/// `ResponseData` (RFC 6960).
#[derive(Clone, Debug, Sequence)]
pub(crate) struct ResponseData<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub version: Option<u8>,
    pub responder_id: AnyRef<'a>,
    pub produced_at: RawGeneralizedTime<'a>,
    pub responses: Vec<SingleResponse<'a>>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub response_extensions: Option<RawSequence<'a>>,
}

/// `SingleResponse` (RFC 6960).
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct SingleResponse<'a> {
    pub cert_id: CertId<'a>,
    pub cert_status: AnyRef<'a>,
    pub this_update: RawGeneralizedTime<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub next_update: Option<RawGeneralizedTime<'a>>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub single_extensions: Option<RawSequence<'a>>,
}

/// `RevokedInfo` (RFC 6960).
#[derive(Clone, Copy, Debug, Sequence)]
pub(crate) struct RevokedInfo<'a> {
    pub revocation_time: RawGeneralizedTime<'a>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub revocation_reason: Option<Enumerated>,
}

/// A context-specific tag.
pub(crate) fn context(constructed: bool, number: u32) -> Tag {
    Tag::ContextSpecific {
        constructed,
        number: TagNumber(number),
    }
}

/// An unsigned big-endian number without leading zeros (zero is empty).
pub(crate) fn unsigned(mut bytes: &[u8]) -> &[u8] {
    while let [0, rest @ ..] = bytes {
        bytes = rest;
    }
    bytes
}

/// `time` as a `GeneralizedTime` value `YYYYMMDDhhmmssZ`, truncated to whole seconds.
pub(crate) fn generalized_time(time: OffsetDateTime) -> String {
    let time = time.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    )
}

/// The signature algorithm the NCA pairs with a key: GOST 34.310-2004, GOST
/// 34.10-2015-512 or sha256WithRSA.
pub(crate) fn signature_alg(alg: KeyAlg) -> SigAlg {
    match alg {
        KeyAlg::Gost2004 => SigAlg::Gost2004,
        KeyAlg::Gost2015_512 => SigAlg::Gost2015_512,
        KeyAlg::Rsa => SigAlg::RsaSha256,
    }
}

/// A reply of `status` with a `text/plain` body.
pub(crate) fn text_reply(status: u16, text: &str) -> HttpReply {
    HttpReply {
        status,
        content_type: Some("text/plain".to_owned()),
        location: None,
        body: text.as_bytes().to_vec(),
    }
}

/// Decodes `%XX` escapes; `None` for a broken one.
fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hex = |b: Option<u8>| char::from(b?).to_digit(16);
            let (high, low) = (hex(bytes.next())?, hex(bytes.next())?);
            out.push(u8::try_from(high * 16 + low).ok()?);
        } else {
            out.push(b);
        }
    }
    Some(out)
}

/// The DER request a GET binding carries in `url`: the base64 (percent-encoded or not) of a
/// DER value that ends the URL's path, after one of its `/`.
pub(crate) fn request_in_url(url: &str) -> Option<Vec<u8>> {
    let path = url.splitn(4, '/').nth(3)?;
    let starts = std::iter::once(0).chain(path.match_indices('/').map(|(i, _)| i + 1));
    starts
        .filter_map(|start| percent_decode(&path[start..]))
        .filter_map(|b64| STANDARD.decode(b64).ok())
        .find(|der| AnyRef::from_der(der).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%2Bb%2f").unwrap(), b"a+b/");
        assert_eq!(percent_decode("%4"), None);
        assert_eq!(percent_decode("%zz"), None);
    }

    #[test]
    fn requests_in_urls() {
        // `MAA=` is the base64 of an empty SEQUENCE.
        assert_eq!(request_in_url("http://h/ocsp/MAA%3D").unwrap(), [0x30, 0]);
        assert_eq!(request_in_url("http://h/MAA=").unwrap(), [0x30, 0]);
        assert_eq!(request_in_url("http://h/ocsp"), None);
    }

    #[test]
    fn generalized_time_truncates_to_utc_seconds() {
        let t = time::macros::datetime!(2026-03-01 07:08:09.75 +06:00);
        assert_eq!(generalized_time(t), "20260301010809Z");
    }
}
