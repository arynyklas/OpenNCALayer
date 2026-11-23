//! An in-process TSA.

use crate::asn1::{
    PkiStatusInfo, RawGeneralizedTime, TimeStampReq, TimeStampResp, TstInfo, generalized_time,
    request_in_url, text_reply, unsigned,
};
use der::asn1::{AnyRef, IntRef, ObjectIdentifier};
use der::{Decode, Encode};
use oncl_pki::cms::{AttrSpec, CertSpec, CoSign, Content, SignSpec, sign_spec};
use oncl_pki::http::{HttpError, HttpMethod, HttpReply, HttpRequest, HttpTransport};
use oncl_pki::oid;
use oncl_pki::pkcs12::KeyEntry;
use std::sync::{Mutex, MutexGuard, PoisonError};
use time::OffsetDateTime;

/// The policy of the NCA's basics TSA, which answers requests without one.
const BASICS_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.398.3.3.2.6.4");
/// Media type of a `TimeStampReq` (RFC 3161 §3.4).
const TIMESTAMP_QUERY: &str = "application/timestamp-query";
/// Media type of a `TimeStampResp` (RFC 3161 §3.4).
const TIMESTAMP_REPLY: &str = "application/timestamp-reply";

/// A TSA answering GET (raw or percent-encoded base64 of the request after the host) and
/// POST requests with a granted `TimeStampResp`: a `TSTInfo` with the request's policy (or
/// the basics one), message imprint and nonce, the current time (or the one set with
/// [`MockTsa::with_gen_time`]) and a serial counting the requests, signed with `entry` as
/// id-ct-TSTInfo. Unreadable requests get HTTP 400, a POST of another content type HTTP
/// 415. Every requested URL and every request read are recorded.
pub struct MockTsa {
    entry: KeyEntry,
    gen_time: Option<OffsetDateTime>,
    calls: Mutex<Vec<String>>,
    requests: Mutex<Vec<Vec<u8>>>,
}

impl MockTsa {
    /// A TSA signing with `entry` (e.g. the synthetic `tsa-gost2015`).
    pub fn new(entry: KeyEntry) -> Self {
        MockTsa {
            entry,
            gen_time: None,
            calls: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// The same TSA with a stopped clock: every token has `gen_time` (to the second) as its
    /// genTime and signingTime.
    #[must_use]
    pub fn with_gen_time(self, gen_time: OffsetDateTime) -> Self {
        MockTsa {
            gen_time: Some(gen_time),
            ..self
        }
    }

    /// URLs requested so far, in order.
    pub fn calls(&self) -> Vec<String> {
        self.lock_calls().clone()
    }

    /// The DER `TimeStampReq`s read so far, in order.
    pub fn requests(&self) -> Vec<Vec<u8>> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn lock_calls(&self) -> MutexGuard<'_, Vec<String>> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records `url`, returning the request's serial number (1, 2, …).
    fn record(&self, url: &str) -> u32 {
        let mut calls = self.lock_calls();
        calls.push(url.to_owned());
        u32::try_from(calls.len()).unwrap_or(u32::MAX)
    }

    fn respond(&self, request: &[u8], serial: u32) -> HttpReply {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request.to_vec());
        match self.time_stamp(request, serial) {
            Ok(body) => HttpReply {
                status: 200,
                content_type: Some(TIMESTAMP_REPLY.to_owned()),
                location: None,
                body,
            },
            Err(e) => text_reply(400, &e),
        }
    }

    /// DER `TimeStampResp` answering the DER `TimeStampReq` `request`.
    fn time_stamp(&self, request: &[u8], serial: u32) -> Result<Vec<u8>, String> {
        let der_error = |e: der::Error| e.to_string();
        let req = TimeStampReq::from_der(request).map_err(der_error)?;
        // The request's nonce is unsigned; echo it as the same INTEGER.
        let nonce = req.nonce.map(|n| uint_contents(n.as_bytes()));
        let nonce = nonce
            .as_deref()
            .map(IntRef::new)
            .transpose()
            .map_err(der_error)?;
        let now = self.gen_time.unwrap_or_else(OffsetDateTime::now_utc);
        let gen_time = generalized_time(now);
        // A leading 01 keeps the INTEGER positive and minimal.
        let mut serial_number = vec![1];
        serial_number.extend_from_slice(&serial.to_be_bytes());
        let tst_info = TstInfo {
            version: 1,
            policy: req.req_policy.unwrap_or(BASICS_POLICY),
            message_imprint: req.message_imprint,
            serial_number: IntRef::new(&serial_number).map_err(der_error)?,
            gen_time: RawGeneralizedTime(gen_time.as_bytes()),
            accuracy: None,
            ordering: None,
            nonce,
            tsa: None,
            extensions: None,
        }
        .to_der()
        .map_err(der_error)?;
        let spec = SignSpec {
            content: Content::Data(&tst_info),
            encapsulate: true,
            cosign: CoSign::Never,
            econtent_type: Some(oid::TST_INFO),
            digest: None,
            attrs: AttrSpec::cades(now),
            certificates: CertSpec::Signer,
        };
        let token = sign_spec(&self.entry, &[], &spec).map_err(|e| e.to_string())?;
        TimeStampResp {
            status: PkiStatusInfo {
                status: 0,
                status_string: None,
                fail_info: None,
            },
            time_stamp_token: Some(AnyRef::from_der(&token).map_err(der_error)?),
        }
        .to_der()
        .map_err(der_error)
    }
}

/// A mock server: the request options do not change what it answers.
impl HttpTransport for MockTsa {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        let serial = self.record(request.url);
        Ok(match request.method {
            HttpMethod::Post => {
                let content_type = request.content_type.unwrap_or_default();
                if content_type == TIMESTAMP_QUERY {
                    self.respond(request.body, serial)
                } else {
                    text_reply(415, content_type)
                }
            }
            HttpMethod::Get => match request_in_url(request.url) {
                Some(der) => self.respond(&der, serial),
                None => text_reply(400, "request is not base64"),
            },
        })
    }
}

/// Contents octets of the DER INTEGER equal to the unsigned big-endian `magnitude`: a `00`
/// sign octet before a set top bit, `00` for zero.
fn uint_contents(magnitude: &[u8]) -> Vec<u8> {
    match unsigned(magnitude) {
        [] => vec![0],
        m if m[0] & 0x80 != 0 => [&[0][..], m].concat(),
        m => m.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_nonces_echo_as_positive_integers() {
        assert_eq!(uint_contents(&[0, 0x7f]), [0x7f]);
        assert_eq!(uint_contents(&[0x80]), [0, 0x80]);
        assert_eq!(uint_contents(&[]), [0]);
    }
}
