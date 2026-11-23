//! An in-process OCSP responder.

use crate::asn1::{
    BasicOcspResponse, CertId, Enumerated, OcspRequest, OcspResponse, RawGeneralizedTime,
    ResponseBytes, ResponseData, RevokedInfo, SingleResponse, context, generalized_time,
    request_in_url, signature_alg, text_reply, unsigned,
};
use der::asn1::{AnyRef, BitStringRef, OctetStringRef};
use der::{Decode, Encode};
use oncl_pki::http::{HttpError, HttpMethod, HttpReply, HttpRequest, HttpTransport};
use oncl_pki::ocsp::CertStatus;
use oncl_pki::oid;
use oncl_pki::pkcs12::KeyEntry;
use spki::AlgorithmIdentifierRef;
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use time::OffsetDateTime;

/// Media type of an `OCSPResponse` (RFC 6960 appendix A).
const OCSP_RESPONSE: &str = "application/ocsp-response";

/// An OCSP responder answering requests of any binding (GET, the NCA GET binding, POST)
/// with a successful `BasicOCSPResponse` signed with `responder`'s key and carrying its
/// certificate, the responder identified by name: the status set for the requested serial
/// number (`good` for any other), thisUpdate a minute ago, nextUpdate in an hour, and the
/// request's extensions (its nonce) echoed as the response's. The `CertID` is echoed with
/// its hash algorithm. Unreadable requests get HTTP 400. Every requested URL and every
/// request read are recorded.
pub struct MockOcsp {
    responder: KeyEntry,
    statuses: BTreeMap<Vec<u8>, CertStatus>,
    now: Option<OffsetDateTime>,
    calls: Mutex<Vec<String>>,
    requests: Mutex<Vec<Vec<u8>>>,
}

impl MockOcsp {
    /// A responder signing with `responder` (e.g. the synthetic `ocsp-gost2015`).
    pub fn new(responder: KeyEntry) -> Self {
        MockOcsp {
            responder,
            statuses: BTreeMap::new(),
            now: None,
            calls: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
        }
    }

    /// The same responder, answering `status` for the serial number `serial_hex` (hex
    /// digits of either case; leading zeros do not matter).
    ///
    /// # Panics
    ///
    /// If `serial_hex` has a character that is not a hex digit.
    #[must_use]
    pub fn status(mut self, serial_hex: &str, status: CertStatus) -> Self {
        self.statuses.insert(serial_from_hex(serial_hex), status);
        self
    }

    /// The same responder with a stopped clock: producedAt is `now`, thisUpdate a minute
    /// before, nextUpdate an hour after.
    #[must_use]
    pub fn with_now(mut self, now: OffsetDateTime) -> Self {
        self.now = Some(now);
        self
    }

    /// URLs requested so far, in order.
    pub fn calls(&self) -> Vec<String> {
        self.lock_calls().clone()
    }

    /// The DER `OCSPRequest`s read so far, in order.
    pub fn requests(&self) -> Vec<Vec<u8>> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn lock_calls(&self) -> MutexGuard<'_, Vec<String>> {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// DER `OCSPResponse` answering the DER `OCSPRequest` `request`.
    fn respond(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        let der_error = |e: der::Error| e.to_string();
        let request = OcspRequest::from_der(request).map_err(der_error)?;
        let cert_id: CertId<'_> = request
            .tbs_request
            .request_list
            .first()
            .ok_or("empty request list")?
            .req_cert;
        let status = self
            .statuses
            .get(unsigned(cert_id.serial_number.as_bytes()))
            .copied()
            .unwrap_or(CertStatus::Good);

        let now = self.now.unwrap_or_else(OffsetDateTime::now_utc);
        let produced_at = generalized_time(now);
        let this_update = generalized_time(now - time::Duration::MINUTE);
        let next_update = generalized_time(now + time::Duration::HOUR);

        let revoked_info = match status {
            CertStatus::Revoked { time, reason } => RevokedInfo {
                revocation_time: RawGeneralizedTime(generalized_time(time).as_bytes()),
                revocation_reason: reason.map(Enumerated),
            }
            .to_der()
            .map_err(der_error)?,
            CertStatus::Good | CertStatus::Unknown => Vec::new(),
        };
        let cert_status = match status {
            CertStatus::Good => AnyRef::new(context(false, 0), &[]),
            CertStatus::Revoked { .. } => AnyRef::new(
                context(true, 1),
                AnyRef::from_der(&revoked_info).map_err(der_error)?.value(),
            ),
            CertStatus::Unknown => AnyRef::new(context(false, 2), &[]),
        }
        .map_err(der_error)?;

        let cert = &self.responder.cert;
        let responder_name = cert
            .tbs_certificate()
            .subject()
            .to_der()
            .map_err(der_error)?;
        let tbs = ResponseData {
            version: None,
            responder_id: AnyRef::new(context(true, 1), &responder_name).map_err(der_error)?,
            produced_at: RawGeneralizedTime(produced_at.as_bytes()),
            responses: vec![SingleResponse {
                cert_id,
                cert_status,
                this_update: RawGeneralizedTime(this_update.as_bytes()),
                next_update: Some(RawGeneralizedTime(next_update.as_bytes())),
                single_extensions: None,
            }],
            response_extensions: request.tbs_request.request_extensions,
        }
        .to_der()
        .map_err(der_error)?;

        let alg = signature_alg(self.responder.key.alg());
        let signature = self
            .responder
            .key
            .sign(alg, &tbs)
            .map_err(|e| e.to_string())?;
        let basic = BasicOcspResponse {
            tbs_response_data: AnyRef::from_der(&tbs).map_err(der_error)?,
            signature_algorithm: AlgorithmIdentifierRef {
                oid: alg.signature_oid(),
                parameters: Some(AnyRef::NULL),
            },
            signature: BitStringRef::from_bytes(&signature).map_err(der_error)?,
            certs: Some(vec![cert.clone()]),
        }
        .to_der()
        .map_err(der_error)?;
        OcspResponse {
            response_status: Enumerated(0),
            response_bytes: Some(ResponseBytes {
                response_type: oid::OCSP_BASIC,
                response: OctetStringRef::new(&basic).map_err(der_error)?,
            }),
        }
        .to_der()
        .map_err(der_error)
    }
}

impl HttpTransport for MockOcsp {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.lock_calls().push(request.url.to_owned());
        let der = match request.method {
            HttpMethod::Post => Some(request.body.to_vec()),
            HttpMethod::Get => request_in_url(request.url),
        };
        let Some(der) = der else {
            return Ok(text_reply(400, "request is not base64"));
        };
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(der.clone());
        Ok(match self.respond(&der) {
            Ok(body) => HttpReply {
                status: 200,
                content_type: Some(OCSP_RESPONSE.to_owned()),
                location: None,
                body,
            },
            Err(e) => text_reply(400, &e),
        })
    }
}

/// Unsigned big-endian bytes of hex digits, without leading zeros.
fn serial_from_hex(hex: &str) -> Vec<u8> {
    let digits: Vec<u8> = hex
        .chars()
        .map(|c| {
            c.to_digit(16)
                .and_then(|d| u8::try_from(d).ok())
                .unwrap_or_else(|| panic!("serial {hex:?} is not hex"))
        })
        .collect();
    let (head, pairs) = digits.split_at(digits.len() % 2);
    let bytes: Vec<u8> = head
        .iter()
        .copied()
        .chain(pairs.chunks(2).map(|p| (p[0] << 4) | p[1]))
        .collect();
    unsigned(&bytes).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_hex_parsing() {
        assert_eq!(serial_from_hex("00aB01"), [0xab, 0x01]);
        assert_eq!(serial_from_hex("abc"), [0x0a, 0xbc]);
        assert_eq!(serial_from_hex("0"), [] as [u8; 0]);
    }
}
