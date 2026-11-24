//! Static revocation data of the synthetic intermediate PKI: CRLs at a fixed time, for tests
//! that only verify already-signed data. They need no live CRL service: the validation time
//! is an input, so a committed CRL serves as well as a freshly signed one.

use super::issue::Key;
use der::asn1::{BitString, Uint, UtcTime};
use der::{Decode, Encode};
use rand_chacha::ChaCha20Rng;
use x509_cert::certificate::Version;
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::ext::pkix::CrlNumber;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Time;

/// thisUpdate of every static CRL: a minute before 2026-11-02 12:00 UTC, the validation time
/// of the tests that read them.
const THIS_UPDATE: &[u8] = b"261102115900Z";
/// nextUpdate of a current CRL: an hour after the validation time.
const NEXT_UPDATE: &[u8] = b"261102130000Z";
/// nextUpdate of a stale CRL: half a minute after thisUpdate, before the validation time.
const STALE_NEXT_UPDATE: &[u8] = b"261102115930Z";
/// When the revoked CRLs say the listed certificate was revoked.
const REVOKED_AT: &[u8] = b"260115080000Z";

/// The static CRLs of `issuer` (`file` the `.cer` name without extension): current and stale,
/// and for each, when `revoked` names a serial number, also one listing it. File name →
/// DER, in the order drawn from `rng`.
pub(super) fn crls(
    file: &str,
    issuer: &Name,
    key: &Key,
    revoked: Option<&[u8]>,
    rng: &mut ChaCha20Rng,
) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let lists: &[(&str, Option<&[u8]>)] = match revoked {
        Some(serial) => &[("", None), ("-revoked", Some(serial))],
        None => &[("", None)],
    };
    for &(tag, serial) in lists {
        for (stale, next) in [("", NEXT_UPDATE), ("-stale", STALE_NEXT_UPDATE)] {
            let der = crl(issuer, key, next, serial, rng);
            out.push((format!("{file}{tag}{stale}.crl"), der));
        }
    }
    out
}

/// A v2 CRL of `issuer` signed with `key`: CRL Number 1, thisUpdate [`THIS_UPDATE`],
/// nextUpdate `next`, and `serial` revoked at [`REVOKED_AT`] without a reason.
fn crl(
    issuer: &Name,
    key: &Key,
    next: &[u8],
    serial: Option<&[u8]>,
    rng: &mut ChaCha20Rng,
) -> Vec<u8> {
    let time = |t: &[u8]| Time::UtcTime(UtcTime::from_der(&utc(t)).expect("UTCTime"));
    let crl_number = CrlNumber(Uint::new(&[1]).expect("1 is an INTEGER"));
    let tbs: TbsCertList = TbsCertList {
        version: Version::V2,
        signature: key.signature_algorithm(),
        issuer: issuer.clone(),
        this_update: time(THIS_UPDATE),
        next_update: Some(time(next)),
        revoked_certificates: serial.map(|serial| {
            vec![RevokedCert {
                serial_number: SerialNumber::new(serial).expect("serial number"),
                revocation_date: time(REVOKED_AT),
                crl_entry_extensions: None,
            }]
        }),
        crl_extensions: Some(vec![super::issue::extension(false, &crl_number)]),
    };
    let tbs_der = tbs.to_der().expect("TBSCertList encodes");
    let signature = key.sign(&tbs_der, rng);
    let list: CertificateList = CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: key.signature_algorithm(),
        signature: BitString::from_bytes(&signature).expect("signature BIT STRING"),
    };
    list.to_der().expect("CertificateList encodes")
}

/// DER of a UTCTime with the value `value`.
fn utc(value: &[u8]) -> Vec<u8> {
    let mut der = vec![0x17, u8::try_from(value.len()).expect("short time")];
    der.extend_from_slice(value);
    der
}
