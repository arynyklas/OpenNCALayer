//! The doubles answer what `oncl-pki`'s real verification accepts: a stamped CMS verifies
//! with its token, an OCSP answer passes `ocsp::check_answer` with the status set, a CRL
//! passes `crl::verify_crl` and lists what was revoked.

use oncl_pki::cert::{self, Certificate};
use oncl_pki::cms::{SignOptions, sign, verify};
use oncl_pki::crl;
use oncl_pki::ocsp::{self, CertStatus};
use oncl_pki::pkcs12::{KeyEntry, load};
use oncl_pki::pkix::CaSet;
use oncl_pki::tsp::{TsaProfile, timestamp_signer, verify_token};
use oncl_pki_testing::{MockCrl, MockOcsp, MockTsa};
use oncl_testkit::{read, synthetic, synthetic_cert};
use std::time::Duration;
use time::OffsetDateTime;
use time::macros::datetime;

fn entry(name: &str) -> KeyEntry {
    let key = synthetic(name);
    load(&read(&key.path), &key.password).unwrap().remove(0)
}

fn cer(name: &str) -> Certificate {
    cert::parse(&synthetic_cert(name)).unwrap()
}

#[test]
fn a_stamped_cms_verifies_with_the_token() {
    let opts = SignOptions {
        encapsulate: true,
        digested: false,
        signing_time: datetime!(2026-03-01 10:20:30 UTC),
    };
    let cms = sign(&entry("user-gost2015-sign"), b"d", &opts).unwrap();
    let tsa = MockTsa::new(entry("tsa-gost2015"));
    let stamped = timestamp_signer(&cms, 0, &TsaProfile::basics_default(), &tsa).unwrap();
    let signers = verify(&stamped, None).unwrap();
    verify_token(signers[0].timestamp_token.as_ref().unwrap()).unwrap();
    assert_eq!(tsa.calls().len(), 1);
}

#[test]
fn ocsp_answers_pass_the_real_check_with_their_status() {
    let issuer = cer("inter-gost2015");
    let cas = CaSet::new(vec![cer("root-gost2015"), issuer.clone()]);
    let good = entry("inter-user-gost2015-sign").cert;
    let revoked = entry("inter-revoked-gost2015-sign").cert;
    let at = datetime!(2026-01-15 08:00 UTC);
    let serial: String = revoked
        .tbs_certificate()
        .serial_number()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let responder = MockOcsp::new(entry("ocsp-gost2015")).status(
        &serial,
        CertStatus::Revoked {
            time: at,
            reason: None,
        },
    );
    let now = OffsetDateTime::now_utc();
    let status = |cert: &Certificate| {
        ocsp::check_answer(cert, &issuer, &cas, &responder, now, Duration::from_secs(5))
            .unwrap()
            .status
    };
    assert_eq!(status(&good), CertStatus::Good);
    assert_eq!(
        status(&revoked),
        CertStatus::Revoked {
            time: at,
            reason: None
        }
    );
}

#[test]
fn a_crl_passes_the_real_check_and_lists_the_revoked() {
    let issuer = cer("inter-gost2015");
    let revoked = entry("inter-revoked-gost2015-sign").cert;
    let serial = revoked.tbs_certificate().serial_number().as_bytes();
    let der = MockCrl::new(entry("inter-gost2015.key"))
        .revoke(serial, datetime!(2026-01-15 08:00 UTC))
        .der();
    let list = crl::verify_crl(&der, &issuer, OffsetDateTime::now_utc()).unwrap();
    let listed = list.tbs_cert_list.revoked_certificates.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].serial_number.as_bytes(), serial);
}
