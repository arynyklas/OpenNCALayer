//! The test doubles of the NCA services that the tests of `oncl-pki` validate against,
//! written on the crate's public API: a TSA ([`MockTsa`]), an OCSP responder
//! ([`MockOcsp`]) and a CRL distribution point ([`MockCrl`]), each of which can also spoil
//! its answer ([`MockTamper`], [`OcspTamper`], [`MockCrl::wrong_key`]); an
//! [`HttpTransport`](oncl_pki::http::HttpTransport) routing by URL prefix
//! ([`RouteTransport`]); and certificates issued on the fly ([`issue_cert`]).
//!
//! This is the one home of the spoiled answers: other crates' tests take the well-behaved
//! services of `oncl-pki-testing` and leave the validation matrix to these tests. Each test
//! binary includes this module with `#[path]`.

#![allow(dead_code, unused_imports)]

mod asn1;
mod cert;
mod crl;
mod ocsp;
mod route;
mod tsa;

pub use cert::{TestCertSpec, issue_cert};
pub use crl::MockCrl;
pub use ocsp::{MockOcsp, OcspTamper};
pub use route::RouteTransport;
pub use tsa::{MockTamper, MockTsa};
