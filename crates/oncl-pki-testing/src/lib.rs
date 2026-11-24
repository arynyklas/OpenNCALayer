//! Test doubles of the NCA services, written on the public API of `oncl-pki`: an in-process
//! TSA ([`MockTsa`]), OCSP responder ([`MockOcsp`]) and CRL distribution point
//! ([`MockCrl`]) that answer correctly, an [`HttpTransport`](oncl_pki::http::HttpTransport)
//! routing by URL prefix ([`RouteTransport`]), and certificates issued on the fly
//! ([`issue_cert`]).
//!
//! They only answer as a well-behaved service does. Their builders set the state a real
//! service could be in, not spoiled answers: a fixed clock (`MockTsa::with_gen_time`,
//! `MockOcsp::with_now`), a CRL's own thisUpdate, nextUpdate (an old CRL is still a
//! correctly signed one) and extra CRL extensions, written as given (e.g. a non-critical one
//! that pads the CRL to a size). Spoiled answers (wrong keys, stale or
//! mismatched responses, HTTP failures) are the business of the tests of `oncl-pki`, which
//! keep their own doubles. Never a dependency of a product crate: a dev-dependency of the
//! crates' tests and a dependency of the test and tooling crates only.

mod asn1;
mod cert;
mod crl;
mod ocsp;
mod route;
mod tsa;

pub use cert::{TestCertSpec, issue_cert};
pub use crl::MockCrl;
pub use ocsp::MockOcsp;
pub use route::RouteTransport;
pub use tsa::MockTsa;
