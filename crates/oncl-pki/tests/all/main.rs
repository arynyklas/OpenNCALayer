//! The integration tests of `oncl-pki` as one test binary: one link of the crate and its
//! dependencies instead of one per file. A test is `<file>::<test>`.
//!
//! `cms_stream` and `metadata_intake` stay binaries of their own: each installs its own
//! `#[global_allocator]`, and a binary has one.

#[path = "../doubles/mod.rs"]
mod doubles;

mod ber;
mod cades;
mod cert_verify;
mod cms;
mod cms_report;
mod cms_signer;
mod cms_spec;
mod cms_stream_sign;
mod configuration_budget;
mod crl;
mod csr;
mod digest_signatures;
mod envelope;
mod evidence;
mod frozen_input;
mod info;
mod input_spool;
mod jks;
mod keystore;
mod ocsp;
mod pkcs12;
mod pkix;
mod private_fs;
mod provisional_input;
mod spki;
mod token_key;
mod tsp;
mod wire_capture;
mod xml_output;
