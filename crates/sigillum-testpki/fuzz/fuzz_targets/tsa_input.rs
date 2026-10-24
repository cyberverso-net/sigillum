//! Fuzz target for the input handling of the `tsa` subcommand of
//! `sigillum-testpki`.
//!
//! The whole input goes to the DER length check, `input::check_der`.
//! When it is valid UTF-8, it also goes to the parsers of the digest
//! algorithm, the digest and the time. The first byte then chooses which
//! file the remaining bytes stand for. When it is even, they are the key
//! file, read with the committed certificate of `pki/tsa`. When it is odd,
//! they are the certificate file, read with the committed test key of
//! `pki/tsa`, so that the DER length check of the certificate, its parsing
//! and the key match check are reached. The key and certificate are public
//! test material.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sigillum_testpki::timestamp::{Tsa, input};

const TSA_KEY: &[u8] = include_bytes!("../../../../testdata/pki/keys/tsa.test-key.pem");
const TSA_CERTIFICATE: &[u8] = include_bytes!("../../../../testdata/pki/tsa.pem");

fuzz_target!(|data: &[u8]| {
    let _ = input::check_der(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = input::digest_algorithm(text);
        let _ = input::hex_digest(text);
        let _ = input::time(text);
    }
    let Some((&selector, file)) = data.split_first() else {
        return;
    };
    if selector % 2 == 0 {
        let _ = Tsa::from_pem(file, TSA_CERTIFICATE);
    } else {
        let _ = input::is_pem(file);
        let _ = Tsa::from_pem(TSA_KEY, file);
    }
});
