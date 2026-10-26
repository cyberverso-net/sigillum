//! Fuzz target for the readers of OpenSSL output and manifest notes in
//! `sigillum-testpki verify --openssl`: the version line of `openssl
//! version`, the times that `openssl crl` prints, the status that `openssl
//! ocsp` prints for a certificate, the covered certificate named in the
//! notes of a manifest entry, and the peek at the content type of a
//! signed document.
//!
//! Every input goes to the peek, whatever its encoding. Valid UTF-8 goes
//! whole to the version, CRL times and notes readers.
//! Its first line is then the certificate argument, and the rest the
//! output of `openssl ocsp`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sigillum_testpki::openssl::{
    covered_certificate, crl_times, is_cms_signed_data, ocsp_status, parse_version,
};

fuzz_target!(|data: &[u8]| {
    let _ = is_cms_signed_data(data);
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_version(text);
    let _ = covered_certificate(text);
    let _ = crl_times(text);
    let (cert, stdout) = text.split_once('\n').unwrap_or((text, ""));
    let _ = ocsp_status(stdout, cert);
});
