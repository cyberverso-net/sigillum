//! Fuzz target for the manifest parser of `sigillum-testpki`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sigillum_testpki::manifest::Manifest;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Manifest::parse(text);
    }
});
