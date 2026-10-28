//! Fuzz target for the manifest parser of `sigillum-testpki`. A manifest
//! that parses is also written back and must read back unchanged, as the
//! generators rely on.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sigillum_testpki::manifest::Manifest;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(manifest) = Manifest::parse(text) {
            assert_eq!(Manifest::parse(&manifest.to_toml()), Ok(manifest));
        }
    }
});
