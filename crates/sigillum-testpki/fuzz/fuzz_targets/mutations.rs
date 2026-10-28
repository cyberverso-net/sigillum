//! Fuzz target for the readers of `sigillum-testpki generate mutations`:
//! the search for the signing-time attribute and for the encapsulated
//! content of a CMS signature, and the reading of a compact JWS. A mutation that succeeds must change what it
//! promises and nothing else.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sigillum_testpki::mutations::{
    duplicate_protected_header_parameter, modify_encapsulated_content, modify_signing_time,
    tamper_protected_header,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(changed) = modify_signing_time(data) {
        assert_eq!(changed.len(), data.len());
        let differing = data.iter().zip(&changed).filter(|(a, b)| a != b).count();
        assert_eq!(differing, 1);
    }
    if let Ok(changed) = modify_encapsulated_content(data) {
        assert_eq!(changed.len(), data.len());
        let differing: Vec<(&u8, &u8)> =
            data.iter().zip(&changed).filter(|(a, b)| a != b).collect();
        assert_eq!(differing.len(), 1);
        assert_eq!(differing[0].0 ^ differing[0].1, 0x20);
    }
    let rest = |jws: &[u8]| -> Vec<u8> {
        jws.iter()
            .position(|&b| b == b'.')
            .map_or_else(Vec::new, |dot| jws[dot..].to_vec())
    };
    if let Ok(tampered) = tamper_protected_header(data) {
        assert_eq!(rest(&tampered), rest(data));
        assert_ne!(tampered, data);
        // The tampered header still holds one integer iat, so a second
        // duplication applies unless the value is near the largest.
        let _ = duplicate_protected_header_parameter(&tampered);
    }
    if let Ok(duplicated) = duplicate_protected_header_parameter(data) {
        assert_eq!(rest(&duplicated), rest(data));
        // With iat now given twice, neither mutation applies again.
        assert!(tamper_protected_header(&duplicated).is_err());
        assert!(duplicate_protected_header_parameter(&duplicated).is_err());
    }
});
