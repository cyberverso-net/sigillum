//! Fuzz target for the readers of `sigillum-testpki generate mutations`:
//! the search for the signing-time attribute and for the encapsulated
//! content of a CMS signature, the reading of a compact JWS, and the
//! reading of the cross-reference tables and of the `ByteRange` of a PDF.
//! A mutation that succeeds must change what it promises and nothing else.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sigillum_testpki::mutations::{
    add_page_content, duplicate_protected_header_parameter, modify_encapsulated_content,
    modify_signing_time, remove_overlay, replace_field_value, switch_page_tree,
    tamper_protected_header, wrap_byte_range,
};

/// The PAdES mutations that append an incremental update.
const UPDATES: [fn(&[u8]) -> Result<Vec<u8>, sigillum_testpki::mutations::Unsupported>; 4] = [
    add_page_content,
    remove_overlay,
    replace_field_value,
    switch_page_tree,
];

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
    // An incremental update keeps every byte of its input, ends with the
    // end-of-file marker, and the change it makes does not apply again.
    for update in UPDATES {
        if let Ok(updated) = update(data) {
            assert!(updated.len() > data.len());
            assert!(updated.starts_with(data));
            assert!(updated.ends_with(b"%%EOF\n"));
            assert!(update(&updated).is_err());
        }
    }
    // The wrapping keeps the length of the file, appends a copy of the end
    // of its input, and changes the input only in the value of the
    // ByteRange; the copy holds the old value, so it does not apply again.
    if let Ok(wrapped) = wrap_byte_range(data) {
        let length = data.len();
        assert!(wrapped.len() > length);
        let copy = &wrapped[length..];
        assert!(data.ends_with(copy));
        let differing: Vec<usize> = (0..length).filter(|&i| wrapped[i] != data[i]).collect();
        if let (Some(first), Some(last)) = (differing.first(), differing.last()) {
            assert!(last - first < 48);
        }
        assert!(wrap_byte_range(&wrapped).is_err());
    }
});
