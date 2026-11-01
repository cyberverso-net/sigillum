//! Behaviour of the `der` 0.8 generation with `cms`, checked for #21.
//!
//! `cms` 0.3.0-rc.0 enables the `ber` feature of `der` in every build that
//! includes it. The finding is recorded in the dated note of 2026-11-01 in
//! ADR-0024. A test that fails after an update means that the behaviour has
//! changed, and the note is checked again before the update is merged.

use der::{Any, Decode, ErrorKind};

/// A SEQUENCE in the indefinite form, holding an empty OCTET STRING, closed
/// by the end-of-contents octets.
const INDEFINITE: [u8; 6] = [0x30, 0x80, 0x04, 0x00, 0x00, 0x00];

/// The `ber` feature only adds a decoder for BER: `from_ber` accepts the
/// indefinite form, and `from_der` still refuses it, as ITU-T X.690
/// (02/2021), clause 10.1, requires of DER.
#[test]
fn der_decoding_refuses_indefinite_lengths_with_the_ber_feature() {
    assert!(Any::from_ber(&INDEFINITE).is_ok());
    assert!(matches!(
        Any::from_der(&INDEFINITE).map_err(|error| error.kind()),
        Err(ErrorKind::IndefiniteLength)
    ));
}
