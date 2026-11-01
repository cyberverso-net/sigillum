//! Behaviour of the `der` 0.8 generation that the rules of ADR-0024 depend on.
//!
//! The findings of #21 are recorded in the dated note of 2026-11-01 in
//! ADR-0024. Each test pins the behaviour of the releases in `Cargo.lock`,
//! `der` 0.8.3 and `const-oid` 0.10.2, including the defects that remain. A
//! test that fails after an update means that the behaviour has changed: the
//! note in ADR-0024 and DIV-2 in `docs/design/divergences.md` are then checked
//! again before the update is merged.

use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{Any, Decode, ErrorKind, Length};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Owned values decoded through `Decode` are checked against the input
/// before their contents are read. `der` 0.8.3 decodes the value inside a
/// nested reader whose length is checked first (`reader::read_value` and
/// `Position::split_nested`), so `Reader::read_vec` is not reached. The
/// nested reader refuses the value with the length of the input: it expects
/// one octet more than the nine it has. A decoder that allocated the
/// declared length first would fail later, in `Reader::read_vec`, expecting
/// the position of the contents plus the declared length, 2^28 + 5 octets.
/// The reproduction in the note of ADR-0024 shows that nothing is allocated.
#[test]
fn owned_values_declaring_more_than_the_input_are_refused() {
    // Each value declares 2^28 - 1 octets of contents and has three.
    let octet_string = [0x04, 0x84, 0x0F, 0xFF, 0xFF, 0xFF, 1, 2, 3];
    let utf8_string = [0x0C, 0x84, 0x0F, 0xFF, 0xFF, 0xFF, 0x61, 0x62, 0x63];
    let refused_by_the_nested_reader = ErrorKind::Incomplete {
        expected_len: Length::new(10),
        actual_len: Length::new(9),
    };

    let refusals = [
        OctetString::from_der(&octet_string)
            .err()
            .map(|error| error.kind()),
        Any::from_der(&octet_string).err().map(|error| error.kind()),
        String::from_der(&utf8_string)
            .err()
            .map(|error| error.kind()),
    ];
    for (index, refusal) in refusals.iter().enumerate() {
        assert_eq!(
            refusal.as_ref(),
            Some(&refused_by_the_nested_reader),
            "value {index}"
        );
    }
}

/// `der` 0.8.3 accepts declared lengths up to 2^32 - 1, where `der` 0.7.10
/// stopped at 2^28 - 1. A direct call of `Reader::read_vec` can therefore
/// request up to 4 GiB.
#[test]
fn declared_lengths_reach_u32_max() {
    assert_eq!(Length::MAX, Length::new(u32::MAX));
}

/// Arcs from 2^28 to 2^32 - 1 are decoded, displayed, iterated and encoded
/// from dotted text without a panic, and both forms agree. The tests run
/// with overflow checks, as fuzz builds do.
#[test]
fn arcs_from_2_pow_28_to_u32_max_round_trip() -> TestResult {
    let cases: [(&[u8], &str, u32); 3] = [
        (
            &[0x2A, 0x81, 0x80, 0x80, 0x80, 0x00],
            "1.2.268435456",
            1 << 28,
        ),
        (
            &[0x2A, 0x84, 0x91, 0xE8, 0xEB, 0x47],
            "1.2.1111111111",
            1_111_111_111,
        ),
        (
            &[0x2A, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F],
            "1.2.4294967295",
            u32::MAX,
        ),
    ];
    for (contents, dotted, arc) in cases {
        let decoded = ObjectIdentifier::from_bytes(contents)?;
        assert_eq!(decoded.to_string(), dotted);
        assert_eq!(decoded.arcs().collect::<Vec<_>>(), [1, 2, arc]);

        let parsed = ObjectIdentifier::new(dotted)?;
        assert_eq!(parsed.as_bytes(), contents, "{dotted}");
        assert_eq!(parsed.arcs().collect::<Vec<_>>(), [1, 2, arc]);
    }
    Ok(())
}

/// Dotted arcs above 32 bits are refused, without a panic or wrapping
/// (RustCrypto/formats#1592 and #1600).
#[test]
fn dotted_arcs_above_u32_are_refused() {
    for dotted in ["1.2.4294967296", "1.2.4294967301"] {
        assert_eq!(
            ObjectIdentifier::new(dotted),
            Err(const_oid::Error::ArcTooBig),
            "{dotted}"
        );
    }
}

/// The encoder from dotted text gives the right contents for the arcs that
/// RustCrypto/formats#1520 and #1753 describe.
#[test]
fn dotted_arcs_of_the_known_encoder_defects_are_encoded_correctly() -> TestResult {
    let cases: [(&str, &[u8]); 4] = [
        ("1.2.128", &[0x2A, 0x81, 0x00]),
        ("1.2.16384", &[0x2A, 0x81, 0x80, 0x00]),
        ("1.2.2097152", &[0x2A, 0x81, 0x80, 0x80, 0x00]),
        (
            "1.1.1.270000000",
            &[0x29, 0x01, 0x81, 0x80, 0xDF, 0xBF, 0x00],
        ),
    ];
    for (dotted, contents) in cases {
        assert_eq!(
            ObjectIdentifier::new(dotted)?.as_bytes(),
            contents,
            "{dotted}"
        );
    }
    Ok(())
}

/// Arcs above 2^32 - 1 are still truncated silently in the DER form:
/// `const-oid` 0.10.2 does not contain RustCrypto/formats#2412. It checks the
/// size of an arc only from its sixth octet (`src/arcs.rs`, lines 89 to 91),
/// and shifts the arc in 32 bits. So every arc of five octets is accepted,
/// and one above 2^32 - 1 keeps only its low 32 bits. An arc of six octets
/// whose last octet is below 0x10 is accepted and truncated too. An arc of
/// six octets with a last octet of 0x10 or more, and an arc of seven octets
/// or more, are refused with `ArcTooBig`. The limit of 2^28 on arcs of
/// ADR-0024, rule 4, therefore stays: the walk refuses every subidentifier
/// of more than four octets before `const-oid` sees it.
#[test]
fn der_arcs_above_u32_are_still_truncated() -> TestResult {
    let truncated: [(&[u8], &str); 5] = [
        (&[0x2A, 0x90, 0x80, 0x80, 0x80, 0x05], "1.2.5"),
        (&[0x2A, 0x9F, 0xFF, 0xFF, 0xFF, 0x7F], "1.2.4294967295"),
        (&[0x2A, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F], "1.2.4294967295"),
        (&[0x2A, 0x81, 0x80, 0x80, 0x80, 0x80, 0x05], "1.2.5"),
        (&[0x2A, 0x81, 0x80, 0x80, 0x80, 0x80, 0x0F], "1.2.15"),
    ];
    for (contents, dotted) in truncated {
        let decoded = ObjectIdentifier::from_bytes(contents)?;
        assert_eq!(decoded.to_string(), dotted, "{contents:02X?}");
        assert_eq!(decoded.arcs().count(), 3, "{contents:02X?}");
    }

    let refused: [&[u8]; 3] = [
        &[0x2A, 0x81, 0x80, 0x80, 0x80, 0x80, 0x10],
        &[0x2A, 0x81, 0x80, 0x80, 0x80, 0x80, 0x7F],
        &[0x2A, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
    ];
    for contents in refused {
        assert_eq!(
            ObjectIdentifier::from_bytes(contents),
            Err(const_oid::Error::ArcTooBig),
            "{contents:02X?}"
        );
    }
    Ok(())
}

/// The structural limits of `const-oid` 0.10.2 differ from those of 0.9.6
/// that ADR-0024, rule 4, lists. One or two contents octets are accepted,
/// and a subidentifier with a leading 0x80 octet, which ITU-T X.690
/// (02/2021), clause 8.19.2, forbids, is decoded. The second arc is still at
/// most 39 under every root, and the contents still hold at most 39 octets.
/// In DER, `const-oid` reads the first subidentifier as one octet, so
/// `88 37 03`, the encoding of `2.999.3`, is read as a first arc of 3 and
/// refused.
#[test]
fn structural_limits_of_const_oid_0_10_2() -> TestResult {
    assert_eq!(ObjectIdentifier::from_bytes(&[0x2A])?.to_string(), "1.2");
    assert_eq!(
        ObjectIdentifier::from_bytes(&[0x2A, 0x03])?.to_string(),
        "1.2.3"
    );
    assert_eq!(
        ObjectIdentifier::from_bytes(&[0x2A, 0x80, 0x01])?.to_string(),
        "1.2.1"
    );
    assert_eq!(
        ObjectIdentifier::new("2.999.3"),
        Err(const_oid::Error::ArcInvalid { arc: 999 })
    );
    assert_eq!(
        ObjectIdentifier::from_bytes(&[0x88, 0x37, 0x03]),
        Err(const_oid::Error::ArcInvalid { arc: 3 })
    );
    assert_eq!(ObjectIdentifier::MAX_SIZE, 39);
    Ok(())
}
