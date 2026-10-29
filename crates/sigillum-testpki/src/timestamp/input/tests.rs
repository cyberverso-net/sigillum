use super::*;
use proptest::prelude::*;

#[test]
fn digest_algorithms_are_read_by_name_or_identifier() {
    let cases = [
        ("SHA-256", DigestAlgorithm::Sha256),
        ("sha256", DigestAlgorithm::Sha256),
        ("Sha-256", DigestAlgorithm::Sha256),
        ("2.16.840.1.101.3.4.2.1", DigestAlgorithm::Sha256),
        ("SHA-384", DigestAlgorithm::Sha384),
        ("SHA384", DigestAlgorithm::Sha384),
        ("2.16.840.1.101.3.4.2.2", DigestAlgorithm::Sha384),
        ("sha-512", DigestAlgorithm::Sha512),
        ("SHA512", DigestAlgorithm::Sha512),
        ("2.16.840.1.101.3.4.2.3", DigestAlgorithm::Sha512),
    ];
    for (value, algorithm) in cases {
        assert_eq!(digest_algorithm(value), Ok(algorithm), "{value}");
    }
    for value in [
        "",
        "SHA-1",
        "1.3.14.3.2.26",
        "SHA3-256",
        "2.16.840.1.101.3.4.2.8",
        "SHA_256",
        "SHA--256",
        "S-HA256",
        " SHA-256",
        "2.16.840.1.101.3.4.2.1.0",
        "1.2.3",
        "md5",
    ] {
        let error = digest_algorithm(value).err().unwrap_or_default();
        assert!(error.contains("unsupported digest algorithm"), "{value}");
    }
}

/// Object identifiers with arcs too large for `const-oid` 0.9.6, whose
/// parser overflows on them, are refused without being parsed. The
/// first is the input on which the fuzz target `tsa_input` found it.
#[test]
fn oversized_object_identifiers_are_refused() {
    for value in [
        "2106481106481.@;.@;01.3.4.2.3",
        "99999999999999999999.1",
        "2.16.840.1.101.3.4.2.99999999999999999999",
        // Leading zeros are not the canonical dotted form, and are
        // refused since the identifiers are compared as text.
        "2.16.840.1.101.3.4.2.01",
        "02.16.840.1.101.3.4.2.1",
    ] {
        let error = digest_algorithm(value).err().unwrap_or_default();
        assert!(error.contains("unsupported digest algorithm"), "{value}");
    }
}

#[test]
fn digests_are_even_hexadecimal() {
    assert_eq!(hex_digest("00ff"), Ok(vec![0x00, 0xff]));
    assert_eq!(hex_digest("ABcd"), Ok(vec![0xab, 0xcd]));
    for value in ["", "0", "abc", "0g", "+1", "-1", " 0", "0 ", "é0", "0x00"] {
        let error = hex_digest(value).err().unwrap_or_default();
        assert!(error.contains("hexadecimal"), "{value:?}");
    }
}

#[test]
fn times_have_the_manifest_form_from_1970() {
    assert!(time("2030-01-15T09:00:00Z").is_ok());
    assert!(time("1970-01-01T00:00:00Z").is_ok());
    for value in [
        "1969-12-31T23:59:59Z",
        "2030-01-15T09:00:00+00:00",
        "2030-01-15T10:00:00+01:00",
        "2030-01-15T09:00:00.5Z",
        "2030-01-15t09:00:00z",
        "2030-01-15T09:00Z",
        "2030-01-15 09:00:00Z",
        "2030-01-15T09:00:60Z",
        "",
    ] {
        let error = time(value).err().unwrap_or_default();
        assert!(error.contains("YYYY-MM-DDTHH:MM:SSZ"), "{value}");
    }
}

#[test]
fn pem_files_may_start_with_a_byte_order_mark_and_white_space() {
    let pem = b"-----BEGIN CERTIFICATE-----\n";
    for prefix in [
        &b""[..],
        b"\xef\xbb\xbf",
        b" \t\r\n\x0b\x0c",
        b"\xef\xbb\xbf \n",
    ] {
        let contents = [prefix, pem].concat();
        assert_eq!(trim_pem_start(&contents), pem, "{prefix:?}");
        assert!(is_pem(&contents), "{prefix:?}");
    }
    assert_eq!(trim_pem_start(b""), b"");
    assert_eq!(trim_pem_start(b" \n"), b"");
    // Only one byte order mark, and only at the start.
    assert!(!is_pem(&[BYTE_ORDER_MARK, BYTE_ORDER_MARK, pem].concat()));
    assert!(!is_pem(&[b" ".as_slice(), BYTE_ORDER_MARK, pem].concat()));
    assert!(!is_pem(b"\x30\x82\x01\x00"));
    assert!(!is_pem(b"-----BEGIN"));
}

#[test]
fn files_are_read_up_to_the_limit() -> Result<(), Box<dyn std::error::Error>> {
    let limit = usize::try_from(MAX_FILE_LEN)?;
    assert_eq!(limit, 65_536);
    let at = vec![b'a'; limit];
    assert_eq!(read_limited(at.as_slice(), MAX_FILE_LEN), Ok(at.clone()));
    let over = vec![b'a'; limit + 1];
    assert_eq!(
        read_limited(over.as_slice(), MAX_FILE_LEN),
        Err(FileError::TooLarge(MAX_FILE_LEN))
    );
    assert_eq!(read_limited(&b""[..], 0), Ok(Vec::new()));
    assert_eq!(read_limited(&b"a"[..], 0), Err(FileError::TooLarge(0)));
    assert_eq!(read_limited(&b"ab"[..], u64::MAX), Ok(b"ab".to_vec()));
    // At most one byte beyond the limit is read from a longer input.
    let mut reader = std::io::repeat(b'a').take(1 << 30);
    assert_eq!(read_limited(&mut reader, 4), Err(FileError::TooLarge(4)));
    assert_eq!(reader.limit(), (1 << 30) - 5);
    // Through the file system, at and over the limit.
    let dir = std::env::temp_dir().join(format!("sigillum-testpki-input-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("at");
    std::fs::write(&path, &at)?;
    assert_eq!(read_file(&path), Ok(at));
    std::fs::write(&path, &over)?;
    assert_eq!(read_file(&path), Err(FileError::TooLarge(MAX_FILE_LEN)));
    let missing = read_file(&dir.join("missing"));
    assert!(matches!(missing, Err(FileError::Io(_))), "{missing:?}");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        FileError::TooLarge(65_536).to_string(),
        "the file is larger than 65536 bytes"
    );
    assert_eq!(FileError::Io("gone".to_owned()).to_string(), "gone");
    Ok(())
}

#[test]
fn der_lengths_must_fit_the_input() {
    let accepted: [&[u8]; 8] = [
        // An empty SEQUENCE, and a NULL.
        &[0x30, 0x00],
        &[0x05, 0x00],
        // A SEQUENCE holding a SEQUENCE and an INTEGER.
        &[0x30, 0x07, 0x30, 0x02, 0x05, 0x00, 0x02, 0x01, 0x01],
        // Long-form lengths of one and two octets.
        &[0x04, 0x81, 0x01, 0xaa],
        &[0x04, 0x82, 0x00, 0x01, 0xaa],
        // A primitive value whose content looks like a bad header.
        &[0x04, 0x02, 0x30, 0x84],
        // A high tag number in two octets, constructed.
        &[0x3f, 0x81, 0x01, 0x02, 0x05, 0x00],
        // A context-specific constructed value.
        &[0xa0, 0x03, 0x02, 0x01, 0x00],
    ];
    for der in accepted {
        assert_eq!(check_der(der), Ok(()), "{der:02x?}");
    }
    let refused: [(&[u8], DerError); 15] = [
        (&[], DerError::Truncated),
        (&[0x30], DerError::Truncated),
        (&[0x02, 0x01], DerError::Truncated),
        // The input of the report: an INTEGER declaring 32 MiB.
        (
            &[0x30, 0x08, 0x30, 0x06, 0x02, 0x84, 0x02, 0x00, 0x00, 0x00],
            DerError::Truncated,
        ),
        // A nested length longer than its parent, which fits the input.
        (
            &[0x30, 0x02, 0x04, 0x03, 0x00, 0x00, 0x00],
            DerError::Truncated,
        ),
        // A parent whose content ends inside a child's header.
        (&[0x30, 0x03, 0x04, 0x00, 0x05, 0x00], DerError::Truncated),
        (&[0x30, 0x80, 0x00, 0x00], DerError::IndefiniteLength),
        (&[0x30, 0x02, 0x30, 0x80], DerError::IndefiniteLength),
        (
            &[0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0xaa],
            DerError::LengthTooLong,
        ),
        (&[0x04, 0xff], DerError::LengthTooLong),
        (&[0x04, 0x82, 0x00], DerError::Truncated),
        (&[0x05, 0x00, 0x05, 0x00], DerError::TrailingData),
        (&[0x1f], DerError::Truncated),
        (
            &[0x1f, 0x81, 0x81, 0x81, 0x81, 0x01, 0x00],
            DerError::TagTooLong,
        ),
        (&[0x1f, 0x81], DerError::Truncated),
    ];
    for (der, error) in refused {
        assert_eq!(check_der(der), Err(error), "{der:02x?}");
    }
    // A four-octet high tag number is the longest accepted.
    assert_eq!(check_der(&[0x1f, 0x81, 0x81, 0x81, 0x01, 0x00]), Ok(()));
}

#[test]
fn der_nesting_is_bounded() {
    let nested = |depth: usize| {
        let mut der = vec![0x05, 0x00];
        for _ in 0..depth {
            let len = u8::try_from(der.len()).unwrap_or(0);
            der.splice(0..0, [0x30, 0x81, len]);
        }
        der
    };
    assert_eq!(check_der(&nested(MAX_DER_DEPTH)), Ok(()));
    assert_eq!(
        check_der(&nested(MAX_DER_DEPTH + 1)),
        Err(DerError::TooDeep)
    );
}

#[test]
fn der_errors_are_described() {
    let cases = [
        (
            DerError::Truncated,
            "a DER length exceeds the bytes available",
        ),
        (
            DerError::IndefiniteLength,
            "a DER value has an indefinite length",
        ),
        (
            DerError::LengthTooLong,
            "a DER length has more than four octets",
        ),
        (DerError::TagTooLong, "a DER tag has more than four octets"),
        (DerError::TooDeep, "DER values are nested more than 32 deep"),
        (DerError::TrailingData, "bytes follow the DER value"),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}

proptest! {
    #[test]
    fn check_der_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        let _ = check_der(&bytes);
    }

    #[test]
    fn hexadecimal_round_trips(bytes in proptest::collection::vec(any::<u8>(), 1..80)) {
        let lower: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        prop_assert_eq!(hex_digest(&lower), Ok(bytes.clone()));
        prop_assert_eq!(hex_digest(&lower.to_uppercase()), Ok(bytes));
    }

    #[test]
    fn parsers_never_panic(value in ".*") {
        let _ = hex_digest(&value);
        let _ = digest_algorithm(&value);
        let _ = time(&value);
        let _ = is_pem(value.as_bytes());
    }
}
