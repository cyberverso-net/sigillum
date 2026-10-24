use std::path::Path;

use time::macros::datetime;

use super::*;

const HEADER: &str = r#"
[header]
format-version = 1
validation-time = "2030-01-15T10:00:00Z"
openssl-version = "3.0.13"
dss-version = "6.5.1"
"#;

const DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const ROOT: &str = r#"
[[artefact]]
id = "pki/root"
path = "pki/root.pem"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
kind = "certificate"
purpose = "Root CA of the test PKI"
expected-openssl = "verified"
expected-dss = { indication = "PASSED" }
"#;

fn with_artefacts(artefacts: &str) -> String {
    format!("{HEADER}\n{artefacts}")
}

/// A second artefact, `pki/leaf`, with the given extra lines.
fn leaf(extra: &str) -> String {
    format!(
        r#"
[[artefact]]
id = "pki/leaf"
path = "pki/leaf.pem"
sha256 = "{DIGEST}"
kind = "certificate"
purpose = "End entity"
expected-openssl = "verified"
expected-dss = {{ indication = "PASSED" }}
{extra}
"#
    )
}

fn parse_err(text: &str) -> Option<ManifestError> {
    Manifest::parse(text).err()
}

fn syntax_message(text: &str) -> Option<String> {
    match parse_err(text) {
        Some(ManifestError::Syntax(message)) => Some(message),
        _ => None,
    }
}

fn is_syntax(error: Option<ManifestError>) -> bool {
    matches!(error, Some(ManifestError::Syntax(_)))
}

#[test]
fn parses_header_only() -> Result<(), ManifestError> {
    let manifest = Manifest::parse(HEADER)?;
    assert_eq!(manifest.header.format_version, 1);
    assert_eq!(
        manifest.header.validation_time,
        datetime!(2030-01-15 10:00:00 UTC)
    );
    assert_eq!(manifest.header.openssl_version, "3.0.13");
    assert_eq!(manifest.header.dss_version, "6.5.1");
    assert!(manifest.artefacts.is_empty());
    Ok(())
}

#[test]
fn parses_an_artefact() -> Result<(), ManifestError> {
    let manifest = Manifest::parse(&with_artefacts(ROOT))?;
    assert_eq!(
        manifest.artefacts,
        vec![Artefact {
            id: "pki/root".into(),
            path: "pki/root.pem".into(),
            sha256: DIGEST.into(),
            kind: Kind::Certificate,
            purpose: "Root CA of the test PKI".into(),
            expected_openssl: OpensslResult::Verified,
            expected_dss: DssResult::Indication {
                indication: Indication::Passed,
                sub_indication: None,
            },
            links: Links::default(),
            notes: None,
        }]
    );
    Ok(())
}

#[test]
fn parses_every_kind_and_result() -> Result<(), ManifestError> {
    let entry = |id: &str, kind: &str, openssl: &str, dss: &str| {
        format!(
            "[[artefact]]\nid = \"{id}\"\npath = \"{id}.der\"\nsha256 = \"{DIGEST}\"\nkind = \"{kind}\"\npurpose = \"p\"\nexpected-openssl = \"{openssl}\"\nexpected-dss = {dss}\n"
        )
    };
    let text = with_artefacts(
        &[
            entry("a", "private-key", "parsed", "\"not-applicable\""),
            entry("b", "crl", "rejected", "\"rejected\""),
            entry(
                "c",
                "ocsp-response",
                "not-applicable",
                "{ indication = \"TOTAL-PASSED\" }",
            ),
            entry(
                "d",
                "timestamp-token",
                "verified",
                "{ indication = \"TOTAL-FAILED\", sub-indication = \"HASH_FAILURE\" }",
            ),
            entry(
                "e",
                "signed-document",
                "not-applicable",
                "{ indication = \"INDETERMINATE\", sub-indication = \"OUT_OF_BOUNDS_NO_POE\" }",
            ),
            entry(
                "f",
                "document",
                "not-applicable",
                "{ indication = \"FAILED\", sub-indication = \"REVOKED\" }",
            ),
        ]
        .concat(),
    );
    let manifest = Manifest::parse(&text)?;
    let kinds: Vec<Kind> = manifest.artefacts.iter().map(|a| a.kind).collect();
    assert_eq!(
        kinds,
        [
            Kind::PrivateKey,
            Kind::Crl,
            Kind::OcspResponse,
            Kind::TimestampToken,
            Kind::SignedDocument,
            Kind::Document
        ]
    );
    let openssl: Vec<OpensslResult> = manifest
        .artefacts
        .iter()
        .map(|a| a.expected_openssl)
        .collect();
    assert_eq!(
        openssl,
        [
            OpensslResult::Parsed,
            OpensslResult::Rejected,
            OpensslResult::NotApplicable,
            OpensslResult::Verified,
            OpensslResult::NotApplicable,
            OpensslResult::NotApplicable
        ]
    );
    let dss: Vec<DssResult> = manifest
        .artefacts
        .iter()
        .map(|a| a.expected_dss.clone())
        .collect();
    let indication = |indication, sub: Option<&str>| DssResult::Indication {
        indication,
        sub_indication: sub.map(Into::into),
    };
    assert_eq!(
        dss,
        [
            DssResult::NotApplicable,
            DssResult::Rejected,
            indication(Indication::TotalPassed, None),
            indication(Indication::TotalFailed, Some("HASH_FAILURE")),
            indication(Indication::Indeterminate, Some("OUT_OF_BOUNDS_NO_POE")),
            indication(Indication::Failed, Some("REVOKED")),
        ]
    );
    Ok(())
}

#[test]
fn parses_links_and_notes() -> Result<(), ManifestError> {
    let text = with_artefacts(&format!(
        "{ROOT}{}{}",
        leaf("notes = \"n\""),
        r#"
[[artefact]]
id = "pki/root-crl"
path = "pki/root.crl"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
kind = "crl"
purpose = "CRL of the root"
expected-openssl = "parsed"
expected-dss = "not-applicable"

[[artefact]]
id = "pki/leaf-ocsp"
path = "pki/leaf.ocsp"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
kind = "ocsp-response"
purpose = "OCSP response for the leaf"
expected-openssl = "parsed"
expected-dss = "not-applicable"
links = { issuer = "pki/root", chain = ["pki/root"], revocation = ["pki/root-crl"], content = "pki/leaf" }
"#
    ));
    let manifest = Manifest::parse(&text)?;
    assert_eq!(manifest.artefacts[1].notes.as_deref(), Some("n"));
    assert_eq!(
        manifest.artefacts[3].links,
        Links {
            issuer: Some("pki/root".into()),
            chain: vec!["pki/root".into()],
            revocation: vec!["pki/root-crl".into()],
            content: Some("pki/leaf".into()),
        }
    );
    Ok(())
}

#[test]
fn rejects_unknown_fields() {
    let header = HEADER.replace("dss-version", "colour = \"red\"\ndss-version");
    assert!(is_syntax(parse_err(&header)));
    assert!(is_syntax(parse_err(&format!("comment = \"x\"\n{HEADER}"))));
    assert!(is_syntax(parse_err(&with_artefacts(
        &ROOT.replace("purpose", "colour = \"red\"\npurpose")
    ))));
    let dss = ROOT.replace(
        r#"{ indication = "PASSED" }"#,
        r#"{ indication = "PASSED", colour = "red" }"#,
    );
    assert!(is_syntax(parse_err(&with_artefacts(&dss))));
    let links = format!("{ROOT}{}", leaf("links = { parent = \"pki/root\" }"));
    assert!(is_syntax(parse_err(&with_artefacts(&links))));
}

#[test]
fn rejects_unknown_values_with_a_helpful_message() {
    for (from, to, hint) in [
        (r#"kind = "certificate""#, r#"kind = "picture""#, "picture"),
        (
            r#"expected-openssl = "verified""#,
            r#"expected-openssl = "maybe""#,
            "maybe",
        ),
        (
            r#"{ indication = "PASSED" }"#,
            r#"{ indication = "GOOD" }"#,
            "GOOD",
        ),
        (
            r#"{ indication = "PASSED" }"#,
            r#""accepted""#,
            "not-applicable",
        ),
        (
            r#"{ indication = "PASSED" }"#,
            r#"{ sub-indication = "NO_POE" }"#,
            "indication",
        ),
        (r#"{ indication = "PASSED" }"#, "42", "not-applicable"),
    ] {
        let message = syntax_message(&with_artefacts(&ROOT.replace(from, to)));
        assert!(
            message.as_deref().is_some_and(|m| m.contains(hint)),
            "{to}: {message:?}"
        );
        assert!(
            message.as_deref().is_some_and(|m| !m.contains("Raw")),
            "{to}: {message:?}"
        );
    }
}

#[test]
fn syntax_errors_name_the_line_and_column() {
    let text = with_artefacts(&ROOT.replace("purpose", "colour = \"red\"\npurpose"));
    let message = syntax_message(&text);
    assert!(
        message
            .as_deref()
            .is_some_and(|m| m.contains("line 14, column 1")),
        "{message:?}"
    );
}

#[test]
fn rejects_missing_fields() {
    for field in [
        "id",
        "path",
        "sha256",
        "kind",
        "purpose",
        "expected-openssl",
        "expected-dss",
    ] {
        let artefact: String = ROOT
            .lines()
            .filter(|line| !line.starts_with(&format!("{field} =")))
            .map(|line| format!("{line}\n"))
            .collect();
        assert!(is_syntax(parse_err(&with_artefacts(&artefact))), "{field}");
    }
    assert!(is_syntax(parse_err(ROOT)));
    assert!(is_syntax(parse_err(
        &HEADER.replace("format-version = 1\n", "")
    )));
}

#[test]
fn rejects_other_format_versions() {
    let text = HEADER.replace("format-version = 1", "format-version = 2");
    assert_eq!(
        parse_err(&text),
        Some(ManifestError::UnsupportedFormatVersion(2))
    );
}

#[test]
fn rejects_duplicate_identifiers() {
    let second = ROOT.replace("pki/root.pem", "pki/root-copy.pem");
    let text = with_artefacts(&format!("{ROOT}\n{second}"));
    assert_eq!(
        parse_err(&text),
        Some(ManifestError::DuplicateIdentifier("pki/root".into()))
    );
}

#[test]
fn rejects_duplicate_paths_ignoring_case() {
    let second = ROOT
        .replace("id = \"pki/root\"", "id = \"pki/root-2\"")
        .replace("pki/root.pem", "PKI/Root.pem");
    let text = with_artefacts(&format!("{ROOT}\n{second}"));
    assert_eq!(
        parse_err(&text),
        Some(ManifestError::DuplicatePath {
            id: "pki/root-2".into(),
            path: "PKI/Root.pem".into(),
        })
    );
}

#[test]
fn rejects_paths_that_conflict_as_file_and_directory() {
    let cases = [
        ("pki/root.pem", "pki/root.pem/x"),
        ("pki/root.pem/x", "pki/root.pem"),
        ("pki/root.pem/x", "PKI/root.pem/y"),
        ("pki/a/x", "pki/A"),
        ("a/B/x", "a/b/y"),
    ];
    for (first, second) in cases {
        let other = ROOT
            .replace("id = \"pki/root\"", "id = \"pki/root-2\"")
            .replace("pki/root.pem", second);
        let text = with_artefacts(&format!("{}\n{other}", ROOT.replace("pki/root.pem", first)));
        assert_eq!(
            parse_err(&text),
            Some(ManifestError::PathConflict {
                id: "pki/root-2".into(),
                path: second.into(),
            }),
            "{first} {second}"
        );
    }
}

#[test]
fn accepts_paths_that_share_a_directory() -> Result<(), ManifestError> {
    let other = ROOT
        .replace("id = \"pki/root\"", "id = \"pki/root-2\"")
        .replace("pki/root.pem", "pki/sub/root.pem");
    let first = ROOT.replace("pki/root.pem", "pki/sub/other.pem");
    Manifest::parse(&with_artefacts(&format!("{first}\n{other}")))?;
    Ok(())
}

#[test]
fn rejects_paths_that_are_not_portable() {
    for path in [
        "../secret.pem",
        "pki/../../secret.pem",
        "/etc/passwd",
        "./pki/root.pem",
        "pki/./root.pem",
        "pki//root.pem",
        "pki/",
        "C:/x",
        "C:x",
        "a:b",
        "CON",
        "nul.txt",
        "pki/com1.pem",
        "COM0.pem",
        "lpt0",
        "LPT9",
        "a/b.",
        "a/ b",
        "pki/root pem",
        "manifest.toml",
        "README.md",
        "readme.MD",
        "",
    ] {
        let text = with_artefacts(&ROOT.replace("pki/root.pem", path));
        assert_eq!(
            parse_err(&text),
            Some(ManifestError::InvalidPath {
                id: "pki/root".into(),
                path: path.into(),
            }),
            "{path}"
        );
    }
    let text = with_artefacts(&ROOT.replace("pki/root.pem", "pki\\\\root.pem"));
    assert!(matches!(
        parse_err(&text),
        Some(ManifestError::InvalidPath { .. })
    ));
}

#[test]
fn accepts_portable_paths() -> Result<(), ManifestError> {
    for path in [
        "pki/keys/root.test-key.pem",
        "COM10.pem",
        "console.pem",
        "a_b-c.d",
    ] {
        let manifest = Manifest::parse(&with_artefacts(&ROOT.replace("pki/root.pem", path)))?;
        assert_eq!(manifest.artefacts[0].path, Path::new(path));
    }
    Ok(())
}

#[test]
fn rejects_identifiers_that_are_not_portable() {
    for id in ["pki root", "pki//root", "/pki", "pki/../root", "é"] {
        let text = with_artefacts(&ROOT.replace("id = \"pki/root\"", &format!("id = \"{id}\"")));
        assert_eq!(
            parse_err(&text),
            Some(ManifestError::InvalidIdentifier(id.into())),
            "{id}"
        );
    }
}

#[test]
fn rejects_malformed_digests() {
    for value in [
        "00",
        &DIGEST.replace('0', "A"),
        &format!("{DIGEST}0"),
        &DIGEST.replacen('0', "g", 1),
    ] {
        let text = with_artefacts(&ROOT.replace(DIGEST, value));
        assert_eq!(
            parse_err(&text),
            Some(ManifestError::InvalidDigest {
                id: "pki/root".into(),
                value: value.to_string(),
            }),
            "{value}"
        );
    }
}

#[test]
fn rejects_empty_text_fields() {
    let text = with_artefacts(&ROOT.replace(r#"id = "pki/root""#, r#"id = """#));
    assert_eq!(
        parse_err(&text),
        Some(ManifestError::EmptyField {
            id: String::new(),
            field: "id"
        })
    );
    let text =
        with_artefacts(&ROOT.replace(r#"purpose = "Root CA of the test PKI""#, r#"purpose = " ""#));
    assert_eq!(
        parse_err(&text),
        Some(ManifestError::EmptyField {
            id: "pki/root".into(),
            field: "purpose"
        })
    );
    let text = with_artefacts(&format!("{ROOT}notes = \"\"\n"));
    assert_eq!(
        parse_err(&text),
        Some(ManifestError::EmptyField {
            id: "pki/root".into(),
            field: "notes"
        })
    );
    let text = HEADER.replace(r#"openssl-version = "3.0.13""#, r#"openssl-version = """#);
    assert_eq!(
        parse_err(&text),
        Some(ManifestError::EmptyField {
            id: String::new(),
            field: "openssl-version"
        })
    );
    let text = HEADER.replace(r#"dss-version = "6.5.1""#, r#"dss-version = """#);
    assert_eq!(
        parse_err(&text),
        Some(ManifestError::EmptyField {
            id: String::new(),
            field: "dss-version"
        })
    );
}

#[test]
fn rejects_validation_times_of_another_form() {
    for value in [
        "2030-01-15",
        "2030-01-15T10:00:00+01:00",
        "2030-01-15T10:00:00+00:00",
        "2030-01-15 10:00:00Z",
        "2030-01-15t10:00:00z",
        "2030-01-15T10:00:00.5Z",
        "2030-12-31T23:59:60Z",
        "2030-02-30T10:00:00Z",
        "15 January 2030",
        "",
    ] {
        let text = HEADER.replace("2030-01-15T10:00:00Z", value);
        assert_eq!(
            parse_err(&text),
            Some(ManifestError::ValidationTime(value.into())),
            "{value}"
        );
    }
}

#[test]
fn rejects_sub_indications_that_do_not_belong_to_the_indication() {
    for (indication, sub) in [
        ("PASSED", "HASH_FAILURE"),
        ("TOTAL-PASSED", "NO_POE"),
        ("TOTAL-FAILED", "NO_POE"),
        ("FAILED", "TRY_LATER"),
        ("INDETERMINATE", "REVOKED"),
        ("INDETERMINATE", "NO_SIGNATURE_FOUND"),
        ("INDETERMINATE", "no_poe"),
        ("INDETERMINATE", ""),
    ] {
        let dss = format!("{{ indication = \"{indication}\", sub-indication = \"{sub}\" }}");
        let text = with_artefacts(&ROOT.replace(r#"{ indication = "PASSED" }"#, &dss));
        assert!(
            matches!(parse_err(&text), Some(ManifestError::InvalidSubIndication { value, .. }) if value == sub),
            "{indication} {sub}"
        );
    }
}

#[test]
fn every_listed_sub_indication_is_accepted() -> Result<(), ManifestError> {
    for (indication, list) in [
        ("TOTAL-FAILED", &FAILED_SUB_INDICATIONS[..]),
        ("FAILED", &FAILED_SUB_INDICATIONS[..]),
        ("INDETERMINATE", &INDETERMINATE_SUB_INDICATIONS[..]),
    ] {
        for sub in list {
            let dss = format!("{{ indication = \"{indication}\", sub-indication = \"{sub}\" }}");
            Manifest::parse(&with_artefacts(
                &ROOT.replace(r#"{ indication = "PASSED" }"#, &dss),
            ))?;
        }
    }
    Ok(())
}

#[test]
fn rejects_links_to_unknown_or_same_artefacts() {
    for (link, value, target) in [
        ("issuer", "\"pki/missing\"", "pki/missing"),
        ("chain", "[\"pki/root\", \"pki/missing\"]", "pki/missing"),
        ("revocation", "[\"pki/leaf\"]", "pki/leaf"),
        ("content", "\"pki/leaf\"", "pki/leaf"),
    ] {
        let text = with_artefacts(&format!(
            "{ROOT}{}",
            leaf(&format!("links = {{ {link} = {value} }}"))
        ));
        assert_eq!(
            parse_err(&text),
            Some(ManifestError::InvalidLink {
                id: "pki/leaf".into(),
                link,
                target: target.into(),
            }),
            "{link}"
        );
    }
}

#[test]
fn rejects_links_to_artefacts_of_the_wrong_kind_or_repeated() {
    let crl = r#"
[[artefact]]
id = "pki/root-crl"
path = "pki/root.crl"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
kind = "crl"
purpose = "CRL of the root"
expected-openssl = "parsed"
expected-dss = "not-applicable"
"#;
    for (link, value, target) in [
        ("issuer", "\"pki/root-crl\"", "pki/root-crl"),
        ("chain", "[\"pki/root-crl\"]", "pki/root-crl"),
        ("chain", "[\"pki/root\", \"pki/root\"]", "pki/root"),
        ("revocation", "[\"pki/root\"]", "pki/root"),
        (
            "revocation",
            "[\"pki/root-crl\", \"pki/root-crl\"]",
            "pki/root-crl",
        ),
    ] {
        let text = with_artefacts(&format!(
            "{ROOT}{crl}{}",
            leaf(&format!("links = {{ {link} = {value} }}"))
        ));
        assert_eq!(
            parse_err(&text),
            Some(ManifestError::LinkMismatch {
                id: "pki/leaf".into(),
                link,
                target: target.into(),
            }),
            "{link} {value}"
        );
    }
}

#[test]
fn rejects_a_chain_that_does_not_start_with_the_issuer() -> Result<(), ManifestError> {
    let other = ROOT
        .replace("id = \"pki/root\"", "id = \"pki/other\"")
        .replace("pki/root.pem", "pki/other.pem");
    let text = |chain: &str| {
        with_artefacts(&format!(
            "{ROOT}{other}{}",
            leaf(&format!(
                "links = {{ issuer = \"pki/root\", chain = {chain} }}"
            ))
        ))
    };
    assert_eq!(
        parse_err(&text("[\"pki/other\", \"pki/root\"]")),
        Some(ManifestError::LinkMismatch {
            id: "pki/leaf".into(),
            link: "chain",
            target: "pki/other".into(),
        })
    );
    Manifest::parse(&text("[\"pki/root\", \"pki/other\"]"))?;
    Manifest::parse(&text("[]"))?;
    Ok(())
}

#[test]
fn custom_is_an_indeterminate_sub_indication() {
    assert!(INDETERMINATE_SUB_INDICATIONS.contains(&"CUSTOM"));
    assert!(!FAILED_SUB_INDICATIONS.contains(&"CUSTOM"));
}

#[test]
fn errors_display_the_cause() {
    let cases = [
        (
            ManifestError::Syntax("bad".into()),
            "the manifest is not valid: bad",
        ),
        (
            ManifestError::UnsupportedFormatVersion(2),
            "the manifest format version 2 is not supported; this program reads version 1",
        ),
        (
            ManifestError::ValidationTime("t".into()),
            "the validation time \"t\" is not of the form YYYY-MM-DDTHH:MM:SSZ",
        ),
        (
            ManifestError::EmptyField {
                id: "x".into(),
                field: "purpose",
            },
            "the field \"purpose\" of \"x\" is empty",
        ),
        (
            ManifestError::EmptyField {
                id: String::new(),
                field: "dss-version",
            },
            "the field \"dss-version\" is empty",
        ),
        (
            ManifestError::InvalidIdentifier("a b".into()),
            "the identifier \"a b\" may only contain letters, digits, '.', '_', '-' and '/' between non-empty parts",
        ),
        (
            ManifestError::DuplicateIdentifier("x".into()),
            "the identifier \"x\" is used more than once",
        ),
        (
            ManifestError::InvalidPath {
                id: "x".into(),
                path: "../y".into(),
            },
            "the path \"../y\" of \"x\" is not a portable relative path inside the corpus",
        ),
        (
            ManifestError::DuplicatePath {
                id: "x".into(),
                path: "Y".into(),
            },
            "the path \"Y\" of \"x\" names a file already listed, ignoring letter case",
        ),
        (
            ManifestError::PathConflict {
                id: "x".into(),
                path: "y/z".into(),
            },
            "the path \"y/z\" of \"x\" conflicts with another path of the manifest, ignoring letter case",
        ),
        (
            ManifestError::LinkMismatch {
                id: "x".into(),
                link: "chain",
                target: "y".into(),
            },
            "the link chain = \"y\" of \"x\" names an artefact of the wrong kind or repeats one",
        ),
        (
            ManifestError::InvalidDigest {
                id: "x".into(),
                value: "00".into(),
            },
            "the sha256 \"00\" of \"x\" is not 64 lower-case hexadecimal digits",
        ),
        (
            ManifestError::InvalidSubIndication {
                id: "x".into(),
                indication: "PASSED",
                value: "NO_POE".into(),
            },
            "the sub-indication \"NO_POE\" of \"x\" is not one of those defined for PASSED",
        ),
        (
            ManifestError::InvalidLink {
                id: "x".into(),
                link: "issuer",
                target: "y".into(),
            },
            "the link issuer = \"y\" of \"x\" does not name another artefact of the manifest",
        ),
        (
            ManifestError::Io("gone".into()),
            "the manifest cannot be read: gone",
        ),
    ];
    for (error, text) in cases {
        assert_eq!(error.to_string(), text);
    }
}

#[test]
fn indications_have_their_manifest_spelling() {
    let spelled: Vec<&str> = [
        Indication::TotalPassed,
        Indication::TotalFailed,
        Indication::Indeterminate,
        Indication::Passed,
        Indication::Failed,
    ]
    .into_iter()
    .map(Indication::as_str)
    .collect();
    assert_eq!(
        spelled,
        [
            "TOTAL-PASSED",
            "TOTAL-FAILED",
            "INDETERMINATE",
            "PASSED",
            "FAILED"
        ]
    );
}

#[test]
fn the_committed_manifest_is_valid() -> Result<(), ManifestError> {
    let text = include_str!("../../../../testdata/manifest.toml");
    let manifest = Manifest::parse(text)?;
    assert_eq!(
        manifest.header.validation_time,
        datetime!(2030-01-15 10:00:00 UTC)
    );
    Ok(())
}
