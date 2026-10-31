use std::path::Path;

use time::macros::datetime;

use super::*;

const HEADER: &str = r#"
[header]
format-version = 3
validation-time = "2030-01-15T10:00:00Z"
openssl-version = "3.5.9"
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
    assert_eq!(manifest.header.format_version, 3);
    assert_eq!(
        manifest.header.validation_time,
        datetime!(2030-01-15 10:00:00 UTC)
    );
    assert_eq!(manifest.header.openssl_version, "3.5.9");
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
            attack_class: None,
            dss_divergence: None,
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
            timestamp_chain: Vec::new(),
        }
    );
    Ok(())
}

#[test]
fn parses_and_writes_a_timestamp_chain() -> Result<(), ManifestError> {
    let text = with_artefacts(&format!(
        "{ROOT}{}",
        leaf("links = { chain = [\"pki/root\"], timestamp-chain = [\"pki/root\"] }")
    ));
    let manifest = Manifest::parse(&text)?;
    assert_eq!(manifest.artefacts[1].links.timestamp_chain, ["pki/root"]);
    let written = manifest.to_toml();
    assert!(
        written.contains("links = { chain = [\"pki/root\"], timestamp-chain = [\"pki/root\"] }"),
        "{written}"
    );
    assert_eq!(Manifest::parse(&written)?, manifest);
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
        &HEADER.replace("format-version = 3\n", "")
    )));
}

#[test]
fn rejects_other_format_versions() {
    // Version 2 had no attack-class; version 3 added it.
    for version in [0, 1, 2, 4] {
        let text = HEADER.replace("format-version = 3", &format!("format-version = {version}"));
        assert_eq!(
            parse_err(&text),
            Some(ManifestError::UnsupportedFormatVersion(version))
        );
    }
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
    let text = HEADER.replace(r#"openssl-version = "3.5.9""#, r#"openssl-version = """#);
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
        ("timestamp-chain", "[\"pki/root-crl\"]", "pki/root-crl"),
        (
            "timestamp-chain",
            "[\"pki/root\", \"pki/root\"]",
            "pki/root",
        ),
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
            "the manifest format version 2 is not supported; this program reads version 3",
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
            ManifestError::AttackClassNotAllowed("x".into()),
            "the attack-class of \"x\" is allowed only on a PAdES signed document: a signed-document whose path ends with .pdf",
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

/// A divergence for every third artefact that DSS processes, with a result
/// other than `expected`.
fn divergence(expected: &DssResult, index: usize) -> Option<Divergence> {
    let other = if *expected
        == (DssResult::Indication {
            indication: Indication::Passed,
            sub_indication: None,
        }) {
        (
            Indication::Indeterminate,
            Some("OUT_OF_BOUNDS_NOT_REVOKED".to_owned()),
        )
    } else {
        (Indication::Passed, None)
    };
    (index.is_multiple_of(3) && *expected != DssResult::NotApplicable).then(|| Divergence {
        entry: format!("DIV-{}", index + 1),
        indication: other.0,
        sub_indication: other.1,
    })
}

/// A manifest with every kind, result and link, and text that needs escaping.
fn varied_manifest() -> Result<Manifest, ManifestError> {
    let mut manifest = Manifest::parse(&with_artefacts(ROOT))?;
    let kinds = [
        Kind::Certificate,
        Kind::PrivateKey,
        Kind::Crl,
        Kind::OcspResponse,
        Kind::TimestampToken,
        Kind::SignedDocument,
        Kind::Document,
    ];
    let openssl = [
        OpensslResult::Verified,
        OpensslResult::Parsed,
        OpensslResult::Rejected,
        OpensslResult::NotApplicable,
    ];
    let dss = [
        DssResult::Rejected,
        DssResult::NotApplicable,
        DssResult::Indication {
            indication: Indication::TotalPassed,
            sub_indication: None,
        },
        DssResult::Indication {
            indication: Indication::TotalFailed,
            sub_indication: Some("HASH_FAILURE".into()),
        },
        DssResult::Indication {
            indication: Indication::Indeterminate,
            sub_indication: Some("CUSTOM".into()),
        },
        DssResult::Indication {
            indication: Indication::Passed,
            sub_indication: None,
        },
        DssResult::Indication {
            indication: Indication::Failed,
            sub_indication: Some("REVOKED".into()),
        },
    ];
    for (index, kind) in kinds.into_iter().enumerate() {
        let id = format!("x/{}", kind.as_str());
        let links = match kind {
            Kind::Certificate => Links {
                issuer: Some("pki/root".into()),
                chain: vec!["pki/root".into()],
                revocation: vec!["x/crl".into(), "x/ocsp-response".into()],
                content: Some("x/document".into()),
                timestamp_chain: Vec::new(),
            },
            _ => Links::default(),
        };
        manifest.upsert(Artefact {
            path: PathBuf::from(format!("{id}.bin")),
            id,
            sha256: DIGEST.into(),
            kind,
            purpose: format!("Purpose with \"quotes\", a back\\slash, a tab\t, é and {index}."),
            expected_openssl: openssl[index % openssl.len()],
            expected_dss: dss[index % dss.len()].clone(),
            links,
            notes: (index % 2 == 0).then(|| "Line one.\nLine 'two'.".to_owned()),
            attack_class: None,
            dss_divergence: divergence(&dss[index % dss.len()], index),
        });
    }
    manifest.upsert(Artefact {
        id: "x/pades".into(),
        path: PathBuf::from("x/pades.pdf"),
        sha256: DIGEST.into(),
        kind: Kind::SignedDocument,
        purpose: "A PAdES variant.".into(),
        expected_openssl: OpensslResult::NotApplicable,
        expected_dss: DssResult::Indication {
            indication: Indication::TotalFailed,
            sub_indication: Some("FORMAT_FAILURE".into()),
        },
        links: Links::default(),
        notes: None,
        dss_divergence: None,
        attack_class: Some(AttackClass::SignatureWrapping),
    });
    Ok(manifest)
}

#[test]
fn writing_and_reading_a_manifest_gives_it_back() -> Result<(), ManifestError> {
    let manifest = varied_manifest()?;
    let text = manifest.to_toml();
    assert_eq!(Manifest::parse(&text)?, manifest);
    assert!(text.starts_with(
        "# Manifest of the test corpus. The format is described in README.md.\n\n[header]\nformat-version = 3\nvalidation-time = \"2030-01-15T10:00:00Z\"\n"
    ));
    assert!(
        manifest
            .artefacts
            .iter()
            .any(|a| a.dss_divergence.is_some())
    );
    let header_only = Manifest::parse(HEADER)?;
    assert_eq!(Manifest::parse(&header_only.to_toml())?, header_only);
    assert_eq!(header_only.to_toml().matches("[[artefact]]").count(), 0);
    Ok(())
}

#[test]
fn the_written_manifest_has_one_line_per_field() -> Result<(), ManifestError> {
    let text = Manifest::parse(&with_artefacts(&format!(
        "{ROOT}{}",
        leaf("notes = \"n\"\nlinks = { issuer = \"pki/root\", chain = [\"pki/root\"] }")
    )))?
    .to_toml();
    let expected = format!(
        "\n[[artefact]]\nid = \"pki/leaf\"\npath = \"pki/leaf.pem\"\nsha256 = \"{DIGEST}\"\nkind = \"certificate\"\npurpose = \"End entity\"\nexpected-openssl = \"verified\"\nexpected-dss = {{ indication = \"PASSED\" }}\nlinks = {{ issuer = \"pki/root\", chain = [\"pki/root\"] }}\nnotes = \"n\"\n"
    );
    assert!(text.ends_with(&expected), "{text}");
    let failed = Manifest::parse(&with_artefacts(&ROOT.replace(
        "{ indication = \"PASSED\" }",
        "{ indication = \"FAILED\", sub-indication = \"REVOKED\" }",
    )))?
    .to_toml();
    assert!(
        failed.contains(
            "\nexpected-dss = { indication = \"FAILED\", sub-indication = \"REVOKED\" }\n"
        )
    );
    Ok(())
}

#[test]
fn upsert_replaces_by_identifier_or_appends() -> Result<(), ManifestError> {
    let mut manifest = Manifest::parse(&with_artefacts(&format!("{ROOT}{}", leaf(""))))?;
    let mut root = manifest.artefacts[0].clone();
    root.purpose = "Replaced".into();
    manifest.upsert(root);
    assert_eq!(manifest.artefacts.len(), 2);
    assert_eq!(manifest.artefacts[0].purpose, "Replaced");
    assert_eq!(manifest.artefacts[1].id, "pki/leaf");
    let mut other = manifest.artefacts[1].clone();
    other.id = "pki/other".into();
    manifest.upsert(other);
    assert_eq!(manifest.artefacts.len(), 3);
    assert_eq!(manifest.artefacts[2].id, "pki/other");
    Ok(())
}

#[test]
fn kinds_and_results_are_written_as_read() -> Result<(), ManifestError> {
    for (kind, text) in [
        (Kind::Certificate, "certificate"),
        (Kind::PrivateKey, "private-key"),
        (Kind::Crl, "crl"),
        (Kind::OcspResponse, "ocsp-response"),
        (Kind::TimestampToken, "timestamp-token"),
        (Kind::SignedDocument, "signed-document"),
        (Kind::Document, "document"),
    ] {
        assert_eq!(kind.as_str(), text);
    }
    for (result, text) in [
        (OpensslResult::Verified, "verified"),
        (OpensslResult::Parsed, "parsed"),
        (OpensslResult::Rejected, "rejected"),
        (OpensslResult::NotApplicable, "not-applicable"),
    ] {
        assert_eq!(result.as_str(), text);
    }
    Ok(())
}

proptest::proptest! {
    /// Any purpose and notes, including quotes, backslashes, control
    /// characters and non-ASCII text, survive writing and reading back.
    #[test]
    fn written_text_fields_read_back_unchanged(
        purpose in "[\"'\\\\\n\r\t a-zé€😀\u{7f}\u{1}]*[a-z]",
        notes in proptest::option::of("[\"'\\\\\n\r\t a-zé€😀\u{7f}\u{1}]*[a-z]"),
        sub in proptest::option::of(proptest::sample::select(INDETERMINATE_SUB_INDICATIONS.to_vec())),
    ) {
        let mut manifest = Manifest::parse(&with_artefacts(ROOT))
            .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
        let mut artefact = manifest.artefacts[0].clone();
        artefact.purpose = purpose;
        artefact.notes = notes;
        artefact.expected_dss = DssResult::Indication {
            indication: Indication::Indeterminate,
            sub_indication: sub.map(str::to_owned),
        };
        manifest.upsert(artefact);
        let read = Manifest::parse(&manifest.to_toml())
            .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
        proptest::prop_assert_eq!(read, manifest);
    }
}

#[test]
fn a_dss_result_is_written_in_words() {
    assert_eq!(DssResult::Rejected.to_string(), "rejected");
    assert_eq!(DssResult::NotApplicable.to_string(), "not-applicable");
    assert_eq!(
        DssResult::Indication {
            indication: Indication::TotalPassed,
            sub_indication: None
        }
        .to_string(),
        "TOTAL-PASSED"
    );
    assert_eq!(
        DssResult::Indication {
            indication: Indication::Indeterminate,
            sub_indication: Some("REVOKED_NO_POE".to_owned())
        }
        .to_string(),
        "INDETERMINATE with REVOKED_NO_POE"
    );
}

// The field dss-divergence, added in format version 2.

const DIVERGENT: &str = r#"dss-divergence = { entry = "DIV-5", indication = "INDETERMINATE", sub-indication = "OUT_OF_BOUNDS_NOT_REVOKED" }"#;

#[test]
fn parses_a_dss_divergence() -> Result<(), ManifestError> {
    let manifest = Manifest::parse(&with_artefacts(&format!("{ROOT}{DIVERGENT}\n")))?;
    let divergence = Divergence {
        entry: "DIV-5".into(),
        indication: Indication::Indeterminate,
        sub_indication: Some("OUT_OF_BOUNDS_NOT_REVOKED".into()),
    };
    assert_eq!(
        manifest.artefacts[0].dss_divergence,
        Some(divergence.clone())
    );
    assert_eq!(
        divergence.result(),
        DssResult::Indication {
            indication: Indication::Indeterminate,
            sub_indication: Some("OUT_OF_BOUNDS_NOT_REVOKED".into()),
        }
    );
    let without = Manifest::parse(&with_artefacts(&format!(
        "{ROOT}dss-divergence = {{ entry = \"DIV-12\", indication = \"FAILED\" }}\n"
    )))?;
    assert_eq!(
        without.artefacts[0].dss_divergence,
        Some(Divergence {
            entry: "DIV-12".into(),
            indication: Indication::Failed,
            sub_indication: None,
        })
    );
    Ok(())
}

#[test]
fn writes_a_dss_divergence_after_the_expected_result() -> Result<(), ManifestError> {
    let text = Manifest::parse(&with_artefacts(&format!(
        "{ROOT}notes = \"n\"\n{DIVERGENT}\n"
    )))?
    .to_toml();
    let expected =
        format!("expected-dss = {{ indication = \"PASSED\" }}\n{DIVERGENT}\nnotes = \"n\"\n");
    assert!(text.ends_with(&expected), "{text}");
    let without = Manifest::parse(&with_artefacts(&format!(
        "{ROOT}dss-divergence = {{ entry = \"DIV-1\", indication = \"FAILED\" }}\n"
    )))?
    .to_toml();
    assert!(
        without.ends_with("\ndss-divergence = { entry = \"DIV-1\", indication = \"FAILED\" }\n"),
        "{without}"
    );
    Ok(())
}

#[test]
fn rejects_a_divergence_entry_that_is_not_a_div_number() {
    for entry in [
        "", "DIV-", "DIV-x", "div-5", "DIV-05", "DIV-0", "DIV-5a", " DIV-5", "DIV--5", "DIV-٥",
    ] {
        let text = with_artefacts(&format!(
            "{ROOT}dss-divergence = {{ entry = \"{entry}\", indication = \"FAILED\" }}\n"
        ));
        assert_eq!(
            parse_err(&text),
            Some(ManifestError::InvalidDivergenceEntry {
                id: "pki/root".into(),
                value: entry.into(),
            }),
            "{entry:?}"
        );
    }
}

#[test]
fn rejects_a_divergence_sub_indication_of_another_indication() {
    let text = with_artefacts(&format!(
        "{ROOT}dss-divergence = {{ entry = \"DIV-5\", indication = \"FAILED\", sub-indication = \"NO_POE\" }}\n"
    ));
    assert_eq!(
        parse_err(&text),
        Some(ManifestError::InvalidSubIndication {
            id: "pki/root".into(),
            indication: "FAILED",
            value: "NO_POE".into(),
        })
    );
    let passed = with_artefacts(&format!(
        "{ROOT}dss-divergence = {{ entry = \"DIV-5\", indication = \"TOTAL-PASSED\", sub-indication = \"CUSTOM\" }}\n"
    ));
    assert!(matches!(
        parse_err(&passed),
        Some(ManifestError::InvalidSubIndication { .. })
    ));
}

#[test]
fn rejects_a_divergence_that_gives_the_predicted_result() {
    let text = with_artefacts(&format!(
        "{ROOT}dss-divergence = {{ entry = \"DIV-5\", indication = \"PASSED\" }}\n"
    ));
    assert_eq!(
        parse_err(&text),
        Some(ManifestError::StaleDivergence {
            id: "pki/root".into()
        })
    );
    // Another sub-indication, or none, is another result.
    let predicted = ROOT.replace(
        "{ indication = \"PASSED\" }",
        "{ indication = \"INDETERMINATE\", sub-indication = \"NO_POE\" }",
    );
    for divergence in [
        "{ entry = \"DIV-5\", indication = \"INDETERMINATE\", sub-indication = \"CUSTOM\" }",
        "{ entry = \"DIV-5\", indication = \"INDETERMINATE\" }",
    ] {
        let text = with_artefacts(&format!("{predicted}dss-divergence = {divergence}\n"));
        assert!(Manifest::parse(&text).is_ok(), "{divergence}");
    }
    let same = with_artefacts(&format!(
        "{predicted}dss-divergence = {{ entry = \"DIV-5\", indication = \"INDETERMINATE\", sub-indication = \"NO_POE\" }}\n"
    ));
    assert!(matches!(
        parse_err(&same),
        Some(ManifestError::StaleDivergence { .. })
    ));
}

#[test]
fn rejects_a_divergence_of_an_artefact_that_dss_does_not_process() {
    let text = with_artefacts(&format!(
        "{}dss-divergence = {{ entry = \"DIV-5\", indication = \"PASSED\" }}\n",
        ROOT.replace("{ indication = \"PASSED\" }", "\"not-applicable\"")
    ));
    assert_eq!(
        parse_err(&text),
        Some(ManifestError::DivergenceNotApplicable {
            id: "pki/root".into()
        })
    );
    // A divergence from a predicted rejection is a divergence.
    let rejected = with_artefacts(&format!(
        "{}dss-divergence = {{ entry = \"DIV-5\", indication = \"PASSED\" }}\n",
        ROOT.replace("{ indication = \"PASSED\" }", "\"rejected\"")
    ));
    assert!(Manifest::parse(&rejected).is_ok());
}

#[test]
fn rejects_a_malformed_divergence_table() {
    for table in [
        "{ indication = \"FAILED\" }",
        "{ entry = \"DIV-5\" }",
        "{ entry = \"DIV-5\", indication = \"FAILED\", colour = \"red\" }",
        "{ entry = \"DIV-5\", indication = \"GOOD\" }",
        "{ entry = 5, indication = \"FAILED\" }",
        "\"DIV-5\"",
        "\"rejected\"",
    ] {
        let text = with_artefacts(&format!("{ROOT}dss-divergence = {table}\n"));
        assert!(is_syntax(parse_err(&text)), "{table}");
    }
}

#[test]
fn divergence_errors_name_the_artefact_and_the_field() {
    let entry = ManifestError::InvalidDivergenceEntry {
        id: "pki/root".into(),
        value: "DIV-x".into(),
    };
    assert_eq!(
        entry.to_string(),
        "the dss-divergence entry \"DIV-x\" of \"pki/root\" is not of the form DIV-<number>"
    );
    assert_eq!(
        ManifestError::StaleDivergence {
            id: "pki/root".into()
        }
        .to_string(),
        "the dss-divergence of \"pki/root\" gives the result that expected-dss predicts, so it records no divergence"
    );
    assert_eq!(
        ManifestError::DivergenceNotApplicable {
            id: "pki/root".into()
        }
        .to_string(),
        "\"pki/root\" has a dss-divergence, but its expected-dss is not-applicable"
    );
}

/// The committed manifest records at least one divergence, and reads
/// every `dss-divergence` line that it holds. The divergences themselves
/// are listed in the manifest only.
#[test]
fn the_committed_manifest_reads_every_divergence_it_holds() -> Result<(), ManifestError> {
    let text = include_str!("../../../../testdata/manifest.toml");
    let manifest = Manifest::parse(text)?;
    let read = manifest
        .artefacts
        .iter()
        .filter(|a| a.dss_divergence.is_some())
        .count();
    let lines = text
        .lines()
        .filter(|line| line.starts_with("dss-divergence = "))
        .count();
    assert!(read > 0, "the manifest records no divergence");
    assert_eq!(read, lines);
    Ok(())
}

proptest::proptest! {
    /// Any divergence entry and result survives writing and reading back.
    #[test]
    fn written_divergences_read_back_unchanged(
        number in 1u32..100_000,
        sub in proptest::option::of(proptest::sample::select(INDETERMINATE_SUB_INDICATIONS.to_vec())),
    ) {
        let mut manifest = Manifest::parse(&with_artefacts(ROOT))
            .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
        let mut artefact = manifest.artefacts[0].clone();
        artefact.dss_divergence = Some(Divergence {
            entry: format!("DIV-{number}"),
            indication: Indication::Indeterminate,
            sub_indication: sub.map(str::to_owned),
        });
        manifest.upsert(artefact);
        let read = Manifest::parse(&manifest.to_toml())
            .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
        proptest::prop_assert_eq!(read, manifest);
    }
}

// The field attack-class, added in format version 3, which the PAdES
// variants under mutations/ carry; these tests build their own entries.

/// A signed document `id` at `path`, with the given extra lines.
fn signed_document(id: &str, path: &str, extra: &str) -> String {
    format!(
        r#"
[[artefact]]
id = "{id}"
path = "{path}"
sha256 = "{DIGEST}"
kind = "signed-document"
purpose = "A signed document"
expected-openssl = "not-applicable"
expected-dss = {{ indication = "TOTAL-PASSED" }}
{extra}
"#
    )
}

#[test]
fn parses_every_attack_class_of_a_pades_document() -> Result<(), ManifestError> {
    let classes = [
        (AttackClass::IncrementalSaving, "incremental-saving"),
        (AttackClass::ShadowHide, "shadow-hide"),
        (AttackClass::ShadowReplace, "shadow-replace"),
        (AttackClass::ShadowHideAndReplace, "shadow-hide-and-replace"),
        (AttackClass::SignatureWrapping, "signature-wrapping"),
        (
            AttackClass::UniversalSignatureForgery,
            "universal-signature-forgery",
        ),
    ];
    assert_eq!(AttackClass::ALL, classes.map(|(class, _)| class));
    for (class, text) in classes {
        assert_eq!(class.as_str(), text);
        let line = format!("attack-class = \"{text}\"");
        let manifest = Manifest::parse(&with_artefacts(&signed_document("m/a", "m/a.pdf", &line)))?;
        assert_eq!(manifest.artefacts[0].attack_class, Some(class));
    }
    // The extension is compared ignoring letter case.
    let upper = Manifest::parse(&with_artefacts(&signed_document(
        "m/a",
        "m/a.PDF",
        "attack-class = \"shadow-hide\"",
    )))?;
    assert_eq!(
        upper.artefacts[0].attack_class,
        Some(AttackClass::ShadowHide)
    );
    // The field is optional, also on a PAdES document.
    let none = Manifest::parse(&with_artefacts(&signed_document("m/a", "m/a.pdf", "")))?;
    assert_eq!(none.artefacts[0].attack_class, None);
    Ok(())
}

#[test]
fn rejects_an_attack_class_outside_pades_signed_documents() {
    let line = "attack-class = \"incremental-saving\"";
    let not_allowed = Some(ManifestError::AttackClassNotAllowed("m/a".into()));
    for path in [
        "m/a.p7m",
        "m/a.p7s",
        "m/a.jws",
        "m/a.json",
        "m/pdf",
        "m/a.pdf.p7s",
        "m/a_pdf",
    ] {
        assert_eq!(
            parse_err(&with_artefacts(&signed_document("m/a", path, line))),
            not_allowed,
            "{path}"
        );
    }
    for kind in ["document", "certificate", "crl", "timestamp-token"] {
        let text = with_artefacts(&signed_document("m/a", "m/a.pdf", line))
            .replace("\"signed-document\"", &format!("\"{kind}\""))
            .replace("{ indication = \"TOTAL-PASSED\" }", "\"not-applicable\"");
        assert_eq!(parse_err(&text), not_allowed, "{kind}");
    }
}

#[test]
fn rejects_unknown_attack_classes() {
    for value in [
        "\"shadow\"",
        "\"\"",
        "\"Incremental-Saving\"",
        "\"incremental_saving\"",
        "1",
    ] {
        let line = format!("attack-class = {value}");
        let text = with_artefacts(&signed_document("m/a", "m/a.pdf", &line));
        assert!(is_syntax(parse_err(&text)), "{value}");
    }
}

#[test]
fn the_attack_class_is_written_after_the_dss_result() -> Result<(), ManifestError> {
    let text = with_artefacts(&format!(
        "{ROOT}{}",
        signed_document(
            "m/a",
            "m/a.pdf",
            "attack-class = \"signature-wrapping\"\nlinks = { issuer = \"pki/root\", chain = [\"pki/root\"] }",
        )
    ));
    let manifest = Manifest::parse(&text)?;
    let written = manifest.to_toml();
    assert!(
        written.contains(
            "\nexpected-dss = { indication = \"TOTAL-PASSED\" }\nattack-class = \"signature-wrapping\"\nlinks = { issuer = \"pki/root\", chain = [\"pki/root\"] }\n"
        ),
        "{written}"
    );
    assert_eq!(written.matches("attack-class").count(), 1);
    assert_eq!(Manifest::parse(&written)?, manifest);
    // After a divergence, when both are present.
    let both = with_artefacts(&signed_document(
        "m/a",
        "m/a.pdf",
        "dss-divergence = { entry = \"DIV-9\", indication = \"TOTAL-FAILED\" }\nattack-class = \"shadow-hide\"",
    ));
    let written = Manifest::parse(&both)?.to_toml();
    assert!(
        written.contains(
            "\ndss-divergence = { entry = \"DIV-9\", indication = \"TOTAL-FAILED\" }\nattack-class = \"shadow-hide\"\n"
        ),
        "{written}"
    );
    Ok(())
}
