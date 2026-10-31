use std::path::PathBuf;

use base64ct::{Base64UrlUnpadded, Encoding};

use super::*;
use crate::manifest::{AttackClass, DssResult, Indication, Kind, OpensslResult};
use crate::openssl::Scratch;
use crate::pki::sha256_hex;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

fn committed_manifest() -> Result<Manifest, Box<dyn std::error::Error>> {
    Ok(Manifest::load(&testdata().join("manifest.toml"))?)
}

fn source_bytes(mutation: Mutation) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let manifest = committed_manifest()?;
    let entry = manifest
        .artefacts
        .iter()
        .find(|a| a.id == mutation.source())
        .ok_or("no source")?;
    Ok(std::fs::read(testdata().join(&entry.path))?)
}

/// The protected header as text, the payload and the signature, as encoded.
type Parts = (String, Vec<u8>, Vec<u8>);

/// The three parts of a compact JWS, with the protected header decoded.
fn jws_parts(jws: &[u8]) -> Result<Parts, Box<dyn std::error::Error>> {
    let text = std::str::from_utf8(jws)?;
    let parts: Vec<&str> = text.split('.').collect();
    assert_eq!(parts.len(), 3, "{text}");
    Ok((
        String::from_utf8(Base64UrlUnpadded::decode_vec(parts[0])?)?,
        parts[1].as_bytes().to_vec(),
        parts[2].as_bytes().to_vec(),
    ))
}

fn compact(header: &str, rest: &str) -> Vec<u8> {
    format!(
        "{}.{rest}",
        Base64UrlUnpadded::encode_string(header.as_bytes())
    )
    .into_bytes()
}

const SIGNING_TIME: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05,
];

/// A signing-time attribute with the time `time`, as UTCTime when it has
/// 13 characters and as GeneralizedTime when it has 15.
fn signing_time(time: &str) -> Vec<u8> {
    let tag = if time.len() == 13 { 0x17 } else { 0x18 };
    let mut set = vec![tag, u8::try_from(time.len()).unwrap_or(0)];
    set.extend_from_slice(time.as_bytes());
    let mut attribute = SIGNING_TIME.to_vec();
    attribute.push(0x31);
    attribute.push(u8::try_from(set.len()).unwrap_or(0));
    attribute.extend(set);
    let mut out = vec![0x30, u8::try_from(attribute.len()).unwrap_or(0)];
    out.extend(attribute);
    out
}

#[test]
fn the_variants_and_their_sources() {
    let plan: Vec<(String, PathBuf, &str)> = MUTATIONS
        .iter()
        .map(|m| (m.id(), m.path(), m.source()))
        .collect();
    assert_eq!(
        plan,
        [
            (
                "mutations/cades-modified-signed-attribute".to_owned(),
                PathBuf::from("mutations/cades-modified-signed-attribute.p7m"),
                "signed/cades-enveloping-b-b-p256",
            ),
            (
                "mutations/cades-modified-content".to_owned(),
                PathBuf::from("mutations/cades-modified-content.p7m"),
                "signed/cades-enveloping-b-b-p256",
            ),
            (
                "mutations/jades-tampered-header".to_owned(),
                PathBuf::from("mutations/jades-tampered-header.jws"),
                "signed/jades-compact-b-b-p256",
            ),
            (
                "mutations/jades-duplicate-header-parameter".to_owned(),
                PathBuf::from("mutations/jades-duplicate-header-parameter.jws"),
                "signed/jades-compact-b-b-p256",
            ),
            (
                "mutations/pades-incremental-update".to_owned(),
                PathBuf::from("mutations/pades-incremental-update.pdf"),
                "signed/pades-b-b-p256",
            ),
            (
                "mutations/pades-shadow-hide".to_owned(),
                PathBuf::from("mutations/pades-shadow-hide.pdf"),
                "signed/pades-shadow-hide-b-b-p256",
            ),
            (
                "mutations/pades-shadow-replace".to_owned(),
                PathBuf::from("mutations/pades-shadow-replace.pdf"),
                "signed/pades-shadow-replace-b-b-p256",
            ),
            (
                "mutations/pades-shadow-hide-and-replace".to_owned(),
                PathBuf::from("mutations/pades-shadow-hide-and-replace.pdf"),
                "signed/pades-shadow-hide-and-replace-b-b-p256",
            ),
            (
                "mutations/pades-partial-byte-range".to_owned(),
                PathBuf::from("mutations/pades-partial-byte-range.pdf"),
                "signed/pades-b-b-p256",
            ),
        ]
    );
}

#[test]
fn the_signing_time_moves_forward_by_one_second() -> TestResult {
    let source = source_bytes(Mutation::CadesModifiedSignedAttribute)?;
    let changed = modify_signing_time(&source)?;
    assert_eq!(changed.len(), source.len());
    let differing: Vec<usize> = (0..source.len())
        .filter(|&i| source[i] != changed[i])
        .collect();
    assert_eq!(differing.len(), 1);
    let at = source
        .windows(SIGNING_TIME.len())
        .position(|w| w == SIGNING_TIME)
        .ok_or("no signing time")?;
    // OID, SET header, UTCTime header, then 13 characters.
    let time = at + SIGNING_TIME.len() + 4;
    assert_eq!(&source[time..time + 13], b"291216100000Z");
    assert_eq!(&changed[time..time + 13], b"291216100001Z");
    assert_eq!(
        Mutation::CadesModifiedSignedAttribute.apply(&source)?,
        changed
    );
    Ok(())
}

#[test]
fn the_signing_time_changes_in_either_time_type() -> TestResult {
    let utc = signing_time("291216100009Z");
    assert_eq!(modify_signing_time(&utc)?, signing_time("291216100008Z"));
    let generalized = signing_time("20291216100030Z");
    assert_eq!(
        modify_signing_time(&generalized)?,
        signing_time("20291216100031Z")
    );
    Ok(())
}

#[test]
fn a_cms_without_one_well_formed_signing_time_is_refused() {
    let mut twice = signing_time("291216100000Z");
    twice.extend(signing_time("291216100000Z"));
    let mut set_tag = signing_time("291216100000Z");
    set_tag[13] = 0x0e;
    let mut set_length = signing_time("291216100000Z");
    set_length[14] = 0x04;
    let mut time_tag = signing_time("291216100000Z");
    time_tag[15] = 0x04;
    let mut time_length = signing_time("291216100000Z");
    time_length[16] = 0x0c;
    let mut truncated = signing_time("291216100000Z");
    truncated.truncate(truncated.len() - 3);
    let cases: [(&str, Vec<u8>); 10] = [
        ("empty", Vec::new()),
        ("no attribute", b"0123456789".to_vec()),
        ("twice", twice),
        ("set tag", set_tag),
        ("set length", set_length),
        ("time tag", time_tag),
        ("time length", time_length),
        ("truncated", truncated),
        ("not digits", signing_time("29121610000AZ")),
        ("no Z", signing_time("2912161000001")),
    ];
    for (name, input) in cases {
        assert!(modify_signing_time(&input).is_err(), "{name}");
    }
    assert!(modify_signing_time(&SIGNING_TIME).is_err());
}

#[test]
fn the_tampered_header_has_iat_one_second_later() -> TestResult {
    let source = source_bytes(Mutation::JadesTamperedHeader)?;
    let tampered = tamper_protected_header(&source)?;
    let (header, payload, signature) = jws_parts(&source)?;
    let (new_header, new_payload, new_signature) = jws_parts(&tampered)?;
    assert_eq!(new_payload, payload);
    assert_eq!(new_signature, signature);
    assert!(header.contains("\"iat\":1892109600"), "{header}");
    assert_eq!(
        new_header,
        header.replace("\"iat\":1892109600", "\"iat\":1892109601")
    );
    let parsed: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&new_header)?;
    assert_eq!(parsed.get("iat"), Some(&serde_json::json!(1_892_109_601)));
    assert_eq!(Mutation::JadesTamperedHeader.apply(&source)?, tampered);
    Ok(())
}

#[test]
fn the_duplicated_parameter_is_iat_a_day_later() -> TestResult {
    let source = source_bytes(Mutation::JadesDuplicateHeaderParameter)?;
    let duplicated = duplicate_protected_header_parameter(&source)?;
    let (header, payload, signature) = jws_parts(&source)?;
    let (new_header, new_payload, new_signature) = jws_parts(&duplicated)?;
    assert_eq!(new_payload, payload);
    assert_eq!(new_signature, signature);
    let stem = header.strip_suffix('}').ok_or("no closing brace")?;
    assert_eq!(new_header, format!("{stem},\"iat\":1892196000}}"));
    assert_eq!(new_header.matches("\"iat\":").count(), 2);
    assert_eq!(
        Mutation::JadesDuplicateHeaderParameter.apply(&source)?,
        duplicated
    );
    Ok(())
}

#[test]
fn small_headers_are_mutated_in_place() -> TestResult {
    let jws = compact("{\"alg\":\"ES256\",\"iat\":9}", "cA.c2ln");
    assert_eq!(
        tamper_protected_header(&jws)?,
        compact("{\"alg\":\"ES256\",\"iat\":10}", "cA.c2ln")
    );
    assert_eq!(
        duplicate_protected_header_parameter(&jws)?,
        compact("{\"alg\":\"ES256\",\"iat\":9,\"iat\":86409}", "cA.c2ln")
    );
    // iat may be the first member and followed by others.
    let first = compact("{\"iat\":1,\"alg\":\"ES256\"}", "cA.c2ln");
    assert_eq!(
        tamper_protected_header(&first)?,
        compact("{\"iat\":2,\"alg\":\"ES256\"}", "cA.c2ln")
    );
    Ok(())
}

#[test]
fn a_jws_without_one_integer_iat_in_a_compact_header_is_refused() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("two parts", b"eyJhIjoxfQ.cA".to_vec()),
        ("four parts", compact("{\"iat\":1}", "cA.c2ln.eA")),
        ("empty payload", compact("{\"iat\":1}", ".c2ln")),
        ("empty signature", compact("{\"iat\":1}", "cA.")),
        ("empty header", b".cA.c2ln".to_vec()),
        ("padded", b"eyJpYXQiOjF9==.cA.c2ln".to_vec()),
        ("not base64url", b"eyJpYXQiOjF9+.cA.c2ln".to_vec()),
        ("not utf-8", b"\xff.cA.c2ln".to_vec()),
        ("not json", compact("{\"iat\":1", "cA.c2ln")),
        ("array", compact("[1]", "cA.c2ln")),
        ("no iat", compact("{\"alg\":\"ES256\"}", "cA.c2ln")),
        ("iat twice", compact("{\"iat\":1,\"iat\":2}", "cA.c2ln")),
        ("iat text", compact("{\"iat\":\"1\"}", "cA.c2ln")),
        ("iat negative", compact("{\"iat\":-1}", "cA.c2ln")),
        ("iat fraction", compact("{\"iat\":1.5}", "cA.c2ln")),
        ("iat nested", compact("{\"x\":{\"iat\":1}}", "cA.c2ln")),
        (
            "iat too large",
            compact("{\"iat\":18446744073709551615}", "cA.c2ln"),
        ),
        ("white space", compact("{\"iat\":1} ", "cA.c2ln")),
    ];
    for (name, input) in cases {
        assert!(tamper_protected_header(&input).is_err(), "tamper: {name}");
        assert!(
            duplicate_protected_header_parameter(&input).is_err(),
            "duplicate: {name}"
        );
    }
}

fn passed() -> DssResult {
    DssResult::Indication {
        indication: Indication::TotalPassed,
        sub_indication: None,
    }
}

#[test]
fn the_pades_variants_carry_the_attack_classes_of_the_threat_model() {
    let classes: Vec<(Mutation, Option<AttackClass>)> =
        MUTATIONS.iter().map(|m| (*m, m.attack_class())).collect();
    assert_eq!(
        classes,
        [
            (Mutation::CadesModifiedSignedAttribute, None),
            (Mutation::CadesModifiedContent, None),
            (Mutation::JadesTamperedHeader, None),
            (Mutation::JadesDuplicateHeaderParameter, None),
            (
                Mutation::PadesIncrementalUpdate,
                Some(AttackClass::IncrementalSaving)
            ),
            (Mutation::PadesShadowHide, Some(AttackClass::ShadowHide)),
            (
                Mutation::PadesShadowReplace,
                Some(AttackClass::ShadowReplace)
            ),
            (
                Mutation::PadesShadowHideAndReplace,
                Some(AttackClass::ShadowHideAndReplace)
            ),
            (
                Mutation::PadesPartialByteRange,
                Some(AttackClass::SignatureWrapping)
            ),
        ]
    );
}

#[test]
fn each_variant_records_its_expected_results() -> TestResult {
    let manifest = committed_manifest()?;
    for mutation in MUTATIONS {
        let source = manifest
            .artefacts
            .iter()
            .find(|a| a.id == mutation.source())
            .ok_or("no source")?;
        let entry = mutation.artefact(source, b"contents");
        let bytes = std::fs::read(testdata().join(&source.path))?;
        assert_eq!(entry.id, mutation.id());
        assert_eq!(entry.path, mutation.path());
        assert_eq!(entry.sha256, sha256_hex(b"contents"));
        assert_eq!(entry.kind, Kind::SignedDocument);
        assert_eq!(entry.links, source.links);
        assert_eq!(entry.attack_class, mutation.attack_class());
        assert!(
            entry.purpose.contains(mutation.source()),
            "{}",
            entry.purpose
        );
        let notes = entry.notes.clone().ok_or("no notes")?;
        assert!(notes.contains("DSS 6.5.1"), "{notes}");
        let failed = |sub: &str| DssResult::Indication {
            indication: Indication::TotalFailed,
            sub_indication: Some(sub.to_owned()),
        };
        match mutation {
            Mutation::CadesModifiedSignedAttribute => {
                assert_eq!(entry.expected_openssl, OpensslResult::Rejected);
                assert_eq!(entry.expected_dss, failed("SIG_CRYPTO_FAILURE"));
                assert_eq!(entry.dss_divergence, None);
                // The times in the notes are those of the source and of the variant.
                let at = bytes
                    .windows(SIGNING_TIME.len())
                    .position(|w| w == SIGNING_TIME)
                    .ok_or("no signing time")?
                    + SIGNING_TIME.len()
                    + 4;
                let changed = mutation.apply(&bytes)?;
                let times = format!(
                    "{} instead of {}",
                    std::str::from_utf8(&changed[at..at + 13])?,
                    std::str::from_utf8(&bytes[at..at + 13])?
                );
                assert!(notes.contains(&times), "{notes}");
                assert!(notes.contains("clause 5.3.4, step 5"), "{notes}");
                assert!(notes.contains("clause 5.2.7.4"), "{notes}");
            }
            Mutation::CadesModifiedContent => {
                assert_eq!(entry.expected_openssl, OpensslResult::Rejected);
                assert_eq!(entry.expected_dss, failed("HASH_FAILURE"));
                assert_eq!(entry.dss_divergence, None);
                assert!(notes.contains("message-digest"), "{notes}");
                assert!(notes.contains("clause 5.3.4, step 5"), "{notes}");
                assert!(notes.contains("clause 5.2.7.3, Table 15"), "{notes}");
            }
            Mutation::JadesTamperedHeader => {
                assert_eq!(entry.expected_openssl, OpensslResult::NotApplicable);
                assert_eq!(entry.expected_dss, failed("SIG_CRYPTO_FAILURE"));
                let divergence = entry.dss_divergence.clone().ok_or("no divergence")?;
                assert_eq!(divergence.entry, "DIV-6");
                assert_eq!(divergence.result(), failed("HASH_FAILURE"));
                assert!(notes.contains("DIV-6"), "{notes}");
                assert!(notes.contains("clause 5.3.4, step 5"), "{notes}");
                let iat = source_iat(&bytes)?;
                assert!(
                    notes.contains(&format!("iat {} instead of {iat}", iat + 1)),
                    "{notes}"
                );
                assert!(notes.contains("clause 5.2.7.3, Table 15"), "{notes}");
                assert!(notes.contains("not to ETSI TS 119 182-1"), "{notes}");
            }
            Mutation::JadesDuplicateHeaderParameter => {
                assert_eq!(entry.expected_openssl, OpensslResult::NotApplicable);
                assert_eq!(entry.expected_dss, DssResult::Rejected);
                assert_eq!(entry.dss_divergence, None);
                assert!(notes.contains("RFC 7515, section 4"), "{notes}");
                assert!(notes.contains("does not show"), "{notes}");
                let iat = source_iat(&bytes)?;
                assert!(
                    notes.contains(&format!("twice, {iat} and then {}", iat + 86_400)),
                    "{notes}"
                );
                assert!(notes.contains("rejects them under ADR-0016"), "{notes}");
            }
            Mutation::PadesIncrementalUpdate => {
                // The decision recorded on issue #32: the result of DSS 6.5.1,
                // with the divergence of sigillum in divergences.md.
                assert_eq!(entry.expected_openssl, OpensslResult::NotApplicable);
                assert_eq!(entry.expected_dss, passed());
                assert_eq!(entry.dss_divergence, None);
                assert_eq!(entry.attack_class, Some(AttackClass::IncrementalSaving));
                assert!(notes.contains("DIV-7"), "{notes}");
                assert!(notes.contains("BBB_FC_DSCNUOM_ANS"), "{notes}");
                assert!(notes.contains("clause 7.5.6"), "{notes}");
            }
            Mutation::PadesShadowHide
            | Mutation::PadesShadowReplace
            | Mutation::PadesShadowHideAndReplace => {
                assert_eq!(entry.expected_openssl, OpensslResult::NotApplicable);
                assert_eq!(entry.expected_dss, passed());
                assert_eq!(entry.dss_divergence, None);
                assert!(notes.contains("clause 7.5.6"), "{notes}");
                assert!(notes.contains("NDSS 2021"), "{notes}");
                assert!(notes.contains("BBB_FC_IVDBSFR_ANS"), "{notes}");
            }
            Mutation::PadesPartialByteRange => {
                assert_eq!(entry.expected_openssl, OpensslResult::NotApplicable);
                assert_eq!(entry.expected_dss, failed("FORMAT_FAILURE"));
                assert_eq!(entry.dss_divergence, None);
                assert_eq!(entry.attack_class, Some(AttackClass::SignatureWrapping));
                assert!(notes.contains("clause 6.3"), "{notes}");
                assert!(notes.contains("ETSI EN 319 142-1 V1.2.1"), "{notes}");
                assert!(notes.contains("clause 12.8.1"), "{notes}");
                assert!(notes.contains("BBB_FC_IBRV_ANS"), "{notes}");
                // The basis of the prediction, and why DSS reports the data
                // not intact although the bytes covered are those signed.
                assert!(notes.contains("clause 5.2.2.1, NOTE"), "{notes}");
                assert!(notes.contains("BBB_CV_IRDOI_ANS"), "{notes}");
                assert!(notes.contains("empty signed content"), "{notes}");
                assert!(!notes.contains("still verify"), "{notes}");
                assert!(notes.contains("the only bytes changed"), "{notes}");
            }
        }
        // The entry is valid in the manifest.
        let mut with = manifest.clone();
        with.upsert(entry);
        Manifest::parse(&with.to_toml())?;
    }
    Ok(())
}

#[test]
fn generate_derives_every_variant_from_the_committed_corpus() -> TestResult {
    let manifest = committed_manifest()?;
    let files = generate(&testdata(), &manifest)?;
    assert_eq!(files.len(), MUTATIONS.len());
    for (file, mutation) in files.iter().zip(MUTATIONS) {
        assert_eq!(file.artefact.id, mutation.id());
        assert_eq!(file.contents, mutation.apply(&source_bytes(mutation)?)?);
        assert_eq!(file.artefact.sha256, sha256_hex(&file.contents));
    }
    assert_eq!(generate(&testdata(), &manifest)?, files);
    Ok(())
}

/// A corpus under a scratch directory with the committed manifest and the
/// sources of the variants.
fn scratch_corpus() -> Result<(Scratch, PathBuf), Box<dyn std::error::Error>> {
    let scratch = Scratch::create()?;
    let root = scratch.path().to_path_buf();
    std::fs::copy(testdata().join("manifest.toml"), root.join("manifest.toml"))?;
    std::fs::create_dir_all(root.join("signed"))?;
    let manifest = committed_manifest()?;
    for mutation in MUTATIONS {
        let entry = manifest
            .artefacts
            .iter()
            .find(|a| a.id == mutation.source())
            .ok_or("no source")?;
        std::fs::copy(testdata().join(&entry.path), root.join(&entry.path))?;
    }
    Ok((scratch, root))
}

#[test]
fn generate_reports_a_missing_unreadable_changed_or_unsuitable_source() -> TestResult {
    let (_scratch, root) = scratch_corpus()?;
    let manifest = committed_manifest()?;
    let mut without = manifest.clone();
    without
        .artefacts
        .retain(|a| a.id != "signed/jades-compact-b-b-p256");
    assert_eq!(
        generate(&root, &without),
        Err(MutationError::NotInManifest(
            "signed/jades-compact-b-b-p256".to_owned()
        ))
    );
    let jws = root.join("signed/jades-compact-b-b-p256.jws");
    std::fs::write(&jws, b"changed")?;
    assert_eq!(
        generate(&root, &manifest),
        Err(MutationError::DigestMismatch(
            "signed/jades-compact-b-b-p256".to_owned()
        ))
    );
    // A source whose entry records it, but which the mutation cannot change.
    let mut unsuitable = manifest.clone();
    for artefact in &mut unsuitable.artefacts {
        if artefact.id == "signed/jades-compact-b-b-p256" {
            artefact.sha256 = sha256_hex(b"changed");
        }
    }
    assert!(matches!(
        generate(&root, &unsuitable),
        Err(MutationError::Mutation { id, .. }) if id == "mutations/jades-tampered-header"
    ));
    std::fs::remove_file(&jws)?;
    assert!(matches!(
        generate(&root, &manifest),
        Err(MutationError::Io(message)) if message.contains("jades-compact-b-b-p256")
    ));
    Ok(())
}

#[test]
fn write_into_corpus_records_the_variants_and_keeps_other_entries() -> TestResult {
    let (_scratch, root) = scratch_corpus()?;
    let path = root.join("manifest.toml");
    let mut stale = committed_manifest()?;
    stale.artefacts.retain(|a| !a.id.starts_with("mutations/"));
    let mut old = stale.artefacts[0].clone();
    old.id = "mutations/stale".to_owned();
    old.path = PathBuf::from("mutations/stale.p7m");
    stale.artefacts.push(old);
    std::fs::write(&path, stale.to_toml())?;
    let summary = write_into_corpus(&path)?;
    assert_eq!(summary.written, MUTATIONS.len());
    assert_eq!(summary.removed, ["mutations/stale"]);
    let written = Manifest::load(&path)?;
    for mutation in MUTATIONS {
        let entry = written
            .artefacts
            .iter()
            .find(|a| a.id == mutation.id())
            .ok_or("not recorded")?;
        assert_eq!(
            entry.sha256,
            sha256_hex(&std::fs::read(root.join(mutation.path()))?)
        );
    }
    let others = |m: &Manifest| -> Vec<String> {
        m.artefacts
            .iter()
            .filter(|a| !a.id.starts_with("mutations/"))
            .map(|a| a.id.clone())
            .collect()
    };
    assert_eq!(others(&written), others(&stale));
    // A second run changes nothing.
    let before = std::fs::read(&path)?;
    write_into_corpus(&path)?;
    assert_eq!(std::fs::read(&path)?, before);
    Ok(())
}

#[test]
fn owns_every_entry_under_its_directory() -> TestResult {
    let manifest = committed_manifest()?;
    let mut artefact = manifest.artefacts[0].clone();
    artefact.id = "mutations/a".to_owned();
    assert!(generated_here(&artefact));
    artefact.id = "mutationsx/a".to_owned();
    assert!(!generated_here(&artefact));
    artefact.id = "signed/a".to_owned();
    assert!(!generated_here(&artefact));
    Ok(())
}

#[test]
fn errors_are_described() {
    let cases = [
        (
            MutationError::NotInManifest("signed/a".into()),
            "the manifest does not list signed/a, from which a malformed variant derives",
        ),
        (
            MutationError::DigestMismatch("signed/a".into()),
            "the file of signed/a differs from the sha256 of its manifest entry",
        ),
        (
            MutationError::Mutation {
                id: "mutations/a".into(),
                reason: Unsupported("no iat"),
            },
            "mutations/a cannot be derived from its source: no iat",
        ),
        (
            MutationError::Io("gone".into()),
            "a source of the malformed variants cannot be read: gone",
        ),
    ];
    for (error, text) in cases {
        assert_eq!(error.to_string(), text);
    }
    assert_eq!(
        GenerateError::Mutation(MutationError::Io("gone".into())).to_string(),
        "a source of the malformed variants cannot be read: gone"
    );
}

/// A protected header of exactly `len` bytes, with `iat` 1.
fn header_of(len: usize) -> String {
    let base = "{\"iat\":1,\"p\":\"\"}";
    format!("{{\"iat\":1,\"p\":\"{}\"}}", "a".repeat(len - base.len()))
}

#[test]
fn a_jws_at_the_size_limits_is_read_and_one_byte_more_is_refused() -> TestResult {
    let header = header_of(MAX_HEADER_LEN);
    assert_eq!(header.len(), MAX_HEADER_LEN);
    let at = compact(&header, "cA.c2ln");
    assert!(tamper_protected_header(&at).is_ok());
    assert!(duplicate_protected_header_parameter(&at).is_ok());
    let over = compact(&header_of(MAX_HEADER_LEN + 1), "cA.c2ln");
    assert!(tamper_protected_header(&over).is_err());
    assert!(duplicate_protected_header_parameter(&over).is_err());
    // The whole input: the payload fills it to the limit.
    let head = Base64UrlUnpadded::encode_string(b"{\"iat\":1}");
    let fill = MAX_JWS_LEN - head.len() - ".".len() - ".c2ln".len();
    let at = format!("{head}.{}.c2ln", "A".repeat(fill)).into_bytes();
    assert_eq!(at.len(), MAX_JWS_LEN);
    assert!(tamper_protected_header(&at).is_ok());
    let over = format!("{head}.{}.c2ln", "A".repeat(fill + 1)).into_bytes();
    assert!(tamper_protected_header(&over).is_err());
    assert!(duplicate_protected_header_parameter(&over).is_err());
    // An input of dots alone, past the limit, is refused.
    let dots = vec![b'.'; MAX_JWS_LEN + 1];
    assert!(tamper_protected_header(&dots).is_err());
    Ok(())
}

#[test]
fn only_the_top_level_iat_is_changed() -> TestResult {
    let cases = [
        (
            "{\"iat\" :1,\"x\":{\"iat\":1}}",
            "{\"iat\" :2,\"x\":{\"iat\":1}}",
            "{\"iat\" :1,\"x\":{\"iat\":1},\"iat\":86401}",
        ),
        (
            "{\"x\":{\"iat\":1},\"iat\":5}",
            "{\"x\":{\"iat\":1},\"iat\":6}",
            "{\"x\":{\"iat\":1},\"iat\":5,\"iat\":86405}",
        ),
        (
            "{\"x\":[{\"iat\":2}],\"iat\":3}",
            "{\"x\":[{\"iat\":2}],\"iat\":4}",
            "{\"x\":[{\"iat\":2}],\"iat\":3,\"iat\":86403}",
        ),
        (
            "{\"s\":\"iat\",\"iat\":3}",
            "{\"s\":\"iat\",\"iat\":4}",
            "{\"s\":\"iat\",\"iat\":3,\"iat\":86403}",
        ),
        (
            "{ \"iat\" : 7 }",
            "{ \"iat\" : 8 }",
            "{ \"iat\" : 7 ,\"iat\":86407}",
        ),
    ];
    for (header, tampered, duplicated) in cases {
        let jws = compact(header, "cA.c2ln");
        assert_eq!(
            tamper_protected_header(&jws)?,
            compact(tampered, "cA.c2ln"),
            "{header}"
        );
        assert_eq!(
            duplicate_protected_header_parameter(&jws)?,
            compact(duplicated, "cA.c2ln"),
            "{header}"
        );
    }
    Ok(())
}

#[test]
fn a_header_with_an_escape_or_a_duplicate_name_is_refused() {
    for header in [
        "{\"a\":{\"iat\":5},\"\\u0069at\":5}",
        "{\"\\u0069at\":1,\"iat\":1}",
        "{\"iat\":1,\"\\u0069at\":1}",
        "{\"iat\":1,\"s\":\"a\\nb\"}",
        "{\"s\":\"\\\"iat\\\":1\"}",
        "{\"iat\":1,\"x\":1,\"x\":2}",
    ] {
        let jws = compact(header, "cA.c2ln");
        assert!(tamper_protected_header(&jws).is_err(), "tamper: {header}");
        assert!(
            duplicate_protected_header_parameter(&jws).is_err(),
            "duplicate: {header}"
        );
    }
}

const ID_DATA: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
];

/// A DER length.
fn der_length(length: usize) -> Vec<u8> {
    match length {
        0..=0x7f => vec![u8::try_from(length).unwrap_or(0)],
        0x80..=0xff => vec![0x81, u8::try_from(length).unwrap_or(0)],
        _ => vec![
            0x82,
            u8::try_from(length >> 8).unwrap_or(0),
            u8::try_from(length & 0xff).unwrap_or(0),
        ],
    }
}

/// The type id-data followed by `[0] EXPLICIT OCTET STRING` with `content`.
fn encapsulated(content: &[u8]) -> Vec<u8> {
    let mut octets = vec![0x04];
    octets.extend(der_length(content.len()));
    octets.extend_from_slice(content);
    let mut out = ID_DATA.to_vec();
    out.push(0xa0);
    out.extend(der_length(octets.len()));
    out.extend(octets);
    out
}

#[test]
fn the_encapsulated_content_changes_in_its_first_octet() -> TestResult {
    let source = source_bytes(Mutation::CadesModifiedContent)?;
    let changed = modify_encapsulated_content(&source)?;
    assert_eq!(changed.len(), source.len());
    let differing: Vec<usize> = (0..source.len())
        .filter(|&i| source[i] != changed[i])
        .collect();
    let content = b"sigillum test corpus: the text payload of the signed corpus under signed/.\n";
    let at = source
        .windows(content.len())
        .position(|w| w == content)
        .ok_or("no content")?;
    assert_eq!(differing, [at]);
    assert_eq!(changed[at], b'S');
    assert_eq!(Mutation::CadesModifiedContent.apply(&source)?, changed);
    Ok(())
}

#[test]
fn the_content_may_have_a_long_length() -> TestResult {
    for length in [1, 0x7f, 0x80, 0xff, 0x100, 0x1000] {
        let content = vec![b'a'; length];
        let mut expected = content.clone();
        expected[0] = b'A';
        let mut input = b"prefix".to_vec();
        input.extend(encapsulated(&content));
        input.extend(b"suffix");
        let mut output = b"prefix".to_vec();
        output.extend(encapsulated(&expected));
        output.extend(b"suffix");
        assert_eq!(modify_encapsulated_content(&input)?, output, "{length}");
    }
    // The content may end the input.
    assert_eq!(
        modify_encapsulated_content(&encapsulated(b"abc"))?,
        encapsulated(b"Abc")
    );
    Ok(())
}

#[test]
fn a_cms_without_one_well_formed_encapsulated_content_is_refused() {
    let good = encapsulated(b"abc");
    let mut twice = good.clone();
    twice.extend(encapsulated(b"abc"));
    let mut constructed = good.clone();
    constructed[13] = 0x24;
    let mut outer_length = good.clone();
    outer_length[12] = 0x06;
    let mut inner_length = good.clone();
    inner_length[14] = 0x04;
    let mut not_explicit = good.clone();
    not_explicit[11] = 0xa1;
    let mut long_form = ID_DATA.to_vec();
    long_form.extend([0xa0, 0x84, 0, 0, 0, 5, 0x04, 0x03, b'a', b'b', b'c']);
    let mut truncated = good.clone();
    truncated.pop();
    let mut non_minimal = ID_DATA.to_vec();
    non_minimal.extend([0xa0, 0x81, 0x05, 0x04, 0x03, b'a', b'b', b'c']);
    let mut non_minimal_two = ID_DATA.to_vec();
    non_minimal_two.extend([0xa0, 0x82, 0x00, 0x05, 0x04, 0x03, b'a', b'b', b'c']);
    let cases: [(&str, Vec<u8>); 12] = [
        ("non-minimal length", non_minimal),
        ("non-minimal two-octet length", non_minimal_two),
        ("empty", Vec::new()),
        ("no content type", b"abc".to_vec()),
        ("twice", twice),
        ("constructed", constructed),
        ("outer length", outer_length),
        ("inner length", inner_length),
        ("not [0]", not_explicit),
        ("long form", long_form),
        ("truncated", truncated),
        ("empty content", encapsulated(b"")),
    ];
    for (name, input) in cases {
        assert!(modify_encapsulated_content(&input).is_err(), "{name}");
    }
    assert!(modify_encapsulated_content(&ID_DATA).is_err());
}

/// The iat of the protected header of a compact JWS.
fn source_iat(jws: &[u8]) -> Result<u64, Box<dyn std::error::Error>> {
    let (header, _, _) = jws_parts(jws)?;
    let parsed: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&header)?;
    Ok(parsed
        .get("iat")
        .and_then(serde_json::Value::as_u64)
        .ok_or("no iat")?)
}

#[test]
fn the_cms_mutations_read_inputs_up_to_their_limit() -> TestResult {
    let signing = signing_time("291216100000Z");
    let content = encapsulated(b"abc");
    for (target, mutate) in [
        (
            &signing,
            modify_signing_time as fn(&[u8]) -> Result<Vec<u8>, Unsupported>,
        ),
        (&content, modify_encapsulated_content),
    ] {
        let mut at = vec![0u8; MAX_CMS_LEN - target.len()];
        at.extend_from_slice(target);
        assert_eq!(at.len(), MAX_CMS_LEN);
        assert!(mutate(&at).is_ok());
        let mut over = vec![0u8; MAX_CMS_LEN + 1 - target.len()];
        over.extend_from_slice(target);
        assert!(mutate(&over).is_err());
    }
    Ok(())
}

#[test]
fn generate_reads_sources_up_to_their_limit() -> TestResult {
    let (_scratch, root) = scratch_corpus()?;
    let source = "signed/cades-enveloping-b-b-p256";
    let mut manifest = committed_manifest()?;
    let path = root.join("signed/cades-enveloping-b-b-p256.p7m");
    let record = |manifest: &mut Manifest, bytes: &[u8]| -> std::io::Result<()> {
        std::fs::write(&path, bytes)?;
        for artefact in &mut manifest.artefacts {
            if artefact.id == source {
                artefact.sha256 = sha256_hex(bytes);
            }
        }
        Ok(())
    };
    // At the limit the file is read, and the mutation then refuses it.
    record(&mut manifest, &vec![0u8; MAX_SOURCE_LEN])?;
    assert!(matches!(
        generate(&root, &manifest),
        Err(MutationError::Mutation { .. })
    ));
    // Past it, the read stops with the limit.
    record(&mut manifest, &vec![0u8; MAX_SOURCE_LEN + 1])?;
    assert!(matches!(
        generate(&root, &manifest),
        Err(MutationError::Io(message)) if message.contains("larger than")
    ));
    Ok(())
}

#[test]
fn regenerating_the_variants_reproduces_the_committed_manifest() -> TestResult {
    let (_scratch, root) = scratch_corpus()?;
    let path = root.join("manifest.toml");
    let mut without = committed_manifest()?;
    without
        .artefacts
        .retain(|a| !a.id.starts_with("mutations/"));
    std::fs::write(&path, without.to_toml())?;
    write_into_corpus(&path)?;
    let committed = std::fs::read_to_string(testdata().join("manifest.toml"))?;
    assert!(std::fs::read_to_string(&path)? == committed);
    Ok(())
}

/// The limits are the values that the documentation and the error
/// messages name, and the corpus sources fit them with a wide margin.
#[test]
fn the_limits_are_those_documented() -> TestResult {
    assert_eq!(MAX_CMS_LEN, 1_048_576);
    assert_eq!(MAX_SOURCE_LEN, 4_194_304);
    assert_eq!(MAX_JWS_LEN, 1_048_576);
    assert_eq!(MAX_HEADER_LEN, 65_536);
    assert_eq!(MAX_PDF_LEN, 4_194_304);
    for mutation in MUTATIONS {
        let limit = if mutation.path().extension().is_some_and(|e| e == "pdf") {
            MAX_PDF_LEN
        } else {
            MAX_CMS_LEN.min(MAX_JWS_LEN)
        };
        assert!(source_bytes(mutation)?.len() * 100 < limit, "{mutation:?}");
    }
    Ok(())
}
