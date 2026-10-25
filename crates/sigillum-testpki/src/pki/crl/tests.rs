//! Tests of the CRLs: each CRL is decoded with `x509-cert` and checked
//! against its specification, the certificates it covers and its manifest
//! entry.

use std::collections::{BTreeSet, HashSet};
use std::sync::OnceLock;

use const_oid::db::rfc5280;
use der::{Decode, Encode};
use proptest::prelude::*;
use time::OffsetDateTime;
use time::macros::datetime;
use x509_cert::crl::CertificateList;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::crl::{CrlNumber, CrlReason};
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};

use super::super::hierarchy::{PLANNED_SIGNING_TIME, Role};
use super::super::keys::KeyType;
use super::super::tests::{TestResult, VALIDATION_TIME, certificate, to_time, verifies};
use super::*;

type Error = Box<dyn std::error::Error>;

fn crls() -> Result<&'static [GeneratedFile], PkiError> {
    static FILES: OnceLock<Result<Vec<GeneratedFile>, PkiError>> = OnceLock::new();
    FILES
        .get_or_init(|| generate(VALIDATION_TIME))
        .as_deref()
        .map_err(Clone::clone)
}

fn crl_spec(name: &str) -> Result<&'static CrlSpec, Error> {
    CRLS.iter()
        .find(|c| c.name == name)
        .ok_or_else(|| format!("no CRL {name}").into())
}

/// The generated file and the decoded CRL of this name.
fn decoded(name: &str) -> Result<(&'static GeneratedFile, CertificateList), Error> {
    let file = crls()?
        .iter()
        .find(|f| f.artefact.id == crl_id(name))
        .ok_or_else(|| format!("no CRL file {name}"))?;
    let crl = CertificateList::from_der(&file.contents)?;
    Ok((file, crl))
}

fn crl_extension(crl: &CertificateList, oid: der::asn1::ObjectIdentifier) -> Option<&Extension> {
    crl.tbs_cert_list
        .crl_extensions
        .as_ref()?
        .iter()
        .find(|e| e.extn_id == oid)
}

const FAMILY_CAS: [&str; 5] = [
    "ca-rsa",
    "ca-rsa-pss",
    "ca-ecdsa",
    "ca-ecdsa-p521",
    "ca-ed25519",
];

/// Acceptance criterion 1: one current CRL for every CA that issues
/// certificates, the root included, named after the CRL distribution
/// points of the certificates it issues.
#[test]
fn there_is_one_current_crl_per_issuing_ca() -> TestResult {
    let issuing: BTreeSet<&str> = CERTIFICATES.iter().filter_map(|s| s.issuer).collect();
    let mut expected: BTreeSet<&str> = FAMILY_CAS.into_iter().collect();
    expected.extend([
        "root-ca",
        "ca-expired",
        "ca-without-ca-flag",
        "ca-without-basic-constraints",
    ]);
    assert_eq!(issuing, expected);
    let current: Vec<&str> = CRLS
        .iter()
        .filter(|c| c.defect.is_none() && c.next_update == NEXT_UPDATE)
        .map(|c| c.issuer)
        .collect();
    assert_eq!(current.len(), expected.len());
    assert_eq!(current.iter().copied().collect::<BTreeSet<_>>(), expected);
    for name in expected {
        let spec = crl_spec(name)?;
        assert_eq!(
            (spec.issuer, spec.this_update, spec.next_update, spec.defect),
            (name, THIS_UPDATE, NEXT_UPDATE, None)
        );
        let (file, _) = decoded(name)?;
        assert_eq!(
            file.artefact.path.to_string_lossy(),
            format!("crl/{name}.crl")
        );
    }
    // The distribution point of every certificate but the root names the
    // file of the current CRL of its issuer.
    for spec in CERTIFICATES.iter().filter(|s| s.issuer.is_some()) {
        let issuer = spec.issuer.ok_or("no issuer")?;
        let uri = format!("{}/crl/{issuer}.crl", super::super::issue::URI_BASE);
        let der = certificate(spec.name)?.to_der()?;
        let found = der.windows(uri.len()).any(|w| w == uri.as_bytes());
        assert!(found, "{}", spec.name);
        assert_eq!(
            current_crl(spec).map(|c| c.name),
            Some(issuer),
            "{}",
            spec.name
        );
    }
    assert_eq!(current_crl(spec_of("root-ca")?), None);
    Ok(())
}

fn spec_of(name: &str) -> Result<&'static CertSpec, Error> {
    hierarchy::find(name).ok_or_else(|| format!("no certificate {name}").into())
}

/// Acceptance criteria 1 and 3, and RFC 5280, section 5.1: each CRL has
/// the fields and extensions of its specification and is signed as it says.
#[test]
fn every_crl_matches_its_specification() -> TestResult {
    let subjects: Vec<_> = CERTIFICATES
        .iter()
        .map(|s| certificate(s.name).map(|c| c.tbs_certificate.subject))
        .collect::<Result<_, _>>()?;
    for spec in &CRLS {
        let (_, crl) = decoded(spec.name)?;
        let tbs = &crl.tbs_cert_list;
        let issuer = certificate(spec.issuer)?;
        assert_eq!(tbs.version, x509_cert::Version::V2, "{}", spec.name);
        let identifier = spec.algorithm.identifier()?;
        assert_eq!(tbs.signature, identifier, "{}", spec.name);
        assert_eq!(crl.signature_algorithm, identifier, "{}", spec.name);
        match spec.defect {
            Some(Defect::WrongIssuerName(common_name)) => {
                assert_eq!(common_name, UNKNOWN_ISSUER);
                assert_eq!(tbs.issuer, issue::name(UNKNOWN_ISSUER)?);
                assert!(!subjects.contains(&tbs.issuer), "{}", spec.name);
            }
            _ => assert_eq!(tbs.issuer, issuer.tbs_certificate.subject, "{}", spec.name),
        }
        assert_eq!(
            to_time(&tbs.this_update)?,
            spec.this_update.from(VALIDATION_TIME)?
        );
        let next_update = tbs.next_update.as_ref().ok_or("no nextUpdate")?;
        assert_eq!(
            to_time(next_update)?,
            spec.next_update.from(VALIDATION_TIME)?
        );
        for time in [&tbs.this_update, next_update] {
            assert!(matches!(time, Time::UtcTime(_)), "{}", spec.name);
        }
        let extensions = tbs.crl_extensions.as_ref().ok_or("no extensions")?;
        // The authority key identifier and the CRL number, and
        // expiredCertsOnCRL where the specification asks for it.
        let expected = 2 + usize::from(spec.expired_certs_on_crl.is_some());
        assert_eq!(extensions.len(), expected, "{}", spec.name);
        assert!(extensions.iter().all(|e| !e.critical), "{}", spec.name);
        let aki = AuthorityKeyIdentifier::from_der(
            crl_extension(&crl, rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER)
                .ok_or("no authority key identifier")?
                .extn_value
                .as_bytes(),
        )?;
        let ski = issuer
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|e| {
                e.iter()
                    .find(|e| e.extn_id == rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER)
            })
            .ok_or("no subject key identifier")?;
        let ski = SubjectKeyIdentifier::from_der(ski.extn_value.as_bytes())?;
        assert_eq!(aki.key_identifier, Some(ski.0), "{}", spec.name);
        assert_eq!(aki.authority_cert_issuer, None);
        assert_eq!(aki.authority_cert_serial_number, None);
        let number = CrlNumber::from_der(
            crl_extension(&crl, rfc5280::ID_CE_CRL_NUMBER)
                .ok_or("no CRL number")?
                .extn_value
                .as_bytes(),
        )?;
        assert_eq!(number.0.as_bytes(), [spec.number], "{}", spec.name);
        let message = tbs.to_der()?;
        let signature = crl.signature.raw_bytes();
        let issuer_spki = issuer.tbs_certificate.subject_public_key_info.to_der()?;
        let by_issuer = verifies(spec.algorithm, &issuer_spki, &message, signature)?;
        match spec.defect {
            Some(Defect::WrongKey(owner)) => {
                assert!(!by_issuer, "{}", spec.name);
                let spki = certificate(owner)?
                    .tbs_certificate
                    .subject_public_key_info
                    .to_der()?;
                assert!(verifies(spec.algorithm, &spki, &message, signature)?);
                assert_eq!(spec_of(owner)?.key, spec_of(spec.issuer)?.key);
            }
            _ => assert!(by_issuer, "{}", spec.name),
        }
        // The CRL is re-encoded unchanged, so it is DER.
        assert_eq!(crl.to_der()?, decoded(spec.name)?.0.contents);
    }
    Ok(())
}

/// Acceptance criterion 2 and RFC 5280, sections 5.1.2.6 and 5.3.1: each
/// CRL lists the certificates of its issuer revoked on or before its
/// thisUpdate, in order of serial number, with the reason code.
#[test]
fn every_crl_lists_the_revoked_certificates_of_its_issuer() -> TestResult {
    for spec in &CRLS {
        let (_, crl) = decoded(spec.name)?;
        let this_update = spec.this_update.from(VALIDATION_TIME)?;
        let mut expected: Vec<&CertSpec> = CERTIFICATES
            .iter()
            .filter(|s| s.issuer == Some(spec.issuer))
            .filter(|s| {
                s.revocation
                    .is_some_and(|r| r.date.from(VALIDATION_TIME).is_ok_and(|d| d <= this_update))
            })
            .collect();
        expected.sort_by_key(|s| s.serial);
        let entries = crl
            .tbs_cert_list
            .revoked_certificates
            .clone()
            .unwrap_or_default();
        if expected.is_empty() {
            assert!(
                crl.tbs_cert_list.revoked_certificates.is_none(),
                "{}",
                spec.name
            );
        }
        assert_eq!(entries.len(), expected.len(), "{}", spec.name);
        for (entry, certificate_spec) in entries.iter().zip(&expected) {
            let issued = certificate(certificate_spec.name)?;
            assert_eq!(entry.serial_number, issued.tbs_certificate.serial_number);
            let revocation = certificate_spec.revocation.ok_or("not revoked")?;
            assert_eq!(
                to_time(&entry.revocation_date)?,
                revocation.date.from(VALIDATION_TIME)?
            );
            let extensions = entry.crl_entry_extensions.as_ref().ok_or("no reason")?;
            assert_eq!(extensions.len(), 1);
            let reason = &extensions[0];
            assert_eq!(reason.extn_id, rfc5280::ID_CE_CRL_REASONS);
            assert!(!reason.critical);
            assert_eq!(
                CrlReason::from_der(reason.extn_value.as_bytes())?,
                revocation.reason
            );
        }
    }
    Ok(())
}

/// Acceptance criterion 2: one end entity per family revoked for key
/// compromise before the planned signing time, and one more after it,
/// both before the validation time. No other certificate is revoked.
#[test]
fn one_signer_per_family_is_revoked_and_one_after_the_planned_signing_time() -> TestResult {
    let signing_time = PLANNED_SIGNING_TIME.from(VALIDATION_TIME)?;
    assert!(signing_time < VALIDATION_TIME);
    let revoked: Vec<&CertSpec> = CERTIFICATES
        .iter()
        .filter(|s| s.revocation.is_some())
        .collect();
    let mut before = Vec::new();
    let mut after = Vec::new();
    for spec in &revoked {
        let revocation = spec.revocation.ok_or("not revoked")?;
        let date = revocation.date.from(VALIDATION_TIME)?;
        assert_eq!(revocation.reason, CrlReason::KeyCompromise, "{}", spec.name);
        assert!(date < VALIDATION_TIME, "{}", spec.name);
        assert_eq!(spec.role, Role::Signer, "{}", spec.name);
        // Valid when revoked, so the revocation is what fails validation.
        assert!(
            spec.not_before.from(VALIDATION_TIME)? < date,
            "{}",
            spec.name
        );
        assert!(spec.not_after.from(VALIDATION_TIME)? > VALIDATION_TIME);
        assert_eq!(spec.expected_openssl, OpensslResult::Rejected);
        assert_eq!(
            spec.expected_dss,
            ExpectedDss {
                indication: Indication::Indeterminate,
                sub_indication: Some("REVOKED_NO_POE"),
            }
        );
        if date < signing_time {
            before.push(spec.issuer.ok_or("no issuer")?);
        } else {
            after.push(spec.name);
        }
        // The revocation is listed by the current CRL of the issuer.
        let crl = current_crl(spec).ok_or("no CRL")?;
        assert!(crl.this_update.from(VALIDATION_TIME)? >= date);
    }
    before.sort_unstable();
    assert_eq!(before, ["ca-ecdsa", "ca-ed25519", "ca-rsa", "ca-rsa-pss"]);
    assert_eq!(after, ["signer-p256-revoked-after-signing"]);
    // The signers of #27 stay valid for the fixtures that use them.
    for name in [
        "signer-rsa-2048",
        "signer-rsa-3072",
        "signer-rsa-sha3-256",
        "signer-rsa-pss-sha256",
        "signer-rsa-pss-sha384",
        "signer-p256",
        "signer-p384",
        "signer-p521",
        "signer-ed25519",
        "tsa",
        "ocsp-responder",
    ] {
        assert_eq!(spec_of(name)?.revocation, None, "{name}");
    }
    Ok(())
}

/// Acceptance criterion 3: the expired CRL, the CRL signed with the wrong
/// key and the CRL with the wrong issuer name, all of `pki/ca-ecdsa`.
#[test]
fn the_defective_crls_have_their_defect() -> TestResult {
    let expired = crl_spec("ca-ecdsa-expired")?;
    assert_eq!((expired.issuer, expired.defect), ("ca-ecdsa", None));
    assert!(expired.next_update.from(VALIDATION_TIME)? < VALIDATION_TIME);
    assert!(expired.number < crl_spec("ca-ecdsa")?.number);
    let (_, crl) = decoded("ca-ecdsa-expired")?;
    let listed = crl.tbs_cert_list.revoked_certificates.unwrap_or_default();
    assert_eq!(listed.len(), 1);
    let wrong_key = crl_spec("ca-ecdsa-wrong-key")?;
    assert_eq!(wrong_key.defect, Some(Defect::WrongKey("signer-p384")));
    let wrong_issuer = crl_spec("ca-ecdsa-wrong-issuer")?;
    assert_eq!(
        wrong_issuer.defect,
        Some(Defect::WrongIssuerName(UNKNOWN_ISSUER))
    );
    for spec in [expired, wrong_key, wrong_issuer] {
        assert_eq!(spec.issuer, "ca-ecdsa");
        assert_eq!(spec.expected_openssl, OpensslResult::Rejected);
        // ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4: the expired CRL is
        // usable but not fresh, so step 4 a) gives TRY_LATER. A CRL that
        // fails RFC 5280, section 6.3.3, step (b) or (g), cannot show that
        // the certificate is not revoked, so path validation fails and
        // step 4 e) gives CERTIFICATE_CHAIN_GENERAL_FAILURE. The notes say
        // that DSS 6.5.1 gives that result.
        let sub_indication = if spec.defect.is_none() {
            "TRY_LATER"
        } else {
            let notes = spec.notes.ok_or("no notes")?;
            assert!(
                notes.contains("DSS 6.5.1 gives this result"),
                "{}",
                spec.name
            );
            "CERTIFICATE_CHAIN_GENERAL_FAILURE"
        };
        assert_eq!(
            spec.expected_dss,
            ExpectedDss {
                indication: Indication::Indeterminate,
                sub_indication: Some(sub_indication),
            },
            "{}",
            spec.name
        );
        assert_eq!(spec.covered, "signer-p256");
        assert!(spec.notes.is_some());
    }
    // The defective CRLs differ from the current one only by their defect.
    let (_, current) = decoded("ca-ecdsa")?;
    for name in ["ca-ecdsa-wrong-key", "ca-ecdsa-wrong-issuer"] {
        let (_, crl) = decoded(name)?;
        assert_eq!(
            crl.tbs_cert_list.revoked_certificates,
            current.tbs_cert_list.revoked_certificates
        );
        assert_eq!(
            crl.tbs_cert_list.crl_extensions,
            current.tbs_cert_list.crl_extensions
        );
    }
    Ok(())
}

/// Acceptance criterion 4: every CRL has a manifest entry with its digest,
/// links to its issuer and chain, and expected results.
#[test]
fn every_crl_has_a_manifest_entry() -> TestResult {
    let files = crls()?;
    assert_eq!(files.len(), CRLS.len());
    let mut manifest = Manifest::parse(
        "[header]\nformat-version = 1\nvalidation-time = \"2030-01-15T10:00:00Z\"\nopenssl-version = \"3.5.9\"\ndss-version = \"6.5.1\"\n",
    )?;
    for file in super::super::tests::generated()? {
        manifest.upsert(file.artefact.clone());
    }
    let mut ids = HashSet::new();
    for (file, spec) in files.iter().zip(&CRLS) {
        let artefact = &file.artefact;
        assert!(ids.insert(artefact.id.clone()));
        assert_eq!(artefact.id, format!("crl/{}", spec.name));
        assert_eq!(
            artefact.path.to_string_lossy(),
            format!("crl/{}.crl", spec.name)
        );
        assert_eq!(artefact.sha256, sha256_hex(&file.contents));
        assert_eq!(artefact.kind, Kind::Crl);
        assert_eq!(artefact.purpose, spec.purpose);
        assert_eq!(artefact.expected_openssl, spec.expected_openssl);
        assert_eq!(
            artefact.expected_dss,
            DssResult::Indication {
                indication: spec.expected_dss.indication,
                sub_indication: spec.expected_dss.sub_indication.map(str::to_owned),
            }
        );
        // OpenSSL verifies exactly the CRLs that are current and have no
        // defect.
        let current = spec.this_update.from(VALIDATION_TIME)? <= VALIDATION_TIME
            && spec.next_update.from(VALIDATION_TIME)? > VALIDATION_TIME;
        assert_eq!(
            artefact.expected_openssl == OpensslResult::Verified,
            current && spec.defect.is_none(),
            "{}",
            spec.name
        );
        // The notes name the covered certificate first. It is issued by
        // the issuer of the CRL and not revoked, and for a current CRL the
        // expected DSS result is the certificate's own.
        let covered = spec_of(spec.covered)?;
        let note = format!("Covered certificate: pki/{}.", spec.covered);
        let notes = artefact.notes.as_deref().ok_or("no notes")?;
        assert!(notes.starts_with(&note), "{}: {notes}", spec.name);
        assert_eq!(covered.issuer, Some(spec.issuer), "{}", spec.name);
        assert_eq!(covered.revocation, None, "{}", spec.name);
        if spec.name == spec.issuer {
            assert_eq!(spec.expected_dss, covered.expected_dss, "{}", spec.name);
        }
        let issuer = certificate_id(spec.issuer);
        assert_eq!(artefact.links.issuer.as_deref(), Some(issuer.as_str()));
        assert_eq!(artefact.links.chain.first(), Some(&issuer));
        assert_eq!(
            artefact.links.chain.last().map(String::as_str),
            Some("pki/root-ca")
        );
        assert!(artefact.links.revocation.is_empty());
        assert_eq!(artefact.links.content, None);
        manifest.upsert(artefact.clone());
    }
    let generated: Vec<String> = files.iter().map(|f| f.artefact.id.clone()).collect();
    link_certificates(&mut manifest, &generated);
    let reparsed = Manifest::parse(&manifest.to_toml())?;
    assert_eq!(reparsed, manifest);
    let link = |id: &str| -> Result<Vec<String>, Error> {
        Ok(reparsed
            .artefacts
            .iter()
            .find(|a| a.id == id)
            .ok_or("no entry")?
            .links
            .revocation
            .clone())
    };
    assert_eq!(link("pki/signer-p256-revoked")?, ["crl/ca-ecdsa"]);
    assert_eq!(link("pki/ca-rsa")?, ["crl/root-ca"]);
    assert!(link("pki/root-ca")?.is_empty());
    assert_eq!(link("pki/signer-under-expired-ca")?, ["crl/ca-expired"]);
    assert_eq!(
        reparsed
            .artefacts
            .iter()
            .filter(|a| a.kind == Kind::Crl)
            .count(),
        CRLS.len()
    );
    Ok(())
}

/// The certificate links keep other revocation artefacts, put the CRL
/// first, drop the CRLs of this generator and skip missing entries.
#[test]
fn certificate_links_replace_only_the_crls_of_this_generator() -> TestResult {
    let mut manifest = Manifest::parse(
        "[header]\nformat-version = 1\nvalidation-time = \"2030-01-15T10:00:00Z\"\nopenssl-version = \"3.5.9\"\ndss-version = \"6.5.1\"\n",
    )?;
    let mut entry = super::super::tests::generated()?
        .iter()
        .find(|f| f.artefact.id == "pki/signer-p256")
        .ok_or("no signer")?
        .artefact
        .clone();
    entry.links.revocation = vec![
        "ocsp/signer-p256".to_owned(),
        "crl/ca-ecdsa-expired".to_owned(),
        "crl/other".to_owned(),
    ];
    let mut other = entry.clone();
    other.id = "pki/signer-p384".to_owned();
    other.kind = Kind::Document;
    other.links.revocation = vec!["crl/ca-ecdsa-expired".to_owned()];
    manifest.artefacts = vec![entry, other];
    link_certificates(
        &mut manifest,
        &["crl/ca-ecdsa".to_owned(), "crl/ca-ecdsa-expired".to_owned()],
    );
    assert_eq!(
        manifest.artefacts[0].links.revocation,
        ["crl/ca-ecdsa", "ocsp/signer-p256", "crl/other"]
    );
    // An entry of another kind with a certificate's identifier is left alone.
    assert_eq!(
        manifest.artefacts[1].links.revocation,
        ["crl/ca-ecdsa-expired"]
    );
    // Running again changes nothing.
    let before = manifest.clone();
    link_certificates(&mut manifest, &["crl/ca-ecdsa".to_owned()]);
    assert_eq!(manifest, before);
    Ok(())
}

#[test]
fn generation_is_reproducible() -> TestResult {
    assert_eq!(generate(VALIDATION_TIME)?.as_slice(), crls()?);
    Ok(())
}

#[test]
fn build_reports_mismatched_keys_and_times_out_of_range() -> TestResult {
    let spec = crl_spec("ca-ed25519")?;
    let ed25519 = KeyPair::derive(KeyType::Ed25519, "ca-ed25519")?;
    let p256 = KeyPair::derive(KeyType::P256, "test/mismatch")?;
    assert_eq!(
        build(spec, &ed25519, &p256, VALIDATION_TIME),
        Err(PkiError::KeyMismatch)
    );
    for (this_update, next_update) in [
        (Offset::years(1_000_000), NEXT_UPDATE),
        (THIS_UPDATE, Offset::years(1_000_000)),
    ] {
        let spec = CrlSpec {
            this_update,
            next_update,
            ..*spec
        };
        assert_eq!(
            build(&spec, &ed25519, &ed25519, VALIDATION_TIME),
            Err(PkiError::Time)
        );
    }
    // A revocation date out of range is reported too.
    assert_eq!(
        revoked_certificates(
            "ca-ed25519",
            VALIDATION_TIME,
            datetime!(-9999-01-01 0:00 UTC)
        ),
        Err(PkiError::Time)
    );
    let unknown = CrlSpec {
        issuer: "nobody",
        ..*spec
    };
    assert_eq!(
        build(&unknown, &ed25519, &ed25519, VALIDATION_TIME),
        Err(PkiError::UnknownIssuer("nobody".to_owned()))
    );
    assert_eq!(
        crl_file(&unknown, Vec::new()).err(),
        Some(PkiError::UnknownIssuer("nobody".to_owned()))
    );
    Ok(())
}

/// After 2049 the CRL times are GeneralizedTime (RFC 5280, section 5.1.2.4).
#[test]
fn times_switch_to_generalized_time_in_2050() -> TestResult {
    let spec = crl_spec("ca-ed25519")?;
    let key = KeyPair::derive(KeyType::Ed25519, "ca-ed25519")?;
    let crl = CertificateList::from_der(&build(
        spec,
        &key,
        &key,
        datetime!(2050-01-01 00:00:00 UTC),
    )?)?;
    assert!(matches!(crl.tbs_cert_list.this_update, Time::UtcTime(_)));
    let next_update = crl.tbs_cert_list.next_update.ok_or("no nextUpdate")?;
    assert!(matches!(next_update, Time::GeneralTime(_)));
    let entries = crl.tbs_cert_list.revoked_certificates.ok_or("no entries")?;
    // The revocation, 60 days earlier, falls in 2049.
    assert!(matches!(entries[0].revocation_date, Time::UtcTime(_)));
    assert!(matches!(
        time(datetime!(2049-12-31 23:59:59 UTC))?,
        Time::UtcTime(_)
    ));
    assert!(matches!(
        time(datetime!(2050-01-01 00:00:00 UTC))?,
        Time::GeneralTime(_)
    ));
    assert_eq!(
        time(datetime!(1969-12-31 23:59:59 UTC)),
        Err(PkiError::Time)
    );
    Ok(())
}

#[test]
fn identifiers_have_the_manifest_form() {
    assert_eq!(crl_id("ca-rsa"), "crl/ca-rsa");
    assert_eq!(DIRECTORY, "crl");
    let entry = |kind, id: &str| Artefact {
        id: id.to_owned(),
        path: PathBuf::from("x"),
        sha256: String::new(),
        kind,
        purpose: String::new(),
        expected_openssl: OpensslResult::Parsed,
        expected_dss: DssResult::NotApplicable,
        links: Links::default(),
        notes: None,
    };
    assert!(generated_here(&entry(Kind::Crl, "crl/a")));
    assert!(!generated_here(&entry(Kind::Crl, "pki/crl/a")));
    assert!(!generated_here(&entry(Kind::Crl, "crls/a")));
    assert!(!generated_here(&entry(Kind::Certificate, "crl/a")));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Every time from 1970 to 9999 is encoded with the type of RFC 5280,
    /// section 5.1.2.4, and decodes to the same second.
    #[test]
    fn times_round_trip(seconds in 0_i64..253_402_300_800) {
        let at = OffsetDateTime::from_unix_timestamp(seconds)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        let encoded = time(at).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(matches!(encoded, Time::UtcTime(_)), at.year() < 2050);
        let der = encoded.to_der().map_err(|e| TestCaseError::fail(e.to_string()))?;
        let decoded = Time::from_der(&der).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(decoded.to_unix_duration().as_secs(), u64::try_from(seconds).unwrap_or_default());
    }

    /// A CRL built at any validation time from 1971 to 2200 decodes, keeps
    /// its times as offsets of that time and verifies with the issuer key.
    #[test]
    fn crls_follow_the_validation_time(seconds in 31_536_000_i64..7_258_118_400) {
        static KEY: OnceLock<Result<KeyPair, PkiError>> = OnceLock::new();
        let key = KEY
            .get_or_init(|| KeyPair::derive(KeyType::Ed25519, "ca-ed25519"))
            .as_ref()
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        let at = OffsetDateTime::from_unix_timestamp(seconds)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        let spec = CRLS.iter().find(|c| c.name == "ca-ed25519")
            .ok_or_else(|| TestCaseError::fail("no CRL"))?;
        let fail = |e: &dyn std::fmt::Display| TestCaseError::fail(e.to_string());
        let der = build(spec, key, key, at).map_err(|e| fail(&e))?;
        let crl = CertificateList::from_der(&der).map_err(|e| fail(&e))?;
        let tbs = &crl.tbs_cert_list;
        let this_update = THIS_UPDATE.from(at).map_err(|e| fail(&e))?;
        prop_assert_eq!(to_time(&tbs.this_update).map_err(|e| fail(&e))?, this_update);
        let message = tbs.to_der().map_err(|e| fail(&e))?;
        let spki = key.spki_der().map_err(|e| fail(&e))?;
        prop_assert!(verifies(spec.algorithm, &spki, &message, crl.signature.raw_bytes())
            .map_err(|e| fail(&e))?);
        prop_assert_eq!(tbs.revoked_certificates.as_ref().map(Vec::len), Some(1));
    }
}

#[test]
fn the_constructor_gives_the_documented_defaults() -> TestResult {
    let spec = crl_spec("ca-rsa")?;
    let built = current(
        "ca-rsa",
        SignatureAlgorithm::RsaPkcs1Sha256,
        "signer-rsa-2048",
        spec.purpose,
    );
    assert_eq!(&built, spec);
    assert_eq!(
        (built.name, built.number, built.defect, built.notes),
        ("ca-rsa", 2, None, None)
    );
    assert_eq!(
        (built.this_update, built.next_update),
        (Offset::days(-1), Offset::days(6))
    );
    assert_eq!(built.expected_openssl, OpensslResult::Verified);
    assert_eq!(built.expected_dss.indication, Indication::Passed);
    Ok(())
}

/// A certificate revoked at the very time of thisUpdate is listed
/// (RFC 5280, section 5.1.2.6), and one revoked a second later is not.
#[test]
fn a_revocation_at_this_update_is_listed() -> TestResult {
    let at = Offset::days(-10).from(VALIDATION_TIME)?;
    let serials = |this_update| -> Result<Vec<Vec<u8>>, PkiError> {
        Ok(
            revoked_certificates("ca-ecdsa", this_update, VALIDATION_TIME)?
                .iter()
                .map(|e| e.serial_number.as_bytes().to_vec())
                .collect(),
        )
    };
    assert_eq!(serials(at)?, [vec![0x12, 0x0A], vec![0x12, 0x0B]]);
    assert_eq!(
        serials(at - time::Duration::seconds(1))?,
        [vec![0x12, 0x0A]]
    );
    // The current CRL of every CA is named after it and has no defect.
    for crl in CRLS.iter().filter(|c| c.name == c.issuer) {
        assert_eq!(crl.defect, None);
        assert_eq!(crl.next_update, NEXT_UPDATE);
    }
    Ok(())
}

/// The planned signing time falls inside the validity of every
/// certificate that valid fixtures use, and of every certificate of its
/// chain, and not at the revocation time of the revoked end entities.
#[test]
fn the_planned_signing_time_is_inside_the_validity_of_the_signers() -> TestResult {
    let signing_time = PLANNED_SIGNING_TIME.from(VALIDATION_TIME)?;
    assert_eq!(signing_time, datetime!(2029-12-16 10:00:00 UTC));
    let used: Vec<&CertSpec> = CERTIFICATES
        .iter()
        .filter(|s| s.expected_openssl == OpensslResult::Verified || s.revocation.is_some())
        .collect();
    for name in ["tsa", "ocsp-responder", "signer-p256", "root-ca"] {
        assert!(used.iter().any(|s| s.name == name), "{name}");
    }
    for spec in used {
        let mut path = vec![spec];
        path.extend(hierarchy::chain(spec)?);
        for certificate in path {
            assert!(
                certificate.not_before.from(VALIDATION_TIME)? < signing_time
                    && certificate.not_after.from(VALIDATION_TIME)? > signing_time,
                "{} in the chain of {}",
                certificate.name,
                spec.name
            );
        }
        if let Some(revocation) = spec.revocation {
            let date = revocation.date.from(VALIDATION_TIME)?;
            assert_ne!(date, signing_time, "{}", spec.name);
        }
    }
    Ok(())
}

/// Issue #75: a CRL of `pki/ca-ecdsa` issued after `pki/signer-expired`
/// expired, with the extension expiredCertsOnCRL of ITU-T X.509 (10/2019),
/// clause 9.5.2.8, whose date precedes that expiry. Its scope then covers
/// the expired certificate, which it shows not revoked, so ETSI EN 319
/// 102-1 V1.4.1, clause 5.2.6.4, step 7, gives OUT_OF_BOUNDS_NOT_REVOKED.
#[test]
fn the_crl_with_expired_certificates_covers_the_expired_signer() -> TestResult {
    let spec = crl_spec("ca-ecdsa-expired-certs")?;
    assert_eq!(
        (spec.issuer, spec.covered, spec.defect),
        ("ca-ecdsa", "signer-expired", None)
    );
    // A later CRL than the current one, with a higher number.
    let current = crl_spec("ca-ecdsa")?;
    assert!(spec.number > current.number);
    let expired = spec_of("signer-expired")?;
    let not_after = expired.not_after.from(VALIDATION_TIME)?;
    let this_update = spec.this_update.from(VALIDATION_TIME)?;
    assert!(this_update > not_after);
    assert!(this_update <= VALIDATION_TIME);
    assert!(spec.next_update.from(VALIDATION_TIME)? > VALIDATION_TIME);
    let since = spec.expired_certs_on_crl.ok_or("no expiredCertsOnCRL")?;
    assert!(since.from(VALIDATION_TIME)? <= not_after);
    assert_eq!(
        spec.expected_dss,
        ExpectedDss {
            indication: Indication::Indeterminate,
            sub_indication: Some("OUT_OF_BOUNDS_NOT_REVOKED"),
        }
    );
    let (_, crl) = decoded("ca-ecdsa-expired-certs")?;
    let oid = der::asn1::ObjectIdentifier::new_unwrap("2.5.29.60");
    let extension = crl_extension(&crl, oid).ok_or("no extension")?;
    // X.509, clause 9.5.2.8: always non-critical; the value is a
    // GeneralizedTime.
    assert!(!extension.critical);
    let value = der::asn1::GeneralizedTime::from_der(extension.extn_value.as_bytes())?;
    assert_eq!(
        value.to_unix_duration().as_secs(),
        u64::try_from(since.from(VALIDATION_TIME)?.unix_timestamp())?
    );
    // The other CRLs carry no such extension.
    for other in CRLS.iter().filter(|c| c.name != spec.name) {
        assert_eq!(other.expired_certs_on_crl, None, "{}", other.name);
        let (_, decoded) = decoded(other.name)?;
        assert!(crl_extension(&decoded, oid).is_none(), "{}", other.name);
    }
    Ok(())
}
