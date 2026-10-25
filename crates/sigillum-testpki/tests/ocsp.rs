//! The committed OCSP responses under `testdata/ocsp/` are what
//! `generate ocsp` produces, each is listed in the manifest, agrees with
//! its entry, and the certificates of the test PKI link their response.

use std::collections::HashSet;
use std::path::PathBuf;

use const_oid::db::rfc6960;
use der::{Decode, DecodePem, Encode};
use sha1::{Digest, Sha1};
use sigillum_testpki::manifest::{Artefact, Kind, Manifest};
use sigillum_testpki::pki::{self, hierarchy, ocsp};
use x509_cert::Certificate;
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

#[test]
fn the_committed_responses_are_reproduced_byte_for_byte() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    let files = ocsp::generate(manifest.header.validation_time)?;
    assert_eq!(files.len(), 31);
    for file in &files {
        let committed = std::fs::read(testdata().join(&file.artefact.path))?;
        assert!(
            committed == file.contents,
            "{} differs from a fresh generation; run sigillum-testpki generate ocsp",
            file.artefact.path.display()
        );
        let entry = manifest
            .artefacts
            .iter()
            .find(|a| a.id == file.artefact.id)
            .ok_or_else(|| format!("{} is not in the manifest", file.artefact.id))?;
        assert_eq!(entry, &file.artefact);
    }
    Ok(())
}

#[test]
fn every_file_under_ocsp_is_in_the_manifest() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    let listed: HashSet<PathBuf> = manifest
        .artefacts
        .iter()
        .filter(|a| a.kind == Kind::OcspResponse)
        .map(|a| a.path.clone())
        .collect();
    assert_eq!(listed.len(), 31);
    let mut found = HashSet::new();
    for entry in std::fs::read_dir(testdata().join(ocsp::DIRECTORY))? {
        let path = PathBuf::from(format!(
            "{}/{}",
            ocsp::DIRECTORY,
            entry?.file_name().to_string_lossy()
        ));
        assert!(listed.contains(&path), "{} is not listed", path.display());
        found.insert(path);
    }
    assert_eq!(found, listed);
    Ok(())
}

fn entry<'a>(manifest: &'a Manifest, id: &str) -> Result<&'a Artefact, String> {
    manifest
        .artefacts
        .iter()
        .find(|a| a.id == id)
        .ok_or_else(|| format!("{id} is not in the manifest"))
}

fn load_certificate(
    manifest: &Manifest,
    id: &str,
) -> Result<Certificate, Box<dyn std::error::Error>> {
    Ok(Certificate::from_pem(std::fs::read(
        testdata().join(&entry(manifest, id)?.path),
    )?)?)
}

/// The test plan of the story: each committed response is parsed, and its
/// status, times and responder are checked against the manifest. The
/// responder is the certificate that `issuer` links, and the covered
/// certificate is the one the notes name first.
#[test]
fn each_response_agrees_with_its_manifest_entry() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    let time = manifest.header.validation_time;
    for artefact in manifest
        .artefacts
        .iter()
        .filter(|a| a.kind == Kind::OcspResponse)
    {
        let der = std::fs::read(testdata().join(&artefact.path))?;
        assert_eq!(pki::sha256_hex(&der), artefact.sha256);
        let response = OcspResponse::from_der(&der)?;
        assert_eq!(response.to_der()?, der, "{} is not DER", artefact.id);
        let notes = artefact.notes.as_deref().ok_or("no notes")?;
        let covered_id = notes
            .strip_prefix("Covered certificate: ")
            .and_then(|rest| {
                rest.split_once(". ")
                    .map(|(id, _)| id)
                    .or(rest.strip_suffix('.'))
            })
            .ok_or_else(|| format!("{}: no covered certificate", artefact.id))?;
        let covered = load_certificate(&manifest, covered_id)?;
        let Some(bytes) = response.response_bytes else {
            assert!(matches!(
                response.response_status,
                OcspResponseStatus::TryLater | OcspResponseStatus::Unauthorized
            ));
            assert!(artefact.links.issuer.is_none(), "{}", artefact.id);
            continue;
        };
        assert_eq!(response.response_status, OcspResponseStatus::Successful);
        assert_eq!(bytes.response_type, rfc6960::ID_PKIX_OCSP_BASIC);
        let basic = BasicOcspResponse::from_der(bytes.response.as_bytes())?;
        let data = &basic.tbs_response_data;
        // The responder: the certificate linked as issuer, identified by
        // its key hash and included in certs.
        let responder_id = artefact.links.issuer.as_deref().ok_or("no responder")?;
        let responder = load_certificate(&manifest, responder_id)?;
        let key = responder
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        assert_eq!(
            data.responder_id,
            ResponderId::ByKey(der::asn1::OctetString::new(Sha1::digest(key).to_vec())?)
        );
        // The covered certificate: the serial number of the single
        // response, under the issuer of the certificate.
        let single = data.responses.first().ok_or("no single response")?;
        assert_eq!(
            single.cert_id.serial_number,
            covered.tbs_certificate.serial_number
        );
        let issuer_id = entry(&manifest, covered_id)?
            .links
            .issuer
            .as_deref()
            .ok_or("no issuer")?;
        let issuer = load_certificate(&manifest, issuer_id)?;
        // A delegated responder includes its certificate in certs; a CA
        // that signs for its own certificates includes none.
        if responder_id == issuer_id {
            assert_eq!(basic.certs, None, "{}", artefact.id);
        } else {
            assert_eq!(basic.certs, Some(vec![responder]), "{}", artefact.id);
        }
        // The CertID names the issuer of the covered certificate, except in
        // the two fixtures of threat K10, which each spoil one hash.
        let name_hash = single.cert_id.issuer_name_hash.as_bytes()
            == Sha1::digest(issuer.tbs_certificate.subject.to_der()?).as_slice();
        let issuer_key = issuer
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        let key_hash =
            single.cert_id.issuer_key_hash.as_bytes() == Sha1::digest(issuer_key).as_slice();
        let expected = match artefact.id.as_str() {
            "ocsp/cert-id-wrong-issuer-name-hash" => (false, true),
            "ocsp/cert-id-wrong-issuer-key-hash" => (true, false),
            _ => (true, true),
        };
        assert_eq!((name_hash, key_hash), expected, "{}", artefact.id);
        // The times, from the validation time of the manifest.
        let seconds = |t: &x509_ocsp::OcspGeneralizedTime| t.0.to_unix_duration().as_secs();
        let offset = |days: i64| -> Result<u64, Box<dyn std::error::Error>> {
            Ok(u64::try_from(
                (time + time::Duration::days(days)).unix_timestamp(),
            )?)
        };
        // ocsp/signer-expired-before-expiry is issued two days before the
        // validation time, before pki/signer-expired expired, and is fresh.
        let late = artefact.id == "ocsp/produced-at-after-validation-time";
        let early = artefact.id == "ocsp/signer-expired-before-expiry";
        let issued = if early { -2 } else { -1 };
        assert_eq!(
            seconds(&data.produced_at),
            offset(if late { 1 } else { issued })?
        );
        assert_eq!(seconds(&single.this_update), offset(issued)?);
        assert_eq!(
            single.next_update.as_ref().map(seconds),
            Some(offset(if early { 5 } else { 6 })?)
        );
        // The status: unknown for ocsp/unknown, otherwise revoked exactly
        // when the purpose says so, and only for a revoked certificate.
        // A revocation counts when it is on or before thisUpdate, as in
        // the CRLs.
        let spec = hierarchy::find(covered_id.trim_start_matches("pki/")).ok_or("no spec")?;
        let revoked = ocsp::revoked_at(spec.revocation, ocsp::THIS_UPDATE, time)?;
        match single.cert_status {
            CertStatus::Unknown(_) => assert_eq!(artefact.id, "ocsp/unknown"),
            CertStatus::Revoked(_) => {
                assert!(revoked, "{}", artefact.id);
                assert!(artefact.purpose.contains("revoked"), "{}", artefact.id);
            }
            CertStatus::Good(_) => {
                assert!(!revoked, "{}", artefact.id);
                assert!(artefact.purpose.contains("good"), "{}", artefact.id);
            }
        }
    }
    Ok(())
}

/// Every certificate with a response links it in `revocation`, after its
/// CRL, and no other certificate links one.
#[test]
fn certificates_link_their_response_after_their_crl() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    for spec in &hierarchy::CERTIFICATES {
        let id = pki::certificate_id(spec.name);
        let links = &entry(&manifest, &id)?.links.revocation;
        let responses: Vec<&String> = links.iter().filter(|r| r.starts_with("ocsp/")).collect();
        match ocsp::current_response(spec) {
            Some(response) => {
                assert_eq!(responses, [&response], "{id}");
                assert_eq!(links.last(), Some(&response), "{id}");
                assert!(links.len() >= 2, "{id}");
            }
            None => assert!(responses.is_empty(), "{id}"),
        }
    }
    Ok(())
}

/// `openssl ocsp` compares `thisUpdate` and `nextUpdate` with the current
/// time only, so the manifest says, for every response with a status,
/// that the expected OpenSSL result does not cover freshness. Responses
/// without a status have no times and do not say it.
#[test]
fn the_manifest_says_that_openssl_does_not_check_freshness() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    let mut signed = 0;
    for artefact in manifest
        .artefacts
        .iter()
        .filter(|a| a.kind == Kind::OcspResponse)
    {
        let notes = artefact.notes.as_deref().ok_or("no notes")?;
        let says_so = notes.ends_with(ocsp::OPENSSL_FRESHNESS_NOTE);
        let has_status = artefact.links.issuer.is_some();
        assert_eq!(says_so, has_status, "{}: {notes}", artefact.id);
        assert_eq!(
            notes.matches(ocsp::OPENSSL_FRESHNESS_NOTE).count(),
            usize::from(has_status)
        );
        signed += usize::from(has_status);
    }
    assert_eq!(signed, 29);
    assert!(ocsp::OPENSSL_FRESHNESS_NOTE.contains("current time"));
    assert!(ocsp::OPENSSL_FRESHNESS_NOTE.contains("not its freshness"));
    Ok(())
}
