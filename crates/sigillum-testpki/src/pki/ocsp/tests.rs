//! Tests of the OCSP responses: each response is decoded with `x509-ocsp`
//! and checked against its specification, the certificates it covers, the
//! CRL of the same issuer and its manifest entry.

use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

use const_oid::db::{rfc5280, rfc5912, rfc6960};
use der::asn1::OctetString;
use der::{Decode, DecodePem, Encode};
use proptest::prelude::*;
use sha1::{Digest, Sha1};
use time::OffsetDateTime;
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::ext::pkix::crl::CrlReason;
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId};

use super::super::hierarchy::{self, CERTIFICATES};
use super::super::keys::{KeyPair, KeyType, SignatureAlgorithm};
use super::super::tests::{TestResult, VALIDATION_TIME, certificate, verifies};
use super::super::{certificate_id, crl, key_id, sha256_hex};
use super::*;
use crate::manifest::{Indication, Kind, Links};

type Error = Box<dyn std::error::Error>;

/// Every end entity of the test PKI other than the responder, in the
/// order of `CERTIFICATES`.
const END_ENTITIES: [&str; 22] = [
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
    "signer-expired",
    "signer-not-yet-valid",
    "signer-under-expired-ca",
    "signer-without-non-repudiation",
    "signer-under-ca-without-ca-flag",
    "signer-under-ca-without-basic-constraints",
    "signer-unknown-critical-extension",
    "signer-rsa-revoked",
    "signer-rsa-pss-revoked",
    "signer-p256-revoked",
    "signer-ed25519-revoked",
    "signer-p256-revoked-after-signing",
];

/// The responses of acceptance criterion 2, then those of threat K10.
const CASES: [&str; 9] = [
    "unknown",
    "responder-without-ocsp-signing",
    "produced-at-after-validation-time",
    "nonce",
    "try-later",
    "unauthorized",
    "cert-id-wrong-issuer-name-hash",
    "cert-id-wrong-issuer-key-hash",
    "signer-expired-before-expiry",
];

/// The certificate that signs the response for an end entity, and its
/// algorithm: `pki/ocsp-responder` for the end entities of `pki/ca-ecdsa`,
/// whose delegated responder it is, and otherwise the issuing CA itself
/// (RFC 6960, section 4.2.2.2), with the algorithm of its CRL.
fn expected_signer(name: &str) -> Result<(&'static str, SignatureAlgorithm), Error> {
    let issuer = hierarchy::find(name)
        .and_then(|s| s.issuer)
        .ok_or("no issuer")?;
    Ok(match issuer {
        "ca-ecdsa" => (RESPONDER, SignatureAlgorithm::EcdsaSha256),
        "ca-rsa" => (issuer, SignatureAlgorithm::RsaPkcs1Sha256),
        "ca-rsa-pss" => (issuer, SignatureAlgorithm::RsaPssSha256),
        "ca-ecdsa-p521" => (issuer, SignatureAlgorithm::EcdsaSha512),
        "ca-ed25519" => (issuer, SignatureAlgorithm::Ed25519),
        "ca-expired" | "ca-without-ca-flag" | "ca-without-basic-constraints" => {
            (issuer, SignatureAlgorithm::EcdsaSha256)
        }
        other => return Err(format!("unexpected issuer {other}").into()),
    })
}

fn files() -> Result<&'static [GeneratedFile], PkiError> {
    static FILES: OnceLock<Result<Vec<GeneratedFile>, PkiError>> = OnceLock::new();
    FILES
        .get_or_init(|| generate(VALIDATION_TIME))
        .as_deref()
        .map_err(Clone::clone)
}

fn file(name: &str) -> Result<&'static GeneratedFile, Error> {
    files()?
        .iter()
        .find(|f| f.artefact.id == ocsp_id(name))
        .ok_or_else(|| format!("no response {name}").into())
}

fn spec(name: &str) -> Result<OcspSpec, Error> {
    responses(VALIDATION_TIME)?
        .into_iter()
        .find(|s| s.name == name)
        .ok_or_else(|| format!("no specification {name}").into())
}

/// The basic response of a successful OCSP response (RFC 6960, section
/// 4.2.1).
fn basic(der: &[u8]) -> Result<BasicOcspResponse, Error> {
    let response = OcspResponse::from_der(der)?;
    assert_eq!(response.to_der()?, der, "not DER");
    assert_eq!(response.response_status, OcspResponseStatus::Successful);
    let bytes = response.response_bytes.ok_or("no responseBytes")?;
    assert_eq!(bytes.response_type, rfc6960::ID_PKIX_OCSP_BASIC);
    let basic = BasicOcspResponse::from_der(bytes.response.as_bytes())?;
    assert_eq!(basic.to_der()?, bytes.response.as_bytes(), "not DER");
    Ok(basic)
}

fn seconds(time: &x509_ocsp::OcspGeneralizedTime) -> Result<i64, Error> {
    Ok(i64::try_from(time.0.to_unix_duration().as_secs())?)
}

fn at(offset: Offset) -> Result<i64, Error> {
    Ok(offset.from(VALIDATION_TIME)?.unix_timestamp())
}

fn sha1(data: &[u8]) -> Result<OctetString, Error> {
    Ok(OctetString::new(Sha1::digest(data).to_vec())?)
}

/// The key hash of RFC 6960, section 4.2.1: the SHA-1 hash of the
/// subjectPublicKey bit string of the certificate, without tag, length and
/// unused-bits octet.
fn key_hash(certificate: &Certificate) -> Result<OctetString, Error> {
    sha1(
        certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )
}

/// The checks that every successful response passes: one single response
/// for `covered`, a SHA-1 CertID of its issuer, the times, the responder
/// identified by key, its certificate in `certs` when it is a delegated
/// responder, and a signature that verifies with its key.
fn check_signed(
    basic: &BasicOcspResponse,
    covered: &str,
    responder: &str,
    algorithm: SignatureAlgorithm,
    produced_at: Offset,
) -> TestResult {
    check_signed_with(
        basic,
        covered,
        (responder, algorithm),
        produced_at,
        CertIdForm::Correct,
    )
}

/// [`check_signed`], with a CertID of the given form.
fn check_signed_with(
    basic: &BasicOcspResponse,
    covered: &str,
    (responder, algorithm): (&str, SignatureAlgorithm),
    produced_at: Offset,
    form: CertIdForm,
) -> TestResult {
    let data = &basic.tbs_response_data;
    assert_eq!(data.version, x509_ocsp::Version::V1);
    assert_eq!(data.responses.len(), 1, "{covered}");
    let single = &data.responses[0];
    let subject = certificate(covered)?;
    let issuer_name = hierarchy::find(covered)
        .and_then(|s| s.issuer)
        .ok_or("no issuer")?;
    let issuer = certificate(issuer_name)?;
    // RFC 6960, section 4.1.1: the CertID with SHA-1 and NULL parameters.
    let id = &single.cert_id;
    assert_eq!(id.hash_algorithm.oid, rfc5912::ID_SHA_1);
    assert_eq!(
        id.hash_algorithm
            .parameters
            .as_ref()
            .map(der::Encode::to_der)
            .transpose()?,
        Some(vec![0x05, 0x00])
    );
    let name_hash = sha1(&issuer.tbs_certificate.subject.to_der()?)?;
    let key_hash_of_issuer = key_hash(&issuer)?;
    let (name_ok, key_ok) = match form {
        CertIdForm::Correct => (true, true),
        CertIdForm::WrongIssuerNameHash => (false, true),
        CertIdForm::WrongIssuerKeyHash => (true, false),
    };
    assert_eq!(id.issuer_name_hash == name_hash, name_ok, "{covered}");
    assert_eq!(
        id.issuer_key_hash == key_hash_of_issuer,
        key_ok,
        "{covered}"
    );
    // A wrong hash is the right one with its last octet inverted.
    for (actual, right) in [
        (&id.issuer_name_hash, &name_hash),
        (&id.issuer_key_hash, &key_hash_of_issuer),
    ] {
        let mut inverted = right.as_bytes().to_vec();
        if let Some(last) = inverted.last_mut() {
            *last = !*last;
        }
        assert!(actual == right || actual.as_bytes() == inverted.as_slice());
    }
    assert_eq!(id.serial_number, subject.tbs_certificate.serial_number);
    assert_eq!(seconds(&data.produced_at)?, at(produced_at)?, "{covered}");
    assert_eq!(seconds(&single.this_update)?, at(THIS_UPDATE)?, "{covered}");
    let next = single.next_update.as_ref().ok_or("no nextUpdate")?;
    assert_eq!(seconds(next)?, at(NEXT_UPDATE)?, "{covered}");
    assert!(single.single_extensions.is_none());
    // RFC 6960, section 4.2.2.3: the responder identified by the hash of
    // its key.
    let signer = certificate(responder)?;
    assert_eq!(data.responder_id, ResponderId::ByKey(key_hash(&signer)?));
    // RFC 6960, section 4.2.1: a delegated responder's certificate in
    // certs; a CA that signs for its own certificates includes none, since
    // the client already has it to check the certificate.
    if responder == issuer_name {
        assert!(basic.certs.is_none(), "{covered}");
    } else {
        assert_eq!(basic.certs.as_deref(), Some([signer.clone()].as_slice()));
    }
    assert_eq!(basic.signature_algorithm, algorithm.identifier()?);
    let spki = signer.tbs_certificate.subject_public_key_info.to_der()?;
    assert!(
        verifies(
            algorithm,
            &spki,
            &data.to_der()?,
            basic.signature.raw_bytes()
        )?,
        "{covered}"
    );
    Ok(())
}

fn status(basic: &BasicOcspResponse) -> Result<CertStatus, Error> {
    Ok(basic
        .tbs_response_data
        .responses
        .first()
        .ok_or("no single response")?
        .cert_status)
}

/// Acceptance criterion 1: every end entity other than the responder has a
/// response, and only those certificates link one.
#[test]
fn every_end_entity_has_a_response() -> TestResult {
    let issuers: BTreeSet<&str> = CERTIFICATES.iter().filter_map(|s| s.issuer).collect();
    let expected: Vec<&str> = CERTIFICATES
        .iter()
        .filter(|s| s.issuer.is_some() && !issuers.contains(s.name) && s.name != RESPONDER)
        .map(|s| s.name)
        .collect();
    assert_eq!(expected, END_ENTITIES);
    for spec in &CERTIFICATES {
        let expected = END_ENTITIES
            .contains(&spec.name)
            .then(|| ocsp_id(spec.name));
        assert_eq!(current_response(spec), expected, "{}", spec.name);
    }
    let names: Vec<String> = responses(VALIDATION_TIME)?
        .into_iter()
        .map(|s| s.name)
        .collect();
    let mut expected: Vec<String> = END_ENTITIES.iter().map(|s| (*s).to_owned()).collect();
    expected.extend(CASES.iter().map(|s| (*s).to_owned()));
    assert_eq!(names, expected);
    for spec in responses(VALIDATION_TIME)?.iter().take(END_ENTITIES.len()) {
        assert_eq!(spec.covered, spec.name);
    }
    assert_eq!(files()?.len(), END_ENTITIES.len() + CASES.len());
    Ok(())
}

/// The revocation date and reason of each serial number that a CRL lists.
type CrlEntries = HashMap<Vec<u8>, (u64, Option<CrlReason>)>;

/// The revoked serial numbers of the current CRL of `issuer`, with the
/// revocation date and reason.
fn crl_entries(issuer: &str) -> Result<CrlEntries, Error> {
    static CRLS: OnceLock<Result<Vec<GeneratedFile>, PkiError>> = OnceLock::new();
    let crls = CRLS
        .get_or_init(|| crl::generate(VALIDATION_TIME))
        .as_deref()
        .map_err(Clone::clone)?;
    let der = &crls
        .iter()
        .find(|f| f.artefact.id == crl::crl_id(issuer))
        .ok_or("no CRL")?
        .contents;
    let list = CertificateList::from_der(der)?;
    let mut revoked = HashMap::new();
    for entry in list.tbs_cert_list.revoked_certificates.unwrap_or_default() {
        let reason = entry
            .crl_entry_extensions
            .as_ref()
            .and_then(|e| e.iter().find(|e| e.extn_id == rfc5280::ID_CE_CRL_REASONS))
            .map(|e| CrlReason::from_der(e.extn_value.as_bytes()))
            .transpose()?;
        revoked.insert(
            entry.serial_number.as_bytes().to_vec(),
            (entry.revocation_date.to_unix_duration().as_secs(), reason),
        );
    }
    Ok(revoked)
}

/// Acceptance criterion 1: each response is signed by `pki/ocsp-responder`
/// for the end entities of `pki/ca-ecdsa` and by the issuing CA itself for
/// the others, with the fixed times, and gives `good` or `revoked` as the
/// CRL of the issuer does, with the same revocation dates and reasons.
#[test]
fn the_responses_agree_with_the_crl_of_their_issuer() -> TestResult {
    let mut found = 0;
    for name in END_ENTITIES {
        let basic = basic(&file(name)?.contents)?;
        let (responder, algorithm) = expected_signer(name)?;
        check_signed(&basic, name, responder, algorithm, PRODUCED_AT)?;
        let issuer = hierarchy::find(name)
            .and_then(|s| s.issuer)
            .ok_or("no issuer")?;
        let revoked = crl_entries(issuer)?;
        let serial = &basic.tbs_response_data.responses[0].cert_id.serial_number;
        match (status(&basic)?, revoked.get(serial.as_bytes())) {
            (CertStatus::Good(_), None) => {}
            (CertStatus::Revoked(info), Some((date, reason))) => {
                found += 1;
                assert_eq!(info.revocation_time.0.to_unix_duration().as_secs(), *date);
                assert_eq!(info.revocation_reason, *reason);
                assert_eq!(info.revocation_reason, Some(CrlReason::KeyCompromise));
            }
            (other, crl) => return Err(format!("{name}: {other:?} against {crl:?}").into()),
        }
        assert!(basic.tbs_response_data.response_extensions.is_none());
    }
    assert_eq!(found, 5);
    Ok(())
}

/// Threat K10: a response for `pki/signer-p256` whose CertID carries a
/// wrong issuer name hash, and one with a wrong issuer key hash (RFC 6960,
/// sections 3.2 and 4.1.1). Everything else is as in `ocsp/signer-p256`.
#[test]
fn the_cert_id_mismatches_change_one_hash_each() -> TestResult {
    for (name, form) in [
        (
            "cert-id-wrong-issuer-name-hash",
            CertIdForm::WrongIssuerNameHash,
        ),
        (
            "cert-id-wrong-issuer-key-hash",
            CertIdForm::WrongIssuerKeyHash,
        ),
    ] {
        let basic = basic(&file(name)?.contents)?;
        check_signed_with(
            &basic,
            "signer-p256",
            (RESPONDER, SignatureAlgorithm::EcdsaSha256),
            PRODUCED_AT,
            form,
        )?;
        assert!(matches!(status(&basic)?, CertStatus::Good(_)));
        let spec = spec(name)?;
        assert_eq!(spec.expected_openssl, OpensslResult::Rejected);
        let Body::Signed(signed) = spec.body else {
            return Err("not signed".into());
        };
        assert_eq!(signed.cert_id, form);
    }
    Ok(())
}

/// Acceptance criterion 2: status `unknown` for `pki/signer-p256`, from
/// `pki/ocsp-responder`.
#[test]
fn the_unknown_response_gives_unknown() -> TestResult {
    let basic = basic(&file("unknown")?.contents)?;
    check_signed(
        &basic,
        "signer-p256",
        RESPONDER,
        SignatureAlgorithm::EcdsaSha256,
        PRODUCED_AT,
    )?;
    assert!(matches!(status(&basic)?, CertStatus::Unknown(_)));
    Ok(())
}

/// Acceptance criterion 2: a response signed by `pki/signer-p384`, issued
/// by the CA of `pki/signer-p256` but without `id-kp-OCSPSigning`
/// (RFC 6960, section 4.2.2.2).
#[test]
fn the_responder_without_ocsp_signing_lacks_only_the_extended_key_usage() -> TestResult {
    let basic = basic(&file("responder-without-ocsp-signing")?.contents)?;
    check_signed(
        &basic,
        "signer-p256",
        "signer-p384",
        SignatureAlgorithm::EcdsaSha384,
        PRODUCED_AT,
    )?;
    assert!(matches!(status(&basic)?, CertStatus::Good(_)));
    let signer = certificate("signer-p384")?;
    let issuer = certificate("ca-ecdsa")?;
    assert_eq!(
        signer.tbs_certificate.issuer,
        issuer.tbs_certificate.subject
    );
    let ocsp_signing = signer
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .filter(|e| e.extn_id == rfc5280::ID_CE_EXT_KEY_USAGE)
        .map(|e| ExtendedKeyUsage::from_der(e.extn_value.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|eku| eku.0.contains(&rfc5280::ID_KP_OCSP_SIGNING));
    assert!(!ocsp_signing);
    // The real responder has it.
    let responder = certificate(RESPONDER)?;
    let eku = responder
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id == rfc5280::ID_CE_EXT_KEY_USAGE)
        .ok_or("no extended key usage")?;
    assert!(
        ExtendedKeyUsage::from_der(eku.extn_value.as_bytes())?
            .0
            .contains(&rfc5280::ID_KP_OCSP_SIGNING)
    );
    Ok(())
}

/// Acceptance criterion 2: `producedAt` one day after the validation time,
/// with the usual `thisUpdate` and `nextUpdate`.
#[test]
fn the_late_response_is_produced_after_the_validation_time() -> TestResult {
    let basic = basic(&file("produced-at-after-validation-time")?.contents)?;
    check_signed(
        &basic,
        "signer-p256",
        RESPONDER,
        SignatureAlgorithm::EcdsaSha256,
        LATE_PRODUCED_AT,
    )?;
    assert!(seconds(&basic.tbs_response_data.produced_at)? > VALIDATION_TIME.unix_timestamp());
    assert!(matches!(status(&basic)?, CertStatus::Good(_)));
    Ok(())
}

/// Acceptance criterion 2: a response with a nonce of 32 octets
/// (RFC 6960, section 4.4.1; RFC 8954, section 2.1), otherwise the same as
/// the response for `pki/signer-p256`.
#[test]
fn the_nonce_response_carries_a_nonce() -> TestResult {
    let basic = basic(&file("nonce")?.contents)?;
    check_signed(
        &basic,
        "signer-p256",
        RESPONDER,
        SignatureAlgorithm::EcdsaSha256,
        PRODUCED_AT,
    )?;
    assert!(matches!(status(&basic)?, CertStatus::Good(_)));
    let extensions = basic
        .tbs_response_data
        .response_extensions
        .as_ref()
        .ok_or("no extensions")?;
    assert_eq!(extensions.len(), 1);
    let nonce = &extensions[0];
    assert_eq!(nonce.extn_id, rfc6960::ID_PKIX_OCSP_NONCE);
    assert!(!nonce.critical);
    let value = OctetString::from_der(nonce.extn_value.as_bytes())?;
    assert_eq!(value.as_bytes().len(), NONCE_LENGTH);
    // The nonce is fixed, so that the response is reproducible: the
    // SHA-256 hash of a label.
    assert_eq!(
        value.as_bytes(),
        sha2::Sha256::digest(b"sigillum-testpki/ocsp-nonce").as_slice()
    );
    Ok(())
}

/// Acceptance criterion 2: `tryLater` and `unauthorized` have no
/// responseBytes (RFC 6960, section 4.2.1).
#[test]
fn the_unsuccessful_responses_have_no_response_bytes() -> TestResult {
    for (name, status, code) in [
        ("try-later", OcspResponseStatus::TryLater, 3),
        ("unauthorized", OcspResponseStatus::Unauthorized, 6),
    ] {
        let der = &file(name)?.contents;
        assert_eq!(der.as_slice(), [0x30, 0x03, 0x0a, 0x01, code]);
        let response = OcspResponse::from_der(der)?;
        assert_eq!(response.response_status, status);
        assert!(response.response_bytes.is_none());
        assert_eq!(unsuccessful(status)?, *der);
        assert_eq!(spec(name)?.body, Body::Unsuccessful(status));
    }
    // A successful response needs responseBytes, so it is refused here.
    assert_eq!(
        unsuccessful(OcspResponseStatus::Successful),
        Err(PkiError::Encoding)
    );
    Ok(())
}

/// Acceptance criterion 3: every response has a manifest entry with its
/// digest, the responder and its chain in its links, and the covered
/// certificate first in its notes.
#[test]
fn every_response_has_a_manifest_entry() -> TestResult {
    let specs = responses(VALIDATION_TIME)?;
    assert_eq!(files()?.len(), specs.len());
    for (file, spec) in files()?.iter().zip(&specs) {
        let artefact = &file.artefact;
        assert_eq!(artefact.id, ocsp_id(&spec.name));
        assert_eq!(
            artefact.path,
            std::path::PathBuf::from(format!("ocsp/{}.der", spec.name))
        );
        assert_eq!(artefact.kind, Kind::OcspResponse);
        assert_eq!(artefact.sha256, sha256_hex(&file.contents));
        assert_eq!(artefact.purpose, spec.purpose);
        assert_eq!(artefact.expected_openssl, spec.expected_openssl);
        assert_eq!(artefact.expected_dss, spec.expected_dss);
        let notes = artefact.notes.as_deref().ok_or("no notes")?;
        let first = format!("Covered certificate: {}.", certificate_id(spec.covered));
        assert!(notes.starts_with(&first), "{notes}");
        assert!(artefact.links.revocation.is_empty());
        assert!(artefact.links.content.is_none());
        match spec.body {
            Body::Signed(signed) => {
                let responder = hierarchy::find(signed.responder).ok_or("no responder")?;
                let mut chain = vec![certificate_id(signed.responder)];
                chain.extend(
                    hierarchy::chain(responder)?
                        .iter()
                        .map(|s| certificate_id(s.name)),
                );
                assert_eq!(artefact.links.issuer, Some(chain[0].clone()));
                assert_eq!(artefact.links.chain, chain);
            }
            Body::Unsuccessful(_) => assert_eq!(artefact.links, Links::default()),
        }
    }
    Ok(())
}

fn indication(indication: Indication, sub_indication: Option<&str>) -> DssResult {
    DssResult::Indication {
        indication,
        sub_indication: sub_indication.map(str::to_owned),
    }
}

/// The expected results: the regular responses inherit the result of the
/// covered certificate; the cases have their own.
#[test]
fn the_expected_results_follow_the_documented_convention() -> TestResult {
    for name in END_ENTITIES {
        let spec = spec(name)?;
        let certificate = hierarchy::find(name).ok_or("no certificate")?;
        // OpenSSL checks the signer at the validation time, and rejects
        // a response whose signer has expired then.
        let signer = hierarchy::find(expected_signer(name)?.0).ok_or("no signer")?;
        let openssl = if signer.not_after.from(VALIDATION_TIME)? < VALIDATION_TIME {
            OpensslResult::Rejected
        } else {
            OpensslResult::Verified
        };
        assert_eq!(spec.expected_openssl, openssl, "{name}");
        assert_eq!(
            spec.expected_dss,
            indication(
                certificate.expected_dss.indication,
                certificate.expected_dss.sub_indication
            ),
            "{name}"
        );
        assert_eq!(spec.covered, certificate.name);
    }
    let chain_failure = indication(
        Indication::Indeterminate,
        Some("CERTIFICATE_CHAIN_GENERAL_FAILURE"),
    );
    let passed = indication(Indication::Passed, None);
    for (name, openssl, dss) in [
        ("unknown", OpensslResult::Verified, chain_failure.clone()),
        (
            "responder-without-ocsp-signing",
            OpensslResult::Rejected,
            chain_failure.clone(),
        ),
        (
            "produced-at-after-validation-time",
            OpensslResult::Verified,
            passed.clone(),
        ),
        ("nonce", OpensslResult::Verified, passed),
        ("try-later", OpensslResult::Rejected, DssResult::Rejected),
        ("unauthorized", OpensslResult::Rejected, DssResult::Rejected),
        (
            "cert-id-wrong-issuer-name-hash",
            OpensslResult::Rejected,
            chain_failure.clone(),
        ),
        (
            "cert-id-wrong-issuer-key-hash",
            OpensslResult::Rejected,
            chain_failure.clone(),
        ),
    ] {
        let spec = spec(name)?;
        assert_eq!(spec.covered, "signer-p256", "{name}");
        assert_eq!(spec.expected_openssl, openssl, "{name}");
        assert_eq!(spec.expected_dss, dss, "{name}");
    }
    Ok(())
}

/// ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, steps 4 and 8: `producedAt`
/// and the validation time fall inside the validity of the certificate
/// that signs each response.
#[test]
fn every_response_is_produced_within_the_validity_of_its_signer() -> TestResult {
    let mut invalid = 0;
    for spec in responses(VALIDATION_TIME)? {
        let Body::Signed(signed) = spec.body else {
            continue;
        };
        let signer = hierarchy::find(signed.responder).ok_or("no signer")?;
        let not_before = signer.not_before.from(VALIDATION_TIME)?;
        let not_after = signer.not_after.from(VALIDATION_TIME)?;
        let produced_at = signed.produced_at.from(VALIDATION_TIME)?;
        assert!(
            not_before <= produced_at && produced_at <= not_after,
            "{}",
            spec.name
        );
        // A response for an end entity whose signer is not valid at the
        // validation time is expected to be rejected by OpenSSL, and only
        // such a response. The corpus has one: pki/ca-expired signed at the
        // instant it expired.
        let valid = not_before <= VALIDATION_TIME && VALIDATION_TIME <= not_after;
        if spec.covered == spec.name {
            assert_eq!(
                valid,
                spec.expected_openssl == OpensslResult::Verified,
                "{}",
                spec.name
            );
            invalid += usize::from(!valid);
        }
    }
    assert_eq!(invalid, 1);
    Ok(())
}

#[test]
fn generation_is_reproducible() -> TestResult {
    assert_eq!(generate(VALIDATION_TIME)?.as_slice(), files()?);
    Ok(())
}

/// The certificate links keep other revocation artefacts, add the response
/// last, drop the responses of this generator and skip other entries.
#[test]
fn certificate_links_replace_only_the_responses_of_this_generator() -> TestResult {
    let mut manifest = Manifest::parse(
        "[header]\nformat-version = 1\nvalidation-time = \"2030-01-15T10:00:00Z\"\nopenssl-version = \"3.0.13\"\ndss-version = \"6.5.1\"\n",
    )?;
    let mut entry = super::super::tests::generated()?
        .iter()
        .find(|f| f.artefact.id == "pki/signer-p256")
        .ok_or("no signer")?
        .artefact
        .clone();
    entry.links.revocation = vec![
        "ocsp/signer-p256".to_owned(),
        "crl/ca-ecdsa".to_owned(),
        "ocsp/old".to_owned(),
        "ocsp/other".to_owned(),
    ];
    let mut other = entry.clone();
    other.id = "pki/signer-p384".to_owned();
    other.kind = Kind::Document;
    other.links.revocation = vec!["ocsp/old".to_owned()];
    let mut root = entry.clone();
    root.id = "pki/root-ca".to_owned();
    root.links.revocation = vec!["ocsp/old".to_owned()];
    manifest.artefacts = vec![entry, other, root];
    link_certificates(
        &mut manifest,
        &["ocsp/signer-p256".to_owned(), "ocsp/old".to_owned()],
    );
    assert_eq!(
        manifest.artefacts[0].links.revocation,
        ["crl/ca-ecdsa", "ocsp/other", "ocsp/signer-p256"]
    );
    // An entry of another kind with a certificate's identifier is left alone.
    assert_eq!(manifest.artefacts[1].links.revocation, ["ocsp/old"]);
    // A certificate without a response loses the links to this generator.
    assert!(manifest.artefacts[2].links.revocation.is_empty());
    // Running again changes nothing.
    let before = manifest.clone();
    link_certificates(&mut manifest, &["ocsp/signer-p256".to_owned()]);
    assert_eq!(manifest, before);
    Ok(())
}

/// Only OCSP responses under `ocsp/` belong to the generator.
#[test]
fn the_generator_owns_the_responses_under_its_directory() -> TestResult {
    let mut artefact = file("signer-p256")?.artefact.clone();
    assert!(generated_here(&artefact));
    artefact.kind = Kind::Crl;
    assert!(!generated_here(&artefact));
    let mut artefact = file("signer-p256")?.artefact.clone();
    artefact.id = "other/signer-p256".to_owned();
    assert!(!generated_here(&artefact));
    Ok(())
}

fn parties<'a>(
    key: &'a KeyPair,
    responder: &'a Certificate,
    issuer: &'a Certificate,
    subject: &'a Certificate,
) -> Parties<'a> {
    Parties {
        responder_key: key,
        responder,
        algorithm: SignatureAlgorithm::EcdsaSha256,
        issuer,
        subject,
        revocation: None,
    }
}

fn regular() -> Signed {
    Signed {
        responder: RESPONDER,
        status: Status::Current,
        produced_at: PRODUCED_AT,
        this_update: THIS_UPDATE,
        next_update: NEXT_UPDATE,
        nonce: false,
        cert_id: CertIdForm::Correct,
    }
}

#[test]
fn sign_reports_times_out_of_range() -> TestResult {
    let key = KeyPair::derive(KeyType::P256, RESPONDER)?;
    let responder = certificate(RESPONDER)?;
    let issuer = certificate("ca-ecdsa")?;
    let subject = certificate("signer-p256")?;
    let far = Offset::years(1_000_000);
    for signed in [
        Signed {
            produced_at: far,
            ..regular()
        },
        Signed {
            this_update: far,
            ..regular()
        },
        Signed {
            next_update: far,
            ..regular()
        },
    ] {
        assert_eq!(
            sign(
                &signed,
                &parties(&key, &responder, &issuer, &subject),
                VALIDATION_TIME
            ),
            Err(PkiError::Time)
        );
    }
    let mut revoked = parties(&key, &responder, &issuer, &subject);
    revoked.revocation = Some(hierarchy::Revocation {
        date: far,
        reason: CrlReason::KeyCompromise,
    });
    assert_eq!(
        sign(&regular(), &revoked, VALIDATION_TIME),
        Err(PkiError::Time)
    );
    Ok(())
}

/// A revocation after `thisUpdate` is not yet known to the responder, as
/// for the CRLs; one at `thisUpdate` is.
#[test]
fn a_revocation_is_reported_from_this_update() -> TestResult {
    let key = KeyPair::derive(KeyType::P256, RESPONDER)?;
    let responder = certificate(RESPONDER)?;
    let issuer = certificate("ca-ecdsa")?;
    let subject = certificate("signer-p256")?;
    for (date, revoked) in [(THIS_UPDATE, true), (Offset::days(0), false)] {
        let mut parties = parties(&key, &responder, &issuer, &subject);
        parties.revocation = Some(hierarchy::Revocation {
            date,
            reason: CrlReason::Superseded,
        });
        let basic = basic(&sign(&regular(), &parties, VALIDATION_TIME)?)?;
        match status(&basic)? {
            CertStatus::Revoked(info) => {
                assert!(revoked);
                assert_eq!(info.revocation_reason, Some(CrlReason::Superseded));
                assert_eq!(seconds(&info.revocation_time)?, at(date)?);
            }
            CertStatus::Good(_) => assert!(!revoked),
            CertStatus::Unknown(_) => return Err("unknown".into()),
        }
    }
    Ok(())
}

/// A key of each type signs with the algorithm that matches it.
#[test]
fn each_algorithm_of_the_test_pki_signs_responses() -> TestResult {
    let issuer = certificate("ca-ecdsa")?;
    let subject = certificate("signer-p256")?;
    for (name, algorithm) in [
        ("ca-rsa", SignatureAlgorithm::RsaPkcs1Sha256),
        ("ca-rsa-pss", SignatureAlgorithm::RsaPssSha256),
        ("signer-p256", SignatureAlgorithm::EcdsaSha256),
        ("signer-p384", SignatureAlgorithm::EcdsaSha384),
        ("signer-p521", SignatureAlgorithm::EcdsaSha512),
        ("signer-ed25519", SignatureAlgorithm::Ed25519),
    ] {
        let spec = hierarchy::find(name).ok_or("no certificate")?;
        let key = KeyPair::derive(spec.key, name)?;
        let signer = certificate(name)?;
        let mut parties = parties(&key, &signer, &issuer, &subject);
        parties.algorithm = algorithm;
        let der = sign(&regular(), &parties, VALIDATION_TIME)?;
        let basic = basic(&der)?;
        assert_eq!(basic.signature_algorithm, algorithm.identifier()?, "{name}");
        let spki = signer.tbs_certificate.subject_public_key_info.to_der()?;
        let message = basic.tbs_response_data.to_der()?;
        assert!(
            verifies(algorithm, &spki, &message, basic.signature.raw_bytes())?,
            "{name}"
        );
    }
    // A key cannot sign with the algorithm of another key type.
    let key = KeyPair::derive(KeyType::P256, RESPONDER)?;
    let responder = certificate(RESPONDER)?;
    let mut mismatched = parties(&key, &responder, &issuer, &subject);
    mismatched.algorithm = SignatureAlgorithm::Ed25519;
    assert_eq!(
        sign(&regular(), &mismatched, VALIDATION_TIME),
        Err(PkiError::Signing)
    );
    // The private key files of the test PKI hold the keys that sign.
    let pem = &super::super::tests::generated()?
        .iter()
        .find(|f| f.artefact.id == key_id(RESPONDER))
        .ok_or("no key")?
        .contents;
    assert_eq!(
        pem,
        KeyPair::derive(KeyType::P256, RESPONDER)?
            .pkcs8_pem()?
            .as_bytes()
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// A response built at any validation time from 1971 to 2200 keeps
    /// its times as offsets of that time and verifies with the key of the
    /// responder.
    #[test]
    fn responses_follow_the_validation_time(seconds_since_1970 in 31_536_000_i64..7_258_118_400) {
        let fail = |e: &dyn std::fmt::Display| TestCaseError::fail(e.to_string());
        let key = KeyPair::derive(KeyType::P256, RESPONDER).map_err(|e| fail(&e))?;
        let responder = certificate(RESPONDER).map_err(|e| fail(&*e))?;
        let issuer = certificate("ca-ecdsa").map_err(|e| fail(&*e))?;
        let subject = certificate("signer-p256").map_err(|e| fail(&*e))?;
        let time = OffsetDateTime::from_unix_timestamp(seconds_since_1970).map_err(|e| fail(&e))?;
        let der = sign(&regular(), &parties(&key, &responder, &issuer, &subject), time)
            .map_err(|e| fail(&e))?;
        let basic = basic(&der).map_err(|e| fail(&*e))?;
        let data = &basic.tbs_response_data;
        let expect = |offset: Offset| offset.from(time).map(OffsetDateTime::unix_timestamp);
        prop_assert_eq!(seconds(&data.produced_at).map_err(|e| fail(&*e))?,
            expect(PRODUCED_AT).map_err(|e| fail(&e))?);
        let single = &data.responses[0];
        prop_assert_eq!(seconds(&single.this_update).map_err(|e| fail(&*e))?,
            expect(THIS_UPDATE).map_err(|e| fail(&e))?);
        let next = single.next_update.as_ref().ok_or_else(|| fail(&"no nextUpdate"))?;
        prop_assert_eq!(seconds(next).map_err(|e| fail(&*e))?,
            expect(NEXT_UPDATE).map_err(|e| fail(&e))?);
        let spki = responder.tbs_certificate.subject_public_key_info.to_der().map_err(|e| fail(&e))?;
        let message = data.to_der().map_err(|e| fail(&e))?;
        prop_assert!(verifies(SignatureAlgorithm::EcdsaSha256, &spki, &message, basic.signature.raw_bytes())
            .map_err(|e| fail(&*e))?);
    }
}

/// The certificates decode from the generated PEM, which the responses
/// embed unchanged.
#[test]
fn the_responder_certificate_is_embedded_unchanged() -> TestResult {
    let pem = &super::super::tests::generated()?
        .iter()
        .find(|f| f.artefact.id == certificate_id(RESPONDER))
        .ok_or("no responder")?
        .contents;
    let responder = Certificate::from_pem(pem)?;
    let basic = basic(&file("signer-p256")?.contents)?;
    assert_eq!(basic.certs.unwrap_or_default(), vec![responder]);
    Ok(())
}

fn signer_with_not_after(not_after: Offset) -> Result<CertSpec, Error> {
    Ok(CertSpec {
        not_after,
        ..*hierarchy::find("ca-rsa").ok_or("no ca-rsa")?
    })
}

/// A signer has expired when its notAfter, an inclusive bound (RFC 5280,
/// section 4.1.2.5), precedes the validation time, counted in calendar
/// years and days.
#[test]
fn a_signer_has_expired_only_after_its_not_after() -> TestResult {
    for (not_after, expired) in [
        (Offset::days(-1), true),
        // notAfter is inclusive: a signer is valid at that instant.
        (Offset::days(0), false),
        (Offset::days(1), false),
        // 2029-01-15 plus 365 days is the validation time itself.
        (
            Offset {
                years: -1,
                days: 365,
            },
            false,
        ),
        // 2031-01-15 less 366 days is the day before.
        (
            Offset {
                years: 1,
                days: -366,
            },
            true,
        ),
    ] {
        let signer = signer_with_not_after(not_after)?;
        assert_eq!(
            expired_at(&signer, VALIDATION_TIME)?,
            expired,
            "{not_after:?}"
        );
    }
    let signer = signer_with_not_after(Offset::years(1_000_000))?;
    assert_eq!(expired_at(&signer, VALIDATION_TIME), Err(PkiError::Time));
    Ok(())
}

/// A revocation counts from thisUpdate on, as in the CRLs: one on or
/// before thisUpdate makes the status revoked, a later one does not.
#[test]
fn a_revocation_counts_from_this_update() -> TestResult {
    let at = |date| hierarchy::Revocation {
        date,
        reason: CrlReason::KeyCompromise,
    };
    assert!(!revoked_at(None, THIS_UPDATE, VALIDATION_TIME)?);
    assert!(revoked_at(
        Some(at(Offset::days(-2))),
        THIS_UPDATE,
        VALIDATION_TIME
    )?);
    assert!(revoked_at(
        Some(at(THIS_UPDATE)),
        THIS_UPDATE,
        VALIDATION_TIME
    )?);
    assert!(!revoked_at(
        Some(at(Offset::days(0))),
        THIS_UPDATE,
        VALIDATION_TIME
    )?);
    assert_eq!(
        revoked_at(
            Some(at(Offset::years(1_000_000))),
            THIS_UPDATE,
            VALIDATION_TIME
        ),
        Err(PkiError::Time)
    );
    // The purpose of each regular response names the status that its
    // response gives.
    for name in END_ENTITIES {
        let certificate = hierarchy::find(name).ok_or("no certificate")?;
        let revoked = revoked_at(certificate.revocation, THIS_UPDATE, VALIDATION_TIME)?;
        let word = if revoked { "revoked" } else { "good" };
        assert!(
            spec(name)?
                .purpose
                .ends_with(&format!("whose status is {word}.")),
            "{name}"
        );
    }
    Ok(())
}

/// Issue #75: a response for `pki/signer-expired` issued before it
/// expired and still fresh at the validation time. It shows no status
/// after expiry, so ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, step 7 and
/// NOTE 8, give OUT_OF_BOUNDS_NO_POE.
#[test]
fn the_response_issued_before_expiry_is_fresh_but_shows_no_later_status() -> TestResult {
    let spec = spec("signer-expired-before-expiry")?;
    assert_eq!(spec.covered, "signer-expired");
    assert_eq!(
        spec.expected_dss,
        indication(Indication::Indeterminate, Some("OUT_OF_BOUNDS_NO_POE"))
    );
    assert!(spec.notes.as_deref().is_some_and(|n| n.contains("DIV-5")));
    let Body::Signed(signed) = spec.body else {
        return Err("not signed".into());
    };
    let not_after = hierarchy::find("signer-expired")
        .ok_or("no certificate")?
        .not_after
        .from(VALIDATION_TIME)?;
    let this_update = signed.this_update.from(VALIDATION_TIME)?;
    let next_update = signed.next_update.from(VALIDATION_TIME)?;
    assert!(this_update < not_after);
    // Fresh under clause 5.2.5.4: issued within nextUpdate minus thisUpdate
    // before the validation time.
    assert!(this_update > VALIDATION_TIME - (next_update - this_update));
    let basic = basic(&file("signer-expired-before-expiry")?.contents)?;
    let single = &basic.tbs_response_data.responses[0];
    assert!(matches!(single.cert_status, CertStatus::Good(_)));
    assert_eq!(seconds(&single.this_update)?, at(signed.this_update)?);
    assert_eq!(
        seconds(&basic.tbs_response_data.produced_at)?,
        at(signed.produced_at)?
    );
    Ok(())
}
