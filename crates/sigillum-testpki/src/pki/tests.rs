// Test code signs and verifies with RSA test keys, which ADR-0010 allows.
#![allow(clippy::disallowed_types)]

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use const_oid::db::{rfc4519, rfc5280, rfc5912, rfc6960, rfc8410};
use der::asn1::{ObjectIdentifier, OctetString};
use der::{Decode, DecodePem, Encode};
use rand_core::RngCore;
use sha2::{Digest, Sha256, Sha384};
use signature::Verifier;
use spki::{DecodePublicKey, SubjectPublicKeyInfoOwned};
use time::OffsetDateTime;
use time::macros::datetime;
use x509_cert::Certificate;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{
    AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, BasicConstraints, CrlDistributionPoints,
    ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectKeyIdentifier,
};

use super::hierarchy::{CERTIFICATES, CertSpec, Offset, Role, ca, chain, find, revoked, signer};
use super::issue::{ORGANISATION, TEST_ARC, UNKNOWN_CRITICAL_EXTENSION, URI_BASE, issue};
use super::keys::{KeyPair, KeyType, RSA_PKCS1_SHA3_256, SignatureAlgorithm};
use super::rng::TestRng;
use super::*;
use crate::manifest::{Indication, Manifest};

pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) const VALIDATION_TIME: OffsetDateTime = datetime!(2030-01-15 10:00:00 UTC);

pub(super) fn generated() -> Result<&'static [GeneratedFile], PkiError> {
    static FILES: OnceLock<Result<Vec<GeneratedFile>, PkiError>> = OnceLock::new();
    FILES
        .get_or_init(|| generate(VALIDATION_TIME))
        .as_deref()
        .map_err(Clone::clone)
}

fn file(id: &str) -> Result<&'static GeneratedFile, Box<dyn std::error::Error>> {
    generated()?
        .iter()
        .find(|f| f.artefact.id == id)
        .ok_or_else(|| format!("no artefact {id}").into())
}

pub(super) fn certificate(name: &str) -> Result<Certificate, Box<dyn std::error::Error>> {
    Ok(Certificate::from_pem(
        &file(&certificate_id(name))?.contents,
    )?)
}

fn spec(name: &str) -> Result<&'static CertSpec, Box<dyn std::error::Error>> {
    find(name).ok_or_else(|| format!("no specification {name}").into())
}

pub(super) fn extension(certificate: &Certificate, oid: ObjectIdentifier) -> Option<&Extension> {
    certificate
        .tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|e| e.extn_id == oid)
}

fn key_usage(certificate: &Certificate) -> Result<KeyUsage, Box<dyn std::error::Error>> {
    let ext = extension(certificate, rfc5280::ID_CE_KEY_USAGE).ok_or("no key usage")?;
    assert!(ext.critical);
    Ok(KeyUsage::from_der(ext.extn_value.as_bytes())?)
}

pub(super) fn to_time(
    time: &x509_cert::time::Time,
) -> Result<OffsetDateTime, Box<dyn std::error::Error>> {
    let seconds = time.to_unix_duration().as_secs();
    Ok(OffsetDateTime::from_unix_timestamp(i64::try_from(
        seconds,
    )?)?)
}

/// Verifies a signature with the RustCrypto verifiers, independently of
/// the signing code.
pub(super) fn verifies(
    algorithm: SignatureAlgorithm,
    spki: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    use SignatureAlgorithm as A;
    Ok(match algorithm {
        A::RsaPkcs1Sha256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(
            rsa::RsaPublicKey::from_public_key_der(spki)?,
        )
        .verify(message, &rsa::pkcs1v15::Signature::try_from(signature)?)
        .is_ok(),
        A::RsaPkcs1Sha3_256 => rsa::pkcs1v15::VerifyingKey::<sha3::Sha3_256>::new(
            rsa::RsaPublicKey::from_public_key_der(spki)?,
        )
        .verify(message, &rsa::pkcs1v15::Signature::try_from(signature)?)
        .is_ok(),
        A::RsaPssSha256 => {
            rsa::pss::VerifyingKey::<Sha256>::new(rsa::RsaPublicKey::from_public_key_der(spki)?)
                .verify(message, &rsa::pss::Signature::try_from(signature)?)
                .is_ok()
        }
        A::RsaPssSha384 => {
            rsa::pss::VerifyingKey::<Sha384>::new(rsa::RsaPublicKey::from_public_key_der(spki)?)
                .verify(message, &rsa::pss::Signature::try_from(signature)?)
                .is_ok()
        }
        A::EcdsaSha256 => p256::ecdsa::VerifyingKey::from_public_key_der(spki)?
            .verify(message, &p256::ecdsa::DerSignature::try_from(signature)?)
            .is_ok(),
        A::EcdsaSha512 => {
            use p521::elliptic_curve::sec1::ToEncodedPoint;
            let point = p521::PublicKey::from_public_key_der(spki)?.to_encoded_point(false);
            p521::ecdsa::VerifyingKey::from_sec1_bytes(point.as_bytes())?
                .verify(message, &p521::ecdsa::Signature::from_der(signature)?)
                .is_ok()
        }
        A::EcdsaSha384 => p384::ecdsa::VerifyingKey::from_public_key_der(spki)?
            .verify(message, &p384::ecdsa::DerSignature::try_from(signature)?)
            .is_ok(),
        A::Ed25519 => ed25519_dalek::VerifyingKey::from_public_key_der(spki)?
            .verify(message, &ed25519_dalek::Signature::from_slice(signature)?)
            .is_ok(),
    })
}

#[test]
fn the_generator_is_reproducible_from_its_label() {
    let mut first = [0; 100];
    let mut second = [0; 100];
    TestRng::new(b"a").fill_bytes(&mut first);
    TestRng::new(b"a").fill_bytes(&mut second);
    assert_eq!(first, second);
    let mut other = [0; 100];
    TestRng::new(b"b").fill_bytes(&mut other);
    assert_ne!(first, other);
}

#[test]
fn the_generator_is_sha256_in_counter_mode() -> TestResult {
    let seed = Sha256::digest(b"sigillum-testpkilabel");
    let block = |counter: u64| {
        let mut hash = Sha256::new();
        hash.update(seed);
        hash.update(counter.to_be_bytes());
        hash.finalize()
    };
    let mut expected = block(0).to_vec();
    expected.extend_from_slice(&block(1));
    let mut rng = TestRng::new(b"label");
    let mut bytes = [0; 64];
    rng.try_fill_bytes(&mut bytes[..5])?;
    rng.fill_bytes(&mut bytes[5..]);
    assert_eq!(bytes.as_slice(), expected.as_slice());
    let mut rng = TestRng::new(b"label");
    assert_eq!(rng.next_u32().to_be_bytes(), expected[..4]);
    assert_eq!(rng.next_u64().to_be_bytes(), expected[4..12]);
    Ok(())
}

#[test]
fn offsets_count_calendar_years_then_days() -> TestResult {
    assert_eq!(
        Offset::years(-2).from(VALIDATION_TIME)?,
        datetime!(2028-01-15 10:00:00 UTC)
    );
    assert_eq!(
        Offset::days(-1).from(VALIDATION_TIME)?,
        datetime!(2030-01-14 10:00:00 UTC)
    );
    assert_eq!(
        Offset { years: 1, days: 1 }.from(VALIDATION_TIME)?,
        datetime!(2031-01-16 10:00:00 UTC)
    );
    assert_eq!(
        Offset::years(1_000_000).from(VALIDATION_TIME),
        Err(PkiError::Time)
    );
    assert_eq!(
        Offset::years(i32::MAX).from(VALIDATION_TIME),
        Err(PkiError::Time)
    );
    assert_eq!(
        Offset::days(i64::MAX / 100_000).from(VALIDATION_TIME),
        Err(PkiError::Time)
    );
    // Day counts whose seconds overflow an i64 are reported, not panicked on.
    for days in [
        i64::MAX,
        i64::MIN,
        i64::MAX / 86_400 + 1,
        i64::MIN / 86_400 - 1,
    ] {
        assert_eq!(
            Offset::days(days).from(VALIDATION_TIME),
            Err(PkiError::Time),
            "{days}"
        );
    }
    assert_eq!(
        Offset::days(-36_500).from(VALIDATION_TIME)?,
        VALIDATION_TIME - time::Duration::days(36_500)
    );
    Ok(())
}

#[test]
fn the_hierarchy_is_consistent() -> TestResult {
    let mut names = HashSet::new();
    let mut serials = HashSet::new();
    for (index, spec) in CERTIFICATES.iter().enumerate() {
        assert!(names.insert(spec.name), "{}", spec.name);
        assert!(serials.insert(spec.serial), "{}", spec.name);
        match spec.issuer {
            None => assert_eq!(spec.role, Role::Root, "{}", spec.name),
            Some(issuer) => {
                let position = CERTIFICATES.iter().position(|s| s.name == issuer);
                assert!(position.is_some_and(|p| p < index), "{}", spec.name);
            }
        }
    }
    assert_eq!(
        CERTIFICATES.iter().filter(|s| s.role == Role::Root).count(),
        1
    );
    assert_eq!(chain(spec("signer-p256")?)?.len(), 2);
    assert!(chain(spec("root-ca")?)?.is_empty());
    let orphan = CertSpec {
        issuer: Some("nobody"),
        ..*spec("signer-p256")?
    };
    assert_eq!(
        chain(&orphan),
        Err(PkiError::UnknownIssuer("nobody".to_owned()))
    );
    Ok(())
}

/// Acceptance criterion 1: one root CA, one issuing CA per signature
/// family, and the end-entity certificates of every algorithm in scope.
#[test]
fn every_algorithm_in_scope_has_a_signing_certificate() -> TestResult {
    use SignatureAlgorithm as A;
    let families: HashSet<_> = CERTIFICATES
        .iter()
        .filter(|s| s.role == Role::IssuingCa && s.not_after.years > 0)
        .map(|s| {
            CERTIFICATES
                .iter()
                .filter(|ee| ee.issuer == Some(s.name) && ee.role == Role::Signer)
                .map(|ee| match ee.algorithm {
                    A::RsaPkcs1Sha256 | A::RsaPkcs1Sha3_256 => "rsa-pkcs1",
                    A::RsaPssSha256 | A::RsaPssSha384 => "rsa-pss",
                    A::EcdsaSha256 | A::EcdsaSha384 | A::EcdsaSha512 => "ecdsa",
                    A::Ed25519 => "ed25519",
                })
                .collect::<HashSet<_>>()
        })
        .filter(|families| families.len() == 1)
        .flatten()
        .collect();
    assert_eq!(
        families,
        HashSet::from(["rsa-pkcs1", "rsa-pss", "ecdsa", "ed25519"])
    );
    let signers: Vec<(KeyType, SignatureAlgorithm)> = CERTIFICATES
        .iter()
        .filter(|s| s.role == Role::Signer)
        .map(|s| (s.key, s.algorithm))
        .collect();
    for wanted in [
        (KeyType::Rsa(2048), A::RsaPkcs1Sha256),
        (KeyType::Rsa(3072), A::RsaPkcs1Sha256),
        (KeyType::Rsa(3072), A::RsaPssSha256),
        (KeyType::Rsa(3072), A::RsaPssSha384),
        (KeyType::Ed25519, A::Ed25519),
    ] {
        assert!(signers.contains(&wanted), "{wanted:?}");
    }
    for curve in [KeyType::P256, KeyType::P384, KeyType::P521] {
        assert!(signers.iter().any(|(key, _)| *key == curve), "{curve:?}");
    }
    assert!(signers.contains(&(KeyType::P521, A::EcdsaSha512)));
    assert_eq!(spec("ca-ecdsa-p521")?.key, KeyType::P521);
    assert!(signers.iter().any(|(_, a)| *a == A::RsaPkcs1Sha3_256));
    Ok(())
}

#[test]
fn algorithm_identifiers_have_the_specified_encoding() -> TestResult {
    use SignatureAlgorithm as A;
    let der = |a: A| a.identifier().and_then(|i| keys::to_der(&i));
    assert_eq!(
        der(A::RsaPkcs1Sha256)?,
        [
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
            0x00
        ]
    );
    assert_eq!(
        der(A::RsaPkcs1Sha3_256)?,
        [
            0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0e, 0x05,
            0x00
        ]
    );
    assert_eq!(
        der(A::EcdsaSha256)?,
        [
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
        ]
    );
    assert_eq!(
        der(A::EcdsaSha384)?,
        [
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03
        ]
    );
    assert_eq!(
        der(A::EcdsaSha512)?,
        [
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04
        ]
    );
    assert_eq!(der(A::Ed25519)?, [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]);
    // RFC 4055, sections 2.1, 2.2 and 3.1: SHA-2 identifiers with NULL
    // parameters, MGF1 with the same hash, a salt as long as the hash, and
    // the default trailer field omitted.
    for (algorithm, hash, salt) in [
        (A::RsaPssSha256, rfc5912::ID_SHA_256, 32),
        (A::RsaPssSha384, rfc5912::ID_SHA_384, 48),
    ] {
        let identifier = algorithm.identifier()?;
        assert_eq!(identifier.oid, rfc5912::ID_RSASSA_PSS);
        let parameters = identifier.parameters.ok_or("no parameters")?;
        let encoded = parameters.to_der()?;
        let params = rsa::pkcs1::RsaPssParams::from_der(&encoded)?;
        assert_eq!(params.hash.oid, hash);
        assert_eq!(params.hash.parameters, Some(der::asn1::AnyRef::NULL));
        assert_eq!(params.mask_gen.oid, rfc5912::ID_MGF_1);
        let mgf_hash = params.mask_gen.parameters.ok_or("no MGF1 hash")?;
        assert_eq!(mgf_hash.oid, hash);
        assert_eq!(params.salt_len, salt);
        assert_eq!(params.trailer_field, rsa::pkcs1::TrailerField::BC);
        // The trailer field is the last element; with its default it is absent.
        assert!(
            !parameters
                .value()
                .ends_with(&[0xa3, 0x03, 0x02, 0x01, 0x01])
        );
    }
    Ok(())
}

#[test]
fn a_key_signs_only_with_its_own_algorithms() -> TestResult {
    let p256 = KeyPair::derive(KeyType::P256, "test/p256")?;
    for algorithm in [
        SignatureAlgorithm::RsaPkcs1Sha256,
        SignatureAlgorithm::RsaPssSha256,
        SignatureAlgorithm::EcdsaSha384,
        SignatureAlgorithm::Ed25519,
    ] {
        assert_eq!(p256.sign(algorithm, b"m"), Err(PkiError::KeyMismatch));
    }
    let p521 = KeyPair::derive(KeyType::P521, "test/p521")?;
    assert_eq!(
        p521.sign(SignatureAlgorithm::EcdsaSha384, b"m"),
        Err(PkiError::KeyMismatch)
    );
    let ed25519 = KeyPair::derive(KeyType::Ed25519, "test/ed25519")?;
    assert_eq!(
        ed25519.sign(SignatureAlgorithm::EcdsaSha256, b"m"),
        Err(PkiError::KeyMismatch)
    );
    Ok(())
}

#[test]
fn keys_are_derived_from_their_label() -> TestResult {
    for key_type in [
        KeyType::P256,
        KeyType::P384,
        KeyType::P521,
        KeyType::Ed25519,
        KeyType::Rsa(1024),
    ] {
        let a = KeyPair::derive(key_type, "test/a")?;
        let b = KeyPair::derive(key_type, "test/a")?;
        let c = KeyPair::derive(key_type, "test/c")?;
        assert_eq!(a.pkcs8_pem()?, b.pkcs8_pem()?, "{key_type:?}");
        assert_ne!(a.pkcs8_pem()?, c.pkcs8_pem()?, "{key_type:?}");
        assert_eq!(a.key_type(), key_type);
    }
    assert_eq!(
        KeyPair::derive(KeyType::Rsa(8), "test/tiny").err(),
        Some(PkiError::KeyGeneration)
    );
    Ok(())
}

#[test]
fn signatures_are_reproducible() -> TestResult {
    let rsa = KeyPair::derive(KeyType::Rsa(1024), "test/rsa")?;
    for algorithm in [
        SignatureAlgorithm::RsaPkcs1Sha256,
        SignatureAlgorithm::RsaPkcs1Sha3_256,
        SignatureAlgorithm::RsaPssSha256,
        SignatureAlgorithm::RsaPssSha384,
    ] {
        let first = rsa.sign(algorithm, b"message")?;
        assert_eq!(first, rsa.sign(algorithm, b"message")?);
        assert!(verifies(algorithm, &rsa.spki_der()?, b"message", &first)?);
        assert!(!verifies(algorithm, &rsa.spki_der()?, b"other", &first)?);
    }
    // RSASSA-PSS salts differ between messages.
    let a = rsa.sign(SignatureAlgorithm::RsaPssSha256, b"a")?;
    let b = rsa.sign(SignatureAlgorithm::RsaPssSha256, b"b")?;
    let spki = rsa.spki_der()?;
    assert!(!verifies(
        SignatureAlgorithm::RsaPssSha256,
        &spki,
        b"b",
        &a
    )?);
    assert!(verifies(SignatureAlgorithm::RsaPssSha256, &spki, b"b", &b)?);
    // ECDSA on P-521: the nonce comes from the message, so signatures of
    // one message repeat and signatures of two messages differ.
    let p521 = KeyPair::derive(KeyType::P521, "test/p521-sign")?;
    let spki = p521.spki_der()?;
    let first = p521.sign(SignatureAlgorithm::EcdsaSha512, b"message")?;
    assert_eq!(
        first,
        p521.sign(SignatureAlgorithm::EcdsaSha512, b"message")?
    );
    assert!(verifies(
        SignatureAlgorithm::EcdsaSha512,
        &spki,
        b"message",
        &first
    )?);
    assert!(!verifies(
        SignatureAlgorithm::EcdsaSha512,
        &spki,
        b"other",
        &first
    )?);
    let other = p521.sign(SignatureAlgorithm::EcdsaSha512, b"other")?;
    assert_ne!(first.get(..40), other.get(..40));
    Ok(())
}

/// Private keys are PKCS#8 (RFC 5958) in PEM with LF line endings.
#[test]
fn private_keys_are_pkcs8_pem() -> TestResult {
    for spec in &CERTIFICATES {
        let file = file(&key_id(spec.name))?;
        let text = std::str::from_utf8(&file.contents)?;
        assert!(
            text.starts_with("-----BEGIN PRIVATE KEY-----\n"),
            "{}",
            spec.name
        );
        assert!(
            text.ends_with("-----END PRIVATE KEY-----\n"),
            "{}",
            spec.name
        );
        assert!(!text.contains('\r'));
        let (label, der) =
            der::pem::decode_vec(&file.contents).map_err(|e| format!("{}: {e}", spec.name))?;
        assert_eq!(label, "PRIVATE KEY");
        let info = pkcs8::PrivateKeyInfo::from_der(&der)?;
        let certificate = certificate(spec.name)?;
        let spki = &certificate.tbs_certificate.subject_public_key_info;
        assert_eq!(info.algorithm.oid, spki.algorithm.oid, "{}", spec.name);
        // RFC 8410, section 7: the version 1 structure, without public key.
        if spec.key == KeyType::Ed25519 {
            assert!(info.public_key.is_none());
        }
        let matches = match spec.key {
            KeyType::Rsa(_) => {
                use pkcs8::DecodePrivateKey;
                rsa::RsaPrivateKey::from_pkcs8_der(&der)?.to_public_key()
                    == rsa::RsaPublicKey::from_public_key_der(&spki.to_der()?)?
            }
            KeyType::P256 => {
                use pkcs8::DecodePrivateKey;
                p256::SecretKey::from_pkcs8_der(&der)?.public_key()
                    == p256::PublicKey::from_public_key_der(&spki.to_der()?)?
            }
            KeyType::P384 => {
                use pkcs8::DecodePrivateKey;
                p384::SecretKey::from_pkcs8_der(&der)?.public_key()
                    == p384::PublicKey::from_public_key_der(&spki.to_der()?)?
            }
            KeyType::P521 => {
                use pkcs8::DecodePrivateKey;
                p521::SecretKey::from_pkcs8_der(&der)?.public_key()
                    == p521::PublicKey::from_public_key_der(&spki.to_der()?)?
            }
            KeyType::Ed25519 => {
                use pkcs8::DecodePrivateKey;
                ed25519_dalek::SigningKey::from_pkcs8_der(&der)?.verifying_key()
                    == ed25519_dalek::VerifyingKey::from_public_key_der(&spki.to_der()?)?
            }
        };
        assert!(matches, "{}", spec.name);
    }
    Ok(())
}

/// Acceptance criteria 1 to 5: every certificate is parsed and its fields
/// are checked against its specification, RFC 5280, sections 4.1 and 4.2.
#[test]
fn every_certificate_matches_its_specification() -> TestResult {
    let mut subject_key_ids: HashMap<&str, Vec<u8>> = HashMap::new();
    for spec in &CERTIFICATES {
        let cert = certificate(spec.name)?;
        let tbs = &cert.tbs_certificate;
        let name = spec.name;
        assert_eq!(tbs.version, x509_cert::Version::V3, "{name}");
        let serial = u64::from_str_radix(&format!("{}", tbs.serial_number).replace(':', ""), 16)?;
        assert_eq!(serial, u64::from(spec.serial), "{name}");
        let identifier = spec.algorithm.identifier()?;
        assert_eq!(tbs.signature, identifier, "{name}");
        assert_eq!(cert.signature_algorithm, identifier, "{name}");

        // Validity, from the fixed validation time, as UTCTime.
        let validity = &tbs.validity;
        assert_eq!(
            to_time(&validity.not_before)?,
            spec.not_before.from(VALIDATION_TIME)?,
            "{name}"
        );
        assert_eq!(
            to_time(&validity.not_after)?,
            spec.not_after.from(VALIDATION_TIME)?,
            "{name}"
        );
        assert!(matches!(
            validity.not_before,
            x509_cert::time::Time::UtcTime(_)
        ));
        assert!(matches!(
            validity.not_after,
            x509_cert::time::Time::UtcTime(_)
        ));

        // Subject: the organisation, then the common name, as UTF8String.
        let attributes: Vec<(ObjectIdentifier, String)> = tbs
            .subject
            .0
            .iter()
            .flat_map(|rdn| rdn.0.iter())
            .map(|atv| {
                (
                    atv.oid,
                    der::asn1::Utf8StringRef::try_from(&atv.value)
                        .map(|s| s.as_str().to_owned())
                        .unwrap_or_default(),
                )
            })
            .collect();
        assert_eq!(
            attributes,
            [
                (rfc4519::O, ORGANISATION.to_owned()),
                (rfc4519::CN, spec.common_name.to_owned())
            ],
            "{name}"
        );

        // Subject public key.
        let key = KeyPair::derive(spec.key, spec.name)?;
        assert_eq!(
            tbs.subject_public_key_info.to_der()?,
            key.spki_der()?,
            "{name}"
        );

        // Issuer name and signature.
        let issuer = match spec.issuer {
            Some(issuer) => certificate(issuer)?,
            None => cert.clone(),
        };
        assert_eq!(
            tbs.issuer.to_der()?,
            issuer.tbs_certificate.subject.to_der()?,
            "{name}"
        );
        assert!(
            verifies(
                spec.algorithm,
                &issuer.tbs_certificate.subject_public_key_info.to_der()?,
                &tbs.to_der()?,
                cert.signature.raw_bytes(),
            )?,
            "{name}"
        );
        assert!(tbs.issuer_unique_id.is_none() && tbs.subject_unique_id.is_none());

        check_extensions(spec, &cert, &issuer, &mut subject_key_ids)?;
    }
    Ok(())
}

fn check_extensions(
    spec: &CertSpec,
    certificate: &Certificate,
    issuer: &Certificate,
    subject_key_ids: &mut HashMap<&str, Vec<u8>>,
) -> TestResult {
    let name = spec.name;
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or("no extensions")?;
    let oids: Vec<ObjectIdentifier> = extensions.iter().map(|e| e.extn_id).collect();
    let mut expected = vec![rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER];
    if spec.issuer.is_some() {
        expected.push(rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER);
    }
    expected.push(rfc5280::ID_CE_KEY_USAGE);
    if matches!(
        spec.role,
        Role::Root | Role::IssuingCa | Role::CaWithoutCaFlag
    ) {
        expected.push(rfc5280::ID_CE_BASIC_CONSTRAINTS);
    }
    if matches!(spec.role, Role::TimeStamping | Role::OcspSigning) {
        expected.push(rfc5280::ID_CE_EXT_KEY_USAGE);
    }
    if spec.issuer.is_some() {
        expected.push(rfc5280::ID_CE_CRL_DISTRIBUTION_POINTS);
        expected.push(rfc5280::ID_PE_AUTHORITY_INFO_ACCESS);
    }
    if spec.role == Role::OcspSigning {
        expected.push(rfc6960::ID_PKIX_OCSP_NOCHECK);
    }
    if spec.role == Role::SignerWithUnknownCriticalExtension {
        expected.push(UNKNOWN_CRITICAL_EXTENSION);
    }
    assert_eq!(oids, expected, "{name}");

    // RFC 5280, section 4.2.1.2, and RFC 7093, section 2, method 1.
    let ski = extension(certificate, rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER).ok_or("no SKI")?;
    assert!(!ski.critical);
    let ski = SubjectKeyIdentifier::from_der(ski.extn_value.as_bytes())?;
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    let hash = Sha256::digest(spki.subject_public_key.raw_bytes());
    assert_eq!(ski.0.as_bytes(), &hash[..20], "{name}");
    subject_key_ids.insert(name, ski.0.as_bytes().to_vec());

    // RFC 5280, section 4.2.1.1: the issuer's subject key identifier.
    if let Some(issuer_name) = spec.issuer {
        let aki =
            extension(certificate, rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER).ok_or("no AKI")?;
        assert!(!aki.critical);
        let aki = AuthorityKeyIdentifier::from_der(aki.extn_value.as_bytes())?;
        let issuer_ski = subject_key_ids.get(issuer_name).ok_or("issuer not seen")?;
        assert_eq!(
            aki.key_identifier.as_ref().map(OctetString::as_bytes),
            Some(issuer_ski.as_slice()),
            "{name}"
        );
        assert!(aki.authority_cert_issuer.is_none() && aki.authority_cert_serial_number.is_none());
    }

    // RFC 5280, section 4.2.1.3.
    let usage = key_usage(certificate)?;
    let expected_usage = match spec.role {
        Role::Root | Role::IssuingCa | Role::CaWithoutCaFlag | Role::CaWithoutBasicConstraints => {
            KeyUsages::KeyCertSign | KeyUsages::CRLSign
        }
        Role::Signer | Role::SignerWithUnknownCriticalExtension => {
            KeyUsages::DigitalSignature | KeyUsages::NonRepudiation
        }
        _ => KeyUsages::DigitalSignature.into(),
    };
    assert_eq!(usage.0, expected_usage, "{name}");

    // RFC 5280, section 4.2.1.9.
    if let Some(bc) = extension(certificate, rfc5280::ID_CE_BASIC_CONSTRAINTS) {
        assert!(bc.critical);
        let bc = BasicConstraints::from_der(bc.extn_value.as_bytes())?;
        let expected = match spec.role {
            Role::Root => (true, None),
            Role::IssuingCa => (true, Some(0)),
            _ => (false, None),
        };
        assert_eq!((bc.ca, bc.path_len_constraint), expected, "{name}");
    }

    // RFC 5280, section 4.2.1.12; RFC 3161, section 2.3; RFC 6960, section 4.2.2.2.
    if let Some(eku) = extension(certificate, rfc5280::ID_CE_EXT_KEY_USAGE) {
        let purposes = ExtendedKeyUsage::from_der(eku.extn_value.as_bytes())?.0;
        match spec.role {
            Role::TimeStamping => {
                assert!(eku.critical);
                assert_eq!(purposes, [rfc5280::ID_KP_TIME_STAMPING]);
            }
            _ => {
                assert!(!eku.critical);
                assert_eq!(purposes, [rfc5280::ID_KP_OCSP_SIGNING]);
            }
        }
    }

    // RFC 6960, section 4.2.2.2.1: a NULL value, non-critical.
    if let Some(nocheck) = extension(certificate, rfc6960::ID_PKIX_OCSP_NOCHECK) {
        assert!(!nocheck.critical);
        assert_eq!(nocheck.extn_value.as_bytes(), [0x05, 0x00]);
    }

    // RFC 5280, sections 4.2.1.13 and 4.2.2.1: URIs under example.invalid.
    if let Some(issuer_name) = spec.issuer {
        let dp = extension(certificate, rfc5280::ID_CE_CRL_DISTRIBUTION_POINTS)
            .ok_or("no CRL distribution points")?;
        assert!(!dp.critical);
        let points = CrlDistributionPoints::from_der(dp.extn_value.as_bytes())?.0;
        let crl_uri = format!("{URI_BASE}/crl/{issuer_name}.crl");
        assert_eq!(
            points,
            [DistributionPoint {
                distribution_point: Some(DistributionPointName::FullName(vec![
                    GeneralName::UniformResourceIdentifier(der::asn1::Ia5String::new(&crl_uri)?)
                ])),
                reasons: None,
                crl_issuer: None,
            }]
        );
        let aia = extension(certificate, rfc5280::ID_PE_AUTHORITY_INFO_ACCESS).ok_or("no AIA")?;
        assert!(!aia.critical);
        let access: Vec<(ObjectIdentifier, String)> =
            AuthorityInfoAccessSyntax::from_der(aia.extn_value.as_bytes())?
                .0
                .into_iter()
                .map(|d| match d.access_location {
                    GeneralName::UniformResourceIdentifier(uri) => {
                        (d.access_method, uri.to_string())
                    }
                    _ => (d.access_method, String::new()),
                })
                .collect();
        let mut expected = vec![(
            rfc5280::ID_AD_CA_ISSUERS,
            format!("{URI_BASE}/ca/{issuer_name}.cer"),
        )];
        if matches!(
            spec.role,
            Role::Signer
                | Role::SignerWithoutNonRepudiation
                | Role::SignerWithUnknownCriticalExtension
                | Role::TimeStamping
        ) {
            expected.push((
                rfc5280::ID_AD_OCSP,
                format!("{URI_BASE}/ocsp/{issuer_name}"),
            ));
        }
        assert_eq!(access, expected, "{name}");
        for (_, uri) in &access {
            assert!(uri.starts_with("http://example.invalid/"), "{uri}");
        }
    }
    // The issuer certificate is only used for its subject key identifier above.
    let _ = issuer;
    Ok(())
}

/// Acceptance criterion 3.
#[test]
fn validity_cases_are_tied_to_the_validation_time() -> TestResult {
    let window =
        |name: &str| -> Result<(OffsetDateTime, OffsetDateTime), Box<dyn std::error::Error>> {
            let certificate = certificate(name)?;
            let validity = &certificate.tbs_certificate.validity;
            Ok((
                to_time(&validity.not_before)?,
                to_time(&validity.not_after)?,
            ))
        };
    let valid =
        |w: (OffsetDateTime, OffsetDateTime)| w.0 <= VALIDATION_TIME && VALIDATION_TIME <= w.1;
    let one_day = time::Duration::days(1);
    for spec in CERTIFICATES.iter().filter(|s| {
        !matches!(
            s.name,
            "signer-expired" | "signer-not-yet-valid" | "ca-expired"
        )
    }) {
        assert!(valid(window(spec.name)?), "{}", spec.name);
    }
    assert_eq!(window("signer-expired")?.1, VALIDATION_TIME - one_day);
    assert_eq!(window("signer-not-yet-valid")?.0, VALIDATION_TIME + one_day);
    assert_eq!(window("ca-expired")?.1, VALIDATION_TIME - one_day);
    assert_eq!(spec("signer-under-expired-ca")?.issuer, Some("ca-expired"));
    // The end entity was issued while its CA was valid.
    assert!(window("signer-under-expired-ca")?.0 > window("ca-expired")?.0);
    Ok(())
}

/// The predictions of the validity cases, from ETSI EN 319 102-1 V1.4.1,
/// clause 5.2.6.4 (issue #75). The revocation data that each certificate
/// links is issued one day before the validation time: at the `notAfter`
/// of the expired certificates, which shows them not revoked over their
/// whole validity (step 7), and before the `notBefore` of the certificate
/// not yet valid, which it cannot cover (step 4 e)).
#[test]
fn validity_cases_have_the_predictions_of_the_standard() -> TestResult {
    let result = |name: &str| -> Result<(Indication, Option<&str>), Box<dyn std::error::Error>> {
        let spec = spec(name)?;
        Ok((
            spec.expected_dss.indication,
            spec.expected_dss.sub_indication,
        ))
    };
    // Step 7 and its NOTE 8: the revocation data of the expired
    // certificates were issued at their notAfter, so they show no status
    // after expiry.
    for name in ["signer-expired", "ca-expired"] {
        assert_eq!(
            result(name)?,
            (Indication::Indeterminate, Some("OUT_OF_BOUNDS_NO_POE")),
            "{name}"
        );
        assert!(
            spec(name)?
                .notes
                .is_some_and(|notes| notes.contains("NOTE 8") && notes.contains("DIV-5")),
            "{name}"
        );
    }
    let response = ocsp::responses(VALIDATION_TIME)?
        .into_iter()
        .find(|spec| spec.name == "signer-expired")
        .and_then(|spec| spec.notes)
        .ok_or("no notes for ocsp/signer-expired")?;
    assert!(
        response.contains("NOTE 8") && response.contains("DIV-5"),
        "{response}"
    );
    // Step 4 excludes the validity of the issuer of the revocation data,
    // which NOTE 6 defers to step 8.
    assert_eq!(
        result("signer-under-expired-ca")?,
        (
            Indication::Indeterminate,
            Some("REVOCATION_OUT_OF_BOUNDS_NO_POE")
        )
    );
    assert!(
        spec("signer-under-expired-ca")?
            .notes
            .is_some_and(|notes| notes.contains("NOTE 6") && notes.contains("step 8"))
    );
    assert_eq!(
        result("signer-not-yet-valid")?,
        (
            Indication::Indeterminate,
            Some("CERTIFICATE_CHAIN_GENERAL_FAILURE")
        )
    );
    assert!(
        spec("signer-not-yet-valid")?
            .notes
            .is_some_and(|notes| notes.contains("step 4 e)")
                && notes.contains("known to contain revocation status information")
                && notes.contains("RevocationAfterCertificateIssuance"))
    );
    Ok(())
}

/// No note of a CRL or an OCSP response guesses a DSS result: each states
/// what DSS 6.5.1 gives under the aligned policy of ADR-0023 (issue #75).
#[test]
fn notes_state_the_results_of_dss_rather_than_guess_them() -> TestResult {
    let mut notes: Vec<String> = crl::CRLS
        .iter()
        .filter_map(|spec| spec.notes.map(str::to_owned))
        .collect();
    notes.extend(
        ocsp::responses(VALIDATION_TIME)?
            .into_iter()
            .filter_map(|spec| spec.notes),
    );
    assert!(notes.len() > 10);
    for note in &notes {
        assert!(!note.contains("likely to report"), "{note}");
        assert!(!note.contains("ignores it instead"), "{note}");
    }
    for name in ["try-later", "unauthorized"] {
        let note = ocsp::responses(VALIDATION_TIME)?
            .into_iter()
            .find(|spec| spec.name == name)
            .and_then(|spec| spec.notes)
            .ok_or("no notes")?;
        assert!(note.contains("the oracle gives rejected"), "{note}");
    }
    let responder = ocsp::responses(VALIDATION_TIME)?
        .into_iter()
        .find(|spec| spec.name == "responder-without-ocsp-signing")
        .and_then(|spec| spec.notes)
        .ok_or("no notes for responder-without-ocsp-signing")?;
    assert!(responder.contains("DIV-3"), "{responder}");
    assert!(responder.contains("crl/ca-ecdsa"), "{responder}");
    Ok(())
}

/// Acceptance criterion 4.
#[test]
fn misconfiguration_cases_have_their_defect() -> TestResult {
    let usage = key_usage(&certificate("signer-without-non-repudiation")?)?;
    assert!(!usage.0.contains(KeyUsages::NonRepudiation));
    assert!(usage.0.contains(KeyUsages::DigitalSignature));
    let ca = certificate("ca-without-ca-flag")?;
    assert!(key_usage(&ca)?.0.contains(KeyUsages::KeyCertSign));
    let bc = extension(&ca, rfc5280::ID_CE_BASIC_CONSTRAINTS).ok_or("no basic constraints")?;
    assert!(!BasicConstraints::from_der(bc.extn_value.as_bytes())?.ca);
    // DER omits a cA that has its default value, FALSE.
    assert_eq!(bc.extn_value.as_bytes(), [0x30, 0x00]);
    assert_eq!(
        spec("signer-under-ca-without-ca-flag")?.issuer,
        Some("ca-without-ca-flag")
    );
    // RFC 5280, section 4.2.1.9: the extension is absent altogether.
    let ca = certificate("ca-without-basic-constraints")?;
    assert!(key_usage(&ca)?.0.contains(KeyUsages::KeyCertSign));
    assert!(extension(&ca, rfc5280::ID_CE_BASIC_CONSTRAINTS).is_none());
    assert_eq!(
        spec("signer-under-ca-without-basic-constraints")?.issuer,
        Some("ca-without-basic-constraints")
    );
    // An unknown extension, critical, with a DER NULL value.
    let unknown = certificate("signer-unknown-critical-extension")?;
    let ext = extension(&unknown, UNKNOWN_CRITICAL_EXTENSION).ok_or("no unknown extension")?;
    assert!(ext.critical);
    assert_eq!(ext.extn_value.as_bytes(), [0x05, 0x00]);
    Ok(())
}

/// The test OIDs sit under the RFC 5612 documentation enterprise number.
#[test]
fn test_oids_use_the_documentation_enterprise_number() {
    assert_eq!(TEST_ARC.to_string(), "1.3.6.1.4.1.32473.1");
    assert_eq!(
        UNKNOWN_CRITICAL_EXTENSION.to_string(),
        "1.3.6.1.4.1.32473.1.1"
    );
    assert_eq!(UNKNOWN_CRITICAL_EXTENSION.parent(), Some(TEST_ARC));
}

/// Acceptance criteria 6 and 7.
#[test]
fn every_file_has_a_manifest_entry() -> TestResult {
    let files = generated()?;
    assert_eq!(files.len(), 2 * CERTIFICATES.len());
    let mut manifest = Manifest::parse(
        "[header]\nformat-version = 3\nvalidation-time = \"2030-01-15T10:00:00Z\"\nopenssl-version = \"3.5.9\"\ndss-version = \"6.5.1\"\n",
    )?;
    for file in files {
        let artefact = &file.artefact;
        assert_eq!(artefact.sha256, sha256_hex(&file.contents));
        let path = artefact.path.to_string_lossy().into_owned();
        match artefact.kind {
            Kind::Certificate => {
                assert_eq!(path, format!("{}.pem", artefact.id));
                assert_eq!(artefact.expected_openssl == OpensslResult::Verified, {
                    matches!(
                        artefact.expected_dss,
                        DssResult::Indication {
                            indication: Indication::Passed,
                            ..
                        }
                    )
                });
            }
            Kind::PrivateKey => {
                assert!(path.starts_with("pki/keys/"), "{path}");
                assert!(path.ends_with(".test-key.pem"), "{path}");
                assert_eq!(artefact.expected_openssl, OpensslResult::Parsed);
                assert_eq!(artefact.expected_dss, DssResult::NotApplicable);
            }
            other => return Err(format!("unexpected kind {other:?}").into()),
        }
        manifest.upsert(artefact.clone());
    }
    let reparsed = Manifest::parse(&manifest.to_toml())?;
    assert_eq!(reparsed, manifest);
    let leaf = reparsed
        .artefacts
        .iter()
        .find(|a| a.id == "pki/signer-rsa-pss-sha256")
        .ok_or("no leaf")?;
    assert_eq!(leaf.links.issuer.as_deref(), Some("pki/ca-rsa-pss"));
    assert_eq!(leaf.links.chain, ["pki/ca-rsa-pss", "pki/root-ca"]);
    Ok(())
}

#[test]
fn generation_is_reproducible() -> TestResult {
    let again = generate(VALIDATION_TIME)?;
    assert_eq!(again.as_slice(), generated()?);
    Ok(())
}

/// The x509-cert path also signs a self-signed certificate, and reports a
/// signing key that cannot sign with the requested algorithm.
#[test]
fn issue_handles_self_signed_and_mismatched_keys() -> TestResult {
    let key = KeyPair::derive(KeyType::Rsa(1024), "test/self-signed")?;
    let spec = CertSpec {
        issuer: None,
        algorithm: SignatureAlgorithm::RsaPssSha256,
        role: Role::Root,
        ..*super::hierarchy::find("root-ca").ok_or("no root")?
    };
    let certificate = Certificate::from_der(&issue(&spec, &key, None, VALIDATION_TIME)?)?;
    let tbs = &certificate.tbs_certificate;
    assert_eq!(tbs.issuer, tbs.subject);
    assert!(verifies(
        SignatureAlgorithm::RsaPssSha256,
        &key.spki_der()?,
        &tbs.to_der()?,
        certificate.signature.raw_bytes()
    )?);
    let p256 = KeyPair::derive(KeyType::P256, "test/mismatch")?;
    for algorithm in [
        SignatureAlgorithm::RsaPssSha256,
        SignatureAlgorithm::Ed25519,
    ] {
        let spec = CertSpec { algorithm, ..spec };
        assert!(
            issue(&spec, &p256, None, VALIDATION_TIME).is_err(),
            "{algorithm:?}"
        );
    }
    let spec = CertSpec {
        not_after: Offset::years(1_000_000),
        ..spec
    };
    assert_eq!(
        issue(&spec, &key, None, VALIDATION_TIME).err(),
        Some(PkiError::Time)
    );
    Ok(())
}

#[test]
fn errors_are_described() {
    let messages = [
        (PkiError::KeyGeneration, "a key pair cannot be generated"),
        (PkiError::Encoding, "a value cannot be encoded"),
        (PkiError::Signing, "a signature cannot be computed"),
        (
            PkiError::KeyMismatch,
            "a key cannot sign with the requested algorithm",
        ),
        (PkiError::Time, "a certificate time is out of range"),
        (
            PkiError::UnknownIssuer("x".to_owned()),
            "the issuer \"x\" is not issued before its certificates",
        ),
    ];
    for (error, message) in messages {
        assert_eq!(error.to_string(), message);
        assert_eq!(GenerateError::Pki(error).to_string(), message);
    }
    assert_eq!(
        GenerateError::Io("x: denied".to_owned()).to_string(),
        "a file cannot be written: x: denied"
    );
    assert_eq!(
        GenerateError::Manifest(ManifestError::Io("x".to_owned())).to_string(),
        "the manifest cannot be read: x"
    );
}

#[test]
fn identifiers_and_digests_have_the_manifest_form() {
    assert_eq!(certificate_id("tsa"), "pki/tsa");
    assert_eq!(key_id("tsa"), "pki/keys/tsa");
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(RSA_PKCS1_SHA3_256.to_string(), "2.16.840.1.101.3.4.3.14");
    assert_eq!(rfc8410::ID_ED_25519.to_string(), "1.3.101.112");
}

#[test]
fn spki_of_each_key_type_parses() -> TestResult {
    for key_type in [
        KeyType::P256,
        KeyType::P384,
        KeyType::P521,
        KeyType::Ed25519,
    ] {
        let key = KeyPair::derive(key_type, "test/spki")?;
        SubjectPublicKeyInfoOwned::from_der(&key.spki_der()?)?;
    }
    Ok(())
}

#[test]
fn the_constructors_give_the_documented_defaults() -> TestResult {
    let built = signer(
        "signer-p256",
        "sigillum test signer P-256",
        KeyType::P256,
        "ca-ecdsa",
        SignatureAlgorithm::EcdsaSha384,
        0x1201,
        "End-entity signing certificate with an ECDSA P-256 key.",
    );
    assert_eq!(&built, spec("signer-p256")?);
    assert_eq!(built.not_before, Offset::years(-1));
    assert_eq!(built.not_after, Offset::years(2));
    let built = ca(
        "ca-rsa",
        "sigillum test RSA PKCS#1 v1.5 CA",
        KeyType::Rsa(3072),
        0x0101,
        "Issuing CA of the RSA PKCS#1 v1.5 family, with an RSA 3072-bit key.",
    );
    assert_eq!(&built, spec("ca-rsa")?);
    assert_eq!(
        (built.role, built.issuer, built.algorithm),
        (
            Role::IssuingCa,
            Some("root-ca"),
            SignatureAlgorithm::RsaPkcs1Sha256
        )
    );
    assert_eq!(
        (built.not_before, built.not_after),
        (Offset::years(-2), Offset::years(5))
    );
    let revocation = spec("signer-p256-revoked")?
        .revocation
        .ok_or("not revoked")?;
    let built = revoked(revocation, *spec("signer-p256")?);
    assert_eq!(built.revocation, Some(revocation));
    assert_eq!(
        (built.expected_openssl, built.expected_dss.indication),
        (OpensslResult::Rejected, Indication::Indeterminate)
    );
    assert_eq!(built.expected_dss.sub_indication, Some("REVOKED_NO_POE"));
    assert_eq!(built.name, "signer-p256");
    Ok(())
}
