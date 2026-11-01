// Test code signs and verifies with RSA test keys, which ADR-0010 allows.
#![allow(clippy::disallowed_types)]

use std::sync::OnceLock;

use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{SignedData, SignerInfo};
use const_oid::db::{rfc5911, rfc5912, rfc8410};
use der::asn1::{GeneralizedTime, ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use sha2::{Digest, Sha256};
use signature::Verifier;
use spki::{DecodePublicKey, SubjectPublicKeyInfoOwned};
use time::OffsetDateTime;
use time::macros::datetime;
use x509_cert::Certificate;
use x509_cert::ext::pkix::name::GeneralName;
use x509_tsp::{TspVersion, TstInfo};

use super::*;
use crate::manifest::{DssResult, Indication, Kind, OpensslResult};
use crate::pki::{self, GeneratedFile, PkiError, certificate_id, key_id};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const VALIDATION_TIME: OffsetDateTime = datetime!(2030-01-15 10:00:00 UTC);
const TIME: OffsetDateTime = datetime!(2030-01-15 09:00:00 UTC);

fn pki_files() -> Result<&'static [GeneratedFile], PkiError> {
    static FILES: OnceLock<Result<Vec<GeneratedFile>, PkiError>> = OnceLock::new();
    FILES
        .get_or_init(|| pki::generate(VALIDATION_TIME))
        .as_deref()
        .map_err(Clone::clone)
}

fn pki_file(id: &str) -> Result<&'static [u8], Box<dyn std::error::Error>> {
    Ok(pki_files()?
        .iter()
        .find(|f| f.artefact.id == id)
        .ok_or_else(|| format!("no artefact {id}"))?
        .contents
        .as_slice())
}

/// The authority of the certificate with this name in the test PKI.
fn authority(name: &str) -> Result<Tsa, Box<dyn std::error::Error>> {
    Ok(Tsa::from_pem(
        pki_file(&key_id(name))?,
        pki_file(&certificate_id(name))?,
    )?)
}

fn tsa() -> Result<Tsa, Box<dyn std::error::Error>> {
    authority("tsa")
}

/// The certificate with this name in the test PKI. The PEM block is
/// decoded in full before its content is read as DER, because
/// `Certificate::from_pem` of `der` 0.7.10 reads the block as it goes and
/// does not end when a read goes past the end of the block, for example
/// a block holding only the octet 0x01, a tag with no length (issue #164).
fn certificate(name: &str) -> Result<Certificate, Box<dyn std::error::Error>> {
    let (label, der) =
        der::pem::decode_vec(pki_file(&certificate_id(name))?).map_err(der::Error::from)?;
    if label != "CERTIFICATE" {
        return Err(format!("a PEM block labelled {label}").into());
    }
    Ok(Certificate::from_der(&der)?)
}

/// A token taken apart.
struct Parsed {
    signed_data: SignedData,
    tst_info_der: Vec<u8>,
    tst_info: TstInfo,
    signer_info: SignerInfo,
}

fn parse(token: &[u8]) -> Result<Parsed, Box<dyn std::error::Error>> {
    let content_info = ContentInfo::from_der(token)?;
    assert_eq!(content_info.content_type, rfc5911::ID_SIGNED_DATA);
    let signed_data: SignedData = content_info.content.decode_as()?;
    assert_eq!(signed_data.encap_content_info.econtent_type, ID_CT_TST_INFO);
    let econtent = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or("no eContent")?;
    let tst_info_der = OctetString::from_der(&econtent.to_der()?)?.into_bytes();
    let tst_info = TstInfo::from_der(&tst_info_der)?;
    let signer_infos = signed_data.signer_infos.0.as_slice();
    assert_eq!(
        signer_infos.len(),
        1,
        "exactly one signer (RFC 3161, 2.4.1)"
    );
    let signer_info = signer_infos.first().ok_or("no signer")?.clone();
    Ok(Parsed {
        signed_data,
        tst_info_der,
        tst_info,
        signer_info,
    })
}

fn attribute(info: &SignerInfo, oid: ObjectIdentifier) -> Option<Vec<u8>> {
    info.signed_attrs
        .as_ref()?
        .iter()
        .find(|a| a.oid == oid)
        .and_then(|a| a.values.iter().next())
        .and_then(|v| v.to_der().ok())
}

/// Verifies a signature value with the public key of a certificate.
fn verifies(
    certificate: &Certificate,
    algorithm: ObjectIdentifier,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    let spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()?;
    Ok(match algorithm {
        rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
            let key = rsa::RsaPublicKey::from_public_key_der(&spki)?;
            let signature = rsa::pkcs1v15::Signature::try_from(signature)?;
            rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key)
                .verify(message, &signature)
                .is_ok()
        }
        rfc5912::ECDSA_WITH_SHA_256 => {
            let key = p256::ecdsa::VerifyingKey::from_public_key_der(&spki)?;
            let signature = p256::ecdsa::DerSignature::try_from(signature)?;
            key.verify(message, &signature).is_ok()
        }
        rfc5912::ECDSA_WITH_SHA_384 => {
            let key = p384::ecdsa::VerifyingKey::from_public_key_der(&spki)?;
            let signature = p384::ecdsa::DerSignature::try_from(signature)?;
            key.verify(message, &signature).is_ok()
        }
        rfc5912::ECDSA_WITH_SHA_512 => {
            let point = SubjectPublicKeyInfoOwned::from_der(&spki)?;
            let key =
                p521::ecdsa::VerifyingKey::from_sec1_bytes(point.subject_public_key.raw_bytes())?;
            let signature = p521::ecdsa::Signature::from_der(signature)?;
            key.verify(message, &signature).is_ok()
        }
        rfc8410::ID_ED_25519 => {
            let key = ed25519_dalek::VerifyingKey::from_public_key_der(&spki)?;
            let signature = ed25519_dalek::Signature::from_slice(signature)?;
            key.verify(message, &signature).is_ok()
        }
        other => return Err(format!("unexpected algorithm {other}").into()),
    })
}

/// Checks every rule of RFC 3161, RFC 5652 and RFC 5816 that the token of
/// `name` must follow, for `digest` with `algorithm` at `time`.
fn check_token(
    token: &[u8],
    name: &str,
    algorithm: DigestAlgorithm,
    digest: &[u8],
    time: OffsetDateTime,
) -> Result<Parsed, Box<dyn std::error::Error>> {
    let parsed = parse(token)?;
    let certificate = certificate(name)?;
    let certificate_der = certificate.to_der()?;

    // RFC 3161, section 2.4.2: the TSTInfo.
    let info = &parsed.tst_info;
    assert_eq!(info.version, TspVersion::V1);
    assert_eq!(info.policy, TSA_POLICY);
    assert_eq!(info.message_imprint.hash_algorithm.oid, algorithm.oid());
    assert!(info.message_imprint.hash_algorithm.parameters.is_none());
    assert_eq!(info.message_imprint.hashed_message.as_bytes(), digest);
    let seconds = time.unix_timestamp();
    assert_eq!(
        info.serial_number.as_bytes(),
        serial_number(&certificate_der, algorithm, digest, seconds)
    );
    assert_eq!(
        info.gen_time,
        GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(u64::try_from(
            seconds
        )?))?
    );
    assert!(info.accuracy.is_none());
    assert!(!info.ordering);
    assert!(info.nonce.is_none());
    assert!(info.tsa.is_none());
    assert!(info.extensions.is_none());

    // RFC 5652, section 5.1: version 3, because eContentType is not id-data.
    let signed_data = &parsed.signed_data;
    assert_eq!(signed_data.version, CmsVersion::V3);
    let certificates = signed_data
        .certificates
        .as_ref()
        .ok_or("no certificates")?
        .0
        .as_slice();
    assert_eq!(certificates.len(), 1);
    assert_eq!(
        certificates.first().ok_or("none")?.to_der()?,
        certificate_der
    );
    assert!(signed_data.crls.is_none());

    // RFC 5652, section 5.3: the signer, identified by issuer and serial.
    let signer_info = &parsed.signer_info;
    assert_eq!(signer_info.version, CmsVersion::V1);
    let SignerIdentifier::IssuerAndSerialNumber(sid) = &signer_info.sid else {
        return Err("the signer is not identified by issuer and serial number".into());
    };
    assert_eq!(sid.issuer, certificate.tbs_certificate.issuer);
    assert_eq!(sid.serial_number, certificate.tbs_certificate.serial_number);
    let digest_algorithms: Vec<_> = signed_data.digest_algorithms.iter().collect();
    assert_eq!(digest_algorithms, vec![&signer_info.digest_alg]);
    assert!(signer_info.digest_alg.parameters.is_none());
    assert!(signer_info.unsigned_attrs.is_none());

    // RFC 5652, section 5.3, and RFC 3161, section 2.4.1: the signed
    // attributes are exactly content type, message digest and the ESS
    // signing certificate. No signingTime is present.
    let attributes = signer_info
        .signed_attrs
        .as_ref()
        .ok_or("no signed attributes")?;
    let mut oids: Vec<ObjectIdentifier> = attributes.iter().map(|a| a.oid).collect();
    oids.sort();
    let mut expected = vec![
        rfc5911::ID_CONTENT_TYPE,
        rfc5911::ID_MESSAGE_DIGEST,
        rfc5911::ID_AA_SIGNING_CERTIFICATE_V_2,
    ];
    expected.sort();
    assert_eq!(oids, expected);
    assert!(attribute(signer_info, rfc5911::ID_SIGNING_TIME).is_none());
    assert!(attributes.iter().all(|a| a.values.len() == 1));
    assert_eq!(
        attribute(signer_info, rfc5911::ID_CONTENT_TYPE),
        Some(ID_CT_TST_INFO.to_der()?)
    );
    let signer_digest = DigestAlgorithm::from_oid(signer_info.digest_alg.oid).ok_or("digest")?;
    assert_eq!(
        attribute(signer_info, rfc5911::ID_MESSAGE_DIGEST),
        Some(OctetString::new(signer_digest.digest(&parsed.tst_info_der))?.to_der()?)
    );

    // RFC 5816, section 2.2.1, and RFC 5035, sections 3 and 4: one ESSCertIDv2
    // with the SHA-256 hash of the certificate, the hash algorithm left at
    // its default and so absent, and the issuer and serial number.
    let value = attribute(signer_info, rfc5911::ID_AA_SIGNING_CERTIFICATE_V_2)
        .ok_or("no signingCertificateV2")?;
    let signing_certificate = SigningCertificateV2::from_der(&value)?;
    assert_eq!(signing_certificate.certs.len(), 1);
    let id = signing_certificate.certs.first().ok_or("no ESSCertIDv2")?;
    assert_eq!(
        id.cert_hash.as_bytes(),
        Sha256::digest(&certificate_der).as_slice()
    );
    assert_eq!(
        id.issuer_serial.issuer,
        vec![GeneralName::DirectoryName(
            certificate.tbs_certificate.issuer.clone()
        )]
    );
    assert_eq!(
        id.issuer_serial.serial_number,
        certificate.tbs_certificate.serial_number
    );
    // The first element of the ESSCertIDv2 sequence is the certHash
    // OCTET STRING: no hashAlgorithm is encoded.
    let id_der = id.to_der()?;
    assert_eq!(id_der.get(2), Some(&0x04));

    // The signature over the DER encoding of the signed attributes.
    assert!(verifies(
        &certificate,
        signer_info.signature_algorithm.oid,
        &attributes.to_der()?,
        signer_info.signature.as_bytes()
    )?);
    Ok(parsed)
}

#[test]
fn digest_algorithms_have_their_identifiers_and_lengths() {
    let expected = [
        (
            DigestAlgorithm::Sha256,
            "2.16.840.1.101.3.4.2.1",
            "SHA-256",
            32,
        ),
        (
            DigestAlgorithm::Sha384,
            "2.16.840.1.101.3.4.2.2",
            "SHA-384",
            48,
        ),
        (
            DigestAlgorithm::Sha512,
            "2.16.840.1.101.3.4.2.3",
            "SHA-512",
            64,
        ),
    ];
    assert_eq!(DigestAlgorithm::ALL.len(), expected.len());
    for (algorithm, oid, name, len) in expected {
        assert_eq!(algorithm.oid().to_string(), oid);
        assert_eq!(DigestAlgorithm::from_oid(algorithm.oid()), Some(algorithm));
        assert_eq!(algorithm.name(), name);
        assert_eq!(algorithm.output_len(), len);
        assert_eq!(algorithm.digest(b"abc").len(), len);
        assert_eq!(algorithm.identifier().oid, algorithm.oid());
        assert!(algorithm.identifier().parameters.is_none());
    }
    // FIPS 180-4 known answers for "abc", first octets.
    assert_eq!(
        DigestAlgorithm::Sha256.digest(b"abc").get(..4),
        Some(&[0xba, 0x78, 0x16, 0xbf][..])
    );
    assert_eq!(
        DigestAlgorithm::Sha384.digest(b"abc").get(..4),
        Some(&[0xcb, 0x00, 0x75, 0x3f][..])
    );
    assert_eq!(
        DigestAlgorithm::Sha512.digest(b"abc").get(..4),
        Some(&[0xdd, 0xaf, 0x35, 0xa1][..])
    );
    // SHA-1 and SHA3-256 are not supported.
    for oid in ["1.3.14.3.2.26", "2.16.840.1.101.3.4.2.8"] {
        assert_eq!(
            DigestAlgorithm::from_oid(ObjectIdentifier::new_unwrap(oid)),
            None
        );
    }
}

#[test]
fn the_policy_is_allocated_under_the_test_arc() {
    assert_eq!(TSA_POLICY.to_string(), "1.3.6.1.4.1.32473.1.2");
    assert_eq!(TSA_POLICY.parent(), Some(crate::pki::issue::TEST_ARC));
    assert_eq!(ID_CT_TST_INFO.to_string(), "1.2.840.113549.1.9.16.1.4");
}

#[test]
fn a_token_follows_rfc_3161_for_every_digest_algorithm() -> TestResult {
    let tsa = tsa()?;
    for algorithm in DigestAlgorithm::ALL {
        let digest = algorithm.digest(b"data");
        let token = tsa.issue(algorithm, &digest, TIME)?;
        let parsed = check_token(&token, "tsa", algorithm, &digest, TIME)?;
        // The TSA key is P-256: ECDSA with SHA-256 (RFC 5753, section 2.1.1).
        assert_eq!(
            parsed.signer_info.signature_algorithm.oid,
            rfc5912::ECDSA_WITH_SHA_256
        );
        assert!(parsed.signer_info.signature_algorithm.parameters.is_none());
        assert_eq!(parsed.signer_info.digest_alg.oid, rfc5912::ID_SHA_256);
    }
    Ok(())
}

#[test]
fn every_key_type_of_the_test_pki_can_sign_a_token() -> TestResult {
    let cases = [
        (
            "signer-rsa-2048",
            rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            rfc5912::ID_SHA_256,
        ),
        (
            "signer-p256",
            rfc5912::ECDSA_WITH_SHA_256,
            rfc5912::ID_SHA_256,
        ),
        (
            "signer-p384",
            rfc5912::ECDSA_WITH_SHA_384,
            rfc5912::ID_SHA_384,
        ),
        (
            "signer-p521",
            rfc5912::ECDSA_WITH_SHA_512,
            rfc5912::ID_SHA_512,
        ),
        // RFC 8419, section 3: SHA-512 digests the signed attributes.
        ("signer-ed25519", rfc8410::ID_ED_25519, rfc5912::ID_SHA_512),
    ];
    for (name, signature, digest_oid) in cases {
        let authority = authority(name)?;
        let digest = DigestAlgorithm::Sha384.digest(name.as_bytes());
        let token = authority.issue(DigestAlgorithm::Sha384, &digest, TIME)?;
        let parsed = check_token(&token, name, DigestAlgorithm::Sha384, &digest, TIME)?;
        assert_eq!(
            parsed.signer_info.signature_algorithm.oid, signature,
            "{name}"
        );
        assert_eq!(parsed.signer_info.digest_alg.oid, digest_oid, "{name}");
        // RFC 4055, section 5: NULL parameters for RSA PKCS#1 v1.5.
        let parameters = parsed.signer_info.signature_algorithm.parameters.as_ref();
        assert_eq!(
            parameters.is_some(),
            signature == rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn tokens_are_reproducible() -> TestResult {
    let digest = DigestAlgorithm::Sha256.digest(b"data");
    let first = tsa()?.issue(DigestAlgorithm::Sha256, &digest, TIME)?;
    assert_eq!(first, tsa()?.issue(DigestAlgorithm::Sha256, &digest, TIME)?);
    Ok(())
}

#[test]
fn the_certificate_may_be_pem_or_der() -> TestResult {
    let key = pki_file(&key_id("tsa"))?;
    let der = certificate("tsa")?.to_der()?;
    let from_der = Tsa::from_pem(key, &der)?;
    assert_eq!(from_der.certificate_der(), der.as_slice());
    assert_eq!(tsa()?.certificate_der(), der.as_slice());
    let digest = DigestAlgorithm::Sha256.digest(b"data");
    assert_eq!(
        from_der.issue(DigestAlgorithm::Sha256, &digest, TIME)?,
        tsa()?.issue(DigestAlgorithm::Sha256, &digest, TIME)?
    );
    Ok(())
}

#[test]
fn pem_input_may_start_with_a_byte_order_mark_and_white_space() -> TestResult {
    let key = pki_file(&key_id("tsa"))?;
    let pem = pki_file(&certificate_id("tsa"))?;
    let expected = tsa()?.certificate_der().to_vec();
    for prefix in [&b"\xef\xbb\xbf"[..], b" \t\r\n", b"\xef\xbb\xbf\n\n"] {
        let prefixed_key = [prefix, key].concat();
        let prefixed_certificate = [prefix, pem].concat();
        let authority = Tsa::from_pem(&prefixed_key, &prefixed_certificate)?;
        assert_eq!(
            authority.certificate_der(),
            expected.as_slice(),
            "{prefix:?}"
        );
    }
    // A byte order mark or white space before DER is not skipped.
    let der = certificate("tsa")?.to_der()?;
    assert_eq!(
        Tsa::from_pem(key, &[b" ".as_slice(), &der].concat()).err(),
        Some(TsaError::Certificate)
    );
    Ok(())
}

/// The serial number, recomputed from its documented definition.
fn documented_serial(certificate: &[u8], oid: &str, digest: &[u8], seconds: i64) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(SERIAL_LABEL);
    hash.update(Sha256::digest(certificate));
    hash.update(
        ObjectIdentifier::new_unwrap(oid)
            .to_der()
            .unwrap_or_default(),
    );
    hash.update(digest);
    hash.update(seconds.to_be_bytes());
    let mut serial = hash.finalize().get(..16).unwrap_or_default().to_vec();
    if let Some(first) = serial.first_mut() {
        *first = (*first & 0x3f) | 0x40;
    }
    serial
}

#[test]
fn serial_numbers_are_derived_from_the_request() -> TestResult {
    let other = certificate("signer-p256")?.to_der()?;
    let certificate = certificate("tsa")?.to_der()?;
    let digest = [0x11; 32];
    let seconds = TIME.unix_timestamp();
    let serial = serial_number(&certificate, DigestAlgorithm::Sha256, &digest, seconds);
    assert_eq!(
        serial.to_vec(),
        documented_serial(&certificate, "2.16.840.1.101.3.4.2.1", &digest, seconds)
    );
    assert_eq!(serial.first().map(|b| b & 0xc0), Some(0x40));
    // Each input changes the serial number; the same request repeats it.
    let mut serials = vec![
        serial,
        serial_number(&other, DigestAlgorithm::Sha256, &digest, seconds),
        serial_number(&certificate, DigestAlgorithm::Sha384, &digest, seconds),
        serial_number(&certificate, DigestAlgorithm::Sha256, &[0x12; 32], seconds),
        serial_number(&certificate, DigestAlgorithm::Sha256, &digest, seconds + 1),
    ];
    assert_eq!(
        serial,
        serial_number(&certificate, DigestAlgorithm::Sha256, &digest, seconds)
    );
    serials.sort();
    serials.dedup();
    assert_eq!(serials.len(), 5);
    Ok(())
}

#[test]
fn invalid_requests_are_refused() -> TestResult {
    let tsa = tsa()?;
    for algorithm in DigestAlgorithm::ALL {
        for len in [0, algorithm.output_len() - 1, algorithm.output_len() + 1] {
            assert_eq!(
                tsa.issue(algorithm, &vec![0; len], TIME),
                Err(TsaError::DigestLength {
                    algorithm,
                    actual: len
                })
            );
        }
    }
    let digest = [0; 32];
    for time in [
        datetime!(1969-12-31 23:59:59 UTC),
        datetime!(2030-01-15 09:00:00.5 UTC),
        datetime!(2030-01-15 09:00:00.000000001 UTC),
    ] {
        assert_eq!(
            tsa.issue(DigestAlgorithm::Sha256, &digest, time),
            Err(TsaError::Time),
            "{time}"
        );
    }
    // The first and last representable seconds.
    tsa.issue(
        DigestAlgorithm::Sha256,
        &digest,
        datetime!(1970-01-01 00:00:00 UTC),
    )?;
    tsa.issue(
        DigestAlgorithm::Sha256,
        &digest,
        datetime!(9999-12-31 23:59:59 UTC),
    )?;
    // Another offset denotes the same instant.
    assert_eq!(
        tsa.issue(
            DigestAlgorithm::Sha256,
            &digest,
            datetime!(2030-01-15 10:00:00 +01:00)
        )?,
        tsa.issue(DigestAlgorithm::Sha256, &digest, TIME)?
    );
    Ok(())
}

#[test]
fn invalid_keys_and_certificates_are_refused() -> TestResult {
    let key = pki_file(&key_id("tsa"))?;
    let other_key = pki_file(&key_id("signer-p256"))?;
    let certificate = pki_file(&certificate_id("tsa"))?;
    let refused = |key: &[u8], certificate: &[u8]| Tsa::from_pem(key, certificate).err();
    assert_eq!(refused(b"", certificate), Some(TsaError::Key));
    assert_eq!(refused(b"not a key", certificate), Some(TsaError::Key));
    // A PEM document with another label.
    assert_eq!(refused(certificate, certificate), Some(TsaError::Key));
    // The key as DER, and bytes that are not UTF-8.
    let (_, document) = der::SecretDocument::from_pem(std::str::from_utf8(key)?)?;
    assert_eq!(
        refused(document.as_bytes(), certificate),
        Some(TsaError::Key)
    );
    assert_eq!(
        refused(b"\xff\xfe\x00key", certificate),
        Some(TsaError::Key)
    );
    // A PKCS#8 key of a type the test PKI does not use: X25519 (RFC 8410).
    let x25519 = with_algorithm(rfc8410::ID_X_25519, None)?;
    assert_eq!(private_key_from_der(&x25519).err(), Some(TsaError::Key));
    // EC keys on secp256k1, which the test PKI does not use, and without
    // curve parameters.
    let secp256k1 = der::Any::from(&ObjectIdentifier::new_unwrap("1.3.132.0.10"));
    let ec = const_oid::db::rfc5912::ID_EC_PUBLIC_KEY;
    for parameters in [Some(secp256k1), None] {
        let key = with_algorithm(ec, parameters)?;
        assert_eq!(private_key_from_der(&key).err(), Some(TsaError::Key));
    }
    // Keys of each supported type whose private key octets are not valid.
    for (oid, parameters) in [
        (
            const_oid::db::rfc5912::RSA_ENCRYPTION,
            Some(der::Any::from(der::asn1::Null)),
        ),
        (
            ec,
            Some(der::Any::from(&const_oid::db::rfc5912::SECP_256_R_1)),
        ),
        (
            ec,
            Some(der::Any::from(&const_oid::db::rfc5912::SECP_384_R_1)),
        ),
        (
            ec,
            Some(der::Any::from(&const_oid::db::rfc5912::SECP_521_R_1)),
        ),
        (rfc8410::ID_ED_25519, None),
    ] {
        let algorithm = pkcs8::spki::AlgorithmIdentifier {
            oid,
            parameters: parameters.as_ref().map(der::AnyRef::from),
        };
        let junk = pkcs8::PrivateKeyInfo::new(algorithm, &[0x30, 0x00]).to_der()?;
        assert_eq!(
            private_key_from_der(&junk).err(),
            Some(TsaError::Key),
            "{oid}"
        );
    }
    assert_eq!(private_key_from_der(b"").err(), Some(TsaError::Key));
    assert_eq!(refused(key, b""), Some(TsaError::Certificate));
    assert_eq!(
        refused(key, b"not a certificate"),
        Some(TsaError::Certificate)
    );
    assert_eq!(
        refused(
            key,
            b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"
        ),
        Some(TsaError::Certificate)
    );
    assert_eq!(refused(other_key, certificate), Some(TsaError::KeyMismatch));
    Ok(())
}

/// The PKCS#8 encoding of the TSA's P-256 key with another algorithm
/// identifier.
fn with_algorithm(
    oid: ObjectIdentifier,
    parameters: Option<der::Any>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key = std::str::from_utf8(pki_file(&key_id("tsa"))?)?;
    let (_, document) = der::SecretDocument::from_pem(key)?;
    let mut info = pkcs8::PrivateKeyInfo::try_from(document.as_bytes())?;
    info.algorithm = pkcs8::spki::AlgorithmIdentifier {
        oid,
        parameters: parameters.as_ref().map(der::AnyRef::from),
    };
    Ok(info.to_der()?)
}

#[test]
fn errors_are_described() {
    let cases = [
        (
            TsaError::Key,
            "the private key is not a PKCS#8 PEM document of an RSA, ECDSA or Ed25519 key of a supported form; DER and other encodings are not accepted, and an RSA key needs two primes of equal size and a modulus of 2048 to 4096 bits",
        ),
        (
            TsaError::PkiNotInManifest("pki/tsa".to_owned()),
            "the manifest does not list pki/tsa, which the timestamp tokens link to; run sigillum-testpki generate pki first",
        ),
        (
            TsaError::Certificate,
            "the certificate is not a PEM or DER X.509 certificate",
        ),
        (
            TsaError::KeyMismatch,
            "the private key does not belong to the certificate",
        ),
        (
            TsaError::DigestLength {
                algorithm: DigestAlgorithm::Sha384,
                actual: 3,
            },
            "a SHA-384 digest has 48 octets, not 3",
        ),
        (
            TsaError::Time,
            "the time must be a whole second from 1970-01-01T00:00:00Z to 9999-12-31T23:59:59Z",
        ),
        (
            TsaError::UnknownCertificate("pki/x".to_owned()),
            "the test PKI has no certificate or key \"pki/x\"",
        ),
        (
            TsaError::Pki(PkiError::Signing),
            "a signature cannot be computed",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
    assert_eq!(
        TsaError::from(PkiError::Encoding),
        TsaError::Pki(PkiError::Encoding)
    );
    assert_eq!(
        GenerateError::Timestamp(TsaError::Time).to_string(),
        TsaError::Time.to_string()
    );
}

fn generated() -> Result<&'static [GeneratedFile], TsaError> {
    static FILES: OnceLock<Result<Vec<GeneratedFile>, TsaError>> = OnceLock::new();
    FILES
        .get_or_init(|| generate(VALIDATION_TIME))
        .as_deref()
        .map_err(Clone::clone)
}

fn token_file(name: &str) -> Result<&'static GeneratedFile, Box<dyn std::error::Error>> {
    let id = format!("{DIRECTORY}/{name}");
    Ok(generated()?
        .iter()
        .find(|f| f.artefact.id == id)
        .ok_or_else(|| format!("no artefact {id}"))?)
}

#[test]
fn the_corpus_has_the_content_and_four_tokens() -> TestResult {
    let ids: Vec<&str> = generated()?
        .iter()
        .map(|f| f.artefact.id.as_str())
        .collect();
    assert_eq!(
        ids,
        vec![
            "timestamps/content",
            "timestamps/valid",
            "timestamps/signer-without-time-stamping",
            "timestamps/imprint-mismatch",
            "timestamps/gen-time-after-validation-time",
        ]
    );
    let content = token_file("content")?;
    assert_eq!(content.contents, CONTENT);
    assert_eq!(
        content.artefact.path.to_string_lossy(),
        "timestamps/content.txt"
    );
    assert_eq!(content.artefact.kind, Kind::Document);
    assert_eq!(
        content.artefact.expected_openssl,
        OpensslResult::NotApplicable
    );
    assert_eq!(content.artefact.expected_dss, DssResult::NotApplicable);
    assert_eq!(content.artefact.links, Links::default());
    for file in generated()? {
        assert_eq!(file.artefact.sha256, pki::sha256_hex(&file.contents));
        assert!(!file.artefact.purpose.trim().is_empty());
    }
    Ok(())
}

#[test]
fn each_token_has_its_defect_and_only_it() -> TestResult {
    let content_digest = DigestAlgorithm::Sha256.digest(CONTENT);
    let mut mismatch = content_digest.clone();
    if let Some(last) = mismatch.last_mut() {
        *last = !*last;
    }
    let before = datetime!(2030-01-14 10:00:00 UTC);
    let after = datetime!(2030-01-16 10:00:00 UTC);
    let cases = [
        (
            "valid",
            "tsa",
            &content_digest,
            before,
            OpensslResult::Verified,
            Indication::Passed,
            None,
        ),
        (
            "signer-without-time-stamping",
            "signer-p256",
            &content_digest,
            before,
            OpensslResult::Rejected,
            Indication::Indeterminate,
            Some("CHAIN_CONSTRAINTS_FAILURE"),
        ),
        (
            "imprint-mismatch",
            "tsa",
            &mismatch,
            before,
            OpensslResult::Rejected,
            Indication::Failed,
            Some("HASH_FAILURE"),
        ),
        (
            "gen-time-after-validation-time",
            "tsa",
            &content_digest,
            after,
            OpensslResult::Verified,
            Indication::Passed,
            None,
        ),
    ];
    let mut serials = Vec::new();
    for (name, signer, digest, time, openssl, indication, sub_indication) in cases {
        let file = token_file(name)?;
        let artefact = &file.artefact;
        assert_eq!(
            artefact.path.to_string_lossy(),
            format!("timestamps/{name}.tst")
        );
        assert_eq!(artefact.kind, Kind::TimestampToken);
        assert_eq!(artefact.expected_openssl, openssl, "{name}");
        assert_eq!(
            artefact.expected_dss,
            DssResult::Indication {
                indication,
                sub_indication: sub_indication.map(str::to_owned)
            },
            "{name}"
        );
        let chain = match signer {
            "tsa" => vec!["pki/tsa", "pki/ca-ecdsa", "pki/root-ca"],
            _ => vec!["pki/signer-p256", "pki/ca-ecdsa", "pki/root-ca"],
        };
        assert_eq!(artefact.links.issuer.as_deref(), chain.first().copied());
        assert_eq!(artefact.links.chain, chain);
        assert_eq!(artefact.links.content.as_deref(), Some(CONTENT_ID));
        assert!(artefact.links.revocation.is_empty());
        assert!(
            artefact
                .notes
                .as_deref()
                .is_some_and(|n| n.contains("prediction"))
        );
        let notes = artefact.notes.as_deref().unwrap_or_default();
        match name {
            // EN 319 102-1 V1.4.1, clause 5.2.6.4, step 4, checks revocation
            // with the CRLs that the chain of pki/tsa links.
            "valid" | "gen-time-after-validation-time" => {
                assert!(notes.contains("5.2.6.4, step 4"), "{name}: {notes}");
                assert!(notes.contains("crl/ca-ecdsa"), "{name}: {notes}");
                assert!(notes.contains("crl/root-ca"), "{name}: {notes}");
                assert!(!notes.contains("later stories"), "{name}: {notes}");
            }
            "imprint-mismatch" => {
                assert!(!notes.contains("5.2.7.4"), "{notes}");
                assert!(notes.contains("data supplied to the validation"), "{notes}");
            }
            _ => {}
        }
        let parsed = check_token(
            &file.contents,
            signer,
            DigestAlgorithm::Sha256,
            digest,
            time,
        )?;
        serials.push(parsed.tst_info.serial_number.as_bytes().to_vec());
        // The signer of the token without id-kp-timeStamping has no
        // extended key usage at all; the TSA has it, critical.
        let eku = certificate(signer)?
            .tbs_certificate
            .extensions
            .unwrap_or_default()
            .into_iter()
            .find(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_EXT_KEY_USAGE);
        assert_eq!(eku.map(|e| e.critical), (signer == "tsa").then_some(true));
    }
    serials.sort();
    serials.dedup();
    assert_eq!(serials.len(), 4, "serial numbers are unique within a run");
    Ok(())
}

#[test]
fn generation_is_reproducible() -> TestResult {
    assert_eq!(generate(VALIDATION_TIME)?, generated()?);
    Ok(())
}

#[test]
fn generation_reports_a_time_out_of_range() {
    // The PKI of this validation time cannot be generated: the root's
    // notBefore would fall before 1970.
    assert!(generate(datetime!(1971-01-01 00:00:00 UTC)).is_err());
}

#[test]
fn only_entries_under_the_directory_belong_here() -> TestResult {
    let file = token_file("valid")?;
    assert!(generated_here(&file.artefact));
    let mut other = file.artefact.clone();
    other.id = "pki/tsa".to_owned();
    assert!(!generated_here(&other));
    other.id = "timestampsx/valid".to_owned();
    assert!(!generated_here(&other));
    Ok(())
}

#[test]
fn the_manifest_must_list_every_certificate_the_tokens_link_to() -> TestResult {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/manifest.toml");
    let mut manifest = Manifest::load(&path)?;
    assert_eq!(check_pki_listed(&manifest), Ok(()));
    for missing in ["pki/tsa", "pki/signer-p256", "pki/ca-ecdsa", "pki/root-ca"] {
        let mut partial = manifest.clone();
        partial.artefacts.retain(|artefact| artefact.id != missing);
        assert_eq!(
            check_pki_listed(&partial),
            Err(TsaError::PkiNotInManifest(missing.to_owned())),
            "{missing}"
        );
    }
    manifest.artefacts.clear();
    assert_eq!(
        check_pki_listed(&manifest),
        Err(TsaError::PkiNotInManifest("pki/tsa".to_owned()))
    );
    Ok(())
}

/// RFC 5280 certificates are DER, and der 0.7.10 allocates the declared
/// length of an INTEGER before it checks the input holds it. Lengths are
/// therefore checked first, and such a certificate is refused.
#[test]
fn a_certificate_with_a_length_beyond_its_input_is_refused() -> TestResult {
    let key = pki_file(&key_id("tsa"))?;
    let bad: &[u8] = &[0x30, 0x08, 0x30, 0x06, 0x02, 0x84, 0x02, 0x00, 0x00, 0x00];
    assert_eq!(input::check_der(bad), Err(input::DerError::Truncated));
    let pem = der::pem::encode_string("CERTIFICATE", der::pem::LineEnding::LF, bad)
        .map_err(|e| format!("{e}"))?;
    for certificate in [bad, pem.as_bytes()] {
        assert_eq!(
            Tsa::from_pem(key, certificate).err(),
            Some(TsaError::Certificate)
        );
    }
    // A PEM document with another label is refused, as before.
    let der = certificate("tsa")?.to_der()?;
    let other = der::pem::encode_string("X509 CRL", der::pem::LineEnding::LF, &der)
        .map_err(|e| format!("{e}"))?;
    assert_eq!(
        Tsa::from_pem(key, other.as_bytes()).err(),
        Some(TsaError::Certificate)
    );
    // A key whose DER length runs past its input is refused too.
    let key_pem = der::pem::encode_string(
        "PRIVATE KEY",
        der::pem::LineEnding::LF,
        &[0x30, 0x06, 0x02, 0x84, 0x02, 0x00, 0x00, 0x00],
    )
    .map_err(|e| format!("{e}"))?;
    assert_eq!(
        Tsa::from_pem(key_pem.as_bytes(), &der).err(),
        Some(TsaError::Key)
    );
    Ok(())
}

/// The certificate of `pki/tsa` with another subject public key bit
/// string, encoded as DER. Its signature no longer verifies, which `Tsa`
/// does not check.
fn tsa_certificate_with_point(point: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut certificate = certificate("tsa")?;
    certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key = der::asn1::BitString::from_bytes(point)?;
    Ok(certificate.to_der()?)
}

/// The SEC 1 point of a P-256 key, compressed or not.
fn p256_point(name: &str, compress: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let pem = std::str::from_utf8(pki_file(&key_id(name))?)?;
    let key: p256::SecretKey = pkcs8::DecodePrivateKey::from_pkcs8_pem(pem)?;
    Ok(key
        .public_key()
        .to_encoded_point(compress)
        .as_bytes()
        .to_vec())
}

/// A certificate may carry the public key as a compressed point (SEC 1,
/// section 2.3.3; RFC 5480, section 2.2). The key matches it all the same.
#[test]
fn the_key_matches_a_certificate_with_a_compressed_point() -> TestResult {
    let key = pki_file(&key_id("tsa"))?;
    let compressed = p256_point("tsa", true)?;
    assert_eq!(compressed.len(), 33);
    let certificate = tsa_certificate_with_point(&compressed)?;
    let authority = Tsa::from_pem(key, &certificate)?;
    assert_eq!(authority.certificate_der(), certificate.as_slice());
    let digest = DigestAlgorithm::Sha256.digest(b"data");
    let token = authority.issue(DigestAlgorithm::Sha256, &digest, TIME)?;
    let parsed = parse(&token)?;
    let expected = parse(&tsa()?.issue(DigestAlgorithm::Sha256, &digest, TIME)?)?;
    // The TSTInfo differs only in the serial number, which is derived from
    // the certificate; the signature verifies with the uncompressed key.
    assert_eq!(parsed.tst_info.gen_time, expected.tst_info.gen_time);
    assert_eq!(
        parsed.tst_info.message_imprint,
        expected.tst_info.message_imprint
    );
    let attributes = parsed
        .signer_info
        .signed_attrs
        .as_ref()
        .ok_or("attributes")?;
    assert!(verifies(
        &certificate_from_der(&tsa_certificate_with_point(&p256_point("tsa", false)?)?)?,
        parsed.signer_info.signature_algorithm.oid,
        &attributes.to_der()?,
        parsed.signer_info.signature.as_bytes()
    )?);
    // The uncompressed point, re-encoded the same way, is the committed
    // certificate.
    assert_eq!(
        tsa_certificate_with_point(&p256_point("tsa", false)?)?,
        tsa()?.certificate_der()
    );
    Ok(())
}

fn certificate_from_der(der: &[u8]) -> Result<Certificate, Box<dyn std::error::Error>> {
    Ok(Certificate::from_der(der)?)
}

#[test]
fn public_keys_are_compared_after_decoding() -> TestResult {
    let key = pki_file(&key_id("tsa"))?;
    // The compressed point of another P-256 key.
    let other = tsa_certificate_with_point(&p256_point("signer-p256", true)?)?;
    assert_eq!(
        Tsa::from_pem(key, &other).err(),
        Some(TsaError::KeyMismatch)
    );
    // Points that are not on the curve, compressed and uncompressed, and a
    // point of the wrong length.
    let mut off_curve = p256_point("tsa", false)?;
    if let Some(last) = off_curve.last_mut() {
        *last ^= 0x01;
    }
    let mut beyond = vec![0x02];
    beyond.extend_from_slice(&[0xff; 32]);
    for point in [off_curve, beyond, vec![0x04; 10], Vec::new()] {
        let certificate = tsa_certificate_with_point(&point)?;
        assert_eq!(
            Tsa::from_pem(key, &certificate).err(),
            Some(TsaError::Certificate),
            "{point:02x?}"
        );
    }
    // A key of the same type and curve as the certificate, but another key.
    for (key_name, certificate_name) in [
        ("signer-rsa-3072", "signer-rsa-sha3-256"),
        ("signer-p384", "ca-ecdsa"),
        ("signer-p521", "ca-ecdsa-p521"),
        ("signer-ed25519", "ca-ed25519"),
    ] {
        assert_eq!(
            Tsa::from_pem(
                pki_file(&key_id(key_name))?,
                pki_file(&certificate_id(certificate_name))?
            )
            .err(),
            Some(TsaError::KeyMismatch),
            "{key_name}"
        );
    }
    // A key of another type or curve than the certificate does not match it.
    for name in [
        "signer-rsa-2048",
        "signer-p384",
        "signer-p521",
        "signer-ed25519",
    ] {
        assert_eq!(
            Tsa::from_pem(pki_file(&key_id(name))?, pki_file(&certificate_id("tsa"))?).err(),
            Some(TsaError::KeyMismatch),
            "{name}"
        );
        assert_eq!(
            Tsa::from_pem(key, pki_file(&certificate_id(name))?).err(),
            Some(TsaError::KeyMismatch),
            "{name}"
        );
    }
    Ok(())
}

/// The certificate is one PEM block, with only a byte order mark and white
/// space before it, or DER. Chain files and the text output of
/// `openssl x509 -text` are refused.
#[test]
fn the_certificate_is_a_single_pem_block_or_der() -> TestResult {
    let key = pki_file(&key_id("tsa"))?;
    let pem = pki_file(&certificate_id("tsa"))?;
    let ca = pki_file(&certificate_id("ca-ecdsa"))?;
    let accepted = |certificate: &[u8]| Tsa::from_pem(key, certificate).is_ok();
    assert!(accepted(pem));
    // The END line may end with or without its line ending.
    let without_newline = pem.strip_suffix(b"\n").ok_or("no final newline")?;
    assert!(accepted(without_newline));
    let refused: [Vec<u8>; 5] = [
        // Even a blank line after the END line.
        [pem, b"\n"].concat(),
        // A chain file: the certificate and its issuer.
        [pem, ca].concat(),
        // Text after the END line.
        [pem, b"trailing text\n"].concat(),
        // Text before the BEGIN line, as openssl x509 -text writes it.
        [b"Certificate:\n    Data:\n".as_slice(), pem].concat(),
        // DER followed by other bytes.
        [certificate("tsa")?.to_der()?, vec![0x00]].concat(),
    ];
    for certificate in refused {
        assert_eq!(
            Tsa::from_pem(key, &certificate).err(),
            Some(TsaError::Certificate)
        );
    }
    Ok(())
}

/// The certificate of `pki/tsa` with the public key of `key` instead of
/// its own, encoded as DER.
fn tsa_certificate_for(key: &rsa::RsaPrivateKey) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use spki::EncodePublicKey;
    let spki = key.to_public_key().to_public_key_der()?;
    let mut certificate = certificate("tsa")?;
    certificate.tbs_certificate.subject_public_key_info =
        SubjectPublicKeyInfoOwned::from_der(spki.as_bytes())?;
    Ok(certificate.to_der()?)
}

/// The RSA key with these primes and the exponent 65537. `from_p_q`
/// computes the private exponent; no prime is generated.
fn rsa_key(p: rsa::BigUint, q: rsa::BigUint) -> Result<rsa::RsaPrivateKey, rsa::Error> {
    rsa::RsaPrivateKey::from_p_q(p, q, rsa::BigUint::from(65_537_u32))
}

/// The Mersenne prime 2^exponent - 1.
fn mersenne(exponent: usize) -> rsa::BigUint {
    (rsa::BigUint::from(1_u8) << exponent) - rsa::BigUint::from(1_u8)
}

/// RSA keys of a form the test PKI does not use are refused before any
/// signature, both from PKCS#8 and as a key pair. With p = 3 and q =
/// 2^607 - 1, rsa 0.9.10 would take practically forever to sign. These
/// checks only construct the authority; nothing is signed.
#[test]
fn rsa_keys_of_an_unsupported_form_are_refused() -> TestResult {
    use pkcs8::EncodePrivateKey;
    let cases = [
        // The reported key: a 609-bit modulus with a 2-bit prime.
        rsa_key(rsa::BigUint::from(3_u8), mersenne(607))?,
        // A 2205-bit modulus, within the size limits, with a 2-bit prime.
        rsa_key(rsa::BigUint::from(3_u8), mersenne(2203))?,
    ];
    for key in cases {
        let certificate = tsa_certificate_for(&key)?;
        let pem = key.to_pkcs8_pem(der::pem::LineEnding::LF)?;
        assert_eq!(
            Tsa::from_pem(pem.as_bytes(), &certificate).err(),
            Some(TsaError::Key)
        );
        assert_eq!(
            Tsa::new(KeyPair::Rsa(Box::new(key)), &certificate).err(),
            Some(TsaError::Key)
        );
    }
    // A balanced key whose modulus is below 2048 bits.
    let KeyPair::Rsa(small) = KeyPair::derive(crate::pki::keys::KeyType::Rsa(1024), "small")?
    else {
        return Err("not an RSA key".into());
    };
    let certificate = tsa_certificate_for(&small)?;
    assert_eq!(
        Tsa::new(KeyPair::Rsa(small), &certificate).err(),
        Some(TsaError::Key)
    );
    // The RSA keys of the test PKI, of 2048 and 3072 bits, are accepted.
    for name in ["signer-rsa-2048", "signer-rsa-3072"] {
        Tsa::from_pem(pki_file(&key_id(name))?, pki_file(&certificate_id(name))?)?;
    }
    Ok(())
}

#[test]
fn rsa_moduli_and_primes_have_bounded_sizes() {
    let accepted: [(usize, &[usize]); 5] = [
        (2048, &[1024, 1024]),
        (2048, &[1023, 1025]),
        (3072, &[1536, 1536]),
        (4096, &[2048, 2048]),
        (4096, &[2047, 2049]),
    ];
    for (modulus, primes) in accepted {
        assert!(supported_rsa_form(modulus, primes), "{modulus} {primes:?}");
    }
    let refused: [(usize, &[usize]); 9] = [
        (2047, &[1023, 1024]),
        (2046, &[1023, 1023]),
        (4097, &[2048, 2049]),
        (2048, &[1022, 1026]),
        (2048, &[1026, 1022]),
        (2048, &[1024]),
        (2048, &[1024, 1024, 1024]),
        (2205, &[2, 2203]),
        (609, &[2, 607]),
    ];
    for (modulus, primes) in refused {
        assert!(!supported_rsa_form(modulus, primes), "{modulus} {primes:?}");
    }
}

/// Issue #75: the notes state the results that the validate-timestamp mode
/// of tools/dss-oracle gives under the aligned policy of ADR-0023, rather
/// than leave them to be confirmed.
#[test]
fn notes_state_the_results_of_dss() {
    for token in &TOKENS {
        assert!(!token.notes.contains("to be confirmed"), "{}", token.name);
        assert!(
            token.notes.contains("DSS 6.5.1 gives this result"),
            "{}",
            token.name
        );
    }
}
