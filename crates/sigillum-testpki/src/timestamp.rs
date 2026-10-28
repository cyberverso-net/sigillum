//! RFC 3161 timestamp tokens, issued for a digest at a given time.
//!
//! A token is a CMS `SignedData` (RFC 5652, section 5) whose encapsulated
//! content is a `TSTInfo` (RFC 3161, section 2.4.2), signed by the
//! timestamping authority. It is assembled by the `cms` `SignedData`
//! builder and carries the ESS `signingCertificateV2` attribute of
//! RFC 5816 and RFC 5035, built here. It carries no `signingTime`
//! attribute, and no time is read from the system clock (ADR-0014).
//!
//! Issuance is reproducible: the signature algorithms of the test PKI are
//! deterministic, and the serial number is derived from the request, as
//! [`serial_number`] describes.

// RSA private-key operations are not constant time (RUSTSEC-2023-0071).
// ADR-0010 allows them here, because timing attacks do not apply to test
// keys.
#![allow(clippy::disallowed_types)]

use std::fmt;
use std::path::{Path, PathBuf};

use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use const_oid::db::{rfc5911, rfc5912};
use der::asn1::{GeneralizedTime, Int, ObjectIdentifier, OctetString, SetOfVec};
use der::{Any, Decode, Encode, Sequence, Tag};
use pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256, Sha384, Sha512};
use spki::AlgorithmIdentifierOwned;
use time::OffsetDateTime;
use x509_cert::Certificate;
use x509_cert::attr::{Attribute, AttributeValue};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::serial_number::SerialNumber;
use x509_tsp::{MessageImprint, TspVersion, TstInfo};

use crate::manifest::{Artefact, DssResult, Indication, Kind, Links, Manifest, OpensslResult};
use crate::pki::hierarchy::Offset;
use crate::pki::keys::{CertSigner, KeyPair, KeyType, SignatureAlgorithm, SignatureBytes};
use crate::pki::{
    self, GenerateError, GeneratedFile, PkiError, Summary, certificate_id, key_id, sha256_hex,
};

pub mod input;

/// The directory of the timestamp tokens, relative to the manifest.
pub const DIRECTORY: &str = "timestamps";

/// The policy of the test timestamping authority, under the sigillum test
/// arc. Its allocation is recorded in `testdata/README.md`.
pub const TSA_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.1.2");

/// `id-ct-TSTInfo`, the content type of a `TSTInfo` (RFC 3161,
/// section 2.4.2).
pub const ID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// A digest algorithm of a message imprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// SHA-256 (RFC 5754, section 2.2).
    Sha256,
    /// SHA-384 (RFC 5754, section 2.3).
    Sha384,
    /// SHA-512 (RFC 5754, section 2.4).
    Sha512,
}

impl DigestAlgorithm {
    /// Every supported digest algorithm.
    pub const ALL: [Self; 3] = [Self::Sha256, Self::Sha384, Self::Sha512];

    /// The object identifier of the algorithm.
    pub fn oid(self) -> ObjectIdentifier {
        match self {
            Self::Sha256 => rfc5912::ID_SHA_256,
            Self::Sha384 => rfc5912::ID_SHA_384,
            Self::Sha512 => rfc5912::ID_SHA_512,
        }
    }

    /// The algorithm with this object identifier, if it is supported.
    pub fn from_oid(oid: ObjectIdentifier) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.oid() == oid)
    }

    /// The name of the algorithm, as FIPS 180-4 writes it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    /// The length of a digest, in octets.
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// The digest of `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// The algorithm identifier, with the parameters absent, as RFC 5754,
    /// section 2, requires of an implementation that generates one.
    pub fn identifier(self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: self.oid(),
            parameters: None,
        }
    }
}

/// An error found while issuing a timestamp token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TsaError {
    /// The private key is not a PKCS#8 PEM document of a supported key type,
    /// or an RSA key does not have the form that [`check_rsa_key`] requires.
    Key,
    /// The certificate is neither a PEM nor a DER X.509 certificate.
    Certificate,
    /// The private key does not belong to the certificate.
    KeyMismatch,
    /// The digest does not have the length of its algorithm's output.
    DigestLength {
        /// The digest algorithm.
        algorithm: DigestAlgorithm,
        /// The length of the given digest, in octets.
        actual: usize,
    },
    /// The time is before 1970, after 9999, or not a whole second.
    Time,
    /// The test PKI has no certificate or key with this identifier or name.
    UnknownCertificate(String),
    /// The manifest does not list this certificate, which a token links to.
    PkiNotInManifest(String),
    /// A value cannot be encoded or signed.
    Pki(PkiError),
}

impl fmt::Display for TsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key => f.write_str(
                "the private key is not a PKCS#8 PEM document of an RSA, ECDSA or Ed25519 key of a supported form; DER and other encodings are not accepted, and an RSA key needs two primes of equal size and a modulus of 2048 to 4096 bits",
            ),
            Self::Certificate => {
                f.write_str("the certificate is not a PEM or DER X.509 certificate")
            }
            Self::KeyMismatch => f.write_str("the private key does not belong to the certificate"),
            Self::DigestLength { algorithm, actual } => write!(
                f,
                "a {} digest has {} octets, not {actual}",
                algorithm.name(),
                algorithm.output_len()
            ),
            Self::Time => f.write_str(
                "the time must be a whole second from 1970-01-01T00:00:00Z to 9999-12-31T23:59:59Z",
            ),
            Self::PkiNotInManifest(id) => write!(
                f,
                "the manifest does not list {id}, which the timestamp tokens link to; run sigillum-testpki generate pki first"
            ),
            Self::UnknownCertificate(name) => {
                write!(f, "the test PKI has no certificate or key \"{name}\"")
            }
            Self::Pki(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for TsaError {}

impl From<PkiError> for TsaError {
    fn from(error: PkiError) -> Self {
        Self::Pki(error)
    }
}

/// A timestamping authority: a private key, its certificate, and the
/// algorithms it signs with.
pub struct Tsa {
    key: KeyPair,
    certificate: Certificate,
    certificate_der: Vec<u8>,
    signature: SignatureAlgorithm,
    digest: DigestAlgorithm,
}

impl Tsa {
    /// Returns the authority with this key and certificate, given as a DER
    /// or PEM X.509 certificate.
    ///
    /// A DER certificate is one value with nothing after it. A PEM
    /// certificate is a single `CERTIFICATE` block: only a UTF-8 byte order
    /// mark and white space may precede it, and nothing may follow the END
    /// line but its line ending. Chain files, which hold several blocks, and
    /// the output of `openssl x509 -text`, which puts text before the block,
    /// are refused. Every DER length is checked against the input before
    /// decoding ([`input::check_der`]).
    ///
    /// An RSA key must have the form that [`check_rsa_key`] describes;
    /// another gives [`TsaError::Key`] before anything is signed.
    ///
    /// The key matches the certificate when their public keys are equal
    /// once decoded, so an elliptic-curve point may be compressed or not in
    /// the certificate; a point that is not on the curve is refused.
    ///
    /// The authority signs with the algorithm that matches its key: RSA
    /// PKCS#1 v1.5 with SHA-256, ECDSA with SHA-256, SHA-384 or SHA-512 on
    /// P-256, P-384 or P-521 (RFC 5753, section 2.1.1), or Ed25519 with
    /// SHA-512 as the digest of the signed attributes (RFC 8419, section 3).
    ///
    /// # Errors
    ///
    /// Returns [`TsaError::Key`] if an RSA key has an unsupported form,
    /// [`TsaError::Certificate`] if the certificate cannot be parsed, and
    /// [`TsaError::KeyMismatch`] if the key does not belong to it.
    pub fn new(key: KeyPair, certificate: &[u8]) -> Result<Self, TsaError> {
        if let KeyPair::Rsa(rsa_key) = &key {
            check_rsa_key(rsa_key)?;
        }
        // The DER is decoded from PEM first, and its lengths are checked
        // before x509-cert decodes it (see input::check_der).
        let der = if input::is_pem(certificate) {
            let (label, der) = der::pem::decode_vec(input::trim_pem_start(certificate))
                .map_err(|_| TsaError::Certificate)?;
            if label != "CERTIFICATE" {
                return Err(TsaError::Certificate);
            }
            der
        } else {
            certificate.to_vec()
        };
        input::check_der(&der).map_err(|_| TsaError::Certificate)?;
        let certificate = Certificate::from_der(&der).map_err(|_| TsaError::Certificate)?;
        let certificate_der = certificate.to_der().map_err(|_| TsaError::Certificate)?;
        if !public_key_matches(&key, &certificate.tbs_certificate.subject_public_key_info)? {
            return Err(TsaError::KeyMismatch);
        }
        let (signature, digest) = match key.key_type() {
            KeyType::Rsa(_) => (SignatureAlgorithm::RsaPkcs1Sha256, DigestAlgorithm::Sha256),
            KeyType::P256 => (SignatureAlgorithm::EcdsaSha256, DigestAlgorithm::Sha256),
            KeyType::P384 => (SignatureAlgorithm::EcdsaSha384, DigestAlgorithm::Sha384),
            KeyType::P521 => (SignatureAlgorithm::EcdsaSha512, DigestAlgorithm::Sha512),
            KeyType::Ed25519 => (SignatureAlgorithm::Ed25519, DigestAlgorithm::Sha512),
        };
        Ok(Self {
            key,
            certificate,
            certificate_der,
            signature,
            digest,
        })
    }

    /// Returns the authority with a PKCS#8 PEM private key (RFC 5958 and
    /// RFC 7468) and a DER or PEM certificate, both as the bytes of their
    /// files. A UTF-8 byte order mark and white space before a PEM document
    /// are ignored. The certificate follows the rules of [`Tsa::new`].
    ///
    /// # Errors
    ///
    /// Returns [`TsaError::Key`] if the key cannot be parsed, and the errors
    /// of [`Tsa::new`].
    pub fn from_pem(key: &[u8], certificate: &[u8]) -> Result<Self, TsaError> {
        let key = std::str::from_utf8(input::trim_pem_start(key)).map_err(invalid_key)?;
        Self::new(private_key(key)?, certificate)
    }

    /// The DER-encoded certificate of the authority.
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Issues a DER-encoded `TimeStampToken` (RFC 3161, section 2.4.2) for
    /// `digest`, computed with `algorithm`, at `time`.
    ///
    /// # Errors
    ///
    /// Returns [`TsaError::DigestLength`] if the digest has the wrong
    /// length, [`TsaError::Time`] if the time cannot be a `genTime`, and
    /// [`TsaError::Pki`] if the token cannot be encoded or signed.
    pub fn issue(
        &self,
        algorithm: DigestAlgorithm,
        digest: &[u8],
        time: OffsetDateTime,
    ) -> Result<Vec<u8>, TsaError> {
        if digest.len() != algorithm.output_len() {
            return Err(TsaError::DigestLength {
                algorithm,
                actual: digest.len(),
            });
        }
        let gen_time = generalized_time(time)?;
        let serial = serial_number(
            &self.certificate_der,
            algorithm,
            digest,
            time.unix_timestamp(),
        );
        // RFC 3161, section 2.4.2: no accuracy, ordering FALSE (the
        // default, so absent), no nonce because there is no request, and
        // no tsa name, which is optional.
        let tst_info = TstInfo {
            version: TspVersion::V1,
            policy: TSA_POLICY,
            message_imprint: MessageImprint {
                hash_algorithm: spki::AlgorithmIdentifier {
                    oid: algorithm.oid(),
                    parameters: None,
                },
                hashed_message: OctetString::new(digest).map_err(encoding)?,
            },
            serial_number: Int::new(&serial).map_err(encoding)?,
            gen_time,
            accuracy: None,
            ordering: false,
            nonce: None,
            tsa: None,
            extensions: None,
        };
        let econtent =
            Any::new(Tag::OctetString, tst_info.to_der().map_err(encoding)?).map_err(encoding)?;
        // RFC 3161, section 2.4.2: the eContentType is id-ct-TSTInfo and
        // the eContent the DER-encoded TSTInfo.
        let content = EncapsulatedContentInfo {
            econtent_type: ID_CT_TST_INFO,
            econtent: Some(econtent),
        };
        let tbs = &self.certificate.tbs_certificate;
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: tbs.issuer.clone(),
            serial_number: tbs.serial_number.clone(),
        });
        let signer = CertSigner::new(&self.key, self.signature)?;
        // RFC 5652, section 5.3: the builder adds the content type and
        // message digest attributes. RFC 3161, section 2.4.1, as updated by
        // RFC 5816, section 2.2.1, requires the ESS signing certificate.
        // No signingTime attribute is added.
        let mut signer_info =
            SignerInfoBuilder::new(&signer, sid, self.digest.identifier(), &content, None)
                .map_err(encoding)?;
        signer_info
            .add_signed_attribute(self.signing_certificate_v2()?)
            .map_err(encoding)?;
        // RFC 3161, section 2.4.1: the TSA certificate is included, as a
        // request with certReq TRUE would ask, so that a verifier needs
        // only the chain above it.
        let token = SignedDataBuilder::new(&content)
            .add_digest_algorithm(self.digest.identifier())
            .and_then(|builder| {
                builder.add_certificate(CertificateChoices::Certificate(self.certificate.clone()))
            })
            .and_then(|builder| builder.add_signer_info::<_, SignatureBytes>(signer_info))
            .and_then(|builder| builder.build())
            .map_err(|_| TsaError::Pki(PkiError::Signing))?;
        token.to_der().map_err(encoding)
    }

    /// The ESS `signingCertificateV2` attribute of the authority's
    /// certificate (RFC 5035, sections 3 and 4): one `ESSCertIDv2` with the
    /// SHA-256 hash of the certificate, the default, and its issuer and
    /// serial number. No policies are given.
    fn signing_certificate_v2(&self) -> Result<Attribute, TsaError> {
        let tbs = &self.certificate.tbs_certificate;
        let value = SigningCertificateV2 {
            certs: vec![EssCertIdV2 {
                cert_hash: OctetString::new(Sha256::digest(&self.certificate_der).to_vec())
                    .map_err(encoding)?,
                issuer_serial: IssuerSerial {
                    issuer: vec![GeneralName::DirectoryName(tbs.issuer.clone())],
                    serial_number: tbs.serial_number.clone(),
                },
            }],
        };
        let value = AttributeValue::encode_from(&value).map_err(encoding)?;
        Ok(Attribute {
            oid: rfc5911::ID_AA_SIGNING_CERTIFICATE_V_2,
            values: SetOfVec::try_from(vec![value]).map_err(encoding)?,
        })
    }
}

/// The smallest RSA modulus that a timestamping authority may have, in bits.
pub const MIN_RSA_BITS: usize = 2048;

/// The largest RSA modulus that a timestamping authority may have, in bits.
pub const MAX_RSA_BITS: usize = 4096;

/// Checks that an RSA private key has the form of the keys of the test PKI
/// before it signs anything.
///
/// RFC 8017, section 3.2, allows any product of distinct odd primes, with a
/// public exponent between 3 and n - 1 (section 3.1). A key with very
/// unequal primes is valid there, yet rsa 0.9.10 may take practically
/// forever to sign with it: with p = 3 and q = 2^607 - 1, the recombination
/// of the Chinese remainder theorem adds p to a negative difference of the
/// order of q one step at a time. This tool therefore accepts only:
///
/// - the key's own consistency check, `RsaPrivateKey::validate`, which
///   checks that the primes multiply to n and that d inverts e;
/// - exactly two primes (the quintuple form of section 3.2, with u = 2);
/// - a modulus of [`MIN_RSA_BITS`] to [`MAX_RSA_BITS`] bits, which covers
///   the 2048-bit and 3072-bit keys of the test PKI;
/// - primes of half the modulus length each, within one bit;
/// - as a consequence of the consistency check, an odd public exponent of
///   at least 3, as section 3.1 requires: the rsa crate refuses an
///   exponent below 2 or above 2^33 - 1, and d e = 1 modulo the even
///   number p - 1 holds only for an odd e.
///
/// # Errors
///
/// Returns [`TsaError::Key`] for a key of another form.
pub fn check_rsa_key(key: &rsa::RsaPrivateKey) -> Result<(), TsaError> {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    key.validate().map_err(invalid_key)?;
    let primes: Vec<usize> = key.primes().iter().map(rsa::BigUint::bits).collect();
    if supported_rsa_form(key.n().bits(), &primes) {
        Ok(())
    } else {
        Err(TsaError::Key)
    }
}

/// Reports whether a modulus of `modulus_bits` with primes of `prime_bits`
/// has the form that [`check_rsa_key`] accepts.
fn supported_rsa_form(modulus_bits: usize, prime_bits: &[usize]) -> bool {
    let half = modulus_bits / 2;
    (MIN_RSA_BITS..=MAX_RSA_BITS).contains(&modulus_bits)
        && prime_bits.len() == 2
        && prime_bits
            .iter()
            .all(|&bits| bits + 1 >= half && bits <= half + 1)
}

/// Reports whether `key` is the private key of the public key in `spki`.
///
/// The public keys are compared after decoding, not as encoded bytes, so
/// that a certificate may carry an elliptic-curve point in compressed or
/// uncompressed form (SEC 1, section 2.3.3; RFC 5480, section 2.2): the
/// point is decoded and checked to lie on the curve, then compared. RSA keys
/// are compared by modulus and public exponent (RFC 8017, section 3.1), and
/// Ed25519 keys by their 32 octets after decoding (RFC 8410, section 4).
/// A public key of another algorithm or curve does not match.
///
/// # Errors
///
/// Returns [`TsaError::Certificate`] if the public key of the certificate,
/// of the key's own algorithm and curve, cannot be decoded.
fn public_key_matches(
    key: &KeyPair,
    spki: &spki::SubjectPublicKeyInfoOwned,
) -> Result<bool, TsaError> {
    use const_oid::db::{rfc5912, rfc8410};
    use spki::DecodePublicKey;
    let curve = || {
        spki.algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok())
    };
    let expected = match key {
        KeyPair::Rsa(_) => spki.algorithm.oid == rfc5912::RSA_ENCRYPTION,
        KeyPair::P256(_) => {
            spki.algorithm.oid == rfc5912::ID_EC_PUBLIC_KEY
                && curve() == Some(rfc5912::SECP_256_R_1)
        }
        KeyPair::P384(_) => {
            spki.algorithm.oid == rfc5912::ID_EC_PUBLIC_KEY
                && curve() == Some(rfc5912::SECP_384_R_1)
        }
        KeyPair::P521(_) => {
            spki.algorithm.oid == rfc5912::ID_EC_PUBLIC_KEY
                && curve() == Some(rfc5912::SECP_521_R_1)
        }
        KeyPair::Ed25519(_) => spki.algorithm.oid == rfc8410::ID_ED_25519,
    };
    if !expected {
        return Ok(false);
    }
    let der = spki.to_der().map_err(|_| TsaError::Certificate)?;
    let invalid = |_| TsaError::Certificate;
    Ok(match key {
        KeyPair::Rsa(private) => {
            let public = rsa::RsaPublicKey::from_public_key_der(&der).map_err(invalid)?;
            public == private.to_public_key()
        }
        KeyPair::P256(private) => {
            p256::PublicKey::from_public_key_der(&der).map_err(invalid)? == private.public_key()
        }
        KeyPair::P384(private) => {
            p384::PublicKey::from_public_key_der(&der).map_err(invalid)? == private.public_key()
        }
        KeyPair::P521(private) => {
            p521::PublicKey::from_public_key_der(&der).map_err(invalid)? == private.public_key()
        }
        KeyPair::Ed25519(private) => {
            ed25519_dalek::VerifyingKey::from_public_key_der(&der).map_err(invalid)?
                == private.verifying_key()
        }
    })
}

/// Parses a PKCS#8 PEM private key of a type of the test PKI.
fn private_key(pem: &str) -> Result<KeyPair, TsaError> {
    let (label, document) = der::SecretDocument::from_pem(pem).map_err(|_| TsaError::Key)?;
    if label != "PRIVATE KEY" {
        return Err(TsaError::Key);
    }
    // The key decoders of RustCrypto borrow their input, so a length beyond
    // it allocates nothing, but the same check keeps both inputs alike.
    input::check_der(document.as_bytes()).map_err(invalid_key)?;
    private_key_from_der(document.as_bytes())
}

/// Parses a PKCS#8 DER private key of a type of the test PKI.
fn private_key_from_der(der: &[u8]) -> Result<KeyPair, TsaError> {
    use const_oid::db::{rfc5912, rfc8410};
    let info = pkcs8::PrivateKeyInfo::try_from(der).map_err(invalid_key)?;
    Ok(match info.algorithm.oid {
        rfc5912::RSA_ENCRYPTION => KeyPair::Rsa(Box::new(
            rsa::RsaPrivateKey::from_pkcs8_der(der).map_err(invalid_key)?,
        )),
        rfc5912::ID_EC_PUBLIC_KEY => match info.algorithm.parameters_oid().map_err(invalid_key)? {
            rfc5912::SECP_256_R_1 => {
                KeyPair::P256(p256::SecretKey::from_pkcs8_der(der).map_err(invalid_key)?)
            }
            rfc5912::SECP_384_R_1 => {
                KeyPair::P384(p384::SecretKey::from_pkcs8_der(der).map_err(invalid_key)?)
            }
            rfc5912::SECP_521_R_1 => {
                KeyPair::P521(p521::SecretKey::from_pkcs8_der(der).map_err(invalid_key)?)
            }
            _ => return Err(TsaError::Key),
        },
        rfc8410::ID_ED_25519 => {
            KeyPair::Ed25519(ed25519_dalek::SigningKey::from_pkcs8_der(der).map_err(invalid_key)?)
        }
        _ => return Err(TsaError::Key),
    })
}

/// Maps an encoding error of any type to [`PkiError::Encoding`].
fn encoding<E>(_: E) -> TsaError {
    TsaError::Pki(PkiError::Encoding)
}

/// Maps a decoding error of any type to [`TsaError::Key`].
fn invalid_key<E>(_: E) -> TsaError {
    TsaError::Key
}

/// The `genTime` of a token at `time`, in whole seconds (RFC 3161,
/// section 2.4.2).
fn generalized_time(time: OffsetDateTime) -> Result<GeneralizedTime, TsaError> {
    if time.nanosecond() != 0 {
        return Err(TsaError::Time);
    }
    let seconds = u64::try_from(time.unix_timestamp()).map_err(|_| TsaError::Time)?;
    GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(seconds))
        .map_err(|_| TsaError::Time)
}

/// The label that starts the input of [`serial_number`].
const SERIAL_LABEL: &[u8] = b"sigillum-testpki/tst-serial";

/// `SigningCertificateV2` (RFC 5035, section 3), without policies.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SigningCertificateV2 {
    certs: Vec<EssCertIdV2>,
}

/// `ESSCertIDv2` (RFC 5035, section 4), with the hash algorithm at its
/// default, SHA-256, and so absent from the encoding.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct EssCertIdV2 {
    cert_hash: OctetString,
    issuer_serial: IssuerSerial,
}

/// `IssuerSerial` (RFC 5035, section 4).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct IssuerSerial {
    issuer: Vec<GeneralName>,
    serial_number: SerialNumber,
}

/// The serial number of the token that `certificate` issues for `digest`,
/// computed with `algorithm`, at `seconds` since 1970-01-01T00:00:00Z.
///
/// RFC 3161, section 2.4.2, requires a serial number unique among the
/// tokens of one authority. Neither a counter nor the clock is used, so
/// that generation stays reproducible and every run of the `tsa`
/// subcommand stands alone. The serial number is the first 16 octets of
/// SHA-256 over a fixed label, the SHA-256 hash of the DER certificate,
/// the DER object identifier of the algorithm, the digest, whose length
/// the algorithm fixes, and the time in seconds since 1970 as a 64-bit
/// big-endian integer. Each input has a fixed or self-delimiting length,
/// so the concatenation is unambiguous. The two top bits
/// of the first octet are then set to `01`, so that the number is positive
/// and always 16 octets long.
///
/// Two requests to one authority that differ in algorithm, digest or time
/// therefore get different serial numbers, except with a probability of
/// about 2^-126 per pair. Two identical requests get the same serial
/// number, and the same token byte for byte.
pub fn serial_number(
    certificate: &[u8],
    algorithm: DigestAlgorithm,
    digest: &[u8],
    seconds: i64,
) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(SERIAL_LABEL);
    hash.update(Sha256::digest(certificate));
    // The DER encoding of an object identifier cannot fail; an empty
    // encoding would still leave the other inputs to distinguish requests.
    hash.update(algorithm.oid().to_der().unwrap_or_default());
    hash.update(digest);
    hash.update(seconds.to_be_bytes());
    let hash = hash.finalize();
    let mut serial = [0; 16];
    serial.copy_from_slice(hash.get(..16).unwrap_or(&[0; 16]));
    serial[0] = (serial[0] & 0x3f) | 0x40;
    serial
}

/// One token of the corpus.
struct TokenSpec {
    name: &'static str,
    signer: &'static str,
    gen_time: Offset,
    imprint: Imprint,
    purpose: &'static str,
    expected_openssl: OpensslResult,
    expected_dss: (Indication, Option<&'static str>),
    notes: &'static str,
}

/// What the message imprint of a token covers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Imprint {
    /// The SHA-256 digest of the content.
    Content,
    /// The SHA-256 digest of the content with its last octet inverted.
    Mismatch,
}

/// The identifier of the data that the tokens cover.
pub const CONTENT_ID: &str = "timestamps/content";

/// The data that the tokens cover.
pub const CONTENT: &[u8] =
    b"sigillum test corpus: the data covered by the timestamp tokens under timestamps/.\n";

/// The tokens of the corpus, each standalone.
const TOKENS: [TokenSpec; 4] = [
    TokenSpec {
        name: "valid",
        signer: "tsa",
        gen_time: Offset::days(-1),
        imprint: Imprint::Content,
        purpose: "Valid timestamp token over timestamps/content, issued by pki/tsa one day before the validation time.",
        expected_openssl: OpensslResult::Verified,
        expected_dss: (Indication::Passed, None),
        notes: "The DSS result is a prediction from ETSI EN 319 102-1 V1.4.1, clause 5.4.4. DSS 6.5.1 gives this result in the validate-timestamp mode of tools/dss-oracle, under the aligned policy of ADR-0023. Step 1 runs the basic signature validation, whose X.509 validation checks revocation (clause 5.2.6.4, step 4) with the CRLs that the chain of pki/tsa links: crl/ca-ecdsa for pki/tsa and crl/root-ca for pki/ca-ecdsa. Neither CRL revokes a certificate of the chain.",
    },
    TokenSpec {
        name: "signer-without-time-stamping",
        signer: "signer-p256",
        gen_time: Offset::days(-1),
        imprint: Imprint::Content,
        purpose: "Timestamp token over timestamps/content, signed by pki/signer-p256, whose certificate lacks the extended key usage id-kp-timeStamping.",
        expected_openssl: OpensslResult::Rejected,
        expected_dss: (Indication::Indeterminate, Some("CHAIN_CONSTRAINTS_FAILURE")),
        notes: "RFC 3161, section 2.3, requires the critical extended key usage id-kp-timeStamping. The DSS result is a prediction from ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, step 5. DSS 6.5.1 gives this result in the validate-timestamp mode of tools/dss-oracle, under the aligned policy of ADR-0023.",
    },
    TokenSpec {
        name: "imprint-mismatch",
        signer: "tsa",
        gen_time: Offset::days(-1),
        imprint: Imprint::Mismatch,
        purpose: "Timestamp token issued by pki/tsa whose message imprint does not match timestamps/content.",
        expected_openssl: OpensslResult::Rejected,
        expected_dss: (Indication::Failed, Some("HASH_FAILURE")),
        notes: "The message imprint is the SHA-256 digest of timestamps/content with its last octet inverted. The token itself is intact. FAILED with HASH_FAILURE is the project's mapping for a message imprint that does not match the data supplied to the validation, as the validate-timestamp mode of tools/dss-oracle compares it. It is a prediction, and DSS 6.5.1 gives this result in that mode, under the aligned policy of ADR-0023.",
    },
    TokenSpec {
        name: "gen-time-after-validation-time",
        signer: "tsa",
        gen_time: Offset::days(1),
        imprint: Imprint::Content,
        purpose: "Timestamp token over timestamps/content, issued by pki/tsa with a genTime one day after the validation time.",
        expected_openssl: OpensslResult::Verified,
        expected_dss: (Indication::Passed, None),
        notes: "openssl ts -verify does not compare genTime with the verification time. Neither does the time-stamp validation building block of ETSI EN 319 102-1 V1.4.1, clause 5.4.4, so the DSS result PASSED is a prediction. DSS 6.5.1 gives this result in the validate-timestamp mode of tools/dss-oracle, under the aligned policy of ADR-0023. As for timestamps/valid, revocation is checked (clause 5.2.6.4, step 4) with the CRLs that the chain of pki/tsa links, crl/ca-ecdsa and crl/root-ca, which revoke none of its certificates. A verifier that uses the token as time evidence must reject a genTime after the validation time.",
    },
];

/// Generates the standalone timestamp tokens of the corpus and the data
/// they cover, with the test PKI of `validation_time`.
///
/// # Errors
///
/// Returns a [`TsaError`] if the test PKI or a token cannot be generated.
pub fn generate(validation_time: OffsetDateTime) -> Result<Vec<GeneratedFile>, TsaError> {
    let pki = pki::generate(validation_time)?;
    let contents = |id: &str| {
        pki.iter()
            .find(|file| file.artefact.id == id)
            .map(|file| file.contents.as_slice())
            .ok_or_else(|| TsaError::UnknownCertificate(id.to_owned()))
    };
    let authority = |name: &str| -> Result<Tsa, TsaError> {
        Tsa::from_pem(contents(&key_id(name))?, contents(&certificate_id(name))?)
    };
    let mut files = vec![content_file()];
    let digest = DigestAlgorithm::Sha256.digest(CONTENT);
    for spec in &TOKENS {
        let imprint = match spec.imprint {
            Imprint::Content => digest.clone(),
            Imprint::Mismatch => {
                let mut other = digest.clone();
                if let Some(last) = other.last_mut() {
                    *last = !*last;
                }
                other
            }
        };
        let time = spec.gen_time.from(validation_time)?;
        let token = authority(spec.signer)?.issue(DigestAlgorithm::Sha256, &imprint, time)?;
        files.push(token_file(spec, token)?);
    }
    Ok(files)
}

/// The file of the data that the tokens cover.
fn content_file() -> GeneratedFile {
    GeneratedFile {
        artefact: Artefact {
            id: CONTENT_ID.to_owned(),
            path: PathBuf::from(format!("{CONTENT_ID}.txt")),
            sha256: sha256_hex(CONTENT),
            kind: Kind::Document,
            purpose: "The data covered by the timestamp tokens under timestamps/.".to_owned(),
            expected_openssl: OpensslResult::NotApplicable,
            expected_dss: DssResult::NotApplicable,
            links: Links::default(),
            attack_class: None,
            dss_divergence: None,
            notes: None,
        },
        contents: CONTENT.to_vec(),
    }
}

/// The file and manifest entry of a token.
fn token_file(spec: &TokenSpec, token: Vec<u8>) -> Result<GeneratedFile, TsaError> {
    let chain = chain_ids(spec.signer)?;
    let (indication, sub_indication) = spec.expected_dss;
    Ok(GeneratedFile {
        artefact: Artefact {
            id: format!("{DIRECTORY}/{}", spec.name),
            path: PathBuf::from(format!("{DIRECTORY}/{}.tst", spec.name)),
            sha256: sha256_hex(&token),
            kind: Kind::TimestampToken,
            purpose: spec.purpose.to_owned(),
            expected_openssl: spec.expected_openssl,
            expected_dss: DssResult::Indication {
                indication,
                sub_indication: sub_indication.map(str::to_owned),
            },
            links: Links {
                issuer: chain.first().cloned(),
                chain,
                revocation: Vec::new(),
                content: Some(CONTENT_ID.to_owned()),
                timestamp_chain: Vec::new(),
            },
            attack_class: None,
            dss_divergence: None,
            notes: Some(spec.notes.to_owned()),
        },
        contents: token,
    })
}

/// The identifiers of the certificate with this name and of the chain
/// above it, up to the root.
fn chain_ids(name: &str) -> Result<Vec<String>, TsaError> {
    let signer = crate::pki::hierarchy::find(name)
        .ok_or_else(|| TsaError::UnknownCertificate(name.to_owned()))?;
    let mut chain = vec![certificate_id(name)];
    chain.extend(
        crate::pki::hierarchy::chain(signer)?
            .iter()
            .map(|issuer| certificate_id(issuer.name)),
    );
    Ok(chain)
}

/// Checks that the manifest lists every certificate the tokens link to.
fn check_pki_listed(manifest: &Manifest) -> Result<(), TsaError> {
    for spec in &TOKENS {
        for id in chain_ids(spec.signer)? {
            if !manifest.artefacts.iter().any(|artefact| artefact.id == id) {
                return Err(TsaError::PkiNotInManifest(id));
            }
        }
    }
    Ok(())
}

/// Reports whether an entry belongs to what `generate timestamps`
/// produces: any entry whose identifier is under [`DIRECTORY`].
fn generated_here(artefact: &Artefact) -> bool {
    artefact.id.starts_with(&format!("{DIRECTORY}/"))
}

/// Generates the timestamp tokens with the validation time of the manifest
/// at `manifest_path`, writes each file under the manifest's directory,
/// and records each in the manifest, as [`pki::write_into_corpus`] does for
/// the test PKI. Every entry under [`DIRECTORY`] belongs to this generator.
/// The manifest must already list the test PKI, which the tokens link to;
/// otherwise nothing is written.
///
/// # Errors
///
/// Returns a [`GenerateError`] if the manifest cannot be read, does not
/// list the test PKI or cannot be updated, or a file cannot be generated
/// or written.
pub fn write_into_corpus(manifest_path: &Path) -> Result<Summary, GenerateError> {
    pki::write_generated(
        manifest_path,
        DIRECTORY,
        generated_here,
        |manifest| {
            check_pki_listed(manifest).map_err(GenerateError::Timestamp)?;
            generate(manifest.header.validation_time).map_err(GenerateError::Timestamp)
        },
        |_, _| {},
    )
}

#[cfg(test)]
mod tests;
