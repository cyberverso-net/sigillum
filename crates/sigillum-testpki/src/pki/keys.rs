//! Key pairs of the test PKI and the signature algorithms they sign with.
//!
//! RSA private-key operations are not constant time (RUSTSEC-2023-0071).
//! ADR-0010 allows them here, because timing attacks do not apply to test
//! keys.
#![allow(clippy::disallowed_types)]

use der::asn1::{AnyRef, ObjectIdentifier};
use der::pem::LineEnding;
use der::{Decode, Encode};
use pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256, Sha384};
use sha3::Sha3_256;
use signature::{RandomizedSigner, SignatureEncoding, Signer};
use spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
    SubjectPublicKeyInfoOwned,
};

use super::PkiError;
use super::rng::TestRng;

/// `id-rsassa-pkcs1-v1_5-with-sha3-256`, from the NIST Computer Security
/// Objects Register (csor 3, nistAlgorithm 4, sigAlgs 3, 14).
pub const RSA_PKCS1_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.14");

/// The type and size of a key pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// RSA with a modulus of this many bits.
    Rsa(usize),
    /// ECDSA on P-256.
    P256,
    /// ECDSA on P-384.
    P384,
    /// ECDSA on P-521.
    P521,
    /// Ed25519.
    Ed25519,
}

/// A signature algorithm used to sign certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// RSA PKCS#1 v1.5 with SHA-256 (RFC 4055, section 5).
    RsaPkcs1Sha256,
    /// RSA PKCS#1 v1.5 with SHA3-256 (NIST Computer Security Objects Register).
    RsaPkcs1Sha3_256,
    /// RSASSA-PSS with SHA-256, MGF1 with SHA-256 and a 32-byte salt (RFC 4055, section 3).
    RsaPssSha256,
    /// RSASSA-PSS with SHA-384, MGF1 with SHA-384 and a 48-byte salt (RFC 4055, section 3).
    RsaPssSha384,
    /// ECDSA with SHA-256 (RFC 5758, section 3.2).
    EcdsaSha256,
    /// ECDSA with SHA-384 (RFC 5758, section 3.2).
    EcdsaSha384,
    /// ECDSA with SHA-512 (RFC 5758, section 3.2), used with P-521 keys.
    EcdsaSha512,
    /// Ed25519 (RFC 8410, section 3).
    Ed25519,
}

impl SignatureAlgorithm {
    /// The algorithm identifier written in `signature` and
    /// `signatureAlgorithm` of a certificate (RFC 5280, section 4.1.1.2).
    ///
    /// # Errors
    ///
    /// Returns [`PkiError::Encoding`] if the parameters cannot be encoded.
    pub fn identifier(self) -> Result<AlgorithmIdentifierOwned, PkiError> {
        use const_oid::db::{rfc5912, rfc8410};
        let null = || Some(AnyRef::NULL.into());
        // RFC 4055, section 5: the parameters of the PKCS#1 v1.5 identifiers
        // are NULL. The SHA-3 identifier takes NULL too, as OpenSSL encodes
        // it; the NIST register does not specify the parameters.
        let (oid, parameters) = match self {
            Self::RsaPkcs1Sha256 => (rfc5912::SHA_256_WITH_RSA_ENCRYPTION, null()),
            Self::RsaPkcs1Sha3_256 => (RSA_PKCS1_SHA3_256, null()),
            Self::RsaPssSha256 => return pss_identifier::<Sha256>(),
            Self::RsaPssSha384 => return pss_identifier::<Sha384>(),
            // RFC 5758, section 3.2 and RFC 8410, section 3: parameters absent.
            Self::EcdsaSha256 => (rfc5912::ECDSA_WITH_SHA_256, None),
            Self::EcdsaSha384 => (rfc5912::ECDSA_WITH_SHA_384, None),
            Self::EcdsaSha512 => (rfc5912::ECDSA_WITH_SHA_512, None),
            Self::Ed25519 => (rfc8410::ID_ED_25519, None),
        };
        Ok(AlgorithmIdentifierOwned { oid, parameters })
    }
}

/// The RSASSA-PSS identifier of RFC 4055, section 3.1, with the hash and
/// MGF1 hash both `D`, a salt as long as the hash and the default trailer.
fn pss_identifier<D>() -> Result<AlgorithmIdentifierOwned, PkiError>
where
    D: Digest + const_oid::AssociatedOid,
{
    // RsaPssParams::new writes NULL hash parameters, as the identifiers of
    // RFC 4055, section 2.1 require, and omits the default trailer field.
    let params = rsa::pkcs1::RsaPssParams::new::<D>(
        u8::try_from(<D as Digest>::output_size()).map_err(|_| PkiError::Encoding)?,
    );
    let parameters = der::asn1::Any::encode_from(&params).map_err(|_| PkiError::Encoding)?;
    Ok(AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ID_RSASSA_PSS,
        parameters: Some(parameters),
    })
}

/// A key pair of the test PKI.
#[derive(Clone)]
pub enum KeyPair {
    /// An RSA key pair.
    Rsa(Box<RsaPrivateKey>),
    /// A P-256 key pair.
    P256(p256::SecretKey),
    /// A P-384 key pair.
    P384(p384::SecretKey),
    /// A P-521 key pair.
    P521(p521::SecretKey),
    /// An Ed25519 key pair.
    Ed25519(ed25519_dalek::SigningKey),
}

impl KeyPair {
    /// Derives the key pair of the given type from a label, reproducibly.
    ///
    /// # Errors
    ///
    /// Returns [`PkiError::KeyGeneration`] if the key cannot be generated.
    pub fn derive(key_type: KeyType, label: &str) -> Result<Self, PkiError> {
        let mut rng = TestRng::new(format!("key/{label}").as_bytes());
        Ok(match key_type {
            KeyType::Rsa(bits) => Self::Rsa(Box::new(
                RsaPrivateKey::new(&mut rng, bits).map_err(|_| PkiError::KeyGeneration)?,
            )),
            KeyType::P256 => Self::P256(p256::SecretKey::random(&mut rng)),
            KeyType::P384 => Self::P384(p384::SecretKey::random(&mut rng)),
            KeyType::P521 => Self::P521(p521::SecretKey::random(&mut rng)),
            KeyType::Ed25519 => Self::Ed25519(ed25519_dalek::SigningKey::generate(&mut rng)),
        })
    }

    /// The type and size of the key.
    pub fn key_type(&self) -> KeyType {
        match self {
            Self::Rsa(key) => KeyType::Rsa(rsa::traits::PublicKeyParts::size(key.as_ref()) * 8),
            Self::P256(_) => KeyType::P256,
            Self::P384(_) => KeyType::P384,
            Self::P521(_) => KeyType::P521,
            Self::Ed25519(_) => KeyType::Ed25519,
        }
    }

    /// The DER-encoded `SubjectPublicKeyInfo` of the public key (RFC 5280,
    /// section 4.1.2.7; RFC 5480 for ECDSA; RFC 8410, section 4 for Ed25519).
    ///
    /// # Errors
    ///
    /// Returns [`PkiError::Encoding`] if the key cannot be encoded.
    pub fn spki_der(&self) -> Result<Vec<u8>, PkiError> {
        let document = match self {
            Self::Rsa(key) => key.to_public_key().to_public_key_der(),
            Self::P256(key) => key.public_key().to_public_key_der(),
            Self::P384(key) => key.public_key().to_public_key_der(),
            Self::P521(key) => key.public_key().to_public_key_der(),
            Self::Ed25519(key) => key.verifying_key().to_public_key_der(),
        };
        document
            .map(|d| d.as_bytes().to_vec())
            .map_err(|_| PkiError::Encoding)
    }

    /// The private key as a PKCS#8 PEM document (RFC 5958 and RFC 7468),
    /// with LF line endings. Ed25519 keys use the version 1 structure of
    /// RFC 8410, section 7, without the public key.
    ///
    /// # Errors
    ///
    /// Returns [`PkiError::Encoding`] if the key cannot be encoded.
    pub fn pkcs8_pem(&self) -> Result<String, PkiError> {
        let document = match self {
            Self::Rsa(key) => key.to_pkcs8_der(),
            Self::P256(key) => key.to_pkcs8_der(),
            Self::P384(key) => key.to_pkcs8_der(),
            Self::P521(key) => key.to_pkcs8_der(),
            Self::Ed25519(key) => ed25519_dalek::pkcs8::KeypairBytes {
                secret_key: key.to_bytes(),
                public_key: None,
            }
            .to_pkcs8_der(),
        }
        .map_err(|_| PkiError::Encoding)?;
        document
            .to_pem("PRIVATE KEY", LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(|_| PkiError::Encoding)
    }

    /// Signs a message, returning the signature value as it is placed in
    /// the `signatureValue` bit string of a certificate.
    ///
    /// ECDSA signatures are DER-encoded `Ecdsa-Sig-Value` structures
    /// (RFC 5758, section 3.2), with RFC 6979 nonces on P-256 and P-384.
    /// On P-521 the nonce comes from a deterministic generator seeded with
    /// the private key and the message, and with RSASSA-PSS the salt from
    /// one seeded with the message. Every signature is therefore
    /// reproducible.
    ///
    /// # Errors
    ///
    /// Returns [`PkiError::KeyMismatch`] if the key cannot sign with the
    /// algorithm, and [`PkiError::Signing`] if signing fails.
    pub fn sign(&self, algorithm: SignatureAlgorithm, message: &[u8]) -> Result<Vec<u8>, PkiError> {
        use SignatureAlgorithm as A;
        let signing = |_| PkiError::Signing;
        match (self, algorithm) {
            (Self::Rsa(key), A::RsaPkcs1Sha256) => {
                rsa::pkcs1v15::SigningKey::<Sha256>::new(key.as_ref().clone())
                    .try_sign(message)
                    .map(|s| s.to_vec())
                    .map_err(signing)
            }
            (Self::Rsa(key), A::RsaPkcs1Sha3_256) => {
                rsa::pkcs1v15::SigningKey::<Sha3_256>::new(key.as_ref().clone())
                    .try_sign(message)
                    .map(|s| s.to_vec())
                    .map_err(signing)
            }
            (Self::Rsa(key), A::RsaPssSha256) => {
                let mut rng = TestRng::new(&salt_label(message));
                rsa::pss::SigningKey::<Sha256>::new(key.as_ref().clone())
                    .try_sign_with_rng(&mut rng, message)
                    .map(|s| s.to_vec())
                    .map_err(signing)
            }
            (Self::Rsa(key), A::RsaPssSha384) => {
                let mut rng = TestRng::new(&salt_label(message));
                rsa::pss::SigningKey::<Sha384>::new(key.as_ref().clone())
                    .try_sign_with_rng(&mut rng, message)
                    .map(|s| s.to_vec())
                    .map_err(signing)
            }
            (Self::P256(key), A::EcdsaSha256) => {
                let signature: p256::ecdsa::DerSignature = p256::ecdsa::SigningKey::from(key)
                    .try_sign(message)
                    .map_err(signing)?;
                Ok(signature.to_vec())
            }
            (Self::P384(key), A::EcdsaSha384) => {
                let signature: p384::ecdsa::DerSignature = p384::ecdsa::SigningKey::from(key)
                    .try_sign(message)
                    .map_err(signing)?;
                Ok(signature.to_vec())
            }
            (Self::P521(key), A::EcdsaSha512) => {
                // p521 0.13 has no RFC 6979 signer. As in RFC 6979, the nonce
                // is derived from the private key and the message, here with
                // a TestRng seeded with both, so signatures are reproducible
                // and two keys never share a nonce for the same message.
                let mut rng = TestRng::new(&nonce_label(&key.to_bytes(), message));
                let signature: p521::ecdsa::Signature =
                    p521::ecdsa::SigningKey::from_bytes(&key.to_bytes())
                        .map_err(signing)?
                        .try_sign_with_rng(&mut rng, message)
                        .map_err(signing)?;
                Ok(signature.to_der().to_vec())
            }
            (Self::Ed25519(key), A::Ed25519) => Ok(key.sign(message).to_vec()),
            _ => Err(PkiError::KeyMismatch),
        }
    }
}

/// The label of the generator that supplies a P-521 ECDSA nonce: the
/// private key followed by the SHA-256 hash of the message.
fn nonce_label(private_key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut label = b"p521-nonce/".to_vec();
    label.extend_from_slice(private_key);
    label.extend_from_slice(&Sha256::digest(message));
    label
}

/// The label of the generator that supplies an RSASSA-PSS salt.
fn salt_label(message: &[u8]) -> Vec<u8> {
    let mut label = b"pss-salt/".to_vec();
    label.extend_from_slice(&Sha256::digest(message));
    label
}

/// A signer for the `x509-cert` certificate builder: a key pair and the
/// algorithm it signs with. It supplies the algorithm identifier that the
/// primitive crates do not, as for SHA3-256 with RSA PKCS#1 v1.5.
pub struct CertSigner<'a> {
    key: &'a KeyPair,
    algorithm: SignatureAlgorithm,
    public_key: PublicKeyDer,
}

impl<'a> CertSigner<'a> {
    /// Returns the signer of `key` with `algorithm`.
    ///
    /// # Errors
    ///
    /// Returns [`PkiError::Encoding`] if the public key cannot be encoded.
    pub fn new(key: &'a KeyPair, algorithm: SignatureAlgorithm) -> Result<Self, PkiError> {
        Ok(Self {
            key,
            algorithm,
            public_key: PublicKeyDer(key.spki_der()?),
        })
    }
}

/// A DER-encoded `SubjectPublicKeyInfo`.
#[derive(Clone)]
pub struct PublicKeyDer(Vec<u8>);

impl EncodePublicKey for PublicKeyDer {
    fn to_public_key_der(&self) -> spki::Result<der::Document> {
        let info = SubjectPublicKeyInfoOwned::from_der(&self.0)?;
        Ok(der::Document::encode_msg(&info)?)
    }
}

/// A signature value, as placed in the `signatureValue` bit string.
pub struct SignatureBytes(Vec<u8>);

impl spki::SignatureBitStringEncoding for SignatureBytes {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        der::asn1::BitString::from_bytes(&self.0)
    }
}

impl signature::Keypair for CertSigner<'_> {
    type VerifyingKey = PublicKeyDer;

    fn verifying_key(&self) -> PublicKeyDer {
        self.public_key.clone()
    }
}

impl DynSignatureAlgorithmIdentifier for CertSigner<'_> {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        self.algorithm
            .identifier()
            .map_err(|_| spki::Error::KeyMalformed)
    }
}

impl Signer<SignatureBytes> for CertSigner<'_> {
    fn try_sign(&self, message: &[u8]) -> Result<SignatureBytes, signature::Error> {
        self.key
            .sign(self.algorithm, message)
            .map(SignatureBytes)
            .map_err(|_| signature::Error::new())
    }
}

/// Encodes a value to DER.
pub(super) fn to_der(value: &impl Encode) -> Result<Vec<u8>, PkiError> {
    value.to_der().map_err(|_| PkiError::Encoding)
}
