//! Issuance of one certificate from its specification.
//!
//! ADR-0021: every certificate is assembled by the `x509-cert` certificate
//! builder and signed through the [`CertSigner`] wrapper, which supplies
//! the algorithm identifiers that the primitive crates do not, as for
//! SHA3-256 with RSA PKCS#1 v1.5 and for ECDSA with P-521.

use std::marker::PhantomData;

use const_oid::AssociatedOid;
use const_oid::db::{rfc5280, rfc6960};
use der::asn1::{Ia5String, ObjectIdentifier, OctetString, SetOfVec, Utf8StringRef};
use der::{Decode, Encode, Length, Writer};
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoOwned;
use time::OffsetDateTime;
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{
    AccessDescription, AuthorityInfoAccessSyntax, AuthorityKeyIdentifier, BasicConstraints,
    CrlDistributionPoints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectKeyIdentifier,
};
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

use super::PkiError;
use super::hierarchy::{CertSpec, Role};
use super::keys::{CertSigner, KeyPair, SignatureBytes, to_der};

/// The organisation named in every subject of the test PKI.
pub const ORGANISATION: &str = "sigillum test PKI";

/// The base of every URI the certificates carry. The `.invalid` top-level
/// domain is reserved by RFC 2606, section 2, so the URIs never resolve.
pub const URI_BASE: &str = "http://example.invalid";

/// The sigillum test arc, under the enterprise number that RFC 5612,
/// section 2, reserves for documentation. Every allocation under it is
/// listed in `testdata/README.md`.
pub const TEST_ARC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.1");

/// An extension that no implementation recognises, under [`TEST_ARC`]. It is
/// critical, so path validation must reject the certificate (RFC 5280,
/// section 4.2, and section 6.1.4, step (o)). Its value is a DER NULL.
pub const UNKNOWN_CRITICAL_EXTENSION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.1.1");

/// The issuer of a certificate: its specification, key and certificate.
pub struct Issuer<'a> {
    /// The specification of the issuer's certificate.
    pub spec: &'a CertSpec,
    /// The issuer's key pair.
    pub key: &'a KeyPair,
    /// The issuer's certificate, DER-encoded.
    pub certificate: &'a [u8],
}

/// Issues the certificate of `spec` for `key`, signed by `issuer`, or
/// self-signed when `issuer` is `None`.
///
/// # Errors
///
/// Returns a [`PkiError`] if a time is out of range, a value cannot be
/// encoded, or the signing key cannot sign with the algorithm of `spec`.
pub fn issue(
    spec: &CertSpec,
    key: &KeyPair,
    issuer: Option<&Issuer<'_>>,
    validation_time: OffsetDateTime,
) -> Result<Vec<u8>, PkiError> {
    let subject_spki = spki_of(key)?;
    let (signing_key, signing_spki) = match issuer {
        Some(issuer) => (issuer.key, spki_of(issuer.key)?),
        None => (key, subject_spki.clone()),
    };
    let extensions = extensions(
        spec,
        issuer.map(|i| i.spec.name),
        &subject_spki,
        &signing_spki,
    )?;
    let validity = (
        spec.not_before.from(validation_time)?,
        spec.not_after.from(validation_time)?,
    );
    with_x509_cert(
        spec,
        &extensions,
        validity,
        subject_spki,
        issuer,
        &CertSigner::new(signing_key, spec.algorithm)?,
    )
}

fn spki_of(key: &KeyPair) -> Result<SubjectPublicKeyInfoOwned, PkiError> {
    SubjectPublicKeyInfoOwned::from_der(&key.spki_der()?).map_err(|_| PkiError::Encoding)
}

/// The extensions of a certificate, in the order they are written.
///
/// - Subject key identifier (RFC 5280, section 4.2.1.2), computed with
///   method 1 of RFC 7093, section 2: the leftmost 160 bits of the SHA-256
///   hash of the subjectPublicKey bit string.
/// - Authority key identifier (RFC 5280, section 4.2.1.1), the subject key
///   identifier of the issuer, except in the self-signed root.
/// - Key usage, critical (RFC 5280, section 4.2.1.3).
/// - Basic constraints, critical, in CA certificates (RFC 5280,
///   section 4.2.1.9).
/// - Extended key usage (RFC 5280, section 4.2.1.12): `id-kp-timeStamping`,
///   critical, for the timestamping authority (RFC 3161, section 2.3), and
///   `id-kp-OCSPSigning` for the OCSP responder (RFC 6960, section 4.2.2.2).
/// - CRL distribution points (RFC 5280, section 4.2.1.13) and authority
///   information access (RFC 5280, section 4.2.2.1), both non-critical,
///   except in the root.
/// - `id-pkix-ocsp-nocheck` for the OCSP responder (RFC 6960,
///   section 4.2.2.2.1), non-critical, with a NULL value.
fn extensions(
    spec: &CertSpec,
    issuer: Option<&str>,
    subject: &SubjectPublicKeyInfoOwned,
    signer: &SubjectPublicKeyInfoOwned,
) -> Result<Vec<Extension>, PkiError> {
    let mut extensions = vec![extension(
        rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER,
        false,
        &SubjectKeyIdentifier(key_identifier(subject)?),
    )?];
    if issuer.is_some() {
        extensions.push(extension(
            rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
            false,
            &AuthorityKeyIdentifier {
                key_identifier: Some(key_identifier(signer)?),
                authority_cert_issuer: None,
                authority_cert_serial_number: None,
            },
        )?);
    }
    let usage = match spec.role {
        Role::Root | Role::IssuingCa | Role::CaWithoutCaFlag | Role::CaWithoutBasicConstraints => {
            KeyUsages::KeyCertSign | KeyUsages::CRLSign
        }
        Role::Signer | Role::SignerWithUnknownCriticalExtension => {
            KeyUsages::DigitalSignature | KeyUsages::NonRepudiation
        }
        Role::SignerWithoutNonRepudiation | Role::TimeStamping | Role::OcspSigning => {
            KeyUsages::DigitalSignature.into()
        }
    };
    extensions.push(extension(rfc5280::ID_CE_KEY_USAGE, true, &KeyUsage(usage))?);
    let constraints = match spec.role {
        Role::Root => Some((true, None)),
        Role::IssuingCa => Some((true, Some(0))),
        // A CA certificate whose basic constraints leave cA at its default,
        // FALSE, so that it may not issue certificates (RFC 5280,
        // sections 4.2.1.9 and 6.1.4, step (k)).
        Role::CaWithoutCaFlag => Some((false, None)),
        _ => None,
    };
    if let Some((ca, path_len_constraint)) = constraints {
        extensions.push(extension(
            rfc5280::ID_CE_BASIC_CONSTRAINTS,
            true,
            &BasicConstraints {
                ca,
                path_len_constraint,
            },
        )?);
    }
    let purpose = match spec.role {
        Role::TimeStamping => Some((rfc5280::ID_KP_TIME_STAMPING, true)),
        Role::OcspSigning => Some((rfc5280::ID_KP_OCSP_SIGNING, false)),
        _ => None,
    };
    if let Some((purpose, critical)) = purpose {
        extensions.push(extension(
            rfc5280::ID_CE_EXT_KEY_USAGE,
            critical,
            &ExtendedKeyUsage(vec![purpose]),
        )?);
    }
    if let Some(issuer) = issuer {
        let crl = DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![uri(&format!(
                "{URI_BASE}/crl/{issuer}.crl"
            ))?])),
            reasons: None,
            crl_issuer: None,
        };
        extensions.push(extension(
            rfc5280::ID_CE_CRL_DISTRIBUTION_POINTS,
            false,
            &CrlDistributionPoints(vec![crl]),
        )?);
        let mut access = vec![AccessDescription {
            access_method: rfc5280::ID_AD_CA_ISSUERS,
            access_location: uri(&format!("{URI_BASE}/ca/{issuer}.cer"))?,
        }];
        if !matches!(
            spec.role,
            Role::IssuingCa
                | Role::CaWithoutCaFlag
                | Role::CaWithoutBasicConstraints
                | Role::OcspSigning
        ) {
            access.push(AccessDescription {
                access_method: rfc5280::ID_AD_OCSP,
                access_location: uri(&format!("{URI_BASE}/ocsp/{issuer}"))?,
            });
        }
        extensions.push(extension(
            rfc5280::ID_PE_AUTHORITY_INFO_ACCESS,
            false,
            &AuthorityInfoAccessSyntax(access),
        )?);
    }
    if spec.role == Role::OcspSigning {
        extensions.push(extension(
            rfc6960::ID_PKIX_OCSP_NOCHECK,
            false,
            &der::asn1::Null,
        )?);
    }
    if spec.role == Role::SignerWithUnknownCriticalExtension {
        extensions.push(extension(
            UNKNOWN_CRITICAL_EXTENSION,
            true,
            &der::asn1::Null,
        )?);
    }
    Ok(extensions)
}

fn extension(
    extn_id: ObjectIdentifier,
    critical: bool,
    value: &impl Encode,
) -> Result<Extension, PkiError> {
    Ok(Extension {
        extn_id,
        critical,
        extn_value: OctetString::new(to_der(value)?).map_err(|_| PkiError::Encoding)?,
    })
}

fn uri(value: &str) -> Result<GeneralName, PkiError> {
    Ia5String::new(value)
        .map(GeneralName::UniformResourceIdentifier)
        .map_err(|_| PkiError::Encoding)
}

/// The key identifier of RFC 7093, section 2, method 1.
fn key_identifier(spki: &SubjectPublicKeyInfoOwned) -> Result<OctetString, PkiError> {
    let hash = Sha256::digest(spki.subject_public_key.raw_bytes());
    OctetString::new(hash.get(..20).unwrap_or_default()).map_err(|_| PkiError::Encoding)
}

/// The subject or issuer name: the organisation, then the common name,
/// each a UTF8String in its own relative distinguished name.
fn name(common_name: &str) -> Result<Name, PkiError> {
    let rdn = |oid, value: &str| -> Result<RelativeDistinguishedName, PkiError> {
        let value = der::asn1::Any::encode_from(
            &Utf8StringRef::new(value).map_err(|_| PkiError::Encoding)?,
        )
        .map_err(|_| PkiError::Encoding)?;
        SetOfVec::try_from(vec![AttributeTypeAndValue { oid, value }])
            .map(RelativeDistinguishedName)
            .map_err(|_| PkiError::Encoding)
    };
    Ok(RdnSequence(vec![
        rdn(const_oid::db::rfc4519::O, ORGANISATION)?,
        rdn(const_oid::db::rfc4519::CN, common_name)?,
    ]))
}

/// A positive serial number of at most two octets (RFC 5280, section 4.1.2.2).
fn serial_bytes(serial: u16) -> Vec<u8> {
    let bytes = serial.to_be_bytes();
    let start = usize::from(bytes[0] == 0);
    bytes.get(start..).unwrap_or_default().to_vec()
}

/// A certificate time. The builder writes it as UTCTime before 2050 and as
/// GeneralizedTime from 2050 (RFC 5280, section 4.1.2.5).
fn time(at: OffsetDateTime) -> Result<Time, PkiError> {
    let seconds = u64::try_from(at.unix_timestamp()).map_err(|_| PkiError::Time)?;
    der::DateTime::from_unix_duration(std::time::Duration::from_secs(seconds))
        .map(|date_time| Time::GeneralTime(der::asn1::GeneralizedTime::from_date_time(date_time)))
        .map_err(|_| PkiError::Time)
}

fn with_x509_cert(
    spec: &CertSpec,
    extensions: &[Extension],
    (not_before, not_after): (OffsetDateTime, OffsetDateTime),
    subject: SubjectPublicKeyInfoOwned,
    issuer: Option<&Issuer<'_>>,
    signer: &CertSigner<'_>,
) -> Result<Vec<u8>, PkiError> {
    let issuer_name = match issuer {
        // The issuer name is copied from the issuer's certificate, so that
        // it matches the subject there octet for octet.
        Some(issuer) => {
            x509_cert::Certificate::from_der(issuer.certificate)
                .map_err(|_| PkiError::Encoding)?
                .tbs_certificate
                .subject
        }
        None => name(spec.common_name)?,
    };
    let mut builder = CertificateBuilder::new(
        Profile::Manual {
            issuer: Some(issuer_name),
        },
        SerialNumber::new(&serial_bytes(spec.serial)).map_err(|_| PkiError::Encoding)?,
        Validity {
            not_before: time(not_before)?,
            not_after: time(not_after)?,
        },
        name(spec.common_name)?,
        subject,
        signer,
    )
    .map_err(|_| PkiError::Encoding)?;
    for extension in extensions {
        add_extension(&mut builder, extension)?;
    }
    let certificate = builder
        .build::<SignatureBytes>()
        .map_err(|_| PkiError::Signing)?;
    to_der(&certificate)
}

/// Adds an extension already encoded, keeping its criticality. The builder
/// takes typed extensions only, so the value is wrapped in a type that
/// carries the extension's object identifier.
fn add_extension(
    builder: &mut CertificateBuilder<'_, CertSigner<'_>>,
    extension: &Extension,
) -> Result<(), PkiError> {
    fn add<O: AssociatedOid>(
        builder: &mut CertificateBuilder<'_, CertSigner<'_>>,
        extension: &Extension,
    ) -> Result<(), PkiError> {
        builder
            .add_extension(&Encoded::<O> {
                extension,
                oid: PhantomData,
            })
            .map_err(|_| PkiError::Encoding)
    }
    match extension.extn_id {
        SubjectKeyIdentifier::OID => add::<SubjectKeyIdentifier>(builder, extension),
        AuthorityKeyIdentifier::OID => add::<AuthorityKeyIdentifier>(builder, extension),
        KeyUsage::OID => add::<KeyUsage>(builder, extension),
        BasicConstraints::OID => add::<BasicConstraints>(builder, extension),
        ExtendedKeyUsage::OID => add::<ExtendedKeyUsage>(builder, extension),
        CrlDistributionPoints::OID => add::<CrlDistributionPoints>(builder, extension),
        AuthorityInfoAccessSyntax::OID => add::<AuthorityInfoAccessSyntax>(builder, extension),
        OcspNoCheck::OID => add::<OcspNoCheck>(builder, extension),
        UnknownCriticalExtension::OID => add::<UnknownCriticalExtension>(builder, extension),
        _ => Err(PkiError::Encoding),
    }
}

/// The object identifier of `id-pkix-ocsp-nocheck` (RFC 6960, section 4.2.2.2.1).
struct OcspNoCheck;

impl AssociatedOid for OcspNoCheck {
    const OID: ObjectIdentifier = rfc6960::ID_PKIX_OCSP_NOCHECK;
}

/// The object identifier of [`UNKNOWN_CRITICAL_EXTENSION`].
struct UnknownCriticalExtension;

impl AssociatedOid for UnknownCriticalExtension {
    const OID: ObjectIdentifier = UNKNOWN_CRITICAL_EXTENSION;
}

/// An encoded extension value, typed by the object identifier of `O`.
struct Encoded<'a, O> {
    extension: &'a Extension,
    oid: PhantomData<O>,
}

impl<O: AssociatedOid> AssociatedOid for Encoded<'_, O> {
    const OID: ObjectIdentifier = O::OID;
}

impl<O> Encode for Encoded<'_, O> {
    fn encoded_len(&self) -> der::Result<Length> {
        Length::try_from(self.extension.extn_value.as_bytes().len())
    }

    fn encode(&self, writer: &mut impl Writer) -> der::Result<()> {
        writer.write(self.extension.extn_value.as_bytes())
    }
}

impl<O: AssociatedOid> AsExtension for Encoded<'_, O> {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        self.extension.critical
    }
}
