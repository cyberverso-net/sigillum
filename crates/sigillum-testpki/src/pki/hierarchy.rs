//! The certificates of the test PKI.
//!
//! One root CA issues one CA per signature family: RSA PKCS#1 v1.5,
//! RSASSA-PSS, ECDSA and Ed25519, and a second ECDSA CA with a P-521 key. Each family CA issues end-entity signing
//! certificates. The ECDSA CA also issues the timestamping authority, the
//! OCSP responder and the validity and misconfiguration cases. Every time
//! is an offset from the fixed validation time of the manifest.

use time::{Duration, OffsetDateTime};

use super::PkiError;
use super::keys::{KeyType, SignatureAlgorithm};
use crate::manifest::{Indication, OpensslResult};
use KeyType::{Ed25519, P256, P384, P521, Rsa};
use SignatureAlgorithm as Sig;

/// What a certificate is for, which fixes its extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The self-signed root CA.
    Root,
    /// A CA that issues end-entity certificates.
    IssuingCa,
    /// A CA certificate whose basic constraints do not assert cA.
    CaWithoutCaFlag,
    /// A CA certificate without the basic constraints extension.
    CaWithoutBasicConstraints,
    /// An end-entity signing certificate, with the `nonRepudiation` key usage.
    Signer,
    /// An end-entity signing certificate without the `nonRepudiation` key usage.
    SignerWithoutNonRepudiation,
    /// An end-entity signing certificate with a critical extension that no
    /// implementation knows, [`super::issue::UNKNOWN_CRITICAL_EXTENSION`].
    SignerWithUnknownCriticalExtension,
    /// A timestamping authority.
    TimeStamping,
    /// A delegated OCSP responder.
    OcspSigning,
}

/// An offset from the validation time, in calendar years and then days.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offset {
    /// Calendar years.
    pub years: i32,
    /// Days added after the years.
    pub days: i64,
}

impl Offset {
    /// An offset of whole calendar years.
    pub const fn years(years: i32) -> Self {
        Self { years, days: 0 }
    }

    /// An offset of whole days.
    pub const fn days(days: i64) -> Self {
        Self { years: 0, days }
    }

    /// The time at this offset from `time`.
    ///
    /// # Errors
    ///
    /// Returns [`PkiError::Time`] if the result does not exist or is out of range.
    pub fn from(self, time: OffsetDateTime) -> Result<OffsetDateTime, PkiError> {
        let year = time.year().checked_add(self.years).ok_or(PkiError::Time)?;
        // Duration::days panics when the seconds overflow, so the days are
        // converted with a checked multiplication.
        let seconds = self.days.checked_mul(86_400).ok_or(PkiError::Time)?;
        time.replace_year(year)
            .ok()
            .and_then(|t| t.checked_add(Duration::seconds(seconds)))
            .ok_or(PkiError::Time)
    }
}

/// The result expected from DSS for a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedDss {
    /// The indication.
    pub indication: Indication,
    /// The sub-indication, if any.
    pub sub_indication: Option<&'static str>,
}

/// The specification of one certificate and its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertSpec {
    /// The name of the certificate and its key, used in paths, identifiers
    /// and URIs.
    pub name: &'static str,
    /// The common name of the subject.
    pub common_name: &'static str,
    /// The type of the subject key.
    pub key: KeyType,
    /// The name of the issuer, or `None` for the self-signed root.
    pub issuer: Option<&'static str>,
    /// The algorithm the issuer signs with.
    pub algorithm: SignatureAlgorithm,
    /// The serial number, unique in the test PKI.
    pub serial: u16,
    /// What the certificate is for.
    pub role: Role,
    /// `notBefore`, from the validation time.
    pub not_before: Offset,
    /// `notAfter`, from the validation time.
    pub not_after: Offset,
    /// Why the certificate exists, for the manifest.
    pub purpose: &'static str,
    /// The result expected from OpenSSL.
    pub expected_openssl: OpensslResult,
    /// The result expected from DSS.
    pub expected_dss: ExpectedDss,
    /// Remarks for the manifest.
    pub notes: Option<&'static str>,
}

const PASSED: ExpectedDss = ExpectedDss {
    indication: Indication::Passed,
    sub_indication: None,
};

/// ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, step 7: the validation time is
/// outside the validity period of the certificate.
const OUT_OF_BOUNDS: ExpectedDss = ExpectedDss {
    indication: Indication::Indeterminate,
    sub_indication: Some("OUT_OF_BOUNDS_NO_POE"),
};

/// ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, step 4 e): the path validation
/// of RFC 5280, section 6.1 fails for another reason than revocation.
const CHAIN_FAILURE: ExpectedDss = ExpectedDss {
    indication: Indication::Indeterminate,
    sub_indication: Some("CERTIFICATE_CHAIN_GENERAL_FAILURE"),
};

/// An end-entity signing certificate, valid from one year before to two
/// years after the validation time.
pub(super) const fn signer(
    name: &'static str,
    common_name: &'static str,
    key: KeyType,
    issuer: &'static str,
    algorithm: SignatureAlgorithm,
    serial: u16,
    purpose: &'static str,
) -> CertSpec {
    CertSpec {
        name,
        common_name,
        key,
        issuer: Some(issuer),
        algorithm,
        serial,
        role: Role::Signer,
        not_before: Offset::years(-1),
        not_after: Offset::years(2),
        purpose,
        expected_openssl: OpensslResult::Verified,
        expected_dss: PASSED,
        notes: None,
    }
}

/// A CA certificate issued by the root, valid from two years before to
/// five years after the validation time.
pub(super) const fn ca(
    name: &'static str,
    common_name: &'static str,
    key: KeyType,
    serial: u16,
    purpose: &'static str,
) -> CertSpec {
    CertSpec {
        role: Role::IssuingCa,
        not_before: Offset::years(-2),
        not_after: Offset::years(5),
        ..signer(
            name,
            common_name,
            key,
            "root-ca",
            Sig::RsaPkcs1Sha256,
            serial,
            purpose,
        )
    }
}

/// Every certificate of the test PKI, each issuer before the certificates
/// it issues.
pub const CERTIFICATES: [CertSpec; 27] = [
    CertSpec {
        issuer: None,
        role: Role::Root,
        not_before: Offset::years(-3),
        not_after: Offset::years(10),
        ..ca(
            "root-ca",
            "sigillum test root CA",
            Rsa(3072),
            0x0001,
            "Self-signed root CA of the test PKI, with an RSA 3072-bit key, the trust anchor of every chain.",
        )
    },
    ca(
        "ca-rsa",
        "sigillum test RSA PKCS#1 v1.5 CA",
        Rsa(3072),
        0x0101,
        "Issuing CA of the RSA PKCS#1 v1.5 family, with an RSA 3072-bit key.",
    ),
    ca(
        "ca-rsa-pss",
        "sigillum test RSASSA-PSS CA",
        Rsa(3072),
        0x0102,
        "Issuing CA of the RSASSA-PSS family, with an RSA 3072-bit key that signs with RSASSA-PSS.",
    ),
    ca(
        "ca-ecdsa",
        "sigillum test ECDSA CA",
        P384,
        0x0103,
        "Issuing CA of the ECDSA family, with a P-384 key that signs with ECDSA and SHA-384.",
    ),
    ca(
        "ca-ecdsa-p521",
        "sigillum test ECDSA P-521 CA",
        P521,
        0x0108,
        "Second issuing CA of the ECDSA family, with a P-521 key that signs with ECDSA and SHA-512.",
    ),
    ca(
        "ca-ed25519",
        "sigillum test Ed25519 CA",
        Ed25519,
        0x0104,
        "Issuing CA of the Ed25519 family.",
    ),
    signer(
        "signer-rsa-2048",
        "sigillum test signer RSA 2048",
        Rsa(2048),
        "ca-rsa",
        Sig::RsaPkcs1Sha256,
        0x1001,
        "End-entity signing certificate with an RSA 2048-bit key, signed with RSA PKCS#1 v1.5 and SHA-256.",
    ),
    signer(
        "signer-rsa-3072",
        "sigillum test signer RSA 3072",
        Rsa(3072),
        "ca-rsa",
        Sig::RsaPkcs1Sha256,
        0x1002,
        "End-entity signing certificate with an RSA 3072-bit key, signed with RSA PKCS#1 v1.5 and SHA-256.",
    ),
    signer(
        "signer-rsa-sha3-256",
        "sigillum test signer RSA SHA3-256",
        Rsa(2048),
        "ca-rsa",
        Sig::RsaPkcs1Sha3_256,
        0x1003,
        "End-entity signing certificate with an RSA 2048-bit key, signed with RSA PKCS#1 v1.5 and SHA3-256.",
    ),
    signer(
        "signer-rsa-pss-sha256",
        "sigillum test signer RSASSA-PSS SHA-256",
        Rsa(3072),
        "ca-rsa-pss",
        Sig::RsaPssSha256,
        0x1101,
        "End-entity signing certificate with an RSA 3072-bit key, signed with RSASSA-PSS and SHA-256.",
    ),
    signer(
        "signer-rsa-pss-sha384",
        "sigillum test signer RSASSA-PSS SHA-384",
        Rsa(3072),
        "ca-rsa-pss",
        Sig::RsaPssSha384,
        0x1102,
        "End-entity signing certificate with an RSA 3072-bit key, signed with RSASSA-PSS and SHA-384.",
    ),
    signer(
        "signer-p256",
        "sigillum test signer P-256",
        P256,
        "ca-ecdsa",
        Sig::EcdsaSha384,
        0x1201,
        "End-entity signing certificate with an ECDSA P-256 key.",
    ),
    signer(
        "signer-p384",
        "sigillum test signer P-384",
        P384,
        "ca-ecdsa",
        Sig::EcdsaSha384,
        0x1202,
        "End-entity signing certificate with an ECDSA P-384 key.",
    ),
    signer(
        "signer-p521",
        "sigillum test signer P-521",
        P521,
        "ca-ecdsa-p521",
        Sig::EcdsaSha512,
        0x1203,
        "End-entity signing certificate with an ECDSA P-521 key, signed with ECDSA on P-521 and SHA-512.",
    ),
    signer(
        "signer-ed25519",
        "sigillum test signer Ed25519",
        Ed25519,
        "ca-ed25519",
        Sig::Ed25519,
        0x1301,
        "End-entity signing certificate with an Ed25519 key.",
    ),
    CertSpec {
        role: Role::TimeStamping,
        ..signer(
            "tsa",
            "sigillum test timestamping authority",
            P256,
            "ca-ecdsa",
            Sig::EcdsaSha384,
            0x1204,
            "Timestamping authority certificate, with the critical extended key usage id-kp-timeStamping.",
        )
    },
    CertSpec {
        role: Role::OcspSigning,
        ..signer(
            "ocsp-responder",
            "sigillum test OCSP responder",
            P256,
            "ca-ecdsa",
            Sig::EcdsaSha384,
            0x1205,
            "Delegated OCSP responder of the ECDSA CA, with id-kp-OCSPSigning and id-pkix-ocsp-nocheck.",
        )
    },
    CertSpec {
        not_after: Offset::days(-1),
        expected_openssl: OpensslResult::Rejected,
        expected_dss: OUT_OF_BOUNDS,
        ..signer(
            "signer-expired",
            "sigillum test signer expired",
            P256,
            "ca-ecdsa",
            Sig::EcdsaSha384,
            0x1206,
            "End-entity signing certificate that expired one day before the validation time.",
        )
    },
    CertSpec {
        not_before: Offset::days(1),
        not_after: Offset::years(1),
        expected_openssl: OpensslResult::Rejected,
        expected_dss: OUT_OF_BOUNDS,
        ..signer(
            "signer-not-yet-valid",
            "sigillum test signer not yet valid",
            P256,
            "ca-ecdsa",
            Sig::EcdsaSha384,
            0x1207,
            "End-entity signing certificate that becomes valid one day after the validation time.",
        )
    },
    CertSpec {
        not_before: Offset::years(-3),
        not_after: Offset::days(-1),
        expected_openssl: OpensslResult::Rejected,
        expected_dss: OUT_OF_BOUNDS,
        ..ca(
            "ca-expired",
            "sigillum test expired CA",
            P256,
            0x0105,
            "Intermediate CA that expired one day before the validation time.",
        )
    },
    CertSpec {
        expected_openssl: OpensslResult::Rejected,
        expected_dss: CHAIN_FAILURE,
        ..signer(
            "signer-under-expired-ca",
            "sigillum test signer under expired CA",
            P256,
            "ca-expired",
            Sig::EcdsaSha256,
            0x1501,
            "End-entity signing certificate, valid at the validation time, issued by an intermediate CA that has expired.",
        )
    },
    CertSpec {
        role: Role::SignerWithoutNonRepudiation,
        ..signer(
            "signer-without-non-repudiation",
            "sigillum test signer without nonRepudiation",
            P256,
            "ca-ecdsa",
            Sig::EcdsaSha384,
            0x1208,
            "End-entity signing certificate whose key usage lacks nonRepudiation.",
        )
    },
    CertSpec {
        role: Role::CaWithoutCaFlag,
        notes: Some(
            "Basic constraints are present and leave cA at its default, FALSE, while the key usage asserts keyCertSign. OpenSSL rejects the certificate itself only with -x509_strict.",
        ),
        ..ca(
            "ca-without-ca-flag",
            "sigillum test CA without cA",
            P256,
            0x0106,
            "CA certificate whose basic constraints do not assert cA.",
        )
    },
    CertSpec {
        expected_openssl: OpensslResult::Rejected,
        expected_dss: CHAIN_FAILURE,
        ..signer(
            "signer-under-ca-without-ca-flag",
            "sigillum test signer under CA without cA",
            P256,
            "ca-without-ca-flag",
            Sig::EcdsaSha256,
            0x1601,
            "End-entity signing certificate issued by a CA certificate whose basic constraints do not assert cA.",
        )
    },
    CertSpec {
        role: Role::CaWithoutBasicConstraints,
        notes: Some(
            "The basic constraints extension is absent (RFC 5280, section 4.2.1.9). OpenSSL rejects the certificate itself only with -x509_strict.",
        ),
        ..ca(
            "ca-without-basic-constraints",
            "sigillum test CA without basic constraints",
            P256,
            0x0107,
            "CA certificate without the basic constraints extension, while the key usage asserts keyCertSign.",
        )
    },
    CertSpec {
        expected_openssl: OpensslResult::Rejected,
        expected_dss: CHAIN_FAILURE,
        ..signer(
            "signer-under-ca-without-basic-constraints",
            "sigillum test signer under CA without basic constraints",
            P256,
            "ca-without-basic-constraints",
            Sig::EcdsaSha256,
            0x1701,
            "End-entity signing certificate issued by a CA certificate without the basic constraints extension.",
        )
    },
    CertSpec {
        role: Role::SignerWithUnknownCriticalExtension,
        expected_openssl: OpensslResult::Rejected,
        expected_dss: CHAIN_FAILURE,
        notes: Some("The extension 1.3.6.1.4.1.32473.1.1 is critical and its value is a DER NULL."),
        ..signer(
            "signer-unknown-critical-extension",
            "sigillum test signer with unknown critical extension",
            P256,
            "ca-ecdsa",
            Sig::EcdsaSha384,
            0x1209,
            "End-entity signing certificate with a critical extension that no implementation recognises.",
        )
    },
];

/// Returns the specification of the certificate with this name.
pub fn find(name: &str) -> Option<&'static CertSpec> {
    CERTIFICATES.iter().find(|spec| spec.name == name)
}

/// The chain above a certificate, from its issuer up to the root.
///
/// # Errors
///
/// Returns [`PkiError::UnknownIssuer`] if an issuer is not in [`CERTIFICATES`].
pub fn chain(spec: &CertSpec) -> Result<Vec<&'static CertSpec>, PkiError> {
    let mut chain = Vec::new();
    let mut next = spec.issuer;
    while let Some(name) = next {
        // Every issuer precedes its certificates in CERTIFICATES, as a test
        // checks, so the chain ends at the root.
        let issuer = find(name).ok_or_else(|| PkiError::UnknownIssuer(name.to_owned()))?;
        chain.push(issuer);
        next = issuer.issuer;
    }
    Ok(chain)
}
