//! The OCSP responses of the test PKI (RFC 6960).
//!
//! ADR-0014: every successful response is assembled by the `x509-ocsp`
//! response builder, with an explicit `producedAt`, and signed through
//! [`CertSigner`], the signer of the certificates. Every time is an offset
//! from the fixed validation time of the manifest, and no time is read from
//! the system clock.
//!
//! Every end entity of the test PKI, other than the responder, gets one
//! response, `good` or `revoked` as the CRL of its CA records it at
//! `thisUpdate`. RFC 6960, section 4.2.2.2, allows two signers, and the
//! corpus has both. `pki/ocsp-responder`, a delegated responder of
//! `pki/ca-ecdsa`, signs for the certificates of that CA. Every other CA
//! signs for its own certificates, with the algorithm of its CRL. The
//! responder carries `id-pkix-ocsp-nocheck` (section 4.2.2.2.1) and gets
//! no response. Eight more responses cover the cases of an `unknown`
//! status, a signer without `id-kp-OCSPSigning`, a `producedAt` after the
//! validation time, a nonce, the response statuses `tryLater` and
//! `unauthorized`, and two `CertID`s with a wrong issuer hash, for threat
//! K10 of the threat model.
//!
//! Each response holds one `SingleResponse`. Its `CertID` uses SHA-1, the
//! algorithm that `openssl ocsp` uses by default and that RFC 5019,
//! section 2.1.1, requires of lightweight clients (RFC 6960, section 4.1.1,
//! leaves it open). The responder is identified by the SHA-1 hash of its
//! key (`byKey`, section 4.2.2.3). A delegated responder includes its
//! certificate in `certs` (section 4.2.1); a CA includes none. The files
//! are DER-encoded `OCSPResponse` structures, named after the certificate
//! they cover or after their case: `ocsp/<name>.der`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use der::DateTime;
use der::DecodePem;
use der::asn1::{GeneralizedTime, OctetString};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use time::OffsetDateTime;
use x509_cert::Certificate;
use x509_ocsp::builder::OcspResponseBuilder;
use x509_ocsp::ext::Nonce;
use x509_ocsp::{
    CertId, CertStatus, OcspGeneralizedTime, OcspResponse, OcspResponseStatus, ResponderId,
    RevokedInfo, SingleResponse,
};

use super::hierarchy::{self, CERTIFICATES, CertSpec, Offset, Revocation};
use super::keys::{CertSigner, KeyPair, KeyType, SignatureAlgorithm, SignatureBytes, to_der};
use super::{GenerateError, GeneratedFile, PkiError, Summary, certificate_id, sha256_hex};
use crate::manifest::{Artefact, DssResult, Indication, Kind, Links, Manifest, OpensslResult};

/// The directory of the OCSP responses, relative to the manifest.
pub const DIRECTORY: &str = "ocsp";

/// The name of the delegated OCSP responder of `pki/ca-ecdsa`, with
/// `id-kp-OCSPSigning` and `id-pkix-ocsp-nocheck`.
pub const RESPONDER: &str = "ocsp-responder";

/// The certificate that signs the response of the case without
/// `id-kp-OCSPSigning`: issued by `pki/ca-ecdsa`, like the responder, but
/// without that extended key usage.
pub const SIGNER_WITHOUT_OCSP_SIGNING: &str = "signer-p384";

/// The certificate that the responses of the cases cover.
pub const CASE_SUBJECT: &str = "signer-p256";

/// `producedAt` of the responses: one day before the validation time.
pub const PRODUCED_AT: Offset = Offset::days(-1);

/// `thisUpdate` of the responses: one day before the validation time, as
/// for the current CRLs.
pub const THIS_UPDATE: Offset = Offset::days(-1);

/// `nextUpdate` of the responses: six days after the validation time, as
/// for the current CRLs.
pub const NEXT_UPDATE: Offset = Offset::days(6);

/// `producedAt` and `thisUpdate` of `ocsp/signer-expired-before-expiry`:
/// two days before the validation time, before `pki/signer-expired`
/// expired.
pub const BEFORE_EXPIRY: Offset = Offset::days(-2);

/// `producedAt` of `ocsp/produced-at-after-validation-time`: one day after
/// the validation time.
pub const LATE_PRODUCED_AT: Offset = Offset::days(1);

/// The length of the nonce of `ocsp/nonce`, in octets: the largest that
/// RFC 8954, section 2.1, allows.
pub const NONCE_LENGTH: usize = 32;

/// The label from which the nonce of `ocsp/nonce` is derived.
const NONCE_LABEL: &[u8] = b"sigillum-testpki/ocsp-nonce";

/// The certificate status that a successful response gives (RFC 6960,
/// section 4.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The status at `thisUpdate`, as the CRL of the issuer records it:
    /// `revoked`, with the date and reason of the CRL, when the
    /// certificate is revoked on or before `thisUpdate`, and `good`
    /// otherwise.
    Current,
    /// `unknown`: the responder does not know the certificate.
    Unknown,
}

/// The form of the `CertID` of a response (RFC 6960, section 4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertIdForm {
    /// The hashes of the issuer of the covered certificate.
    Correct,
    /// The issuer name hash with its last octet inverted.
    WrongIssuerNameHash,
    /// The issuer key hash with its last octet inverted.
    WrongIssuerKeyHash,
}

/// A successful response, with one `SingleResponse` for the covered
/// certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signed {
    /// The name of the certificate that signs the response.
    pub responder: &'static str,
    /// The status of the covered certificate.
    pub status: Status,
    /// `producedAt`, from the validation time.
    pub produced_at: Offset,
    /// `thisUpdate`, from the validation time.
    pub this_update: Offset,
    /// `nextUpdate`, from the validation time.
    pub next_update: Offset,
    /// Whether the response carries the nonce extension (RFC 6960, section
    /// 4.4.1).
    pub nonce: bool,
    /// The form of the `CertID`.
    pub cert_id: CertIdForm,
}

/// The body of a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    /// A successful response, signed.
    Signed(Signed),
    /// A response with another status and no `responseBytes` (RFC 6960,
    /// section 4.2.1).
    Unsuccessful(OcspResponseStatus),
}

/// The specification of one OCSP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcspSpec {
    /// The name of the response, used in its path and identifier.
    pub name: String,
    /// The name of the covered certificate: the certificate whose status
    /// the response gives, or would give for an unsuccessful response, and
    /// whose validation with this response gives the expected DSS result.
    /// The manifest notes name it first.
    pub covered: &'static str,
    /// The body of the response.
    pub body: Body,
    /// Why the response exists, for the manifest.
    pub purpose: String,
    /// The result expected from OpenSSL.
    pub expected_openssl: OpensslResult,
    /// The result expected from DSS: the X.509 certificate validation of
    /// ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, of the covered
    /// certificate, with this response as its revocation data.
    pub expected_dss: DssResult,
    /// Remarks for the manifest, after the covered certificate.
    pub notes: Option<String>,
}

/// The last sentence of the notes of every response with a status.
/// `openssl ocsp` compares `thisUpdate` and `nextUpdate` with the current
/// time only, and `-attime` sets the time of the path validation of the
/// signer, so the expected OpenSSL result cannot cover freshness.
pub const OPENSSL_FRESHNESS_NOTE: &str = "openssl ocsp compares thisUpdate and nextUpdate with the current time only, so the expected OpenSSL result covers the parsing of the response, its signature and the path of its signer at the validation time, and not its freshness.";

/// The identifier of the response with this name.
pub fn ocsp_id(name: &str) -> String {
    format!("{DIRECTORY}/{name}")
}

/// Reports whether this certificate has a response: an end entity, one
/// that issues no certificate, other than the responder, which carries
/// `id-pkix-ocsp-nocheck` (RFC 6960, section 4.2.2.2.1).
fn answered(spec: &CertSpec) -> bool {
    spec.issuer.is_some()
        && spec.name != RESPONDER
        && !CERTIFICATES.iter().any(|s| s.issuer == Some(spec.name))
}

/// The certificate that signs the response for an end entity issued by
/// `issuer` (RFC 6960, section 4.2.2.2): the delegated responder for the
/// certificates of the CA that issued it, and otherwise the CA itself.
fn responder_for(issuer: &'static str) -> &'static str {
    if hierarchy::find(RESPONDER).and_then(|r| r.issuer) == Some(issuer) {
        RESPONDER
    } else {
        issuer
    }
}

/// The algorithm that the certificate `name` signs responses with: a CA
/// signs as it signs its CRL, and another certificate with the algorithm
/// that matches its key.
fn responder_algorithm(spec: &CertSpec) -> SignatureAlgorithm {
    super::crl::CRLS
        .iter()
        .find(|crl| crl.name == spec.name)
        .map_or_else(|| signature_algorithm(spec.key), |crl| crl.algorithm)
}

/// The identifier of the response that the manifest entry of `spec` links
/// in `revocation`, or `None` when the certificate has no response.
pub fn current_response(spec: &CertSpec) -> Option<String> {
    answered(spec).then(|| ocsp_id(spec.name))
}

/// The response of `pki/ocsp-responder` at the usual times.
const REGULAR: Signed = Signed {
    responder: RESPONDER,
    status: Status::Current,
    produced_at: PRODUCED_AT,
    this_update: THIS_UPDATE,
    next_update: NEXT_UPDATE,
    nonce: false,
    cert_id: CertIdForm::Correct,
};

/// The covered certificate's path validation fails because no usable
/// revocation data shows that it is not revoked (RFC 5280, section 6.1.3,
/// step (a)(3)), which ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, step 4 e),
/// reports.
fn chain_failure() -> DssResult {
    DssResult::Indication {
        indication: Indication::Indeterminate,
        sub_indication: Some("CERTIFICATE_CHAIN_GENERAL_FAILURE".to_owned()),
    }
}

/// The covered certificate passes (ETSI EN 319 102-1 V1.4.1, clause
/// 5.2.6.4, step 9).
fn passed() -> DssResult {
    DssResult::Indication {
        indication: Indication::Passed,
        sub_indication: None,
    }
}

/// The response for the end entity `spec`, from its signer: the delegated
/// responder for the certificates of `pki/ca-ecdsa`, and otherwise the CA
/// that issued it. A signer that has expired at the validation time is
/// expected to be rejected by OpenSSL, which checks it at that time.
fn regular(spec: &CertSpec, validation_time: OffsetDateTime) -> Result<OcspSpec, PkiError> {
    let responder = spec.issuer.map_or(RESPONDER, responder_for);
    let signer =
        hierarchy::find(responder).ok_or_else(|| PkiError::UnknownIssuer(responder.to_owned()))?;
    let signer_expired = expired_at(signer, validation_time)?;
    let status = if revoked_at(spec.revocation, REGULAR.this_update, validation_time)? {
        "revoked"
    } else {
        "good"
    };
    Ok(OcspSpec {
        name: spec.name.to_owned(),
        covered: spec.name,
        body: Body::Signed(Signed {
            responder,
            ..REGULAR
        }),
        purpose: format!(
            "OCSP response of {} for {}, whose status is {status}.",
            certificate_id(responder),
            certificate_id(spec.name)
        ),
        expected_openssl: if signer_expired {
            OpensslResult::Rejected
        } else {
            OpensslResult::Verified
        },
        // The covered certificate's own expected result, which already
        // assumes the revocation data that its entry links.
        expected_dss: DssResult::Indication {
            indication: spec.expected_dss.indication,
            sub_indication: spec.expected_dss.sub_indication.map(str::to_owned),
        },
        notes: if spec.name == "signer-expired" {
            Some("thisUpdate equals the notAfter of pki/signer-expired, and the response carries no archiveCutoff, so it shows no status after the certificate expired, as ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, NOTE 8, describes for a certificate known not to have been revoked. Step 7 then gives OUT_OF_BOUNDS_NO_POE. DSS 6.5.1 gives OUT_OF_BOUNDS_NOT_REVOKED, a class 2 divergence recorded as DIV-5 in docs/design/divergences.md.".to_owned())
        } else {
            signer_expired.then(|| {
            format!(
                "Signed by {}, which expired one day before the validation time, at the instant it signed, so within its validity, because notAfter is inclusive (RFC 5280, section 4.1.2.5). openssl ocsp checks the signer at the validation time given with -attime, when it has expired, and rejects the response with \"certificate has expired\".",
                certificate_id(responder)
            )
            })
        },
    })
}

/// A case of acceptance criterion 2, covering [`CASE_SUBJECT`].
fn case(
    name: &str,
    body: Body,
    purpose: &str,
    expected: (OpensslResult, DssResult),
    notes: &str,
) -> OcspSpec {
    OcspSpec {
        name: name.to_owned(),
        covered: CASE_SUBJECT,
        body,
        purpose: purpose.to_owned(),
        expected_openssl: expected.0,
        expected_dss: expected.1,
        notes: Some(notes.to_owned()),
    }
}

/// The notes of a response for threat K10 of the threat model, whose
/// `hash` of the `CertID` is altered.
fn k10_notes(hash: &str) -> String {
    format!(
        "A fixture for threat K10 of the threat model. The {hash} of the CertID is that of pki/ca-ecdsa with its last octet inverted; the other fields are those of ocsp/signer-p256. RFC 6960, sections 3.2 and 4.1.1: the CertID does not identify the certificate, so the response does not apply to it, and openssl ocsp finds no status for it. OpenSSL also fails to verify the response, because pki/ocsp-responder is not a delegated responder of the CA that the CertID names (RFC 6960, section 4.2.2.2); a test of sigillum should assert the first reason, that the response does not apply to the certificate. The DSS result is a prediction: without a response that applies to the certificate, the path validation cannot show that it is not revoked (RFC 5280, section 6.1.3, step (a)(3)), and step 4 e) of ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, applies. DSS 6.5.1 gives this result."
    )
}

/// Every OCSP response at `validation_time`: one for each end entity other
/// than the responder, in the order of [`CERTIFICATES`], then the six
/// cases of acceptance criterion 2, the two of threat K10, and a response
/// for `pki/signer-expired` issued before it expired (issue #75).
///
/// # Errors
///
/// Returns [`PkiError::UnknownIssuer`] if a signer is not in the test PKI,
/// and [`PkiError::Time`] if a time is out of range.
pub fn responses(validation_time: OffsetDateTime) -> Result<Vec<OcspSpec>, PkiError> {
    if hierarchy::find(RESPONDER).is_none() {
        return Err(PkiError::UnknownIssuer(RESPONDER.to_owned()));
    }
    let mut specs: Vec<OcspSpec> = CERTIFICATES
        .iter()
        .filter(|spec| answered(spec))
        .map(|spec| regular(spec, validation_time))
        .collect::<Result<_, _>>()?;
    specs.extend([
        case(
            "unknown",
            Body::Signed(Signed {
                status: Status::Unknown,
                ..REGULAR
            }),
            "OCSP response of pki/ocsp-responder for pki/signer-p256 whose status is unknown.",
            (OpensslResult::Verified, chain_failure()),
            "RFC 6960, section 2.2: unknown means that the responder does not know the certificate. The response verifies, so OpenSSL accepts it and reports the status. The DSS result is a prediction: the response shows neither good nor revoked, so the path validation cannot show that the certificate is not revoked (RFC 5280, section 6.1.3, step (a)(3)), and step 4 e) of ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, applies. DSS 6.5.1 gives this result.",
        ),
        case(
            "responder-without-ocsp-signing",
            Body::Signed(Signed {
                responder: SIGNER_WITHOUT_OCSP_SIGNING,
                ..REGULAR
            }),
            "OCSP response for pki/signer-p256, whose status is good, signed by pki/signer-p384, which pki/ca-ecdsa issued without the extended key usage id-kp-OCSPSigning.",
            (OpensslResult::Rejected, chain_failure()),
            "RFC 6960, section 4.2.2.2: a client must reject a response whose signer is neither the CA, nor a certificate of the CA with id-kp-OCSPSigning, nor a locally configured responder. The status is good. The DSS result is a prediction: without a usable response the path validation cannot show that the certificate is not revoked (RFC 5280, section 6.1.3, step (a)(3)), and step 4 e) of ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, applies. DSS 6.5.1 gives this result for another reason: it finds no revocation data for pki/signer-p384, the signer of the response, and does not check id-kp-OCSPSigning. Given crl/ca-ecdsa as well, which covers pki/signer-p384, DSS accepts the response and gives PASSED, a class 1 divergence recorded as DIV-3 in docs/design/divergences.md.",
        ),
        case(
            "produced-at-after-validation-time",
            Body::Signed(Signed {
                produced_at: LATE_PRODUCED_AT,
                ..REGULAR
            }),
            "OCSP response of pki/ocsp-responder for pki/signer-p256, whose status is good, produced one day after the validation time.",
            (OpensslResult::Verified, passed()),
            "thisUpdate and nextUpdate are those of the other responses. openssl ocsp does not compare producedAt with the verification time. The DSS result PASSED is a prediction from ETSI EN 319 102-1 V1.4.1: the revocation freshness checker of clause 5.2.5.4 uses thisUpdate (NOTE 3), and clause 5.2.6.4, step 4, checks only that producedAt falls within the validity of the responder certificate. DSS 6.5.1 gives this result. A verifier that uses the response as evidence at the validation time must reject it, because it did not exist then.",
        ),
        case(
            "nonce",
            Body::Signed(Signed {
                nonce: true,
                ..REGULAR
            }),
            "OCSP response of pki/ocsp-responder for pki/signer-p256, whose status is good, with a nonce extension.",
            (OpensslResult::Verified, passed()),
            "The nonce (RFC 6960, section 4.4.1) holds 32 octets, the most that RFC 8954, section 2.1, allows: the SHA-256 hash of a fixed label, so that the response is reproducible. No request matches it; openssl ocsp -respin checks a nonce only against a request. The DSS result is a prediction from ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, step 9.",
        ),
        case(
            "try-later",
            Body::Unsuccessful(OcspResponseStatus::TryLater),
            "OCSP response with the status tryLater and no response bytes.",
            (OpensslResult::Rejected, DssResult::Rejected),
            "RFC 6960, section 4.2.1: a response whose status is not successful has no responseBytes, and so no certificate status. The covered certificate is the one that a request would have named. DSS 6.5.1 cannot load the response as revocation data, so the validate-certificate mode of tools/dss-oracle rejects it: the oracle gives rejected.",
        ),
        case(
            "unauthorized",
            Body::Unsuccessful(OcspResponseStatus::Unauthorized),
            "OCSP response with the status unauthorized and no response bytes.",
            (OpensslResult::Rejected, DssResult::Rejected),
            "RFC 6960, section 4.2.1: a response whose status is not successful has no responseBytes, and so no certificate status. The covered certificate is the one that a request would have named. DSS 6.5.1 cannot load the response as revocation data, so the validate-certificate mode of tools/dss-oracle rejects it: the oracle gives rejected.",
        ),
        case(
            "cert-id-wrong-issuer-name-hash",
            Body::Signed(Signed {
                cert_id: CertIdForm::WrongIssuerNameHash,
                ..REGULAR
            }),
            "OCSP response of pki/ocsp-responder, whose status is good, whose CertID has the serial number of pki/signer-p256 and a wrong issuer name hash.",
            (OpensslResult::Rejected, chain_failure()),
            &k10_notes("issuer name hash"),
        ),
        case(
            "cert-id-wrong-issuer-key-hash",
            Body::Signed(Signed {
                cert_id: CertIdForm::WrongIssuerKeyHash,
                ..REGULAR
            }),
            "OCSP response of pki/ocsp-responder, whose status is good, whose CertID has the serial number of pki/signer-p256 and a wrong issuer key hash.",
            (OpensslResult::Rejected, chain_failure()),
            &k10_notes("issuer key hash"),
        ),
        OcspSpec {
            name: "signer-expired-before-expiry".to_owned(),
            covered: "signer-expired",
            body: Body::Signed(Signed {
                produced_at: BEFORE_EXPIRY,
                this_update: BEFORE_EXPIRY,
                next_update: Offset::days(5),
                ..REGULAR
            }),
            purpose: "OCSP response of pki/ocsp-responder for pki/signer-expired, whose status is good, issued two days before the validation time, before the certificate expired.".to_owned(),
            expected_openssl: OpensslResult::Verified,
            // ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, step 7 and NOTE 8:
            // the response is fresh (clause 5.2.5.4) but shows no status
            // after the certificate expired.
            expected_dss: DssResult::Indication {
                indication: Indication::Indeterminate,
                sub_indication: Some("OUT_OF_BOUNDS_NO_POE".to_owned()),
            },
            notes: Some("thisUpdate is two days and nextUpdate five days from the validation time, so the response is fresh under clause 5.2.5.4 of ETSI EN 319 102-1 V1.4.1. It was issued one day before pki/signer-expired expired, so it shows no status after expiry, as clause 5.2.6.4, NOTE 8, describes for a certificate known not to have been revoked, and step 7 gives OUT_OF_BOUNDS_NO_POE. DIV-5 in docs/design/divergences.md records the result of DSS 6.5.1.".to_owned()),
        },
    ]);
    Ok(specs)
}

/// Reports whether `signer` has expired at `validation_time`: whether its
/// `notAfter`, an inclusive bound (RFC 5280, section 4.1.2.5), precedes
/// that time.
///
/// # Errors
///
/// Returns [`PkiError::Time`] if `notAfter` is out of range.
pub fn expired_at(signer: &CertSpec, validation_time: OffsetDateTime) -> Result<bool, PkiError> {
    Ok(signer.not_after.from(validation_time)? < validation_time)
}

/// Reports whether a certificate with this `revocation` is revoked at
/// `this_update`, from `validation_time`: whether it is revoked on or
/// before then, as the CRL of its issuer lists it (RFC 5280, section
/// 5.1.2.6).
///
/// # Errors
///
/// Returns [`PkiError::Time`] if a time is out of range.
pub fn revoked_at(
    revocation: Option<Revocation>,
    this_update: Offset,
    validation_time: OffsetDateTime,
) -> Result<bool, PkiError> {
    match revocation {
        Some(revocation) => {
            Ok(revocation.date.from(validation_time)? <= this_update.from(validation_time)?)
        }
        None => Ok(false),
    }
}

/// The certificates and key that a successful response needs.
pub struct Parties<'a> {
    /// The private key of the certificate that signs the response.
    pub responder_key: &'a KeyPair,
    /// The certificate that signs the response.
    pub responder: &'a Certificate,
    /// The algorithm the responder signs with.
    pub algorithm: SignatureAlgorithm,
    /// The certificate of the issuer of the covered certificate.
    pub issuer: &'a Certificate,
    /// The covered certificate.
    pub subject: &'a Certificate,
    /// The revocation of the covered certificate, as the CRL of its issuer
    /// records it, or `None` if it is not revoked.
    pub revocation: Option<Revocation>,
}

/// The algorithm that a key of this type signs responses with: RSA
/// PKCS#1 v1.5 with SHA-256, ECDSA with the hash that RFC 5480, section 4,
/// pairs with the curve, identified as RFC 5758, section 3.2, specifies,
/// or Ed25519 (RFC 8410, section 3).
fn signature_algorithm(key: KeyType) -> SignatureAlgorithm {
    match key {
        KeyType::Rsa(_) => SignatureAlgorithm::RsaPkcs1Sha256,
        KeyType::P256 => SignatureAlgorithm::EcdsaSha256,
        KeyType::P384 => SignatureAlgorithm::EcdsaSha384,
        KeyType::P521 => SignatureAlgorithm::EcdsaSha512,
        KeyType::Ed25519 => SignatureAlgorithm::Ed25519,
    }
}

/// An OCSP time: a GeneralizedTime in whole seconds (RFC 6960, section
/// 4.2.2.1; RFC 5280, section 4.1.2.5.2).
fn generalized_time(at: OffsetDateTime) -> Result<OcspGeneralizedTime, PkiError> {
    let seconds = u64::try_from(at.unix_timestamp()).map_err(|_| PkiError::Time)?;
    let date_time = DateTime::from_unix_duration(std::time::Duration::from_secs(seconds))
        .map_err(|_| PkiError::Time)?;
    Ok(OcspGeneralizedTime(GeneralizedTime::from_date_time(
        date_time,
    )))
}

/// The nonce of `ocsp/nonce`: the SHA-256 hash of [`NONCE_LABEL`].
fn nonce() -> Result<Nonce, PkiError> {
    Nonce::new(Sha256::digest(NONCE_LABEL).to_vec()).map_err(|_| PkiError::Encoding)
}

/// Builds and signs a successful response (RFC 6960, section 4.2.1) for
/// the covered certificate of `parties`, at the times of `signed` from
/// `validation_time`, signed by `parties.responder_key` with
/// `parties.algorithm`.
///
/// With [`Status::Current`], the status is `revoked` when
/// `parties.revocation` is on or before `thisUpdate`, as the CRL of the
/// issuer lists it, and `good` otherwise. The `responder` field of
/// `signed` is not used; `parties` gives the signer.
///
/// # Errors
///
/// Returns [`PkiError::Time`] if a time is out of range,
/// [`PkiError::Encoding`] if a value cannot be encoded, and
/// [`PkiError::Signing`] if the response cannot be signed.
pub fn sign(
    signed: &Signed,
    parties: &Parties<'_>,
    validation_time: OffsetDateTime,
) -> Result<Vec<u8>, PkiError> {
    let this_update = signed.this_update.from(validation_time)?;
    let next_update = signed.next_update.from(validation_time)?;
    let produced_at = signed.produced_at.from(validation_time)?;
    let status = match (signed.status, parties.revocation) {
        (Status::Unknown, _) => CertStatus::unknown(),
        (Status::Current, Some(revocation))
            if revoked_at(Some(revocation), signed.this_update, validation_time)? =>
        {
            CertStatus::revoked(RevokedInfo {
                revocation_time: generalized_time(revocation.date.from(validation_time)?)?,
                revocation_reason: Some(revocation.reason),
            })
        }
        (Status::Current, _) => CertStatus::good(),
    };
    // RFC 6960, section 4.1.1: the CertID, here with SHA-1.
    let mut cert_id =
        CertId::from_cert::<Sha1>(parties.issuer, parties.subject).map_err(encoding)?;
    // Threat K10: one hash spoilt, by inverting its last octet.
    let spoilt = match signed.cert_id {
        CertIdForm::Correct => None,
        CertIdForm::WrongIssuerNameHash => Some(&mut cert_id.issuer_name_hash),
        CertIdForm::WrongIssuerKeyHash => Some(&mut cert_id.issuer_key_hash),
    };
    if let Some(hash) = spoilt {
        let mut bytes = hash.as_bytes().to_vec();
        if let Some(last) = bytes.last_mut() {
            *last = !*last;
        }
        *hash = OctetString::new(bytes).map_err(encoding)?;
    }
    let single = SingleResponse::new(cert_id, status, generalized_time(this_update)?)
        .with_next_update(generalized_time(next_update)?);
    // RFC 6960, sections 4.2.1 and 4.2.2.3: byKey, the SHA-1 hash of the
    // subjectPublicKey bit string of the responder.
    let key_hash = Sha1::digest(
        parties
            .responder
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    );
    let mut builder = OcspResponseBuilder::new(ResponderId::ByKey(
        OctetString::new(key_hash.to_vec()).map_err(encoding)?,
    ))
    .with_single_response(single);
    if signed.nonce {
        builder = builder.with_extension(nonce()?).map_err(encoding)?;
    }
    let mut signer = CertSigner::new(parties.responder_key, parties.algorithm)?;
    // RFC 6960, section 4.2.1: a delegated responder includes its
    // certificate in certs, so that a client needs only the chain above
    // it. A CA that signs for its own certificates includes none: the
    // client already holds it, to check the certificate and to compute the
    // CertID, and certs is then absent.
    let certs = (parties.responder != parties.issuer).then(|| vec![parties.responder.clone()]);
    let response = builder
        .sign::<_, SignatureBytes>(&mut signer, certs, generalized_time(produced_at)?)
        .map_err(|_| PkiError::Signing)?;
    to_der(&response)
}

/// Encodes a response with a status other than `successful`, without
/// `responseBytes` (RFC 6960, section 4.2.1).
///
/// # Errors
///
/// Returns [`PkiError::Encoding`] for the status `successful`, which needs
/// `responseBytes`, or if the response cannot be encoded.
pub fn unsuccessful(status: OcspResponseStatus) -> Result<Vec<u8>, PkiError> {
    if status == OcspResponseStatus::Successful {
        return Err(PkiError::Encoding);
    }
    to_der(&OcspResponse {
        response_status: status,
        response_bytes: None,
    })
}

/// Maps an encoding error of any type to [`PkiError::Encoding`].
fn encoding<E>(_: E) -> PkiError {
    PkiError::Encoding
}

/// Generates every response of [`responses`], in that order, with the
/// test PKI of `validation_time`, regenerated in memory so that the
/// responses always match `generate pki`.
///
/// # Errors
///
/// Returns a [`PkiError`] if the test PKI or a response cannot be
/// produced.
pub fn generate(validation_time: OffsetDateTime) -> Result<Vec<GeneratedFile>, PkiError> {
    let pki = super::generate(validation_time)?;
    let contents: HashMap<&str, &[u8]> = pki
        .iter()
        .map(|file| (file.artefact.id.as_str(), file.contents.as_slice()))
        .collect();
    let unknown = |name: &str| PkiError::UnknownIssuer(name.to_owned());
    let certificate = |name: &str| -> Result<Certificate, PkiError> {
        let pem = contents
            .get(certificate_id(name).as_str())
            .ok_or_else(|| unknown(name))?;
        Certificate::from_pem(pem).map_err(|_| PkiError::Encoding)
    };
    // The keys of the test PKI are derived from their names, as the key
    // files of generate pki are.
    let key = |name: &str| -> Result<KeyPair, PkiError> {
        let spec = hierarchy::find(name).ok_or_else(|| unknown(name))?;
        KeyPair::derive(spec.key, spec.name)
    };
    let mut files = Vec::new();
    for spec in responses(validation_time)? {
        let der = match spec.body {
            Body::Unsuccessful(status) => unsuccessful(status)?,
            Body::Signed(signed) => {
                let covered = hierarchy::find(spec.covered).ok_or_else(|| unknown(spec.covered))?;
                let issuer = covered.issuer.ok_or_else(|| unknown(spec.covered))?;
                sign(
                    &signed,
                    &Parties {
                        responder_key: &key(signed.responder)?,
                        responder: &certificate(signed.responder)?,
                        algorithm: responder_algorithm(
                            hierarchy::find(signed.responder)
                                .ok_or_else(|| unknown(signed.responder))?,
                        ),
                        issuer: &certificate(issuer)?,
                        subject: &certificate(spec.covered)?,
                        revocation: covered.revocation,
                    },
                    validation_time,
                )?
            }
        };
        files.push(response_file(&spec, der)?);
    }
    Ok(files)
}

fn response_file(spec: &OcspSpec, der: Vec<u8>) -> Result<GeneratedFile, PkiError> {
    let links = match spec.body {
        Body::Signed(signed) => {
            let responder = hierarchy::find(signed.responder)
                .ok_or_else(|| PkiError::UnknownIssuer(signed.responder.to_owned()))?;
            let mut chain = vec![certificate_id(responder.name)];
            chain.extend(
                hierarchy::chain(responder)?
                    .iter()
                    .map(|above| certificate_id(above.name)),
            );
            Links {
                issuer: chain.first().cloned(),
                chain,
                revocation: Vec::new(),
                content: None,
            }
        }
        Body::Unsuccessful(_) => Links::default(),
    };
    let covered = format!("Covered certificate: {}.", certificate_id(spec.covered));
    let freshness = match spec.body {
        Body::Signed(_) => Some(OPENSSL_FRESHNESS_NOTE),
        Body::Unsuccessful(_) => None,
    };
    let artefact = Artefact {
        id: ocsp_id(&spec.name),
        path: PathBuf::from(format!("{DIRECTORY}/{}.der", spec.name)),
        sha256: sha256_hex(&der),
        kind: Kind::OcspResponse,
        purpose: spec.purpose.clone(),
        expected_openssl: spec.expected_openssl,
        expected_dss: spec.expected_dss.clone(),
        links,
        notes: Some(
            [Some(covered.as_str()), spec.notes.as_deref(), freshness]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" "),
        ),
    };
    Ok(GeneratedFile {
        artefact,
        contents: der,
    })
}

/// Reports whether an entry belongs to what `generate ocsp` produces: an
/// OCSP response whose identifier is under [`DIRECTORY`].
fn generated_here(artefact: &Artefact) -> bool {
    artefact.kind == Kind::OcspResponse && artefact.id.starts_with(&format!("{DIRECTORY}/"))
}

/// Generates the OCSP responses with the validation time of the manifest
/// at `manifest_path`, writes each file under the manifest's directory,
/// and records each in the manifest, as [`super::write_into_corpus`] does
/// for the certificates. The certificates must already be in the manifest.
///
/// The `revocation` links of the response entries it replaces are kept.
/// Response entries under [`DIRECTORY`] that the generator no longer
/// produces are removed, with every `revocation` link to them; their files
/// are not deleted. In each certificate entry of the test PKI, the
/// `revocation` links to responses of this generator are replaced by a
/// link to the certificate's response, if it has one, in last place, and
/// other links are kept.
///
/// # Errors
///
/// Returns a [`GenerateError`] if the manifest cannot be read or updated,
/// for example because it lacks the certificates that the responses link,
/// or a file cannot be generated or written.
pub fn write_into_corpus(manifest_path: &Path) -> Result<Summary, GenerateError> {
    super::write_generated(
        manifest_path,
        DIRECTORY,
        generated_here,
        |manifest| generate(manifest.header.validation_time).map_err(GenerateError::Pki),
        link_certificates,
    )
}

/// Sets the `revocation` links of the certificate entries of the test PKI:
/// the links to `generated` responses are replaced by the certificate's
/// response, if it has one, in last place. `generate crls` puts its CRL in
/// first place, so the order is the same whichever runs last.
fn link_certificates(manifest: &mut Manifest, generated: &[String]) {
    for spec in &CERTIFICATES {
        let id = certificate_id(spec.name);
        let Some(entry) = manifest
            .artefacts
            .iter_mut()
            .find(|a| a.id == id && a.kind == Kind::Certificate)
        else {
            continue;
        };
        entry
            .links
            .revocation
            .retain(|link| !generated.contains(link));
        if let Some(response) = current_response(spec) {
            entry.links.revocation.push(response);
        }
    }
}

#[cfg(test)]
mod tests;
