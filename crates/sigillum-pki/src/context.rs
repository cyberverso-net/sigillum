//! The context shared by every format and by verification (ADR-0026,
//! decisions 3 and 4).

use crate::error::{Error, ErrorKind};
use crate::limits::Limits;
use crate::time::UnixTime;

/// Holds what every operation receives besides its document and options:
/// the times, the trust anchors, the certificates and revocation data the
/// caller already has, the limits, and the choices that relax a defensive
/// rule.
///
/// A context is built through [`for_signing`](Self::for_signing) or
/// [`for_validation`](Self::for_validation), which take the required
/// times, then completed with the `with_` and `allow_` methods. A new
/// context has no trust anchor, no certificate, no revocation data,
/// [`Limits::default`] and every relaxing choice off.
///
/// Certificates and revocation data are kept as given, in DER. They are
/// untrusted until used: each is decoded under the size limit of its
/// [kind](crate::InputKind) and validated when an operation needs it, so
/// the order in which the limits and the material are set does not matter.
/// The trust anchors are trusted as given.
///
/// Signing operations require the same signing time and the same supplied
/// evidence at every call of one operation, because they are part of what
/// is signed (ADR-0026, decision 6).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Context {
    signing_time: Option<UnixTime>,
    validation_time: UnixTime,
    trust_anchors: Vec<Vec<u8>>,
    certificates: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
    ocsp_responses: Vec<Vec<u8>>,
    limits: Limits,
    lower_level_on_unknown_revocation: bool,
}

impl Context {
    /// Creates a context for signing, which requires both times
    /// (ADR-0026, decision 3).
    ///
    /// `signing_time` becomes the `signing-time` attribute of CAdES and the
    /// `iat` header parameter of JAdES. `validation_time` is the time at
    /// which the signer chain and the fetched evidence are checked before
    /// embedding (ADR-0017, rules 6 and 7).
    #[must_use]
    pub const fn for_signing(signing_time: UnixTime, validation_time: UnixTime) -> Self {
        Self::new(Some(signing_time), validation_time)
    }

    /// Creates a context for an operation that validates without signing,
    /// such as verification in phase 2. It has no signing time.
    #[must_use]
    pub const fn for_validation(validation_time: UnixTime) -> Self {
        Self::new(None, validation_time)
    }

    const fn new(signing_time: Option<UnixTime>, validation_time: UnixTime) -> Self {
        Self {
            signing_time,
            validation_time,
            trust_anchors: Vec::new(),
            certificates: Vec::new(),
            crls: Vec::new(),
            ocsp_responses: Vec::new(),
            limits: Limits::new(),
            lower_level_on_unknown_revocation: false,
        }
    }

    /// Returns the signing time, if the context was created for signing.
    #[must_use]
    pub const fn signing_time(&self) -> Option<UnixTime> {
        self.signing_time
    }

    /// Returns the signing time, for operations that sign.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] if the context was created by
    /// [`for_validation`](Self::for_validation) and has no signing time.
    pub const fn require_signing_time(&self) -> Result<UnixTime, Error> {
        match self.signing_time {
            Some(time) => Ok(time),
            None => Err(Error::new(
                ErrorKind::InvalidInput,
                "the context has no signing time",
            )),
        }
    }

    /// Returns the validation time.
    #[must_use]
    pub const fn validation_time(&self) -> UnixTime {
        self.validation_time
    }

    /// Returns the trust anchors, as DER certificates, in the order added.
    #[must_use]
    pub fn trust_anchors(&self) -> &[Vec<u8>] {
        &self.trust_anchors
    }

    /// Adds a trust anchor, as a DER certificate, for checking the signer
    /// chain and the chains of fetched evidence (ADR-0012).
    #[must_use]
    pub fn with_trust_anchor(mut self, der: Vec<u8>) -> Self {
        self.trust_anchors.push(der);
        self
    }

    /// Returns the additional certificates, as DER, in the order added.
    #[must_use]
    pub fn certificates(&self) -> &[Vec<u8>] {
        &self.certificates
    }

    /// Adds a certificate, as DER, that the caller already has, so that no
    /// request is made for it. It is only a candidate for path building,
    /// never trusted as an anchor.
    #[must_use]
    pub fn with_certificate(mut self, der: Vec<u8>) -> Self {
        self.certificates.push(der);
        self
    }

    /// Returns the certificate revocation lists, as DER, in the order
    /// added.
    #[must_use]
    pub fn crls(&self) -> &[Vec<u8>] {
        &self.crls
    }

    /// Adds a certificate revocation list, as DER, that the caller already
    /// has (RFC 5280, section 5). It is validated before use, as fetched
    /// evidence is (ADR-0017, rule 6).
    #[must_use]
    pub fn with_crl(mut self, der: Vec<u8>) -> Self {
        self.crls.push(der);
        self
    }

    /// Returns the OCSP responses, as DER, in the order added.
    #[must_use]
    pub fn ocsp_responses(&self) -> &[Vec<u8>] {
        &self.ocsp_responses
    }

    /// Adds an OCSP response, as DER, that the caller already has (RFC
    /// 6960, section 4.2). It is validated before use, as fetched evidence
    /// is (ADR-0017, rule 6).
    #[must_use]
    pub fn with_ocsp_response(mut self, der: Vec<u8>) -> Self {
        self.ocsp_responses.push(der);
        self
    }

    /// Returns the limits.
    #[must_use]
    pub const fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Replaces the limits.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Returns whether the caller accepts a lower level than B-LT when the
    /// revocation status of the signing certificate cannot be determined.
    /// Off by default.
    #[must_use]
    pub const fn allows_lower_level_on_unknown_revocation(&self) -> bool {
        self.lower_level_on_unknown_revocation
    }

    /// Accepts a lower level than B-LT when the revocation status of the
    /// signing certificate cannot be determined, instead of the error
    /// [`ErrorKind::EvidenceUnavailable`] (ADR-0017, rule 7; ADR-0026,
    /// decision 2). The operation then completes at the highest level its
    /// evidence reaches. A revoked signing certificate is still refused
    /// with [`ErrorKind::EvidenceRejected`], and a missing signature
    /// timestamp at B-T or above is still `EvidenceUnavailable`.
    ///
    /// This relaxes a defensive rule, so it is off until called.
    #[must_use]
    pub const fn allow_lower_level_on_unknown_revocation(mut self) -> Self {
        self.lower_level_on_unknown_revocation = true;
        self
    }
}
