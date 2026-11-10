//! Limits on untrusted input and on the evidence loop (ADR-0024, rule 1;
//! ADR-0026, decision 4; threat P2 of the threat model).
//!
//! Every limit has a documented default and a documented maximum. A caller
//! may set any value from zero up to the maximum. A lower value can only
//! refuse more input, so it never weakens a defence. A value above the
//! maximum is refused when it is set, with [`ErrorKind::InvalidInput`].
//! An input or a count that goes beyond its limit is refused with
//! [`ErrorKind::LimitExceeded`].
//!
//! The defaults suit a mobile device that holds the document in memory
//! (ADR-0026, decision 7). The maxima keep every limit within what a 32-bit
//! target, such as `wasm32-unknown-unknown`, can address. Sizes are in
//! bytes and use `u64`, and counts use `u32`, so that the bindings see the
//! same width on every target.

use crate::error::{Error, ErrorKind};

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// Names a kind of input that has its own size limit.
///
/// More kinds may be added before 1.0, each with its own default and
/// maximum.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputKind {
    /// The content to be signed, or a signed object given for
    /// verification: a CMS structure, a PDF file or a JWS. Default 64 MiB,
    /// maximum 1 GiB. Documents are held in memory in phase 1 (ADR-0026,
    /// decision 7). The default leaves room for scanned PDF files on a
    /// mobile device; the maximum is a quarter of the address space of a
    /// 32-bit target.
    Document,
    /// One X.509 certificate in DER, from the signer chain, the context or
    /// a response. Default 64 KiB, maximum 1 MiB. Certificates are usually
    /// a few kilobytes; the default leaves room for large extensions.
    Certificate,
    /// One certificate revocation list in DER (RFC 5280, section 5).
    /// Default 16 MiB, maximum 256 MiB. CRLs of large certification
    /// authorities reach several megabytes.
    Crl,
    /// One OCSP response in DER (RFC 6960, section 4.2). Default 64 KiB,
    /// maximum 1 MiB. A response holds a few certificates at most.
    OcspResponse,
    /// One timestamp token in DER (RFC 3161, section 2.4.2). Default
    /// 64 KiB, maximum 1 MiB. A token holds the certificates of its
    /// timestamping unit at most.
    TimestampToken,
    /// One decoded JOSE header of a JWS (RFC 7515, section 4). Default
    /// 64 KiB, maximum 1 MiB. The unsigned header can carry the
    /// validation data of B-LT in `etsiU` (ETSI TS 119 182-1 V1.2.1,
    /// clause 5.3), each value bounded by its own kind once decoded.
    JoseHeader,
    /// A prepared or assembly state returned by the caller (ADR-0026,
    /// decision 6, point 7). Default 32 MiB, maximum 1 GiB. An assembly
    /// state keeps the evidence of earlier rounds, which can include CRLs,
    /// so a state with a few large CRLs can need more than the default.
    /// The state encoder (#131) must therefore refuse to write a state above
    /// this limit, so that `resume` never meets one. A caller
    /// who raises the [`Crl`](Self::Crl) limit should raise this limit
    /// too.
    State,
}

impl InputKind {
    /// Returns the default size limit of this kind, in bytes.
    #[must_use]
    pub const fn default_size(self) -> u64 {
        match self {
            Self::Document => 64 * MIB,
            Self::Certificate | Self::OcspResponse | Self::TimestampToken | Self::JoseHeader => {
                64 * KIB
            }
            Self::Crl => 16 * MIB,
            Self::State => 32 * MIB,
        }
    }

    /// Returns the largest size limit that can be set for this kind, in
    /// bytes.
    #[must_use]
    pub const fn maximum_size(self) -> u64 {
        match self {
            Self::Document | Self::State => GIB,
            Self::Certificate | Self::OcspResponse | Self::TimestampToken | Self::JoseHeader => MIB,
            Self::Crl => 256 * MIB,
        }
    }
}

/// Names an encoding that has its own nesting depth limit.
///
/// More encodings may be added before 1.0, each with its own default and
/// maximum. The depth of PDF arrays and dictionaries comes with the PDF
/// stories, with the other PDF limits of threat P2.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncodingKind {
    /// DER (ITU-T X.690 (02/2021), clause 10): the nesting of constructed
    /// values. Default 32 levels, maximum 64. The default is the fixed
    /// depth of 32 of the walk of `sigillum-testpki`, against which the
    /// library walk is compared (ADR-0025, rule 5). A certificate nests
    /// about ten levels deep.
    Der,
    /// JSON (RFC 8259, section 9): the nesting of arrays and objects, as
    /// in a JOSE header. Default 32 levels, maximum 64. A JAdES header
    /// nests a few levels deep.
    Json,
}

impl EncodingKind {
    /// Returns the default nesting depth limit of this encoding, in levels.
    #[must_use]
    pub const fn default_depth(self) -> u32 {
        match self {
            Self::Der | Self::Json => 32,
        }
    }

    /// Returns the largest nesting depth limit that can be set for this
    /// encoding, in levels: twice the default, so that decoders that
    /// recurse keep a small stack.
    #[must_use]
    pub const fn maximum_depth(self) -> u32 {
        match self {
            Self::Der | Self::Json => 64,
        }
    }
}

/// Holds the limits that bound one operation.
///
/// `Limits` is `Copy`: it holds numbers only.
///
/// [`Limits::new`] and [`Limits::default`] give the documented defaults.
/// Each `with_` method sets one limit and refuses a value above its
/// maximum.
///
/// The sizes and the nesting depths bound each input as it is decoded. The
/// number of evidence rounds and the number of evidence requests are
/// counted over the whole signing operation, across `assemble` and every
/// `resume`, as ADR-0017, rule 3, bounds requests per operation. The
/// assembly state carries the counts from one call to the next (ADR-0026,
/// decision 6, points 4 and 5). The library does not trust that state, so
/// the bound holds as long as the caller's loop passes the state on
/// without altering it. A caller that alters it only runs more requests
/// that it performs itself. The driver `sign_with` keeps its own count
/// outside the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Limits {
    der_depth: u32,
    json_depth: u32,
    rounds: u32,
    requests: u32,
    response_size: u64,
    document: u64,
    certificate: u64,
    crl: u64,
    ocsp_response: u64,
    timestamp_token: u64,
    jose_header: u64,
    state: u64,
}

impl Limits {
    /// The default number of evidence rounds of one signing operation: 8.
    /// B-LT needs a timestamp, the revocation data of the signer chain and
    /// of the evidence, and possibly missing certificates of each, which
    /// fit in a few rounds.
    pub const DEFAULT_ROUNDS: u32 = 8;
    /// The largest number of evidence rounds that can be set: 32.
    pub const MAXIMUM_ROUNDS: u32 = 32;
    /// The default number of evidence requests of one signing operation,
    /// over all its rounds: 32 (ADR-0017, rule 3).
    pub const DEFAULT_REQUESTS: u32 = 32;
    /// The largest number of evidence requests that can be set: 256.
    pub const MAXIMUM_REQUESTS: u32 = 256;
    /// The default maximum size of one fetched response, in bytes: 16 MiB,
    /// the default size of a CRL (ADR-0017, rule 8). It bounds any response
    /// that a fetcher returns, and the decoded response is also bounded by
    /// the size of its own kind. How an evidence request states its bound
    /// is left to the evidence loop (#145).
    pub const DEFAULT_RESPONSE_SIZE: u64 = 16 * MIB;
    /// The largest response size that can be set, in bytes: 256 MiB, the
    /// maximum size of a CRL.
    pub const MAXIMUM_RESPONSE_SIZE: u64 = 256 * MIB;

    /// Creates the limits with every default.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            der_depth: EncodingKind::Der.default_depth(),
            json_depth: EncodingKind::Json.default_depth(),
            rounds: Self::DEFAULT_ROUNDS,
            requests: Self::DEFAULT_REQUESTS,
            response_size: Self::DEFAULT_RESPONSE_SIZE,
            document: InputKind::Document.default_size(),
            certificate: InputKind::Certificate.default_size(),
            crl: InputKind::Crl.default_size(),
            ocsp_response: InputKind::OcspResponse.default_size(),
            timestamp_token: InputKind::TimestampToken.default_size(),
            jose_header: InputKind::JoseHeader.default_size(),
            state: InputKind::State.default_size(),
        }
    }

    /// Returns the nesting depth limit of `encoding`: the deepest nesting
    /// that its decoder accepts. It bounds nesting only.
    #[must_use]
    pub const fn depth(&self, encoding: EncodingKind) -> u32 {
        match encoding {
            EncodingKind::Der => self.der_depth,
            EncodingKind::Json => self.json_depth,
        }
    }

    /// Sets the nesting depth limit of `encoding`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] if `depth` is above
    /// [`EncodingKind::maximum_depth`] for `encoding`.
    pub fn with_depth(mut self, encoding: EncodingKind, depth: u32) -> Result<Self, Error> {
        if depth > encoding.maximum_depth() {
            return Err(above_maximum(match encoding {
                EncodingKind::Der => "the DER nesting depth limit is above its maximum",
                EncodingKind::Json => "the JSON nesting depth limit is above its maximum",
            }));
        }
        let field = match encoding {
            EncodingKind::Der => &mut self.der_depth,
            EncodingKind::Json => &mut self.json_depth,
        };
        *field = depth;
        Ok(self)
    }

    /// Returns the largest number of evidence rounds of one signing
    /// operation, counted over all its calls.
    #[must_use]
    pub const fn rounds(&self) -> u32 {
        self.rounds
    }

    /// Sets the largest number of evidence rounds. Zero allows no round, so
    /// every evidence must come from the context.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] if `rounds` is above
    /// [`MAXIMUM_ROUNDS`](Self::MAXIMUM_ROUNDS).
    pub fn with_rounds(mut self, rounds: u32) -> Result<Self, Error> {
        if rounds > Self::MAXIMUM_ROUNDS {
            return Err(above_maximum(
                "the evidence round limit is above its maximum",
            ));
        }
        self.rounds = rounds;
        Ok(self)
    }

    /// Returns the largest number of evidence requests of one signing
    /// operation, counted over all its rounds and calls (ADR-0017, rule 3).
    #[must_use]
    pub const fn requests(&self) -> u32 {
        self.requests
    }

    /// Sets the largest number of evidence requests. Zero allows no
    /// request.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] if `requests` is above
    /// [`MAXIMUM_REQUESTS`](Self::MAXIMUM_REQUESTS).
    pub fn with_requests(mut self, requests: u32) -> Result<Self, Error> {
        if requests > Self::MAXIMUM_REQUESTS {
            return Err(above_maximum(
                "the evidence request limit is above its maximum",
            ));
        }
        self.requests = requests;
        Ok(self)
    }

    /// Returns the largest size of any response that a fetcher returns, in
    /// bytes (ADR-0017, rule 8).
    #[must_use]
    pub const fn response_size(&self) -> u64 {
        self.response_size
    }

    /// Sets the largest size of one fetched response, in bytes.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] if `bytes` is above
    /// [`MAXIMUM_RESPONSE_SIZE`](Self::MAXIMUM_RESPONSE_SIZE).
    pub fn with_response_size(mut self, bytes: u64) -> Result<Self, Error> {
        if bytes > Self::MAXIMUM_RESPONSE_SIZE {
            return Err(above_maximum(
                "the response size limit is above its maximum",
            ));
        }
        self.response_size = bytes;
        Ok(self)
    }

    /// Returns the size limit of one input of `kind`, in bytes.
    #[must_use]
    pub const fn input_size(&self, kind: InputKind) -> u64 {
        match kind {
            InputKind::Document => self.document,
            InputKind::Certificate => self.certificate,
            InputKind::Crl => self.crl,
            InputKind::OcspResponse => self.ocsp_response,
            InputKind::TimestampToken => self.timestamp_token,
            InputKind::JoseHeader => self.jose_header,
            InputKind::State => self.state,
        }
    }

    /// Sets the size limit of one input of `kind`, in bytes. Zero refuses
    /// every input of that kind that is not empty.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidInput`] if `bytes` is above
    /// [`InputKind::maximum_size`] for `kind`.
    pub fn with_input_size(mut self, kind: InputKind, bytes: u64) -> Result<Self, Error> {
        if bytes > kind.maximum_size() {
            return Err(above_maximum("the input size limit is above its maximum"));
        }
        let field = match kind {
            InputKind::Document => &mut self.document,
            InputKind::Certificate => &mut self.certificate,
            InputKind::Crl => &mut self.crl,
            InputKind::OcspResponse => &mut self.ocsp_response,
            InputKind::TimestampToken => &mut self.timestamp_token,
            InputKind::JoseHeader => &mut self.jose_header,
            InputKind::State => &mut self.state,
        };
        *field = bytes;
        Ok(self)
    }

    /// Checks the length of one input of `kind` against its size limit,
    /// before any decoding (ADR-0024, rule 1).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::LimitExceeded`] if `len` is above the limit.
    pub fn check_input_size(&self, kind: InputKind, len: usize) -> Result<(), Error> {
        match u64::try_from(len) {
            Ok(len) if len <= self.input_size(kind) => Ok(()),
            _ => Err(Error::new(
                ErrorKind::LimitExceeded,
                "the input is larger than its size limit",
            )),
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::new()
    }
}

const fn above_maximum(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidInput, message)
}
