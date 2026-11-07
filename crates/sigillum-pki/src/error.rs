//! The error type shared by every library crate (ADR-0026, decision 8).
//!
//! An error carries a kind, a fixed message and, where one applies, a
//! location in the input. It holds no bytes of the input, no document
//! content and no key material (threat R3 of the threat model). By
//! convention, checked in review, the message and the member names of a
//! JSON pointer are fixed text written in the source of sigillum, never
//! text taken from the input. A location otherwise holds only numbers.
//!
//! Errors are for operations that cannot complete. Verification results in
//! phase 2 are values, not errors (ADR-0017, rule 4).

use std::fmt;

/// Classifies an [`Error`] by its cause, so that callers and bindings can
/// react to it without reading the message.
///
/// The categories are those of ADR-0026, decision 8. The binding layer maps
/// each kind to an exception or error class of the target language. More
/// kinds may be added before 1.0.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The input does not follow its encoding, for example DER that the
    /// length walk refuses, a JSON value that does not parse, or an ECDSA
    /// value stated as `Der` that is not an `ECDSA-Sig-Value`.
    Malformed,
    /// A limit of the context was reached, such as an input size, the
    /// nesting depth, the number of evidence rounds or requests, or a
    /// response size. See [`Limits`](crate::Limits).
    LimitExceeded,
    /// The input or option is valid, but outside the scope of sigillum
    /// (ADR-0007), such as an excluded algorithm or an object identifier
    /// with an arc of 2^28 or more (ADR-0024, rule 4).
    NotSupported,
    /// The arguments are inconsistent with each other or with the rules of
    /// the API, such as a key type that does not match the signature
    /// algorithm, a key usage that forbids signing (threat G4), a missing
    /// signing time, or a limit above its maximum.
    InvalidInput,
    /// A state belongs to another format, version or step, or fails the
    /// early consistency check with the inputs supplied again, or responses
    /// do not match the pending requests by identifier (ADR-0026,
    /// decision 6).
    StateMismatch,
    /// A signature value does not verify over the data to be signed with
    /// the key of the signing certificate (threat G2; ADR-0017, rule 1).
    SignatureMismatch,
    /// Fetched or supplied evidence fails its checks, or the signing
    /// certificate is revoked (threats G5 to G7; ADR-0017, rules 6 and 7).
    EvidenceRejected,
    /// Evidence that the requested level needs could not be retrieved, and
    /// no other source remains (ADR-0026, decision 2).
    EvidenceUnavailable,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed input",
            Self::LimitExceeded => "limit exceeded",
            Self::NotSupported => "not supported",
            Self::InvalidInput => "invalid input",
            Self::StateMismatch => "state mismatch",
            Self::SignatureMismatch => "signature mismatch",
            Self::EvidenceRejected => "evidence rejected",
            Self::EvidenceUnavailable => "evidence unavailable",
        })
    }
}

/// Points to the place in the input where an [`Error`] arose.
///
/// A location holds positions and names of structure, never content. More
/// forms may be added before 1.0.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Location {
    /// A byte offset from the first byte of the input passed to the
    /// public call that failed. An error inside an encapsulated value,
    /// such as the contents of an OCTET STRING, still counts from the start
    /// of that outer input, not from the start of the inner value.
    Offset(u64),
    /// A JSON pointer ([RFC 6901](https://www.rfc-editor.org/rfc/rfc6901))
    /// into a JSON value, such as a JOSE header.
    JsonPointer(JsonPointer),
    /// An indirect object of a PDF file, by its object number and
    /// generation number (ISO 32000-1:2008, clause 7.3.10).
    PdfObject {
        /// The object number.
        number: u32,
        /// The generation number.
        generation: u16,
    },
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offset(offset) => write!(f, "offset {offset}"),
            Self::JsonPointer(pointer) => write!(f, "JSON pointer {pointer}"),
            Self::PdfObject { number, generation } => {
                write!(f, "PDF object {number} {generation}")
            }
        }
    }
}

/// One reference token of a [`JsonPointer`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonPointerToken {
    /// A member of an object, by a name that sigillum knows. By
    /// convention, checked in review, the name is fixed text in the source
    /// of sigillum, never a name taken from the input.
    Member(&'static str),
    /// An element of an array, by its index from zero.
    Index(u32),
}

/// Identifies a value inside a JSON document, as an
/// [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) JSON pointer.
///
/// Member names are names that sigillum knows, such as `sigD` or
/// `x5t#S256`, written as fixed text in its source. By convention, checked
/// in review, a pointer never repeats a name taken from the input. A
/// decoder that meets an unknown member stops the pointer at its parent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct JsonPointer {
    tokens: Vec<JsonPointerToken>,
}

impl JsonPointer {
    /// Returns the pointer to the whole document, written as the empty
    /// string.
    #[must_use]
    pub const fn root() -> Self {
        Self { tokens: Vec::new() }
    }

    /// Returns this pointer extended by the member `name`.
    #[must_use]
    pub fn member(mut self, name: &'static str) -> Self {
        self.tokens.push(JsonPointerToken::Member(name));
        self
    }

    /// Returns this pointer extended by the array element at `index`.
    #[must_use]
    pub fn index(mut self, index: u32) -> Self {
        self.tokens.push(JsonPointerToken::Index(index));
        self
    }

    /// Returns the reference tokens, from the root outwards.
    #[must_use]
    pub fn tokens(&self) -> &[JsonPointerToken] {
        &self.tokens
    }
}

/// Writes the pointer in the syntax of RFC 6901, section 3, with `~`
/// escaped as `~0` and `/` as `~1`. The root is the empty string.
impl fmt::Display for JsonPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for token in &self.tokens {
            f.write_str("/")?;
            match token {
                JsonPointerToken::Member(name) => {
                    for c in name.chars() {
                        match c {
                            '~' => f.write_str("~0")?,
                            '/' => f.write_str("~1")?,
                            _ => write!(f, "{c}")?,
                        }
                    }
                }
                JsonPointerToken::Index(index) => write!(f, "{index}")?,
            }
        }
        Ok(())
    }
}

/// Reports why an operation of sigillum could not complete.
///
/// The error carries a [kind](ErrorKind), a fixed message and, where one
/// applies, a [location](Location) in the input. It never carries bytes of
/// the input, document content or key material (ADR-0026, decision 8;
/// threat R3).
///
/// The displayed form is the kind, the message and the location, for
/// example `malformed input: the length runs past the input, at offset 17`.
/// Callers that react to an error should use [`kind`](Self::kind), not
/// the text, which may change between versions.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Error {
    kind: ErrorKind,
    message: &'static str,
    location: Option<Location>,
}

impl Error {
    /// Creates an error of `kind` with a fixed `message` and no location.
    ///
    /// The message describes the cause in a short phrase without a final
    /// full stop. By convention, checked in review, it is fixed text in
    /// the source of sigillum and never contains input.
    #[must_use]
    pub const fn new(kind: ErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            location: None,
        }
    }

    /// Returns this error with `location` as the place where it arose,
    /// replacing any earlier location.
    #[must_use]
    pub fn at(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }

    /// Returns the kind of the error.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns the fixed message of the error.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }

    /// Returns the location in the input, where one applies.
    #[must_use]
    pub const fn location(&self) -> Option<&Location> {
        self.location.as_ref()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)?;
        if let Some(location) = &self.location {
            write!(f, ", at {location}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}
