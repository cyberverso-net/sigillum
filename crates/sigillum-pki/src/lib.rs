//! Public-key infrastructure building blocks for sigillum.
//!
//! This crate will provide, in phase 1 of the roadmap:
//!
//! - algorithm identifiers and policies for digests and signatures;
//! - X.509 certificate parsing and path building to a caller-supplied trust anchor
//!   (RFC 5280);
//! - OCSP (RFC 6960) and CRL (RFC 5280) processing for embedding revocation data;
//! - RFC 3161 timestamp requests and responses;
//! - the `Signer` interface, through which private-key operations are delegated to a
//!   platform keystore, a smart card or a remote signing service;
//! - the evidence requests and responses through which the format crates ask the
//!   caller for timestamps, revocation data and certificates, and the `Fetcher`
//!   interface, a convenience for Rust callers that perform these requests with
//!   blocking network access (ADR-0026, decision 2).
//!
//! The crate performs no network access of its own. See `docs/design/architecture.md`.
//!
//! It also provides the types that every format crate shares
//! (ADR-0026, decisions 3, 4 and 8):
//!
//! - [`Context`], with the signing and validation times as [`UnixTime`],
//!   the trust anchors, the material the caller already has, the
//!   [`Limits`] and the choices that relax a defensive rule;
//! - [`Limits`] and [`InputKind`], with a documented default and maximum
//!   for each limit (ADR-0024, rule 1; threat P2);
//! - [`Error`], with its [`ErrorKind`] and [`Location`], which never
//!   carries input content (threat R3).

#![forbid(unsafe_code)]

mod context;
mod error;
mod limits;
mod time;

pub use context::Context;
pub use error::{Error, ErrorKind, JsonPointer, JsonPointerToken, Location};
pub use limits::{InputKind, Limits};
pub use time::UnixTime;
