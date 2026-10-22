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
//! - the `Fetcher` interface, through which all network retrieval is delegated to the
//!   caller.
//!
//! The crate performs no network access of its own. See `docs/design/architecture.md`.

#![forbid(unsafe_code)]
