//! Generator and checker of the sigillum test PKI and corpus.
//!
//! This crate is not published. It owns the test corpus under `testdata/`
//! and its manifest, as decided in ADR-0014 of the sigillum documentation.
//! It must not depend on any `sigillum-*` library crate, because those are
//! the code under test.

#![forbid(unsafe_code)]

pub mod documents;
pub mod dss;
pub mod manifest;
pub mod mutations;
pub mod openssl;
pub mod pki;
pub mod signed;
pub mod timestamp;
