//! Differential test harness comparing sigillum with DSS.
//!
//! This crate is not published. It drives `tools/dss-oracle`, which runs a
//! pinned DSS release as a separate process with a fixed validation time,
//! offline certificate and revocation sources and the aligned validation
//! policy (ADR-0013 and ADR-0023 of the sigillum documentation). DSS is
//! used strictly as a black box; see `docs/design/conformance.md` and the
//! provenance rule in `CONTRIBUTING.md`.
//!
//! The API has three parts:
//!
//! - [`Validation`] describes one run of a validation mode of the tool,
//!   for a certificate, a timestamp token or a signed document, with the
//!   files that DSS may use. [`Validation::for_artefact`] gives the run of
//!   an artefact of the test corpus, as `sigillum-testpki verify --dss`
//!   makes it, and [`validate_corpus`] runs the whole corpus.
//! - [`Summary`] is the `summary.json` that a run writes.
//! - [`Expected`] is what a summary must contain, and [`check`] compares
//!   them. A [`Mismatch`] lists each member that differs, by its JSON
//!   pointer, with the expected and the found value.
//!
//! [`run`] runs a validation with any [`Oracle`]. With the feature `dss`,
//! off by default, `dss::Dss` runs the real tool with Java. Without it,
//! the crate builds and its tests run on every platform, without Java or
//! Maven. The manifest reader and the process runner come from
//! `sigillum-testpki`, which depends on no sigillum crate.
//!
//! ```
//! use sigillum_oracle::{Expected, Indication, Summary, check};
//!
//! let summary = Summary::parse(r#"{
//!   "format-version": 3,
//!   "oracle": { "dss-version": "6.5.1" },
//!   "mode": "validate-certificate",
//!   "validation-time": "2030-01-15T10:00:00Z",
//!   "policy": "aligned-1",
//!   "result": "validated",
//!   "indication": "INDETERMINATE",
//!   "sub-indication": "REVOKED_NO_POE",
//!   "details": {}
//! }"#)?;
//! let expected = Expected::indication(Indication::Passed, None);
//! let mismatch = check(&summary, &expected).err().ok_or("no mismatch")?;
//! assert_eq!(
//!     mismatch.to_string(),
//!     "summary.json differs in 2 members:\n  \
//!      /indication: expected \"PASSED\", found \"INDETERMINATE\"\n  \
//!      /sub-indication: expected null, found \"REVOKED_NO_POE\""
//! );
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod compare;
#[cfg(feature = "dss")]
pub mod dss;
mod summary;
mod validation;

pub use compare::{
    Difference, Expected, MAX_LISTED_BYTES, MAX_LISTED_DIFFERENCES, Mismatch, check, differences,
    identical,
};
pub use sigillum_testpki::dss::{Mode, Oracle};
pub use sigillum_testpki::manifest::{DssResult, Indication};
pub use summary::{FORMAT_VERSION, Summary, SummaryError};
pub use validation::{
    CorpusResult, OracleError, TimeError, Validation, differing_runs, run, validate_corpus,
};
