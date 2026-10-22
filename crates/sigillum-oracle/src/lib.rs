//! Differential test harness comparing sigillum with DSS.
//!
//! This crate is not published. It will drive a pinned DSS release running as a
//! separate process, submit signed objects with a fixed validation time and offline
//! certificate, revocation and timestamp sources, and compare the results with
//! sigillum's expectations. DSS is used strictly as a black box; see
//! `docs/design/conformance.md` and the provenance rule in `CONTRIBUTING.md`.

#![forbid(unsafe_code)]
