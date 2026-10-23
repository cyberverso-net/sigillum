//! CAdES signature creation for sigillum.
//!
//! This crate will provide, in phase 1 of the roadmap, CAdES-BES (CAdES-E-BES in
//! ETSI EN 319 122-2, clause 4.3) and the baseline levels B-B, B-T and B-LT
//! defined in ETSI EN 319 122-1, in enveloping and detached packaging, using the
//! two-step prepare and assemble flow described in `docs/design/architecture.md`.

#![forbid(unsafe_code)]
