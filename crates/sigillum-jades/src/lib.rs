//! JAdES signature creation for sigillum.
//!
//! This crate will provide, in phase 1 of the roadmap, the baseline levels B-B, B-T
//! and B-LT defined in ETSI TS 119 182-1: JWS JSON serialisation (flattened and
//! general) and compact serialisation for B-B, enveloping and detached signatures,
//! the ETSI header parameters, and unsigned properties in the `etsiU` header, using
//! the signing flow described in `docs/design/architecture.md`: `prepare`, then
//! `assemble` with the signature value, then `resume` for each round of evidence
//! requests.

#![forbid(unsafe_code)]
