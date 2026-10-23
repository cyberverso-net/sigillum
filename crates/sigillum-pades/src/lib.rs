//! PAdES signature creation for sigillum.
//!
//! This crate will provide, in phase 1 of the roadmap, PAdES-BES (PAdES-E-BES in
//! ETSI EN 319 142-2, clause 5.3) and the baseline levels B-B, B-T and B-LT
//! defined in ETSI EN 319 142-1: the signature dictionary, the document security
//! store, and an invisible or simple visible appearance. Incremental updates of
//! the PDF document are written by `sigillum-pdf`.

#![forbid(unsafe_code)]
