# Architecture

This document gives an overview of the workspace and its main design choices. The reasoning behind each significant decision is recorded in the [architecture decision records](adr/README.md); questions still open are listed at the end and are settled during phase 0.

## Workspace layout

| Crate | Role | Published |
| --- | --- | --- |
| `sigillum-pki` | Algorithms, certificates, path building to a supplied anchor, OCSP, CRL, RFC 3161 timestamps, signer and fetcher interfaces | Yes |
| `sigillum-cms` | CMS SignedData and EnvelopedData construction and parsing, CAdES signed and unsigned attributes | Yes |
| `sigillum-cades` | CAdES profiles: BES, baseline B-B, B-T, B-LT | Yes |
| `sigillum-pades` | PAdES profiles: incremental update, signature dictionary, document security store, appearance | Yes |
| `sigillum-jades` | JAdES profiles: JWS serialisations, ETSI header parameters, unsigned properties | Yes |
| `sigillum-ffi` | UniFFI bindings for Kotlin and Swift; `wasm-bindgen` bindings for JavaScript | Yes, from phase 1 |
| `sigillum-oracle` | Differential test harness driving DSS as an external process | No |

The crate names `sigillum` and `sigillum-core` on crates.io belong to an unrelated project; all crates of this project carry the `sigillum-` prefix followed by a functional name. An umbrella crate (`sigillum-ades`) may be added once the public API stabilises.

## Design overview

| Topic | Choice | Record |
| --- | --- | --- |
| Implementation language and bindings | Rust; UniFFI for Kotlin and Swift; `wasm-bindgen` for JavaScript | [ADR-0002](adr/0002-implement-in-rust.md) |
| Licence and contributions | Apache-2.0 OR MIT; Developer Certificate of Origin | [ADR-0003](adr/0003-licence-and-contribution-terms.md) |
| Relationship with DSS | External test oracle only; no DSS code or test data | [ADR-0004](adr/0004-dss-as-test-oracle.md) |
| Signing flow | Two steps, `prepare` and `assemble`; keys stay with an external signer | [ADR-0005](adr/0005-two-step-signing.md) |
| Network access | None in the core; caller-supplied `Fetcher` | [ADR-0006](adr/0006-no-network-access-in-core.md) |
| Scope and unsupported input | Baseline-first creation; explicit "not supported" results | [ADR-0007](adr/0007-asymmetric-scope.md) |
| JAdES | Baseline B-B to B-LT in scope, after CAdES and PAdES | [ADR-0008](adr/0008-include-jades-baseline.md) |
| XAdES | Deferred; reviewed once the phase 3 XML component for trusted lists exists | [ADR-0009](adr/0009-keep-xades-deferred.md) |

### Errors, not panics

Malformed input never causes a panic. Every parser returns a typed error. `clippy::unwrap_used`, `clippy::expect_used` and `clippy::panic` are denied in library code.

### Memory safety

`unsafe` code is denied across the workspace, and every crate except `sigillum-ffi` forbids it outright with `#![forbid(unsafe_code)]`. Generated binding code in `sigillum-ffi` may require it.

### Minimum supported Rust version

Rust 1.85 (edition 2024). Raised only in a minor release, with notice in the changelog.

## Open questions for phase 0

Each of these is settled by an ADR before the dependent stories start.

| Question | Candidates | Deciding factors |
| --- | --- | --- |
| Cryptographic backend | RustCrypto by default; `aws-lc-rs` behind a feature flag for deployments that need a validated module | Portability, binary size, availability of a validated module |
| ASN.1, X.509 and CMS foundations | RustCrypto `der`, `spki`, `x509-cert`, `cms`, with contributions upstream | Completeness, maintenance, API stability |
| Certificate path validation | `pkix-path` or an in-house implementation | Algorithm coverage, RFC 5280 completeness, maintenance risk |
| JAdES implementation basis | Build on the existing `jades` crate, contribute to it, or implement on top of `sigillum-pki` | Conformance to TS 119 182-1, API fit with ADR-0005 and ADR-0006, maintenance |
| PDF reading and incremental writing | An existing parser (for example `lopdf`) with a purpose-built incremental writer, or a minimal in-house reader | Robustness against malformed files, exact control over byte ranges |
| DSS deployment for the oracle | Validation web service in a container, or command-line demonstration | Determinism, CI cost, ease of pinning a release |
