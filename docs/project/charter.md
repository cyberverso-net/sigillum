# Project charter

## Mission

To provide a portable, memory-safe and verifiably interoperable implementation of the core of European advanced electronic signatures, so that applications on mobile devices, desktops and in browsers can create and check AdES signatures locally, to the same standard as server-side systems built on DSS.

## Context

The European framework for electronic signatures rests on the eIDAS Regulation, [Regulation (EU) No 910/2014](http://data.europa.eu/eli/reg/2014/910/oj) of 23 July 2014 as amended by [Regulation (EU) 2024/1183](http://data.europa.eu/eli/reg/2024/1183/oj) of 11 April 2024, and on the ETSI standards for signature formats (EN 319 122, EN 319 142 and related parts) and for validation (EN 319 102-1, TS 119 102-2, TS 119 172-4, TS 119 615). The European Commission's DSS library implements these standards in Java and is the de facto reference implementation.

The European Digital Identity Wallet brings qualified electronic signatures to mobile devices at scale. Existing mobile stacks cover signature creation at the most basic level and do not validate. Native desktop applications either bundle a Java runtime or implement signature formats ad hoc. There is no portable, standards-complete alternative.

## Goals

Each goal has a criterion by which it is judged met. Criteria marked *to be set at the start of phase 1* depend on measurements that have not yet been taken.

| Id | Goal | Criterion |
| --- | --- | --- |
| G1 | **Interoperability.** Signatures created by sigillum are accepted by the reference implementation. | Every signature in the test corpus validates in the latest DSS release with the expected indication; zero unexplained divergences. |
| G2 | **Portability.** One core serves every target platform. | The same crates build and pass tests on Android, iOS, macOS, Windows, Linux and `wasm32`; no Java runtime and no C or C++ dependency in the default build. |
| G3 | **Safety.** Parsing hostile input cannot compromise the host or produce a false acceptance. | `#![forbid(unsafe_code)]` in every crate except the binding layer; every parser covered by continuous fuzzing; an independent security review before any validation feature is declared stable. |
| G4 | **Efficiency.** The library is small and fast enough for mobile use. | Binary size and signing latency targets, *to be set at the start of phase 1* from measurements of current mobile and JVM stacks. |
| G5 | **Honest results.** The library never claims more than it has checked. | Every unsupported feature encountered during verification yields an explicit "not supported" outcome; the conformance suite tests this for each excluded feature. |
| G6 | **Clean provenance.** The code can be used under its stated licence without encumbrance. | Implementation derived from published specifications, each change citing its clauses; no code or test data under licences incompatible with Apache-2.0 OR MIT (see [CONTRIBUTING.md](../../CONTRIBUTING.md)). |
| G7 | **Usability by integrators.** Adopting the library is straightforward. | Idiomatic Kotlin, Swift and JavaScript bindings; documented examples for remote signing through the Cloud Signature Consortium API and for platform keystores. |

## Guiding principles

1. **Narrow and correct before broad.** A small feature set that is demonstrably equivalent to the reference is worth more than a large one that is not.
2. **Specifications are normative, DSS is the oracle.** Where the ETSI text and DSS disagree, the specification prevails, and the divergence is recorded and reported upstream.
3. **Offline first.** The core performs no network access of its own; retrieval of certificates, revocation data and timestamps goes through interfaces supplied by the caller.
4. **Signing keys stay outside.** The core computes what is to be signed and assembles the result; private-key operations are delegated to a signer interface (platform keystore, smart card middleware, remote signing service).
5. **Modern defaults, legacy on request.** Creation uses current baseline profiles and algorithms only; support for older material is an explicit, separately tested profile.
6. **Upstream what is generic.** Improvements to general-purpose building blocks (CMS, timestamping, OCSP, canonicalisation) are contributed to the relevant Rust ecosystem projects rather than kept in-house.

## Out of scope for the project as a whole

- Operating as, or being certified as, a qualified trust service.
- Feature parity with DSS.
- Server-side deployment concerns (web services, clustering, persistence).

## First user

The first consumer of the library is a native desktop application for drafting and filing documents in the Italian civil e-justice system (Processo Civile Telematico), which requires CAdES and PAdES signatures and CMS encryption. The project is designed so that this use case is fully served at the end of phase 1, independently of any further adoption.
