# Roadmap

The project advances in phases. Each phase ends at a gate with explicit exit criteria; the next phase starts only when they are met. Durations are indicative estimates for a single part-time maintainer and will be revised after phase 0.

Phase 3 runs in parallel with phases 1 and 2: its first step, the validation logic, operates on diagnostic data produced by DSS and therefore needs no sigillum parser.

## Phase 0: baseline and harness (indicative: 1 to 2 months)

Deliverables:

- Repository, licences, contribution rules and continuous integration in place.
- Differential test harness (`sigillum-oracle`) able to submit a signed object to a pinned DSS release running as a separate process, with fixed validation time and offline certificate, revocation and timestamp sources, and to collect the reports.
- Initial corpus of test vectors, generated from a private test PKI (root and issuing CAs, OCSP responder, CRLs, timestamping authority) created for the project.
- Measurements of the reference points for goal G4: signing latency and memory on a mid-range Android device and an iPhone, binary size, for at least DSS on a JVM and the PoDoFo-based stack used in current mobile wallets.

Exit criteria:

- The harness runs in CI and reproduces DSS results deterministically.
- Size and latency targets for G4 are written into the [charter](charter.md).

## Phase 1: creation (indicative: 6 to 9 months)

Deliverables:

- `sigillum-pki`: certificates, path building to a supplied anchor, OCSP and CRL handling, RFC 3161 client, signer and fetcher interfaces.
- `sigillum-cms`: CMS SignedData and EnvelopedData construction and parsing.
- `sigillum-cades`: CAdES-BES and baseline B-B, B-T, B-LT, enveloping and detached.
- `sigillum-pades`: PAdES-BES and baseline B-B, B-T, B-LT, incremental update, document security store, invisible and simple visible appearance.
- `sigillum-ffi`: Kotlin and Swift bindings through UniFFI; WASM build with `wasm-bindgen`.
- Example applications: remote signing through the Cloud Signature Consortium API; PKCS#12 for local testing.

Exit criteria:

- Every signature produced over the corpus validates in DSS with the expected indication; zero unexplained divergences.
- All parsers under continuous fuzzing, with no open crash.
- Builds and tests pass on Android, iOS, macOS, Windows, Linux and `wasm32`.
- The G4 targets set in phase 0 are met.
- First release (0.1) published on crates.io.

## Phase 2: basic verification (indicative: about 6 months)

Deliverables:

- Verification of CAdES and PAdES signatures as defined in [scope.md](scope.md): integrity, chain, revocation, timestamps, object-level PDF modification detection.
- Reporting in the ETSI TS 119 102-2 format and a compact summary.
- Explicit "not supported" results for every deferred and excluded feature.

Exit criteria:

- Indications and sub-indications match DSS on the corpus for every case within scope; every out-of-scope case returns INDETERMINATE with a "not supported" reason.
- Independent security review of the parsing and verification code commissioned or completed.

## Phase 3: validation engine (parallel track, indicative: 12 to 18 months)

Deliverables:

- Implementation of the ETSI EN 319 102-1 validation processes (basic, with time, long-term) and the qualification determination of TS 119 172-4 and TS 119 615, under a fixed default policy.
- Step one: the engine consumes DSS diagnostic data and is compared with DSS reports for every check.
- Step two: sigillum's own parsers produce the diagnostic data; EU trusted list (LOTL and national lists) retrieval, signature verification and history.
- Baseline -LTA for CAdES and PAdES.

Exit criteria:

- Agreement with DSS on the corpus at the level of individual constraints.
- Participation in an ETSI remote signature plugtest.

## Phase 4: extensions (only with a partner and funding)

Candidates, in the order set by demand: XAdES baseline, ASiC-E with XAdES, JAdES, the archival profile, counter-signatures, configurable policy, C ABI.

## Tracking

Progress is tracked in GitHub issues and milestones named after the phases. This document records intent and gates; it is updated when a gate is passed or a phase is re-planned.
