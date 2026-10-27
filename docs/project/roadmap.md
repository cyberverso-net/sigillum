# Roadmap

The project advances in phases. Each phase ends at a gate with explicit exit criteria; the next phase starts only when they are met. Durations are indicative estimates for a single part-time maintainer and will be revised after phase 0.

Phase 3 runs in parallel with phases 1 and 2: its first step, the validation logic, operates on diagnostic data produced by DSS and therefore needs no sigillum parser.

## Phase 0: baseline and harness (indicative: 1 to 2 months)

Deliverables:

- Repository, licences, contribution rules and continuous integration in place.
- Differential test harness (`sigillum-oracle`) with the command-line tool `tools/dss-oracle` ([ADR-0013](../design/adr/0013-dss-oracle-command-line-tool.md)). It submits a signed object to a pinned DSS release running as a separate process and collects the reports. Validation uses a fixed time and offline certificate, revocation and timestamp sources.
- Test PKI generator (`sigillum-testpki`) and initial corpus of test vectors under `testdata/`, with a manifest of expected results ([ADR-0014](../design/adr/0014-test-pki-and-corpus.md)).
- Measurement of DSS on a JVM on a desktop machine, the first reference point for goal G4, following the [measurement protocol](measurements.md). It covers signing latency, memory and binary size.

Exit criteria:

- The harness runs in CI and reproduces DSS results deterministically.
- The threat model has been reviewed and updated for the phase's deliverables.

## Phase 1: creation (indicative: 6 to 9 months)

Deliverables:

- At the start of the phase, the remaining reference points for goal G4 and the targets for G4. The PoDoFo-based signing stack of the EUDI Wallet reference implementation is measured on a mid-range Android device and an iPhone, following the [measurement protocol](measurements.md). Size and latency targets for G4 are then written into the [charter](charter.md).
- `sigillum-pki`: certificates, path building to a supplied anchor, OCSP and CRL handling, RFC 3161 client, signer and fetcher interfaces.
- `sigillum-cms`: CMS SignedData, EnvelopedData and AuthEnvelopedData construction and parsing.
- `sigillum-cades`: CAdES-BES and baseline B-B, B-T, B-LT, enveloping and detached.
- `sigillum-pdf`: minimal PDF reader, append-only incremental-update writer and revision analysis ([ADR-0015](../design/adr/0015-pdf-reader-and-incremental-writer.md)).
- `sigillum-pades`: PAdES-BES and baseline B-B, B-T, B-LT on top of `sigillum-pdf`: signature dictionary, document security store, invisible and simple visible appearance.
- `sigillum-jades`: JAdES baseline B-B, B-T, B-LT, JWS JSON and compact serialisations, enveloping and detached. Delivered after CAdES and PAdES; it may follow in release 0.2 without delaying release 0.1 ([ADR-0008](../design/adr/0008-include-jades-baseline.md)).
- `sigillum-ffi`: Kotlin and Swift bindings through UniFFI; WASM build with `wasm-bindgen`.
- Example applications: remote signing through the Cloud Signature Consortium API; PKCS#12 for local testing.

Exit criteria:

- Every signature produced over the corpus validates in DSS with the expected indication; zero unexplained divergences.
- All parsers under continuous fuzzing, with no open crash.
- Builds and tests pass on Android, iOS, macOS, Windows, Linux and `wasm32`.
- The G4 targets set at the start of the phase are met.
- First release (0.1), covering at least CAdES, PAdES and CMS encryption (AuthEnvelopedData and EnvelopedData), published on crates.io.
- The threat model has been reviewed and updated for the phase's deliverables.

## Phase 2: basic verification (indicative: about 6 months)

Deliverables:

- Verification of CAdES, PAdES and JAdES signatures as defined in [scope.md](scope.md): integrity, chain, revocation, timestamps, object-level PDF modification detection.
- Reporting in the ETSI TS 119 102-2 format and a compact summary.
- Explicit "not supported" results for every deferred and excluded feature.

Exit criteria:

- Indications and sub-indications match DSS on the corpus for every case within scope; every out-of-scope case returns INDETERMINATE with a "not supported" reason.
- Independent security review of the parsing and verification code commissioned or completed.
- The threat model has been reviewed and updated for the phase's deliverables.

## Phase 3: validation engine (parallel track, indicative: 12 to 18 months)

Deliverables:

- Implementation of the ETSI EN 319 102-1 validation processes (basic, with time, long-term) and the qualification determination of TS 119 172-4 and TS 119 615, under a fixed default policy.
- Step one: the engine consumes DSS diagnostic data and is compared with DSS reports for every check.
- Step two: sigillum's own parsers produce the diagnostic data; EU trusted list (LOTL and national lists) retrieval, signature verification and history. The hardened XML component built for trusted-list signatures is designed so that it can later support XAdES ([ADR-0009](../design/adr/0009-keep-xades-deferred.md)).
- Baseline -LTA for CAdES, PAdES and JAdES.

Exit criteria:

- Agreement with DSS on the corpus at the level of individual constraints.
- Participation in an ETSI remote signature plugtest.
- The threat model has been reviewed and updated for the phase's deliverables.

## Phase 4: extensions (only with a partner and funding)

Candidates, in the order set by demand: XAdES baseline, ASiC-E with XAdES, the archival profile, counter-signatures, configurable policy, C ABI.

## Tracking

Progress is tracked in GitHub issues and milestones named after the phases. This document records intent and gates; it is updated when a gate is passed or a phase is re-planned.
