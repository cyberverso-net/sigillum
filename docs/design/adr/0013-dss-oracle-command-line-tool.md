# ADR-0013: Run DSS through a purpose-built command-line tool

- **Status:** Accepted
- **Date:** 2026-10-23
- **Issue:** #19

## Context

[ADR-0004](0004-dss-as-test-oracle.md) makes DSS the test oracle. The differential tests need DSS to run with a fixed validation time and a chosen validation policy. Certificates, OCSP responses, CRLs and timestamps must be supplied offline, and the reports returned in a machine-readable form. They must be deterministic and cheap enough to run in continuous integration. The test PKI of [ADR-0014](0014-test-pki-and-corpus.md) also needs DSS to check isolated PKI artefacts and to produce signed documents as verification fixtures.

The DSS demonstration web application validates at the current time, retrieves revocation data online, and needs a long-lived server in continuous integration.

## Decision

The repository contains a small Java command-line tool, `tools/dss-oracle`, built with Maven against a pinned DSS release from Maven Central. Every mode works offline, with trust anchors, offline certificate and revocation sources, and a fixed validation or signing time. The tool has four modes:

- **validate-document** takes a signed document, optional detached content and a policy, and writes the DSS diagnostic data, detailed report and simple report as files;
- **validate-certificate** takes a certificate with its chain, offline OCSP responses and CRLs, and validates it at the fixed validation time. This is how OCSP responses and CRLs are checked;
- **validate-timestamp** takes a standalone RFC 3161 timestamp token and validates it;
- **sign** creates CAdES, PAdES and JAdES signatures with test PKI keys, a fixed signing time and the levels requested, for use as verification fixtures. Its timestamp source calls `sigillum-testpki` to issue each token for the given digest at the fixed time, so no clock is read.

Each result must match the one recorded in the manifest. An artefact counts as rejected only when DSS cannot parse it; a failed validation is recorded as an indication and a sub-indication. The Rust crate `sigillum-oracle` and the fixture checks of `sigillum-testpki` drive this tool as a separate process and compare its output with the expected results.

**Licensing.** The tool's code is written for this project and licensed like the rest of the repository; it is not adapted from DSS cookbook or demonstration code. DSS, licensed under LGPL-2.1, is a build-time and test-time dependency resolved by Maven. No artefact that contains DSS is committed, published or distributed, so the distribution conditions of LGPL-2.1 do not arise. The tool keeps the licence set by [ADR-0003](0003-licence-and-contribution-terms.md). Its Maven dependencies fall outside the dependency-licence policy that `cargo deny` enforces, so they are reviewed by hand whenever they change.

**Platforms.** Differential tests and fixture checks need a Java runtime and run on Linux only. The integration tests of `sigillum-oracle` will be behind a Cargo feature, `dss`, off by default, which must build without Java or Maven. The cross-platform test job does not enable it, because it tests `sigillum-oracle` with its default features only; a dedicated Linux job will enable the feature and provide Java and Maven.

The pinned DSS version is recorded in the tool's build file. It is upgraded only through a pull request that reviews any change in results.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| DSS demonstration web application in a container | Ready-made | Current time only; online revocation retrieval; long-lived server |
| DSS REST service with a custom configuration | Reusable by others | Server to operate; configuration as complex as a command-line tool |
| Purpose-built command-line tool | Deterministic; offline; one process per run; easy to pin | A small amount of Java code to maintain, growing with its four modes |

## Consequences

The tool is kept minimal: it configures DSS, signs or validates, and writes the results. It contains no comparison logic, which stays in `sigillum-oracle` and `sigillum-testpki`. The quality gates describe the separate differential-test and fixture-verification jobs.
