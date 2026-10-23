# ADR-0013: Run DSS through a purpose-built command-line tool

- **Status:** Accepted
- **Date:** 2026-10-23

## Context

[ADR-0004](0004-dss-as-test-oracle.md) makes DSS the test oracle. The differential tests need DSS to run with a fixed validation time, with certificates, OCSP responses, CRLs and timestamps supplied offline, with a chosen validation policy, and with reports returned in a machine-readable form. They must be deterministic and cheap enough to run in continuous integration.

The DSS demonstration web application offers a validation service, but it validates at the current time and retrieves revocation data online, and running it in CI requires a long-lived server.

## Decision

The repository contains a small Java command-line tool, `tools/dss-oracle`, built with Maven against a pinned DSS release. It takes a signed document, optional detached content, trust anchors, offline certificate and revocation sources, a validation time and a policy, and writes the DSS diagnostic data, detailed report and simple report as files. The Rust crate `sigillum-oracle` drives this tool as a separate process and compares its output with sigillum's expectations.

The tool's own code is licensed like the rest of the repository. DSS is a build-time and test-time dependency resolved from its Maven repository; it is not copied into the repository or distributed with sigillum. The pinned DSS version is recorded in the tool's build file and upgraded only through a pull request that reviews any change in results.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| DSS demonstration web application in a container | Ready-made | Current time only; online revocation retrieval; long-lived server in CI |
| DSS REST service with a custom configuration | Reusable by others | Server to operate; configuration as complex as a command-line tool |
| Purpose-built command-line tool | Deterministic; offline; one process per run; easy to pin | A small amount of Java code to maintain |

## Consequences

Continuous integration needs a Java runtime and Maven for the jobs that run differential tests. These jobs run on Linux only. The tool is kept minimal: it configures DSS and writes reports, and contains no comparison logic, which stays in `sigillum-oracle`.
