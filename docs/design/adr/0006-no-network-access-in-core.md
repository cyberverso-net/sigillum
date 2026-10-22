# ADR-0006: No network access in the core

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

Creating signatures at levels B-T and above, and verifying signatures, require timestamps, OCSP responses, CRLs and sometimes intermediate certificates from the network. Mobile and desktop applications have their own requirements for proxies, certificate pinning, caching, consent and privacy. Tests must be deterministic.

## Decision

The core crates never open network connections. All retrieval goes through a `Fetcher` interface supplied by the caller. An optional adapter crate may provide a default HTTPS implementation; it is not a dependency of the core.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Built-in HTTP client | Works out of the box | Imposes a network stack on every platform; hard to test; privacy decisions taken away from the application |
| Caller-supplied fetcher | Applications keep control; deterministic offline tests; smaller binaries | Callers must provide an implementation |

## Consequences

The core has no HTTP or TLS dependency. Examples and the optional adapter show how to implement the fetcher. Offline operation is the default mode for tests and for the differential harness.
