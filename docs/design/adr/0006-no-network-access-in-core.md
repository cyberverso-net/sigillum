# ADR-0006: No network access in the core

- **Status:** Accepted; retrieval through a `Fetcher` during signature creation superseded by [ADR-0026](0026-public-api-conventions.md)
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

## Notes

- **2026-10-27.** [ADR-0026](0026-public-api-conventions.md), decision 2, replaces the rule that all retrieval goes through a `Fetcher`, for retrieval during signature creation. The format crates return evidence requests to the caller, who performs them and passes the responses back. The `Fetcher` becomes a convenience over that loop for Rust callers with blocking network access. The core still performs no network access and has no HTTP or TLS dependency. Retrieval during verification is decided in phase 2. This note does not change the record above.
