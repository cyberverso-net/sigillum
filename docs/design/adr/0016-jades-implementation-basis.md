# ADR-0016: Implement JAdES on sigillum's own foundations

- **Status:** Accepted
- **Date:** 2026-10-23
- **Issue:** #19

## Context

[ADR-0008](0008-include-jades-baseline.md) brought JAdES baseline into scope. It left open whether to build on the existing `jades` crate (BSD-2-Clause, version 0.1.0, published on 1 June 2026) or to implement JAdES on top of `sigillum-pki`.

## Decision

JAdES is implemented in `sigillum-jades` on top of `sigillum-pki`, using `serde_json` for JSON values and the RFC 7515 base64url encoding. The `jades` crate is not a dependency.

The reasons are consistency and control. JAdES must follow the two-step signing flow of [ADR-0005](0005-two-step-signing.md) and perform no network access ([ADR-0006](0006-no-network-access-in-core.md)). It must share certificate, timestamp and revocation handling with CAdES and PAdES, and report unsupported input as [ADR-0007](0007-asymmetric-scope.md) requires. Adapting an external crate to all four constraints would cost more than the JWS layer it provides.

RFC 7515, section 4, allows a parser either to reject JOSE headers with duplicate parameter names or to keep the last occurrence. sigillum rejects them, because accepting them lets two implementations read different headers from the same signature. JOSE headers are therefore parsed with a deserialiser that rejects duplicate member names, not with the default map type of `serde_json`, which keeps the last occurrence.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Depend on the `jades` crate | Less code at first | Different API model; own handling of certificates, timestamps and revocation; single maintainer |
| Contribute sigillum's needs to the `jades` crate | Shared effort | Design changes the crate may not accept; coordination cost |
| Own implementation on `sigillum-pki` | Same model and guarantees as the other formats | JWS layer to write and test |

## Consequences

The `jades` crate may be used in tests as an independent implementation for cross-checking. Findings that concern it are reported to its maintainer.
