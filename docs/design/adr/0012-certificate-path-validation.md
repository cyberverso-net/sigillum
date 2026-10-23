# ADR-0012: Implement certificate path validation in sigillum

- **Status:** Accepted
- **Date:** 2026-10-23

## Context

AdES creation at level B-LT and AdES verification need certificate path building and validation according to RFC 5280, section 6. AdES differs from web PKI in three ways: validation must be possible at a time in the past, for example the time of a signature timestamp, as the validation processes of ETSI EN 319 102-1 require; all algorithms in scope must be supported, including RSASSA-PSS, Ed25519 and P-521; and missing intermediate certificates may have to be retrieved through the authority information access extension, which under [ADR-0006](0006-no-network-access-in-core.md) must go through the caller's fetcher.

Existing Rust validators do not fit. `rustls-webpki` targets TLS server authentication at the current time. `pkix-path` is recent, maintained by a single author, and does not yet support RSASSA-PSS, Ed25519 or P-521.

## Decision

sigillum implements path building and RFC 5280 basic path validation in `sigillum-pki`, on top of `x509-cert` ([ADR-0011](0011-asn1-x509-cms-foundations.md)) and the provider interface of [ADR-0010](0010-cryptographic-backend.md). The validation time is always an explicit input. The implementation covers signature verification, validity periods, basic constraints, key usage and extended key usage, name constraints and revocation status supplied by the caller or embedded in the signature. Certificate policy identifiers are collected for later qualification checks; certificates that require explicit policy processing beyond this yield a "not supported" result under [ADR-0007](0007-asymmetric-scope.md).

The implementation is tested against the RFC 5280 path validation test suite published by NIST (PKITS) where it applies, and against DSS through the differential harness.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| `rustls-webpki` | Mature, audited | Web PKI only; no validation at a past time; limited algorithms |
| `pkix-path` | Follows RFC 5280 closely | Young, single maintainer; missing algorithms and path building |
| In-house implementation | Fits AdES needs exactly; same API conventions as the rest of sigillum | Effort; must be tested thoroughly |

## Consequences

Path validation is one of the critical modules subject to the mutation-testing threshold in the quality gates. PKITS test vectors are added to the test corpus with their licence recorded.
