# ADR-0012: Implement certificate path validation in sigillum

- **Status:** Accepted; retrieval through the caller's fetcher during signature creation superseded by [ADR-0026](0026-public-api-conventions.md)
- **Date:** 2026-10-23
- **Issue:** #19

## Context

AdES creation at level B-LT and AdES verification need certificate path building and validation according to RFC 5280, section 6. In AdES, validation also has to:

- run at a time chosen by the caller, often in the past, such as the time of a signature timestamp;
- use revocation data embedded in the signature or supplied by the caller, including OCSP responses;
- support every algorithm in scope, including RSASSA-PSS keys identified as `id-RSASSA-PSS`;
- report failures in terms that map onto the indications and sub-indications of ETSI EN 319 102-1 V1.4.1;
- retrieve missing intermediate certificates only through the caller's fetcher ([ADR-0006](0006-no-network-access-in-core.md)).

Two Rust validators were considered. `rustls-webpki` validates at a caller-supplied time and supports Ed25519 and RSASSA-PSS signatures, but it is built for TLS. It has no certificate policy processing, no OCSP, TLS-oriented extended key usage checks and no support for `id-RSASSA-PSS` keys. Its signature verification is pluggable through `rustls-pki-types`. `pkix-path` 0.3 implements RFC 5280 closely, including policy processing, has a pluggable signature verifier and is tested with PKITS; path building and revocation live in sibling crates. It is young and has a single maintainer, and its results are not expressed in AdES terms.

## Decision

sigillum implements path building and RFC 5280 path validation in `sigillum-pki`, on top of `x509-cert` ([ADR-0011](0011-asn1-x509-cms-foundations.md)) and the provider interface of [ADR-0010](0010-cryptographic-backend.md). The validation time is always an explicit input. Results carry the information needed to derive EN 319 102-1 sub-indications.

The implementation covers signature verification, validity periods, basic constraints, key usage and extended key usage, name constraints, and revocation status from embedded or supplied OCSP responses and CRLs. Certificate policy identifiers are collected for later qualification checks. Of the policy inputs of RFC 5280, section 6.1.1, only these values are supported: `user-initial-policy-set` is {`anyPolicy`}, and `initial-policy-mapping-inhibit`, `initial-explicit-policy` and `initial-any-policy-inhibit` are false. The same section does not require conforming implementations to support the setting of all its inputs. Explicit policy processing is required when the caller supplies any other value for these inputs. It is also required when the path contains a `policyMappings` or `inhibitAnyPolicy` extension, or a `policyConstraints` extension with `requireExplicitPolicy`. In those cases:

- **verification** returns INDETERMINATE with a "not supported" reason ([ADR-0007](0007-asymmetric-scope.md));
- **creation** at B-LT fails with a typed "not supported" error, so that no signature is produced on an unvalidated path.

`pkix-path` and `rustls-webpki` are used in tests as independent implementations to cross-check results where their scope overlaps.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| `rustls-webpki` | Mature; its predecessor `webpki` was audited in 2020 | TLS-oriented; no policy processing, no OCSP, no `id-RSASSA-PSS` keys |
| `pkix-path` and sibling crates | Close to RFC 5280; pluggable verifier; PKITS-tested | Young, single maintainer; results not in AdES terms; three crates to integrate (`pkix-path`, `pkix-path-builder`, `pkix-revocation`) |
| Contribute to or fork `pkix-path` | Shared effort; existing test coverage | Design changes for AdES may not fit the upstream project; a fork carries the maintenance alone |
| Own implementation | Fits AdES needs exactly; same API conventions as the rest of sigillum | Effort; must be tested thoroughly |

## Consequences

Path validation is a critical module subject to the mutation-testing threshold in the quality gates. The NIST PKITS test vectors are used where they apply. Because PKITS states no licence and includes private keys, the vectors are downloaded at test time and checked against a recorded digest, not committed ([ADR-0014](0014-test-pki-and-corpus.md)).

## Notes

- **2026-10-27.** [ADR-0026](0026-public-api-conventions.md), decision 2, replaces the caller's fetcher as the only route for retrieval during signature creation. There, missing intermediate certificates of the chains of evidence, such as those of a TSA or an OCSP responder, are requested through the evidence requests that the format crates return to the caller, who passes the responses back. The chain of the signing certificate is never completed by retrieval: the caller supplies it in full, and an incomplete chain is refused with `InvalidInput`. The `Fetcher` is a convenience over that loop. The core still performs no network access. Retrieval during verification is decided in phase 2. This note does not change the record above.
