# ADR-0011: Build ASN.1, X.509 and CMS on the RustCrypto formats crates

- **Status:** Accepted
- **Date:** 2026-10-23
- **Issue:** #19

## Context

Every signature format in scope rests on DER-encoded structures: X.509 certificates and CRLs (RFC 5280), OCSP responses (RFC 6960), timestamp tokens (RFC 3161) and CMS (RFC 5652). Writing an ASN.1 layer from scratch is costly and error-prone. The RustCrypto formats project maintains `der`, `spki`, `x509-cert`, `x509-ocsp` and `cms`, which are pure Rust and widely used.

The RustCrypto crates are moving between two generations. The stable releases of `x509-ocsp` (0.2.1) and `cms` (0.2.3) belong to the generation built on `der` 0.7 and `x509-cert` 0.2. The newer generation is built on `der` 0.8, `x509-cert` 0.3 and `signature` 3. It has stable primitives such as `p256` 0.14 and `ed25519-dalek` 3, but no `x509-ocsp` release and only a release candidate of `cms`. The types and traits of the two generations do not interoperate, so one generation must be chosen for the whole set.

## Decision

sigillum uses the RustCrypto formats crates for encoding and decoding, pinned to the **stable `der` 0.7 generation**. The set is `der` 0.7, `spki` 0.7, `x509-cert` 0.2, `x509-ocsp` 0.2, `cms` 0.2, with the matching primitives (`signature` 2, `rsa` 0.9, `p256` 0.13, `p384` 0.13, `p521` 0.13, `ed25519-dalek` 2, `sha2` 0.10, `sha3` 0.10). Every dependency is then a stable release, and the set is consistent.

Structures missing upstream are defined in sigillum with the same `der` derive conventions, and offered upstream when they are of general use. Examples are the CAdES signed and unsigned attributes of ETSI EN 319 122-1 V1.3.1. The RFC 3161 structures come from `x509-tsp` 0.1, which belongs to this generation.

The public API of sigillum never exposes types from these crates. Moving to the `der` 0.8 generation is therefore an internal change. It is tracked as an issue and planned once stable `cms`, `x509-ocsp` and `rsa` 0.10 releases exist for that generation, preferably before the first sigillum release.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Stable `der` 0.7 generation | All stable; consistent; OCSP available | A migration ahead; older primitive releases |
| `der` 0.8 generation with release candidates | No later migration | Release candidates in a security library; no `x509-ocsp`, so OCSP structures must be written in sigillum |
| `rasn` | Broad ASN.1 coverage | Smaller X.509 and CMS ecosystem |
| In-house ASN.1 layer | Full control | Large effort; high defect risk |

## Consequences

An internal adapter layer converts between RustCrypto types and sigillum's own types. Dependabot groups the RustCrypto updates so that the set moves together, and major-version updates of this set are handled by the migration issue, not by individual Dependabot pull requests.

The rules for decoding untrusted input with these crates are set by [ADR-0024](0024-bounded-decoding-of-untrusted-input.md).
