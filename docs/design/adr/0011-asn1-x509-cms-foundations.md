# ADR-0011: Build ASN.1, X.509 and CMS on the RustCrypto formats crates

- **Status:** Accepted
- **Date:** 2026-10-23

## Context

Every signature format in scope rests on DER-encoded structures: X.509 certificates and CRLs (RFC 5280), OCSP responses (RFC 6960), timestamp tokens (RFC 3161) and CMS (RFC 5652). Writing an ASN.1 layer from scratch is costly and error-prone. The RustCrypto project maintains `der`, `spki`, `x509-cert` and `cms`, which are pure Rust, `no_std` capable and widely used. Some are pre-1.0 and their releases are not always aligned: at the time of writing the stable `cms` release depends on an older `x509-cert` line than the latest stable `x509-cert`.

## Decision

sigillum uses `der`, `spki`, `x509-cert`, `x509-ocsp` and `cms` from the RustCrypto formats project for encoding and decoding. Structures missing upstream, such as the CAdES signed and unsigned attributes of ETSI EN 319 122-1 and the RFC 3161 timestamp structures where needed, are defined in sigillum with the same `der` derive conventions, and offered upstream when they are of general use.

Versions are pinned to a mutually compatible set and upgraded together. sigillum's public API does not expose types from these crates directly, so that their breaking changes do not become breaking changes for sigillum users.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| RustCrypto formats crates | Pure Rust, portable, maintained, shared with the wider ecosystem | Pre-1.0 churn; some structures missing |
| `rasn` | Broad ASN.1 coverage, code generation | Smaller X.509 and CMS ecosystem; less use in security-critical projects |
| In-house ASN.1 layer | Full control | Large effort; high defect risk; no shared review |
| `openssl` bindings | Complete | C dependency; conflicts with ADR-0002 and ADR-0010 |

## Consequences

An internal adapter layer converts between RustCrypto types and sigillum's own types. Dependabot updates to these crates are grouped and reviewed together. Contributions upstream are tracked as issues in this repository.
