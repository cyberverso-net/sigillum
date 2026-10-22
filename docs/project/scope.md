# Scope

This document fixes what sigillum implements, what it defers and what it excludes. It is the reference for deciding whether a proposed feature belongs in the project. Changes to it follow the process in [GOVERNANCE.md](../../GOVERNANCE.md).

The scope is asymmetric by design. **Creation** is restricted to current baseline profiles and modern algorithms, because nobody needs to produce legacy signature forms today. **Verification** must handle what users actually receive; for the target users (wallets, desktop and browser applications) that means recent signatures. Support for older material is a separate *archival profile*, deferred until there is demand.

## In scope (phases 1 and 2)

### Signature formats and levels

| Format | Levels created | Packaging | Standard |
| --- | --- | --- | --- |
| CAdES | B-B, B-T, B-LT; CAdES-BES | Enveloping (`.p7m`) and detached | ETSI EN 319 122-1 and -2 |
| PAdES | B-B, B-T, B-LT; PAdES-BES | Incremental update, invisible or with a visible appearance | ETSI EN 319 142-1 and -2 |
| CMS EnvelopedData | Not applicable | Key transport (RSA-OAEP, RSA PKCS#1 v1.5 for compatibility) and key agreement (ECDH) | RFC 5652, RFC 5753 |

CAdES-BES and PAdES-BES are retained because they remain required by existing national systems, including the Italian Processo Civile Telematico, and are structurally close to baseline B-B.

### Cryptographic algorithms (creation)

- Digests: SHA-256, SHA-384, SHA-512; SHA3-256, SHA3-384, SHA3-512.
- Signatures: RSA PKCS#1 v1.5 and RSASSA-PSS (2048 bits and above); ECDSA on P-256, P-384 and P-521; Ed25519.

### Supporting functions

- X.509 certificate parsing and path building to a caller-supplied trust anchor.
- OCSP and CRL processing for embedding revocation data at B-LT.
- RFC 3161 timestamp requests and responses.
- A signer interface for external private-key operations, with adapters for the Cloud Signature Consortium API and for PKCS#12 (tests only).
- A fetcher interface for HTTP(S) retrieval, supplied by the caller.

### Verification (phase 2)

Basic verification of CAdES and PAdES signatures: cryptographic integrity, certificate chain to a caller-supplied trust anchor, revocation status from embedded or supplied data, timestamp integrity, and object-level detection of PDF modifications after signing. Results use the indications and sub-indications of ETSI EN 319 102-1 and are reported in the ETSI TS 119 102-2 format, with a compact summary for applications. This is not a full EN 319 102-1 validation and is labelled as such.

### Bindings

Kotlin and Swift through UniFFI; JavaScript and TypeScript through `wasm-bindgen`. A C ABI may follow if a consumer needs it.

## Deferred

These are expected to be added later, in the order of the [roadmap](roadmap.md) and subject to demand.

| Item | Condition for inclusion |
| --- | --- |
| Full EN 319 102-1 validation engine with qualification (TS 119 172-4, TS 119 615) and EU trusted lists | Phase 3 |
| Baseline -LTA for CAdES and PAdES | Phase 3 or a partner need |
| XAdES baseline (namespaces 1.3.2 and 1.4.1 only) | Partner need |
| ASiC-E with XAdES, then ASiC-S and ASiC-E with CAdES | Partner need |
| JAdES baseline | Partner need |
| Archival profile: validation of CAdES and XAdES -C, -X, -XL, -A, PAdES-LTV, pre-eIDAS qualification rules | Demand from an archival or validation-service user |
| Counter-signatures | Demand |
| Configurable validation policy | Demand from a validation-service user |
| C ABI | Demand |

## Excluded

These are not planned. Proposals to include them need to explain why the reasons below no longer hold.

| Item | Reason |
| --- | --- |
| Creation of legacy forms (-C, -X, -XL, -A, PAdES-LTV) | Obsolete for new signatures |
| XAdES namespaces 1.1.1 and 1.2.2 | Predate the current XAdES standard |
| Creation with MD2, MD5, SHA-1, RIPEMD-160, Whirlpool, DSA | Insecure or obsolete; on verification these are recognised and rejected under the cryptographic policy, without being implemented |
| Explicit signature policies (EPES policy documents and policy stores) | Rarely used; verification checks presence and digest only |
| OpenDocument signatures | Niche format |
| PDF/A conformance checking | Outside the signature domain |
| Modification detection that requires page rendering | Requires a rendering engine, unsuitable for mobile |
| LDAP and FTP retrieval | Rare in current European CA practice |
| Smart-card and keystore drivers (PKCS#11, CAPI, keychain) inside the core | Belong to the platform layer, behind the signer interface |
| Multiple report renderings (HTML, PDF, XSLT) | Applications render their own; one standard report suffices |
| Evidence records, CB-AdES, mdoc, SD-JWT, attestations | Served by dedicated libraries or outside the target use cases |
| REST or SOAP services | The library is consumed in process |

## Unsupported input

Encountering any deferred or excluded feature during verification produces an INDETERMINATE result with an explicit "not supported" reason, never a pass. The conformance suite contains at least one test per excluded feature to enforce this (goal G5 in the [charter](charter.md)).
