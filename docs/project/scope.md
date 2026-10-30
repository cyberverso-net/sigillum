# Scope

This document fixes what sigillum implements, what it defers and what it excludes. It is the reference for deciding whether a proposed feature belongs in the project. Changes to it follow the process in [GOVERNANCE.md](../../GOVERNANCE.md).

The scope is asymmetric by design. **Creation** is restricted to current baseline profiles and modern algorithms, because nobody needs to produce legacy signature forms today. **Verification** must handle what users actually receive; for the target users (wallets, desktop and browser applications) that means recent signatures. Support for older material is a separate *archival profile*, deferred until there is demand.

## In scope (phases 1 and 2)

### Signature formats and levels

| Format | Levels created | Packaging | Standard |
| --- | --- | --- | --- |
| CAdES | B-B, B-T, B-LT; CAdES-BES | Enveloping (`.p7m`) and detached | ETSI EN 319 122-1 V1.3.1 and EN 319 122-2 V1.1.1 |
| PAdES | B-B, B-T, B-LT; PAdES-BES | Incremental update, invisible or with a visible appearance | ETSI EN 319 142-1 V1.2.1 and EN 319 142-2 V1.2.1 |
| JAdES | B-B, B-T, B-LT | JWS JSON serialisation, flattened and general; compact serialisation for B-B only; enveloping, or detached through the `ObjectIdByURIHash` mechanism, or the `ObjectIdByURI` mechanism with a single object ([ADR-0018](../design/adr/0018-restrict-jades-payloads-and-detached-mechanisms.md)) | ETSI TS 119 182-1 V1.2.1 |
| CMS EnvelopedData and AuthEnvelopedData | Not applicable | Authenticated encryption by default: `AuthEnvelopedData` with AES-GCM. `EnvelopedData` with AES-CBC for receiving systems that require it, documented as giving no integrity. Key transport (RSA-OAEP, RSA PKCS#1 v1.5 for compatibility) and key agreement (ECDH) | RFC 5652, RFC 5083, RFC 5084, RFC 5753; RFC 8551, sections 2.3 and 2.7, for ECDH ephemeral-static with `AuthEnvelopedData` |

CAdES-BES and PAdES-BES are retained because they remain required by existing national systems, including the Italian Processo Civile Telematico, and are structurally close to baseline B-B. They correspond to the CAdES-E-BES and PAdES-E-BES signature types of ETSI EN 319 122-2 and EN 319 142-2. At PAdES B-T and B-LT, sigillum creates the trusted time as a signature timestamp. On verification, a document timestamp (`/DocTimeStamp`, `ETSI.RFC3161`) also counts as time evidence at B-T and B-LT. ETSI EN 319 142-1 V1.2.1, clause 6.3, item n, allows both.

The target versions of the standards are those listed in Annex I of [Commission Implementing Regulation (EU) 2026/248](http://data.europa.eu/eli/reg_impl/2026/248/oj) of 2 February 2026: ETSI EN 319 122-1 V1.3.1, ETSI EN 319 142-1 V1.2.1 and ETSI TS 119 182-1 V1.2.1. Annex I names no part 2, so the part 2 targets are the latest published versions, ETSI EN 319 122-2 V1.1.1 (2016-04) and ETSI EN 319 142-2 V1.2.1 (2025-07). JAdES signatures always carry the `x5c` header parameter, as required by the adaptation of clause 5.1.8 in that Annex. Verification does not reject a signature without `x5c`. It proceeds when the signing certificate is available, from `x5c` or from the caller. The indication follows ETSI EN 319 102-1 V1.4.1 and may be TOTAL-PASSED. The missing `x5c` is reported as a separate, machine-readable conformance finding ([ADR-0017](../design/adr/0017-defensive-api-rules.md)). Without the signing certificate, the result is INDETERMINATE, as ETSI EN 319 102-1 V1.4.1, clause 5.2.3, prescribes. Unsigned properties in the `etsiU` header are created in base64url-encoded form only. Unencoded payloads (`b64` set to false, RFC 7797) are excluded ([ADR-0018](../design/adr/0018-restrict-jades-payloads-and-detached-mechanisms.md)). JAdES is delivered after CAdES and PAdES, as recorded in [ADR-0008](../design/adr/0008-include-jades-baseline.md).

### Cryptographic algorithms (creation)

The algorithms follow [ETSI TS 119 312 V2.1.1](https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/02.01.01_60/ts_119312v020101p.pdf), Cryptographic Suites.

- Digests: SHA-256, SHA-384, SHA-512; SHA3-256, SHA3-384, SHA3-512.
- Signatures: RSASSA-PSS and RSA PKCS#1 v1.5; ECDSA on P-256, P-384 and P-521; Ed25519. TS 119 312 V2.1.1 recommends RSA keys of 3000 bits and above (Table 6).
- RSA PKCS#1 v1.5 is a legacy mechanism in TS 119 312 V2.1.1 (clause 3.4, Table 2), while RSASSA-PSS is recommended. PKCS#1 v1.5 is kept for interoperability, which clause 4 allows for legacy mechanisms.
- RSA keys of 2048 to 2999 bits are accepted for creation as legacy. TS 119 312 V2.1.1 (Table 6 and clause 8.4) stops the issuing of certificates with such keys after 2026-12-31 and ends their validity no later than 2028-12-31. Creation refuses such a key with "not supported" when the signing time is after 2028-12-31, whatever the validity period of the certificate, because a certificate may state a validity period that ends later.
- Expiry dates of algorithms and key sizes come from TS 119 312 V2.1.1. Where its normative tables and its informative Annex D differ, the normative tables prevail. The dates themselves are set in phase 2, with the cryptographic policy of verification (threat K6 of the [threat model](../design/threat-model.md)).

### Supporting functions

- X.509 certificate parsing and path building to a caller-supplied trust anchor.
- OCSP and CRL processing for embedding revocation data at B-LT.
- RFC 3161 timestamp requests and responses.
- A signer interface for external private-key operations, with adapters for the Cloud Signature Consortium API and for PKCS#12 (tests only).
- A fetcher interface for HTTP(S) retrieval, supplied by the caller.

### Verification (phase 2)

Basic verification of CAdES, PAdES and JAdES signatures: cryptographic integrity, certificate chain to a caller-supplied trust anchor, revocation status from embedded or supplied data, timestamp integrity, object-level detection of PDF modifications after signing, and, for JAdES, both base64url-encoded and clear JSON incorporation of unsigned properties. Results use the indications and sub-indications of ETSI EN 319 102-1 and are reported in the ETSI TS 119 102-2 format, with a compact summary for applications. This is not a full EN 319 102-1 validation and is labelled as such.

### Bindings

Kotlin and Swift through UniFFI; JavaScript and TypeScript through `wasm-bindgen`. A C ABI may follow if a consumer needs it.

## Deferred

These are expected to be added later, in the order of the [roadmap](roadmap.md) and subject to demand.

| Item | Condition for inclusion |
| --- | --- |
| Full EN 319 102-1 validation engine with qualification (TS 119 172-4, TS 119 615) and EU trusted lists | Phase 3 |
| Baseline -LTA for CAdES, PAdES and JAdES | Phase 3 or a partner need |
| XAdES baseline (namespaces 1.3.2 and 1.4.1 only) | Review after the phase 3 XML component for trusted lists, or a partner need; reasons in [ADR-0009](../design/adr/0009-keep-xades-deferred.md) |
| ASiC-E with XAdES, then ASiC-S and ASiC-E with CAdES | Partner need |
| Archival profile: validation of CAdES and XAdES -C, -X, -XL, -A, PAdES-LTV, pre-eIDAS qualification rules | Demand from an archival or validation-service user |
| Counter-signatures | Demand |
| Configurable validation policy | Demand from a validation-service user |
| C ABI | Demand |
| DSA on verification | Demand. Until then a DSA signature is reported as not supported ([ADR-0007](../design/adr/0007-asymmetric-scope.md)) |
| On verification: Ed448, ML-DSA, SLH-DSA, LMS, XMSS, the Brainpool and FRP256v1 curves, SHA-224 | Demand, or the publication of the post-quantum migration document that TS 119 312 V2.1.1, clause 8.5, announces. Until then they are reported as not supported |

## Excluded

These are not planned. Proposals to include them need to explain why the reasons below no longer hold.

| Item | Reason |
| --- | --- |
| Creation of legacy forms (-C, -X, -XL, -A, PAdES-LTV) | Obsolete for new signatures |
| XAdES namespaces 1.1.1 and 1.2.2 | Predate the current XAdES standard |
| Creation with DSA | No target user, and rare in European signing certificates. Verification is deferred (see above) |
| Creation with MD2, MD5, SHA-1, RIPEMD-160, Whirlpool | Insecure or obsolete; on verification these are recognised and rejected under the cryptographic policy, without being implemented. SHA-1 is the one exception, implemented for one purpose only: a lookup identifier where a standard specifies or permits SHA-1 for that identifier. It is never accepted for integrity or signatures. The only cases are the hash algorithm of an OCSP `CertID` ([RFC 6960](https://www.rfc-editor.org/rfc/rfc6960), section 4.1.1) and the `byKey` responder identifier (RFC 6960, sections 4.2.1 and 4.2.2.3). Key identifiers computed with method 1 of [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280), section 4.2.1.2, are the third case. Threat K10 of the [threat model](../design/threat-model.md) gives the reason |
| Explicit signature policies (EPES policy documents and policy stores) | Rarely used; verification checks presence and digest only |
| OpenDocument signatures | Niche format |
| PDF/A conformance checking | Outside the signature domain |
| Modification detection that requires page rendering | Requires a rendering engine, unsuitable for mobile |
| LDAP and FTP retrieval | Rare in current European CA practice |
| Smart-card and keystore drivers (PKCS#11, CAPI, keychain) inside the core | Belong to the platform layer, behind the signer interface |
| Multiple report renderings (HTML, PDF, XSLT) | Applications render their own; one standard report suffices |
| Evidence records, CB-AdES, mdoc, SD-JWT, attestations | Served by dedicated libraries or outside the target use cases |
| JAdES unencoded payloads (`b64` set to false, RFC 7797) | Payload ambiguity (threat J6 of the threat model); no current user ([ADR-0018](../design/adr/0018-restrict-jades-payloads-and-detached-mechanisms.md)) |
| JAdES detached signatures through the `HttpHeaders` mechanism | Requires unencoded payloads (TS 119 182-1 V1.2.1, clauses 5.1.10 and 5.2.8.2), excluded for threat J6; designed for signing HTTP messages, outside the target uses ([ADR-0018](../design/adr/0018-restrict-jades-payloads-and-detached-mechanisms.md)) |
| Encrypted PDF documents | Decrypting and re-encrypting the document is outside the signature domain. Signing is refused with a typed error; verification reports INDETERMINATE with "not supported" (threat D7) |
| REST or SOAP services | The library is consumed in process |

## Unsupported input

Encountering any deferred or excluded feature during verification produces an INDETERMINATE result with an explicit "not supported" reason, never a pass. The conformance suite contains at least one test per excluded feature to enforce this (goal G5 in the [charter](charter.md)).
