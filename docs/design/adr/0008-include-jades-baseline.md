# ADR-0008: Include JAdES baseline in scope

- **Status:** Accepted
- **Date:** 2026-10-23

## Context

[ADR-0007](0007-asymmetric-scope.md) and [scope.md](../../project/scope.md) deferred JAdES (ETSI TS 119 182-1) until a partner needed it. Three facts have since weighed in favour of including it.

1. [Commission Implementing Regulation (EU) 2026/248](http://data.europa.eu/eli/reg_impl/2026/248/oj) of 2 February 2026, on the formats of advanced electronic signatures and seals to be recognised by public sector bodies, lists the JAdES Baseline Profile (ETSI TS 119 182-1 V1.2.1) in its Annex I alongside the XAdES, CAdES and PAdES baseline profiles. Annex I replaces clause 5.1.8 of TS 119 182-1 so that the `x5c` header parameter must be present in every JAdES signature, as a signed or unsigned header parameter. Article 1(1) and Article 3(1), which make Annex I binding, apply from 23 February 2027. Verifiers in the public sector, and the applications that produce signatures for them, will need JAdES support.
2. JAdES is built on JSON Web Signature (RFC 7515), the format already used by mobile wallets, OpenID for Verifiable Presentations, SD-JWT and the Cloud Signature Consortium API. It is the most natural AdES format for the mobile and browser environments that sigillum targets.
3. Most of the work is already in scope. Certificates, timestamps, OCSP and CRL handling come from `sigillum-pki`. JWS signs the exact base64url-encoded bytes, so no XML canonicalisation is needed, and there is no PDF structure to update. The remaining work is the JWS serialisations, the ETSI header parameters and the unsigned properties.

JAdES is not needed by the project's first user, which requires CAdES and PAdES only.

## Decision

JAdES baseline is moved from *deferred* to *in scope*:

- **Creation (phase 1):** levels B-B, B-T and B-LT; JWS JSON serialisation, flattened and general, and compact serialisation for B-B only; enveloping and detached signatures, the latter through the `ObjectIdByURI` and `ObjectIdByURIHash` mechanisms of the `sigD` header parameter; the `x5c` header parameter always present; unsigned properties in the `etsiU` header created in base64url-encoded form only. The work is a separate epic delivered after CAdES and PAdES, and may follow in release 0.2 without delaying release 0.1.
- **Verification (phase 2):** basic verification as for CAdES and PAdES, accepting both base64url-encoded and clear JSON incorporation of unsigned properties.
- **Archival level (phase 3):** baseline B-LTA, together with CAdES and PAdES.

The `HttpHeaders` mechanism of `sigD`, designed for signing HTTP messages in open banking APIs, remains deferred.

The deferral of the `HttpHeaders` mechanism is changed by [ADR-0018](0018-exclude-unencoded-jades-payloads.md).

A new crate, `sigillum-jades`, holds the implementation. Whether to build on the existing `jades` crate (BSD-2-Clause, version 0.1.0, published June 2026) or to implement on top of `sigillum-pki` is decided by a separate ADR in phase 0.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Keep JAdES deferred until a partner asks | Smallest phase 1 | Misses a format that public sector bodies must recognise from 2027 and that fits the target platforms best |
| Include JAdES alongside CAdES and PAdES in release 0.1 | Complete format set at first release | Delays the first user's release for a format it does not need |
| Include JAdES as a separate phase 1 epic after CAdES and PAdES | Early availability; first user unaffected; low marginal cost | Phase 1 grows by an estimated one or two months |

## Consequences

`scope.md`, `roadmap.md` and `architecture.md` are updated, and `sigillum-jades` is added to the workspace. The test PKI and the differential harness of phase 0 must cover JAdES. The verification "not supported" tests of [ADR-0007](0007-asymmetric-scope.md) extend to JAdES features left out, such as the `HttpHeaders` mechanism.
