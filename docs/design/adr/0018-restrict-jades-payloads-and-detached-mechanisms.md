# ADR-0018: Exclude unencoded JAdES payloads and restrict detached mechanisms

- **Status:** Accepted
- **Date:** 2026-10-24
- **Issue:** #9

## Context

ETSI TS 119 182-1 V1.2.1 allows the `b64` header parameter of [RFC 7797](https://www.rfc-editor.org/rfc/rfc7797) to be set to false, so that the JWS payload is carried unencoded. RFC 7797, section 8, states the consequences. Encoding no longer keeps the delimiters of the serialisation out of the payload, so the application must ensure that the payload contains none (section 5). The application must also ensure that the payload is not modified in transit. If a signature sets `b64` to false but does not list it in `crit`, which section 6 requires, a verifier that does not process `b64` still validates it. That verifier reads a different payload: the base64url decoding of the bytes received (section 8). An attacker can craft such signatures. This is threat J6 of the [threat model](../threat-model.md).

The `sigD` header parameter offers three mechanisms for detached signatures:

- `HttpHeaders` (clause 5.2.8.2). [ADR-0008](0008-include-jades-baseline.md) left it deferred. It requires `b64` set to false (clauses 5.1.10 and 5.2.8.2). It is designed for signing HTTP messages. The target users named in [scope.md](../../project/scope.md) (wallets, desktop and browser applications) do not sign HTTP messages.
- `ObjectIdByURI` (clause 5.2.8.3.2). It carries no digest for each object. The payload's contribution to the signing input is the base64url encodings of the objects, concatenated without separators. With more than one object, the boundary between objects is not signed. The objects `abc` and `defghi` encode to `YWJj` and `ZGVmZ2hp`, and the objects `abcdef` and `ghi` encode to `YWJjZGVm` and `Z2hp`. Both pairs give the same signing input, so an attacker can change both objects without invalidating the signature. This is threat J5.
- `ObjectIdByURIHash` (clause 5.2.8.3.3). It signs a digest of each object in `sigD`, so each object is bound on its own.

## Decision

sigillum excludes unencoded JAdES payloads and restricts the detached mechanisms, in creation and in verification:

1. No JAdES signature is created with `b64` set to false.
2. The `HttpHeaders` mechanism of `sigD` is excluded, because it requires unencoded payloads. This changes the deferral recorded in ADR-0008.
3. The `ObjectIdByURI` mechanism is supported with a single object only. Detached signatures over more than one object use `ObjectIdByURIHash`. Creation refuses `ObjectIdByURI` with more than one object. This narrows the `ObjectIdByURI` support decided in ADR-0008.
4. On verification, a signature with `b64` set to false, with the `HttpHeaders` mechanism, or with `ObjectIdByURI` over more than one object yields INDETERMINATE with a "not supported" reason ([ADR-0007](0007-asymmetric-scope.md)).

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Keep `b64` and `HttpHeaders` deferred | No decision needed now | Leaves open a feature whose main risk is known; demand alone would bring it in |
| Support `b64` set to false for detached payloads only | Covers the `HttpHeaders` mechanism | The payload ambiguity of J6 remains for verifiers; HTTP message signing has no current user |
| Exclude `b64` set to false and `HttpHeaders` | No payload ambiguity; smaller verification surface | Signatures over HTTP messages, used in some open banking APIs, cannot be created or verified |
| Accept `ObjectIdByURI` with any number of objects | Accepts every conforming signature, as DSS does | The boundary between objects is not signed, so objects can be substituted |
| Restrict `ObjectIdByURI` to one object | Every supported mechanism binds each object; `ObjectIdByURIHash` covers several objects | Conforming signatures over several objects with `ObjectIdByURI` are reported as not supported |

## Consequences

[scope.md](../../project/scope.md) lists the excluded items under *Excluded* and the restriction in the JAdES row. A proposal to include them must explain why the reasons above no longer hold. The conformance suite contains a "not supported" test for each, as required by goal G5 of the [charter](../../project/charter.md). Verification of `ObjectIdByURI` over several objects differs from DSS, which accepts such signatures; the difference is recorded in [divergences.md](../divergences.md). ADR-0008 carries a cross-reference to this ADR.
