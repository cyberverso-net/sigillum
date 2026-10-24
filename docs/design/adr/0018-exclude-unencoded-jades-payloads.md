# ADR-0018: Exclude unencoded JAdES payloads

- **Status:** Accepted
- **Date:** 2026-10-24
- **Issue:** #9

## Context

ETSI TS 119 182-1 V1.2.1 allows the `b64` header parameter of [RFC 7797](https://www.rfc-editor.org/rfc/rfc7797) to be set to false, so that the JWS payload is carried unencoded. RFC 7797, section 8, states the consequences. Encoding no longer keeps the delimiters of the serialisation out of the payload, so the application must ensure that the payload contains none (section 5). The application must also ensure that the payload is not modified in transit. If a signature sets `b64` to false but does not list it in `crit`, which section 6 requires, a verifier that does not process `b64` still validates it. That verifier reads a different payload: the base64url decoding of the bytes received (section 8). An attacker can craft such signatures. This is threat J6 of the [threat model](../threat-model.md).

[ADR-0008](0008-include-jades-baseline.md) left the `HttpHeaders` mechanism of `sigD` deferred. That mechanism requires `b64` set to false (TS 119 182-1 V1.2.1, clauses 5.1.10 and 5.2.8.2). It is designed for signing HTTP messages. The target users named in [scope.md](../../project/scope.md) (wallets, desktop and browser applications) do not sign HTTP messages.

## Decision

sigillum excludes unencoded JAdES payloads, in creation and in verification:

1. No JAdES signature is created with `b64` set to false.
2. The `HttpHeaders` mechanism of `sigD` is excluded, because it requires unencoded payloads. This changes the deferral recorded in ADR-0008.
3. On verification, a signature with `b64` set to false, or with the `HttpHeaders` mechanism, yields INDETERMINATE with a "not supported" reason ([ADR-0007](0007-asymmetric-scope.md)).

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Keep both deferred | No decision needed now | Leaves open a feature whose main risk is known; demand alone would bring it in |
| Support `b64` set to false for detached payloads only | Covers the `HttpHeaders` mechanism | The payload ambiguity of J6 remains for verifiers; HTTP message signing has no current user |
| Exclude both | No payload ambiguity; smaller verification surface | Signatures over HTTP messages, used in some open banking APIs, cannot be created or verified |

## Consequences

[scope.md](../../project/scope.md) lists both items under *Excluded*. A proposal to include them must explain why the reasons above no longer hold. The conformance suite contains a "not supported" test for each, as required by goal G5 of the [charter](../../project/charter.md). ADR-0008 carries a cross-reference to this ADR.
