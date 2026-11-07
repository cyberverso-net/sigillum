# ADR-0027: Develop JAdES alongside CAdES and PAdES

- **Status:** Accepted
- **Date:** 2026-11-14
- **Issue:** #133

## Context

[ADR-0008](0008-include-jades-baseline.md) includes JAdES baseline B-B, B-T and B-LT in the scope, and orders its delivery after CAdES and PAdES, allowing it to follow in release 0.2 without delaying release 0.1. The [roadmap](../../project/roadmap.md) repeats this order.

Two facts have changed the balance since then.

- [ADR-0026](0026-public-api-conventions.md) fixes one API shape for every format crate. If only CMS-based formats use that API before it is published, it may fit binary CMS structures and not JSON. JAdES B-B is a JWS with the ETSI header parameters, without timestamps or revocation data. It is small enough to serve as the second consumer of the API from the start.
- `sigillum-jades` depends on no sigillum crate other than `sigillum-pki`, in particular not on `sigillum-cms` or `sigillum-pdf` ([architecture.md](../architecture.md)). Phase 1 work can run in parallel where crates do not depend on each other, so JAdES B-T and B-LT need not wait for PAdES, which depends on the new `sigillum-pdf` crate.

Phase 1 should still not start with JAdES. A CAdES signature can be checked by two independent verifiers, OpenSSL and DSS, while a JAdES signature is checked by DSS only. The first end-to-end signature tests the foundations of `sigillum-pki`, and two verifiers separate defects of sigillum from defects of the oracle. CAdES is also the basis of PAdES, and release 0.1 requires CAdES, PAdES and CMS encryption.

## Decision

1. CAdES remains the first format implemented end to end, from B-B to B-LT.
2. JAdES B-B is implemented early in phase 1, together with CAdES B-B and right after the shared types of ADR-0026, as the second user of the shared API. Both must fit the conventions of ADR-0026 without format-specific exceptions.
3. JAdES B-T and B-LT follow CAdES B-LT, in parallel with `sigillum-pdf` and PAdES, rather than after PAdES.
4. Release 0.1 still requires CAdES, PAdES and CMS encryption. JAdES enters release 0.1 if it meets the conformance, fuzzing and platform criteria of phase 1 before release 0.1 is ready; otherwise it follows in 0.2. It never delays release 0.1.
5. This decision replaces the ordering in ADR-0008. The rest of ADR-0008, which sets the scope of JAdES, is unchanged.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| JAdES after CAdES and PAdES (ADR-0008 as written) | Focus on the formats release 0.1 requires | API designed around CMS only; JAdES waits for the PDF work it does not depend on |
| JAdES first | JSON format natural for mobile and browsers; no dependency on the `cms` release candidate | Only one verifier (DSS) for the first end-to-end signatures, since OpenSSL cannot check JAdES ([ADR-0014](0014-test-pki-and-corpus.md)); the first format would rest on a Technical Specification (ETSI TS 119 182-1), not a European Standard; release 0.1 moves further away |
| JAdES B-B with CAdES B-B, then JAdES in parallel with PAdES (chosen) | API tried on a binary and a JSON format; JAdES no longer waits for PDF; CAdES still tests the foundations with two verifiers | Two format crates active at the start of phase 1 |

## Consequences

- [scope.md](../../project/scope.md), the [roadmap](../../project/roadmap.md) and the JAdES row of [architecture.md](../architecture.md) are updated to state the new order. The change follows the comment period of [GOVERNANCE.md](../../../GOVERNANCE.md) for scope and roadmap changes.
- Phase 1 planning includes a JAdES B-B story alongside CAdES B-B. JAdES B-T and B-LT are later stories of the same JAdES epic, planned to run alongside the PDF and PAdES epic.
- [ADR-0008](0008-include-jades-baseline.md) and [ADR-0026](0026-public-api-conventions.md) carry dated notes on this decision.
- The JAdES restrictions of [ADR-0016](0016-jades-implementation-basis.md) and [ADR-0018](0018-restrict-jades-payloads-and-detached-mechanisms.md), the input size limit of [ADR-0024](0024-bounded-decoding-of-untrusted-input.md), rule 1, and the nesting limits of threat P2 of the [threat model](../threat-model.md) apply to JSON from the first JAdES story.
