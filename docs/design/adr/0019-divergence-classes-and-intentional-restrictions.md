# ADR-0019: Divergence classes and intentional restrictions

- **Status:** Accepted
- **Date:** 2026-10-24
- **Issue:** #9

## Context

[conformance.md](../conformance.md) allowed sigillum to differ from DSS in two cases: when the ETSI text requires it, or when DSS behaviour appears incorrect. Each case was recorded in [divergences.md](../divergences.md) with a link to a report made to the DSS maintainers.

The [threat model](../threat-model.md) asks for stricter behaviour than DSS may show in several places:

- Some rules are permitted, not required, by the cited standard. A JWS parser may reject duplicate header names (J1, RFC 7515, section 4). A base64 decoder may reject non-zero pad bits (J7, RFC 4648, section 3.5). A verifier may check the cofactorless Ed25519 equation (RFC 8032, section 5.1.7).
- Some rules restrict what the standard allows. [ADR-0018](0018-restrict-jades-payloads-and-detached-mechanisms.md) restricts the `ObjectIdByURI` mechanism of JAdES to a single object, because with several objects the boundary between them is not signed. DSS accepts such signatures, and so does ETSI TS 119 182-1 V1.2.1, clause 5.2.8.3.2. Ed25519 public keys of small order are another case (K9).

Neither kind fits the two cases as written.

## Decision

A divergence from DSS belongs to one of three classes. Each entry in divergences.md names its class and cites the clause or ADR concerned.

1. **Required or explicitly permitted by the cited standard.** The entry cites the clause. An upstream report to the DSS maintainers is required when DSS accepts what the standard forbids. It is optional when the standard permits both behaviours.
2. **DSS behaviour appears incorrect.** An upstream report to the DSS maintainers is required.
3. **Intentional restriction for security.** sigillum deliberately restricts behaviour that the standard allows. This is acceptable provided that:
   1. the restriction is decided in an ADR;
   2. affected signatures yield INDETERMINATE with "not supported" ([ADR-0007](0007-asymmetric-scope.md)), never TOTAL-FAILED;
   3. a fixture exercises the restriction, and the oracle comparison records it as an expected divergence.

   An upstream report is optional. It goes to the DSS maintainers, or to ETSI ESI when the weakness lies in the standard.

This ADR also decides one restriction of the third class. An Ed25519 public key of small order is detected before verification, and the signature yields INDETERMINATE with "not supported", not a signature failure (threat K9). RFC 8032 does not forbid such keys, but a signature under one can verify for many or all messages.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Keep the two original cases | No change to the process | Behaviour that the standard permits but DSS does not adopt, and every intentional restriction, would be an unrecorded divergence, which conformance.md treats as a defect |
| Name ETSI ESI as the upstream for each restriction, within the original cases | No new class | Requires an outward report before each restriction can be recorded; misstates the case, since the standard is followed, not contradicted |
| Record restrictions only in their ADRs, not in divergences.md | No change to divergences.md | The oracle comparison would report each difference as a failure |
| Let intentional restrictions yield TOTAL-FAILED | Simpler result model | A signature that conforms to the standard would be reported as invalid, which overstates what sigillum knows |
| Accept Ed25519 public keys of small order, or report them as a signature failure | Follows RFC 8032 to the letter, or keeps the result model simple | Accepting them lets one signature cover many messages; a failure would report a conforming signature as invalid |
| Three classes, as above | Each divergence is recorded with its basis; the third class stays narrow | More to explain to contributors |

## Consequences

conformance.md lists the three classes and links this ADR. Each entry in divergences.md names its class: the clause for the first, the report for the second, the deciding ADR for the third. The differential harness needs a way to mark a fixture's DSS result as an expected divergence. Phase 1 stories for Ed25519 include a fixture with a small-order public key.
