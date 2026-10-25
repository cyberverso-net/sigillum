# ADR-0009: Keep XAdES deferred

- **Status:** Accepted
- **Date:** 2026-10-23

## Context

[ADR-0008](0008-include-jades-baseline.md) brought JAdES into scope, partly because [Commission Implementing Regulation (EU) 2026/248](http://data.europa.eu/eli/reg_impl/2026/248/oj) of 2 February 2026 lists it among the formats that public sector bodies must recognise from 23 February 2027. The same Annex I lists the XAdES Baseline Profile (ETSI EN 319 132-1 V1.3.1), which is more widely used than JAdES: it is accepted by the Italian e-invoicing system (FatturaPA) and is common in several Member States, including through ASiC-E containers. The question is whether XAdES should be brought into scope on the same grounds.

## Decision

XAdES remains deferred, for four reasons.

1. **Cost.** XAdES requires a hardened XML parser, the canonicalisation algorithms (Canonical XML 1.0 and 1.1, Exclusive XML Canonicalization), XMLDSig transforms, and resolution of references and ID attributes. No production-ready implementation of these exists in Rust; building one would be the largest component of the project after the validation engine.
2. **Security risk.** XML signature verification is exposed to signature wrapping attacks, in which the verifier checks one element while the application uses another. This is the best-documented class of vulnerability in XML signatures, and its attack surface is at odds with the project's central requirement never to accept an invalid signature.
3. **Fit with the target platforms.** sigillum serves mobile, desktop and browser applications, where CAdES, PAdES and JAdES are the natural formats. XAdES is mainly used in server-side and structured document workflows, which DSS and existing Java stacks already serve well.
4. **No current user.** The project's first user requires CAdES and PAdES only. Adding XAdES would delay the first release without serving a known user.

The recognition obligation of Implementing Regulation (EU) 2026/248 falls mainly on server-side verifiers, which DSS already serves, and does not change this balance for a library aimed at devices.

XAdES remains in the *deferred* list of [scope.md](../../project/scope.md) rather than the *excluded* list. Phase 3 requires verification of the XMLDSig signatures on EU trusted lists, which will produce a hardened XML component; once it exists, the cost of XAdES falls substantially and this decision should be reviewed.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Include XAdES creation and verification in phase 1 | Complete Annex I format coverage early | Largest single cost in the project; high security risk; no current user; delays the first release |
| Include XAdES verification only, in phase 2 | Serves recipients of XAdES documents | Carries the full XML cost and the wrapping risk before the XML component is justified by trusted lists |
| Keep XAdES deferred and review after the phase 3 XML component | Cost and risk incurred once, for a need that is certain | Users who receive XAdES documents must use another tool until then |

## Consequences

Verification of an XAdES signature yields INDETERMINATE with a "not supported" reason, as required by [ADR-0007](0007-asymmetric-scope.md). The XML component built in phase 3 for trusted lists is designed so that it can later support XAdES. This ADR is reviewed when that component is complete, or earlier if a partner commits to the work.
