# ADR-0017: Apply defensive rules to the signing and verification API

- **Status:** Accepted; fetcher interface of rules 3 and 8 and the state check of rule 2 superseded by [ADR-0026](0026-public-api-conventions.md)
- **Date:** 2026-10-23
- **Issue:** #9

## Context

The [threat model](../threat-model.md) identifies threats that the public API itself must address:

- **G1.** The state serialised between `prepare` and `assemble` ([ADR-0005](0005-two-step-signing.md)) is held by the application and may be altered, so that the signer signs data for another document.
- **G2.** A signer, local or remote, may return a signature value made with another key, or a malformed value. Without a check, sigillum would assemble and return a signature that no verifier accepts, or one that binds the wrong key.
- **F2.** URLs inside certificates (authority information access, CRL distribution points, OCSP locations) are chosen by whoever issued or crafted the certificate. Passed unfiltered to the caller's fetcher ([ADR-0006](0006-no-network-access-in-core.md)), they could reach unexpected schemes or internal addresses, or cause unbounded chains of requests.
- **R1.** Applications may treat an INDETERMINATE or partial result as valid if the API makes that easy, for example through a single boolean.
- **D12.** A document may carry a certification signature whose DocMDP permissions forbid further changes, including a new signature.
- **G5, G6.** At B-T and B-LT, `assemble` embeds timestamp tokens and revocation data from the caller's fetcher, which an attacker may control. Embedded unchecked, they become false evidence.
- **G7.** The signing certificate may already be revoked, or its status unknown, when a B-LT signature is produced.
- **F1.** A fetcher may return a response of any size, which the library would then have to hold and parse.

For JAdES, threat J4 requires that a signature without the `x5c` header parameter be reported as not meeting Annex I of [Commission Implementing Regulation (EU) 2026/248](http://data.europa.eu/eli/reg_impl/2026/248/oj) of 2 February 2026. Its indication does not change.

## Decision

1. **Verify after signing.** `assemble` verifies the signature value received from the signer against the data to be signed and the public key of the signing certificate. If verification fails, `assemble` returns a typed error and produces no output.
2. **Re-supply the document.** `assemble` takes the document again, computes its digest and compares it with the digest bound in the prepared state. A mismatch is a typed error. The prepared state also binds the signing certificate and every signed attribute; `assemble` rejects a state whose content is inconsistent.
3. **Restrict fetcher requests.** The core passes to the fetcher only URLs with the `http` or `https` scheme; other URLs are skipped and reported. The number of fetcher requests per operation is bounded, with a documented default and a caller-configurable maximum. Each request states the URL and the certificate extension it came from, so that the caller can apply its own policy, such as blocking private addresses.
4. **Make the valid outcome explicit.** The verification API exposes a single valid outcome, corresponding to the TOTAL-PASSED indication of ETSI EN 319 102-1 V1.4.1. Every other indication, with its sub-indication, is a distinct variant that the caller must handle; there is no boolean "is valid" that maps INDETERMINATE or partial results to true. Unsupported features yield INDETERMINATE with a "not supported" reason ([ADR-0007](0007-asymmetric-scope.md)). Alongside the indication, results carry a list of conformance findings, each machine-readable. A finding records a requirement outside ETSI EN 319 102-1 that the signature does not meet, such as the `x5c` requirement of Annex I of Implementing Regulation (EU) 2026/248. Findings never change the indication.
5. **Respect certification permissions.** `prepare` refuses, with a typed error, to add a signature that the document's DocMDP permissions forbid.
6. **Check fetched evidence before embedding it.** `assemble` validates fetched timestamp tokens before embedding them. It checks the message imprint, the nonce when one was sent, the timestamping purpose and the chain to a caller-supplied anchor. It validates revocation data exactly as verification does. Any failure is a typed error.
7. **Refuse B-LT on a revoked certificate.** `assemble` refuses to produce B-LT when the signing certificate is revoked. An unknown status is an error, unless the caller explicitly accepts a lower level.
8. **Bound fetched responses.** The fetcher interface carries a maximum response size, so that the caller's fetcher can stop reading early. The library rejects larger responses.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Trust the signer's output | One fewer verification | Wrong or foreign signatures reach the caller undetected |
| Trust the prepared state alone | Simpler `assemble` call | Altered state leads to a signature over another document |
| Authenticate the prepared state with a key held by the library | Detects tampering without the document | The library would have to hold a secret key, while it holds no key material today ([ADR-0005](0005-two-step-signing.md) keeps private keys outside); key management moves to the caller |
| Pass every URL to the fetcher | Simplest | The library would hand attacker-chosen requests to the caller without any filter |
| Boolean validity plus details | Convenient | Encourages treating INDETERMINATE as valid |
| Report non-conformance to Annex I as a different indication | One field to read | Mixes the recognition rules of a regulation with signature validity under EN 319 102-1 |
| Embed fetched evidence unchecked | Simpler `assemble` | Forged or stale evidence becomes part of the signature |
| No limit on fetched response size | Simpler fetcher interface | A fetcher can make the library hold any amount of data |
| Defensive rules above | Each threat addressed in the API itself | One extra verification per signature; the caller passes the document twice and handles every indication; signing at B-T and B-LT validates what it embeds |

## Consequences

This refines [ADR-0005](0005-two-step-signing.md): `assemble` takes the document as well as the state and the signature value. Phase 1 stories for `prepare` and `assemble` include tests for a wrong signature value, a value from another key, a malformed value, an altered document and an altered state. The fetcher interface carries the URL origin and a maximum response size, and the request bound is configurable. Phase 1 stories for PAdES, for B-T and B-LT and for the fetcher include tests for rules 5 to 8. Phase 2 stories define the result types so that only TOTAL-PASSED is a valid outcome, with a list of conformance findings beside the indication. The cost of the extra verification is included in the measurements of goal G4.

## Notes

- **2026-10-27.** [ADR-0026](0026-public-api-conventions.md), decision 2, replaces the fetcher interface by evidence requests that the format crates return to the caller, with the `Fetcher` as a convenience over that loop. The restrictions of rule 3 and the bound of rule 8 now apply to these requests and responses: each request carries an `http` or `https` URL only, and states the certificate extension it came from, when it came from one, and the maximum response size, and the number of rounds and requests is bounded by the context for each call, and across calls only while the caller passes the state on unchanged; the caller, or the driver `sign_with`, keeps the budget across calls (decision 6 of ADR-0026). Decision 6 of ADR-0026 replaces the comparison of rule 2 with the prepared state: the states are never authoritative. `assemble` and `resume` receive the document, the signer chain and the options again, recompute everything that is signed, and accept the signature value only if it verifies over the recomputed data with the key of the re-supplied signing certificate (rule 1). Rule 2 is thereby met without trusting the state. Evidence kept in a state is validated again as rule 6 requires. Rule 6 is extended by one check that does not depend on the state: a signature timestamp is accepted only if its `genTime`, widened by its stated accuracy, does not precede the signing time supplied by the caller (decision 2 of ADR-0026). Rules 1, 2, 6 and 7 apply to `resume` as to `assemble`. This note does not change the record above.
