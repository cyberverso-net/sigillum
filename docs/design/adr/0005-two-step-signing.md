# ADR-0005: Two-step signing with an external signer

- **Status:** Accepted; retrieval by `assemble` and binding of the inputs by the state superseded by [ADR-0026](0026-public-api-conventions.md)
- **Date:** 2026-10-22

## Context

Private keys for advanced and qualified signatures live in places the library cannot and should not control: platform keystores, smart cards, and remote qualified signature creation devices reached through the Cloud Signature Consortium API. Remote signing is asynchronous and may involve user authentication on another device. A mobile user interface must not block while it waits.

## Decision

Signature creation is split into two calls. `prepare` takes the document, the signer's certificate chain and the requested profile, and returns the data to be signed (or its digest) with an opaque, serialisable state. The caller obtains the signature value from the key holder. `assemble` takes the state and the signature value and produces the signed object, retrieving timestamps and revocation data when the profile requires them.

A convenience `Signer` interface wraps both calls for callers whose key holder is synchronous.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Library holds the private key | Simple API | Unacceptable for qualified signatures; keys must stay in their device |
| Synchronous signer callback only | Simple for local keys | Blocks during remote signing; awkward across language bindings |
| Two-step prepare and assemble | Fits remote, asynchronous and local signing alike; keys never enter the library | Callers manage the state between the two calls |

## Consequences

The prepared state must be serialisable and must bind all inputs, so that `assemble` cannot be called with a mismatched document or certificate. Binding layers expose both calls directly.

## Notes

- **2026-10-27.** [ADR-0026](0026-public-api-conventions.md), decision 2, changes how `assemble` obtains timestamps and revocation data. `assemble` no longer retrieves them. When it needs evidence from outside, it returns the requests to the caller, who performs them and passes the responses to `resume`. Decision 6 of ADR-0026 also replaces the binding described in the Consequences: the prepared state is never authoritative. `assemble` and `resume` receive the document, the signer chain and the options again, recompute everything that is signed, and accept the signature value only if it verifies over the recomputed data. The two steps, the external key holder and the `Signer` convenience stay as decided above. This note does not change the record above.
