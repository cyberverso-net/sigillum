# ADR-0007: Asymmetric scope and explicit unsupported results

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

DSS supports 37 signature levels, legacy XAdES namespaces, obsolete algorithms, explicit signature policies and many other features accumulated over fifteen years. Much of this serves archival validation of old signatures and server deployments, not the target users of sigillum. Implementing it all would delay useful releases by years. A verifier with a reduced scope must not mislead its users about what it has checked.

## Decision

Creation is limited to current baseline profiles, CAdES-BES and PAdES-BES, and modern algorithms. Verification covers what the target users receive; support for older material is a separate archival profile, deferred until there is demand. The detailed lists are in [scope.md](../../project/scope.md).

Whenever verification encounters a feature outside the supported scope, the result is INDETERMINATE with an explicit "not supported" reason. It is never a pass.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Feature parity with DSS | Complete | Years before a first useful release |
| Narrow scope, silent on unsupported input | Simple | Misleading; a security risk |
| Narrow scope with explicit unsupported results | Early value; honest results | Users with legacy material must use another tool for now |

## Consequences

The conformance suite contains at least one test per deferred or excluded feature that checks for the "not supported" result. Extending the scope requires an update to `scope.md` and, for significant additions, a new ADR.
