# ADR-0004: Use DSS as a test oracle

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

DSS is the reference implementation of the AdES standards and the natural benchmark for correctness. It is licensed under LGPL-2.1, which is not compatible with distributing sigillum under Apache-2.0 OR MIT ([ADR-0003](0003-licence-and-contribution-terms.md)) if DSS code were incorporated. Its observable behaviour is the best available evidence of interoperability.

## Decision

sigillum is implemented from the published specifications and contains no code taken from DSS. DSS is used as a test oracle: sigillum's test harness submits signed objects to a pinned DSS release running as a separate process and compares its reports with the expected results. DSS is never linked into sigillum. DSS test resources are not copied into this repository, because they are distributed under LGPL-2.1.

Where the specification and DSS disagree, the specification prevails; the divergence is recorded in [divergences.md](../divergences.md) and reported to the DSS maintainers.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Port DSS code | Faster to reach parity | Derivative work under LGPL-2.1; inherits DSS defects |
| No comparison with DSS | No dependency on a JVM in testing | No practical evidence of interoperability |
| DSS as an external test oracle | Strong interoperability evidence; licences remain separate | Requires a test harness and a JVM in CI |

## Consequences

The test harness (`sigillum-oracle`) and a Java runtime are required in continuous integration. Contributors confirm, through their DCO sign-off, that their contributions contain no code under incompatible licences, as described in [CONTRIBUTING.md](../../../CONTRIBUTING.md).
