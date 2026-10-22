# ADR-0003: Licence under Apache-2.0 OR MIT with a Developer Certificate of Origin

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

The intended users include mobile wallet providers, application developers and public administrations. Licence terms that restrict static linking or require source disclosure deter adoption in mobile applications, where libraries are linked statically. The project should be easy to contribute to.

## Decision

The code is licensed under Apache-2.0 OR MIT, at the user's option, following the Rust ecosystem convention. Contributions are accepted under the same terms, certified by a Developer Certificate of Origin sign-off on each commit. There is no contributor licence agreement.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| LGPL-2.1 (as DSS) | Same licence as the reference implementation | Relinking obligations are awkward for statically linked mobile applications |
| EUPL-1.2 | Aligned with EU public-sector policy | Weak copyleft; less common in the Rust ecosystem |
| AGPL with commercial dual licence | Revenue option | Blocks adoption by wallets and public administrations; requires a CLA |
| Apache-2.0 OR MIT | Maximum adoption; patent grant through Apache-2.0; ecosystem convention | No copyleft protection |

## Consequences

Dependencies must carry compatible licences; this is enforced with `cargo deny`. Without a CLA, a future licence change would require the consent of every copyright holder; this is accepted. Provenance is protected separately by the provenance rule ([ADR-0004](0004-dss-as-test-oracle.md)).
