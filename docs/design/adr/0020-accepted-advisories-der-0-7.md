# ADR-0020: Accepted advisories on the der 0.7 generation

- **Status:** Accepted; rule 4 superseded by [ADR-0025](0025-build-phase-1-on-der-0-8.md)
- **Date:** 2026-10-24
- **Issue:** #27

## Context

[ADR-0011](0011-asn1-x509-cms-foundations.md) builds on the `der` 0.7 generation of the RustCrypto crates until the migration to the `der` 0.8 generation (#21). `cargo deny` fails the build on any security advisory that is not explicitly accepted. Two advisories cover crates of this generation that the workspace uses.

- **RUSTSEC-2023-0071** (`rsa`). The advisory states: "Due to a non-constant-time implementation, information about the private key is leaked through timing information which is observable over the network." It lists no patched version, and says that rsa 0.9.10 and rsa 0.10.0-rc.18 were still affected as of 2026-09-12. [ADR-0010](0010-cryptographic-backend.md) already accepts it and restricts library crates to public-key operations, enforced by `clippy.toml`.
- **RUSTSEC-2026-0387** (`crypto-bigint`, published 2026-10-23). The advisory states: "Several operations intended to be constant-time could execute secret-dependent branches, depending on the compiler and target CPU. These include subtraction, zero counting, division, and Montgomery multiplication." Its impact is on "applications using affected operations on secret integers". Its version data (patched in 0.7.6 and later, with no unaffected range) covers crypto-bigint 0.5.5, which the workspace uses through `elliptic-curve` 0.13, a dependency of `p256`, `p384` and `p521` 0.13. The advisory does not say whether crypto-bigint 0.5 contains the faulty code, nor which operations of the curve crates are affected.

`sigillum-testpki` uses these crates to sign with test keys, which have no value and are published in the repository.

## Decision

1. Both advisories are accepted in `deny.toml`, each entry pointing to this ADR. This ADR records the acceptance of RUSTSEC-2023-0071 by reference to ADR-0010, which is not rewritten.
2. The justification is the same for both. In library crates, elliptic-curve and RSA code operates only on public data: verification of signatures, and for RSA, encryption to recipients. The test PKI signs with test keys only.
3. Until #21 is done, no library code performs elliptic-curve operations on secret values. A story that needs one, such as key agreement for EnvelopedData recipients with elliptic-curve keys, depends on #21.
4. The acceptance of RUSTSEC-2026-0387 expires when #21 is merged. The migration checks in `Cargo.lock` that crypto-bigint resolves to 0.7.6 or later, and removes the entry from `deny.toml`.
5. The acceptance of RUSTSEC-2023-0071 expires when a release of `rsa` fixes the advisory. Each update of `rsa` checks the advisory's patched versions.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Migrate to the `der` 0.8 generation now (#21) | Removes RUSTSEC-2026-0387 | Large change, and the reason ADR-0011 chose the `der` 0.7 generation still holds; does not remove RUSTSEC-2023-0071 |
| Wait for a crypto-bigint 0.5 backport | No accepted advisory | No backport is announced; the test PKI and every story that uses the curve crates stay blocked |
| Accept the advisories with the rules above | Work continues; the exposure is limited to public data and test keys, and expires with #21 or an `rsa` fix | `deny.toml` ignores apply to the whole workspace, so the rule on secret values relies on review until #21 |

## Consequences

`deny.toml` lists both advisories with a reason that names this ADR. Reviews of library code check that no elliptic-curve operation on secret values is added before #21. Issue #21 records that the RUSTSEC-2026-0387 entry is removed by the migration, and that stories with elliptic-curve operations on secret values depend on it.

## Notes

- **2026-10-27.** [ADR-0025](0025-build-phase-1-on-der-0-8.md), rule 6, changes the scope of the acceptance of RUSTSEC-2026-0387. The acceptance ends for the library when the library crates move to the `der` 0.8 generation (#21). From then on, rule 3 no longer blocks elliptic-curve operations on secret values in library code. The `deny.toml` entry stays for `sigillum-testpki`, which uses test keys only, until `sigillum-testpki` moves to the 0.8 generation; until then, the acceptance is reviewed before each release in the release checklist in #55. Because `deny.toml` ignores apply to the whole workspace, a CI check fails if `crypto-bigint` 0.5 enters the dependency graph of a library crate. This replaces rule 4, which removed the entry when #21 merged. The check of rule 4 in `Cargo.lock` also changes: `crypto-bigint` must resolve to 0.7.9 or later instead of 0.7.6 or later, because releases 0.7.0 to 0.7.8 are yanked. The sentence of the Consequences that #21 records the removal of the RUSTSEC-2026-0387 entry no longer holds, because the entry stays for `sigillum-testpki`. The acceptance of RUSTSEC-2023-0071 is unchanged. This note does not change the record above.
