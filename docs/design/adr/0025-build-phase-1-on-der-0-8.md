# ADR-0025: Build phase 1 on the der 0.8 generation

- **Status:** Accepted
- **Date:** 2026-10-27
- **Issue:** #21

## Context

[ADR-0011](0011-asn1-x509-cms-foundations.md) pinned the RustCrypto formats crates to the stable `der` 0.7 generation. It planned the move to the `der` 0.8 generation once stable releases of `cms`, `x509-ocsp` and `rsa` 0.10 existed, preferably before the first sigillum release. The move is tracked in #21.

Phase 1 starts with the library code that every later crate builds on: certificates, path validation, revocation and timestamps in `sigillum-pki`, then CMS SignedData. If this code is written on the 0.7 generation, it has to be migrated within the same phase. The public API does not expose these types, so the migration is internal. It still touches every decoding and encoding path written in phase 1.

On 27 October 2026, crates.io shows the following state of the 0.8 generation:

| Crate | Version | State |
| --- | --- | --- |
| `der` | 0.8.3 | Stable |
| `spki` | 0.8.1 | Stable |
| `x509-cert` | 0.3.0 | Stable since July 2026 |
| `const-oid` | 0.10.2 | Stable; does not contain RustCrypto/formats#2412 |
| `elliptic-curve`, `p256`, `p384`, `p521` | 0.14 (`p256`, `p384` and `p521` 0.14.0) | Stable; `elliptic-curve` 0.14 requires `crypto-bigint` 0.7.5 or later (0.14.0 and 0.14.1), 0.7.7 or later (0.14.2) or 0.7.8 or later (0.14.3). Releases 0.7.0 to 0.7.8 of `crypto-bigint` are yanked, and the first release with the fix of RUSTSEC-2026-0387 is 0.7.6, so the lock file must resolve 0.7.9 or later |
| `ed25519-dalek` | 3.0.0 | Stable |
| `signature` | 3.0.0 | Stable |
| `sha2`, `sha1` | 0.11 | Stable |
| `sha3` | 0.12.0 | Stable since May 2026, on `digest` 0.11 |
| `cms` | 0.3.0-rc.0 | Release candidate, 13 October 2026 |
| `rsa` | 0.10.0-rc.19 | Release candidate; the 0.10 line has gone through 20 release candidates, `rc.0` to `rc.19` |
| `x509-ocsp` | 0.3.0-pre | Not published; on the `master` branch only. The latest release, 0.2.1, dates from January 2024 and belongs to the 0.7 generation |
| `x509-tsp` | 0.2.0-pre | Not published; on the `master` branch only. The latest release, 0.1.0, belongs to the 0.7 generation |

Two further facts bear on the choice.

- RUSTSEC-2026-0387 affects `crypto-bigint` 0.5, reached through `elliptic-curve` 0.13 in the 0.7 generation. It is fixed in `crypto-bigint` 0.7.6. [ADR-0020](0020-accepted-advisories-der-0-7.md) accepts the advisory only while no library code performs elliptic-curve operations on secret values. This blocks ECDH key agreement for EnvelopedData recipients, which [scope.md](../../project/scope.md) includes. The 0.8 generation uses `crypto-bigint` 0.7.
- The OCSP and RFC 3161 structures needed by sigillum are small, fixed ASN.1 modules: [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960), section 4 and Appendix B, and [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161), section 2.4. [ADR-0024](0024-bounded-decoding-of-untrusted-input.md) already requires sigillum to control how untrusted DER reaches the decoder.

## Decision

1. Phase 1 library code is written on the `der` 0.8 generation from its first story. The set is `der` 0.8, `spki` 0.8, `x509-cert` 0.3, `const-oid` 0.10, `elliptic-curve` 0.14 with `p256`, `p384` and `p521` 0.14, `ed25519-dalek` 3, `signature` 3, `sha2` 0.11 and `sha3` 0.12, with the matching `aes`, `aes-gcm` and `cbc` releases. `sha1` 0.11 is added for lookup identifiers only, as scope.md allows. `crypto-bigint` resolves to 0.7.9 or later.
2. `cms` and `rsa` are used at their current release candidates, pinned with an exact version requirement (`=0.3.0-rc.0`, `=0.10.0-rc.19`). Each later release candidate or stable release is adopted in its own pull request, which runs the full quality gates and the differential tests. The rules of [ADR-0010](0010-cryptographic-backend.md) on `rsa` are unchanged: public-key operations only, enforced by lint. `cms` is used with its default features disabled and without its `builder` feature. Creating and verifying SignedData needs only the structures of the crate. Its SignedData builder calls the signer within one call, which does not fit the two steps of [ADR-0005](0005-two-step-signing.md). Whether CMS encryption uses the `builder` feature is decided when encryption is planned, and the transitive dependencies listed in the Consequences are checked again then.
3. sigillum defines the OCSP structures of RFC 6960 and the timestamp structures of RFC 3161 in `sigillum-pki`. They are written from the RFCs only, with the `der` 0.8 derive conventions, and are not exposed in the public API. They are offered upstream if `x509-ocsp` and `x509-tsp` are not released for the 0.8 generation.
4. Release 0.1 is not blocked by the release candidates. Before release 0.1, the maintainer records in the release checklist in #55 whether `cms` and `rsa` have stable releases, and accepts or postpones any remaining release candidate explicitly.
5. The test tooling (`sigillum-testpki`, `tools/dss-oracle`) is not required to migrate. `sigillum-testpki` stays on the 0.7 generation and depends on no library crate, under the crate-graph rule stated in [architecture.md](../architecture.md) and enforced by `crates/sigillum-testpki/tests/crate_graph.rs` since #26. It therefore keeps its own length walk, and the library gets its own module, written from [ITU-T X.690 (02/2021)](https://www.itu.int/rec/T-REC-X.690-202102-I/en). This replaces the last sentences of rule 3 of ADR-0024, which had `sigillum-testpki` use the library module. A differential test in `sigillum-oracle`, which may depend on both, runs the two walks over the same inputs, so that the two independent implementations check each other. It compares only the structural checks: the identifier octets (a truncated tag, a tag number of more than four octets), the length octets (the indefinite form, more than four subsequent octets, a length past its parent or the input), the nesting depth and trailing data. The library walk runs in whole-input mode, not in the mode of ADR-0024, rule 2, that returns the length of a leading value, and with the fixed depth limit of 32 of `sigillum-testpki`. `check_der` counts constructed values: it accepts 32 constructed values nested inside each other, with any primitive value inside the innermost, and refuses 33 (`MAX_DER_DEPTH` and its test `der_nesting_is_bounded`). The library walk is run with the same bound. The expected differences, the object identifier content checks of ADR-0024, rule 4, and the configurable depth, are mapped explicitly. The walk of `sigillum-testpki` stays as it is.
6. Consequences for earlier records:
   - [ADR-0011](0011-asn1-x509-cms-foundations.md) is superseded in its choice of generation. Its other rules stay: the public API exposes no type of these crates, and missing structures are defined in sigillum with the same conventions.
   - In [ADR-0020](0020-accepted-advisories-der-0-7.md), the acceptance of RUSTSEC-2026-0387 ends for the library when this decision is implemented, and rule 3 no longer blocks elliptic-curve operations on secret values in library code. The `deny.toml` entry stays for `sigillum-testpki`, which uses test keys only. That acceptance ends when `sigillum-testpki` moves to the 0.8 generation; until then, it is reviewed before each release in the release checklist in #55. Because `deny.toml` ignores apply to the whole workspace, a CI check fails if `crypto-bigint` 0.5 enters the dependency graph of a library crate. This replaces rule 4 of ADR-0020, which removed the entry when #21 merged.
   - Rule 3 of [ADR-0024](0024-bounded-decoding-of-untrusted-input.md) changes as rule 5 above states. The other rules of ADR-0024 stay in force. `const-oid` 0.10.2 does not contain RustCrypto/formats#2412, so the limit of 2^28 on arcs remains.
   - #21 changes from a later migration into the first task of phase 1: adopt the 0.8 generation in the library crates and check the behaviours that ADR-0024 lists.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Stay on the 0.7 generation and migrate later (ADR-0011 as written) | Only stable releases; no work on OCSP and timestamp structures | Every phase 1 decoding and encoding path is written twice; ECDH for EnvelopedData stays blocked by RUSTSEC-2026-0387; `x509-ocsp` 0.2 has had no release since January 2024 |
| Wait until every 0.8 crate is stable | Only stable releases, no rework | The start of phase 1 depends on release dates outside the project's control; `rsa` 0.10 has gone through 20 release candidates without a stable release |
| Use `x509-ocsp` and `x509-tsp` from the `master` branch | No own structures | Git dependencies cannot be published to crates.io; the unreleased code changes without notice |
| Help upstream release `x509-ocsp` and `x509-tsp` for the 0.8 generation (both on `master`), and wait for those releases | Structures maintained upstream, as principle 6 of the [charter](../../project/charter.md) prefers | The start of the revocation and timestamp work depends on release dates outside the project's control. Rule 3 keeps to principle 6 another way: sigillum's own structures are offered upstream if no release comes |
| Keep `rsa` 0.9 alongside the 0.8 generation | Stable `rsa` release | Two generations of `digest`, `signature` and `der` in the dependency graph; key and digest types have to be converted by hand at every call |
| Build on the 0.8 generation, with pinned release candidates and own OCSP and timestamp structures (chosen) | No migration of phase 1 code; RUSTSEC-2026-0387 no longer applies to the library; ECDH unblocked; full control of the OCSP and timestamp decoding paths | Two release candidates to follow until they are stable; two small ASN.1 modules to write, test and fuzz |

## Consequences

- The first phase 1 task, #21, replaces the 0.7 generation in the library crates, updates `deny.toml`, `supply-chain/` and the Dependabot groups, adds the CI check that fails if `crypto-bigint` 0.5 enters the dependency graph of a library crate, and checks the `der` 0.8 behaviours listed in ADR-0024 and #21.
- The OCSP and timestamp structures each need a story with known-answer tests against the corpus, a fuzz target and a cross-check with OpenSSL. These are needed in phase 1 in any case, for revocation and timestamp handling.
- `cms` and `rsa` leave the Dependabot group for RustCrypto and are updated individually, so that each release candidate arrives in its own pull request and is adopted deliberately. The group list, the ignore list and the check of their consistency change together.
- The architecture document is updated: the external crates of the diagram become the 0.8 generation, and `x509-ocsp` and `x509-tsp` are replaced by sigillum's own modules.
- If `cms` 0.3 is still a release candidate when CMS encryption is implemented, its encryption builders are reviewed before use, as for any release candidate.
- With the dependency set of rule 1 and `cms` without features, as resolved on 27 October 2026, the library graph holds three release candidates: `cms` 0.3.0-rc.0, `rsa` 0.10.0-rc.19, and `pkcs1` 0.8.0-rc.5, which `rsa` requires through its default `encoding` feature. It holds no duplicate crate. The `builder` feature of `cms` would add `ansi-x963-kdf` 0.1.0-rc.2 and a second `sha3`, 0.11 beside 0.12. `deny.toml` sets `all-features = true`, so `cargo deny` also checks the features that sigillum does not use, `builder` included. #21 verifies this list against `Cargo.lock` and applies the feature selection.
