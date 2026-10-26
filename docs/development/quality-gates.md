# Quality gates

Every change must pass the gates below before it is merged. Continuous integration enforces the automated gates; the remainder are checked by the author before review and confirmed by the reviewer.

## Automated gates

| Gate | Command or tool | Requirement |
| --- | --- | --- |
| Formatting | `cargo fmt --all --check` | No differences |
| Linting | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | No warnings |
| Tests | `cargo test --workspace --all-features --exclude sigillum-oracle` and `cargo test -p sigillum-oracle` | All pass on Linux, macOS and Windows |
| Documentation | `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps` | No warnings; every public item documented |
| Minimum Rust version | `cargo check --workspace --all-features --all-targets` with the declared `rust-version` | Builds, including tests and benchmarks |
| Portability | `cargo check` for `wasm32-unknown-unknown`, `aarch64-apple-ios`, `aarch64-linux-android` | Builds |
| Dependencies | `cargo deny check` | No licence, advisory or source violations |
| Dependency audits | `cargo vet --locked` | Every third-party dependency is covered by an audit or a recorded exemption, as described below |
| Sign-off | DCO check | Every commit signed off |
| Commit signatures | Verified commit signatures check | Every commit in the pull request has a verified signature |
| Dependabot lists | `.github/scripts/check-dependabot-lists.sh` | The RustCrypto group and the ignore rules in `dependabot.yml` name the same crates |
| Fixture verification with OpenSSL | `sigillum-testpki verify --openssl` with the OpenSSL release named in the manifest, and with OpenSSL 4.0.3 through `--openssl-version`, each built from source and run without network, Linux | Every artefact matches the OpenSSL result in its manifest |
| Fixture verification with DSS (planned with the test PKI, phase 0) | `sigillum-testpki verify` with `tools/dss-oracle` run without network, Linux | Every artefact matches the DSS result in its manifest |
| DSS oracle build | `mvn -B verify` in `tools/dss-oracle`, Java 21, Linux; the tool then runs without network | Builds, its tests pass, and it runs offline |
| Signed corpus | `sigillum-testpki generate documents` and `generate signed` with `tools/dss-oracle`, run without network, Linux | The regenerated `testdata/` is identical, byte for byte, to the committed one |
| Differential tests (planned with the harness, phase 0) | `cargo test -p sigillum-oracle --features dss` on Linux, with Java and Maven, running `tools/dss-oracle` without network | Pass |

The `dss` feature of `sigillum-oracle` is excluded from the cross-platform test job, which tests `sigillum-oracle` with its default features only.

## Dependency audits

`cargo vet` checks that someone has reviewed the code of every third-party crate in `Cargo.lock`. Its configuration and records are in `supply-chain/`.

- **Criteria.** Both criteria are built into `cargo vet`.
  - Normal and build dependencies must meet `safe-to-deploy`. It attests that the crate will not introduce a serious security vulnerability to production software exposed to untrusted input.
  - Dependencies used only in tests and benchmarks must meet `safe-to-run`. It attests only that running the crate on a developer machine or in CI is safe.
  - The unpublished tooling crates `sigillum-oracle`, `sigillum-testpki` and `sigillum-bench` are never deployed. A `[policy]` entry in `supply-chain/config.toml` requires only `safe-to-run` of all their dependencies.
  - A new tooling crate gets its `[policy]` entry in the pull request that adds it to the workspace. `cargo vet` rejects entries for crates that are not in the workspace.
- **Cryptography.** Neither criterion attests that a crate implements cryptography correctly, and no criterion for that is required for now. Whether cryptographic crates must meet one, such as `crypto-safe` from Google's audits, is reviewed before release 0.1.
- **Trusted publishers.** Some RustCrypto and dalek crates are trusted for `safe-to-deploy` when released by a publisher that crates.io has recorded for them.
  - The set starts from the `rustcrypto-dalek` group of `.github/dependabot.yml`, declared with default features and the `cms` builder. It covers the `der` 0.7 generation of [ADR-0011](../design/adr/0011-asn1-x509-cms-foundations.md) and the `der` 0.8 generation.
  - The set includes the dependencies of that group that `cargo vet` sees, hosted under the RustCrypto or dalek-cryptography organisations on GitHub. `cargo vet` reads the dependency graph of `cargo metadata` with all features, so this includes optional dependencies that a build does not activate.
  - It excludes `getrandom`, `rand` and `rand_core`, which come from elsewhere.
  - For each crate, the publishers are those that crates.io recorded for its releases from 2022-01-01 to 2026-10-24. Publishers whose only releases in that period neither generation uses are left out.
  - A publisher is a crates.io user, or the release workflow of a RustCrypto repository through trusted publishing.
  - Each entry in `supply-chain/audits.toml` names one crate and one publisher. It covers releases published from 2022-01-01 up to, but not including, 2027-10-24. Releases from that period stay trusted after it.
  - Before 2027-10-24 the entries are checked again against crates.io and extended or removed, as tracked in #63. A release by any other publisher, or a crate outside the set, needs an audit.
- **Trusted publishers of tooling dependencies.** Some third-party crates used only by the tooling crates are trusted for `safe-to-run`, never for `safe-to-deploy`.
  - An entry names a crate and a crates.io user who published a version of it, the anchor.
  - Audits imported from Mozilla or the Bytecode Alliance, full or delta, must lead from the anchor to the version in `Cargo.lock`. Often the anchor is that version itself.
  - Mozilla or the Bytecode Alliance must trust that user for that crate, in an entry whose period covers the publication of the anchor.
  - The entry starts with the period of that imported entry, but not before 2022-01-01. It ends on 2027-10-24 and is then checked again, as tracked in #63.
- **Build-time dependencies.** Some crates trusted only at `safe-to-run` are also common proc-macro and build dependencies, such as `syn`, `proc-macro2` and `serde`. When a library crate first depends on them, they need `safe-to-deploy` coverage, through an audit, an import or a trusted publisher.
- **Exemptions.** The remaining dependencies of the tooling crates are exempted at `safe-to-run` in `supply-chain/config.toml`. They were generated with `cargo vet regenerate exemptions`.
  - Each exemption is reviewed before release 0.1, as tracked in #63. It is then audited, covered by an import or a trusted publisher, or kept with a recorded reason.
  - No dependency of a published crate is exempted.
- **Imported audits.** The audits published by Mozilla, Google and the Bytecode Alliance are imported, as listed in `supply-chain/config.toml`.
  - Some imported entries are wildcard audits, which trust the releases of a crate by a given publisher within a period.
  - `supply-chain/imports.lock` records the imported audits that apply. Continuous integration then runs `cargo vet --locked` without fetching them, so the result depends only on the committed files.
- **Version.** Contributors use the version of `cargo vet` that `.github/workflows/cargo-vet.yml` pins. They install it with `cargo install cargo-vet --locked --version 0.10.3`.
  - A newer version may rewrite the store in a format the pinned one rejects.
  - When a new version changes the store format, `supply-chain/config.toml` is updated in the same pull request.
- **Review.** The reviewer of a pull request checks every new audit, exemption, wildcard audit and publisher entry in `supply-chain/`.

When a dependency is added or updated:

1. The author runs `cargo vet` locally. It fetches the imported audits and updates `imports.lock`.
2. If an imported audit covers the crate, the updated lock file is committed with the change.
3. Otherwise the author reviews the crate, or the difference from an audited version, and records the review with `cargo vet certify`. The notes say what was checked.
4. Where a review is not yet possible, the author records an exemption with `cargo vet add-exemption`. Its notes name the issue that tracks the review.

Dependabot changes `Cargo.toml` and `Cargo.lock` but not `supply-chain/`, so its updates fail the check even when an imported audit covers the new version. The maintainer runs `cargo vet` on the Dependabot branch and pushes the refreshed `imports.lock`, with any audits or exemptions. The commit is signed and signed off, and Dependabot then stops rebasing that branch.

Trusting another publisher, with `cargo vet trust`, or adding another source of audits is a decision recorded in the pull request that makes it.

## Author gates

| Gate | Tool | Threshold |
| --- | --- | --- |
| Line coverage of new and changed code | `cargo llvm-cov` | At least 90% |
| Mutation score in critical modules (signing, verification, parsers) | `cargo mutants` | At least 80% of mutants caught |
| Fuzzing of each new or changed parser | `cargo fuzz` | At least 10 minutes per target without a finding |
| Differential tests against DSS | `sigillum-oracle` | No unexplained divergence |

Thresholds apply to the change under review. A shortfall is acceptable only with a written justification in the pull request, for example code that is unreachable by construction.

The fuzzing threshold applies to parsers in the library crates and in the Rust tools. The Java test tool `tools/dss-oracle` is covered instead by a deterministic JUnit mutation test of its inputs, run by `mvn verify`, because it is not distributed and reads only project fixtures and sigillum output. Its README describes the test.

## Kinds of test

- **Unit tests** for each function's contract, including error paths.
- **Property tests** (`proptest`) for encoders and decoders, in particular round trips and invariants.
- **Known-answer tests** using vectors published in the relevant RFCs and standards.
- **Differential tests** comparing results with DSS, as described in [conformance.md](../design/conformance.md).
- **Negative tests** for malformed, tampered and unsupported input, including the "not supported" result required by [ADR-0007](../design/adr/0007-asymmetric-scope.md).
- **Fuzz targets** for every parser.

## Review checklist

The reviewer, and the author before requesting review, checks that:

1. Each acceptance criterion is met and has a test that would fail without the change.
2. The implementation follows the cited clauses of the standards; deviations are recorded.
3. No input can cause a panic, unbounded allocation or unbounded recursion. Decoding of untrusted input follows [ADR-0024](../design/adr/0024-bounded-decoding-of-untrusted-input.md).
4. Errors are typed and informative, and do not leak secret material.
5. Cryptographic comparisons that involve secrets run in constant time.
6. Unsupported input yields an explicit "not supported" result, never a pass.
7. The public API is consistent with existing crates and with [ADR-0005](../design/adr/0005-two-step-signing.md) and [ADR-0006](../design/adr/0006-no-network-access-in-core.md).
8. New dependencies are justified and pass `cargo deny` and `cargo vet`.
9. The provenance rule in [CONTRIBUTING.md](../../CONTRIBUTING.md) is respected: no code or test data under incompatible licences.
10. Documentation and comments follow the [style guide](style-guide.md).
11. The change is consistent with the [threat model](../design/threat-model.md); a new interface, format or dependency class updates it.
