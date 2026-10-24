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
| Sign-off | DCO check | Every commit signed off |
| Commit signatures | Verified commit signatures check | Every commit in the pull request has a verified signature |
| Dependabot lists | `.github/scripts/check-dependabot-lists.sh` | The RustCrypto group and the ignore rules in `dependabot.yml` name the same crates |
| Fixture verification (planned with the test PKI, phase 0) | `sigillum-testpki verify` with OpenSSL and `tools/dss-oracle` run without network, Linux | Every artefact matches the result in its manifest |
| DSS oracle build | `mvn -B verify` in `tools/dss-oracle`, Java 21, Linux; the tool then runs without network | Builds, its tests pass, and it runs offline |
| Differential tests (planned with the harness, phase 0) | `cargo test -p sigillum-oracle --features dss` on Linux, with Java and Maven, running `tools/dss-oracle` without network | Pass |

The `dss` feature of `sigillum-oracle` is excluded from the cross-platform test job, which tests `sigillum-oracle` with its default features only.

## Author gates

| Gate | Tool | Threshold |
| --- | --- | --- |
| Line coverage of new and changed code | `cargo llvm-cov` | At least 90% |
| Mutation score in critical modules (signing, verification, parsers) | `cargo mutants` | At least 80% of mutants caught |
| Fuzzing of each new or changed parser | `cargo fuzz` | At least 10 minutes per target without a finding |
| Differential tests against DSS | `sigillum-oracle` | No unexplained divergence |

Thresholds apply to the change under review. A shortfall is acceptable only with a written justification in the pull request, for example code that is unreachable by construction.

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
3. No input can cause a panic, unbounded allocation or unbounded recursion.
4. Errors are typed and informative, and do not leak secret material.
5. Cryptographic comparisons that involve secrets run in constant time.
6. Unsupported input yields an explicit "not supported" result, never a pass.
7. The public API is consistent with existing crates and with [ADR-0005](../design/adr/0005-two-step-signing.md) and [ADR-0006](../design/adr/0006-no-network-access-in-core.md).
8. New dependencies are justified and pass `cargo deny`.
9. The provenance rule in [CONTRIBUTING.md](../../CONTRIBUTING.md) is respected: no code or test data under incompatible licences.
10. Documentation and comments follow the [style guide](style-guide.md).
11. The change is consistent with the [threat model](../design/threat-model.md); a new interface, format or dependency class updates it.
