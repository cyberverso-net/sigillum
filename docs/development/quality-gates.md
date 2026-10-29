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
| Sign-off | DCO check | Every commit of the pull request signed off. In the merge queue the check relies on the pull request, as described in [process.md](process.md#merging-through-the-merge-queue) |
| Commit signatures | Verified commit signatures check | Every commit in the pull request has a verified signature. In the merge queue the check relies on the pull request, as for the sign-off |
| Code scanning | CodeQL default setup and the code scanning rule of the ruleset on `main`, as described below | No CodeQL security alert of high or critical severity whose lines are all in the pull request diff |
| Dependabot lists | `.github/scripts/check-dependabot-lists.sh`, with its tests in `.github/scripts/test-check-dependabot-lists.sh` | The RustCrypto group and the ignore rules in `dependabot.yml` name the same crates. The Maven entry lists every directory with a `pom.xml`, and its `maven-routine` group excludes the DSS artefacts of the `dss` group |
| Fixture verification with OpenSSL | `sigillum-testpki verify --openssl` with the OpenSSL release named in the manifest, and with OpenSSL 4.0.3 through `--openssl-version`, each built from source and run without network, Linux | Every artefact matches the OpenSSL result in its manifest |
| Fixture verification with DSS | `sigillum-testpki verify --dss` with `tools/dss-oracle`, built against the DSS release named in the manifest and run without network, Linux | Every artefact matches the DSS result in its manifest, or, for an artefact whose `dss-divergence` names a divergence recorded in `docs/design/divergences.md`, the result of DSS that the field records |
| DSS oracle build | `mvn -B verify` in `tools/dss-oracle`, Java 21, Linux; the tool then runs without network | Builds, its tests pass, and it runs offline |
| Signed corpus | `sigillum-testpki generate documents`, `generate signed` with `tools/dss-oracle`, and `generate mutations`, run without network, Linux | The regenerated `testdata/` is identical, byte for byte, to the committed one |
| Development image versions | `tools/dev-image/check-versions.sh`, with its tests in `tools/dev-image/test-check-versions.sh` | The versions in `tools/dev-image/versions.env` are those that the workflows, the manifest and `Cargo.toml` pin. A newer stable Rust or Temurin 21 release, or a new Ubuntu release behind `ubuntu-latest`, is reported as a warning |
| Development image (when its inputs change, and weekly) | `tools/dev-image/run.sh tools/dev-image/smoke.sh` on `linux/amd64` and `linux/arm64`, then a build of `tools/dss-oracle` without network | The image builds, every download matches its recorded digest, each tool is the version of `versions.env`, and Maven needs no network |
| Differential tests | `cargo test -p sigillum-oracle --features dss` in `differential.yml` on Linux, with Java and Maven, running `tools/dss-oracle` without network | Pass: every artefact of the corpus that DSS processes gives its expected result, or the result of its recorded divergence, and two runs of the whole corpus give the same `summary.json`, byte for byte |

The `dss` feature of `sigillum-oracle` is excluded from the cross-platform test job, which tests `sigillum-oracle` with its default features only.

Each required check runs on the pull request and again on the merge group in the merge queue, except where the table says otherwise. [process.md](process.md#merging-through-the-merge-queue) describes the queue.

## Code scanning merge protection

CodeQL runs through the default setup of code scanning. The ruleset on `main` holds a code scanning rule: a pull request cannot be merged while CodeQL reports a security alert of high or critical severity, while its analysis is in progress, or if CodeQL is not configured. The rule is not a status check, and it has two limits, both accepted:

- **Merge groups.** The rule does not apply to merge groups in the merge queue. It is expected to be enforced on the pull request before the pull request can be queued, so that the queue combines only pull requests that passed it. GitHub's documentation does not state this; the first pull request merged through the queue confirms it, and this text is corrected if it does not hold.
- **Lines in the diff.** The rule considers only an alert whose lines are all in the pull request diff, which means a new finding. An alert that already exists on `main` does not block a pull request. It goes through triage in the code scanning alerts of the repository instead.

The rule also does not apply to Dependabot pull requests analysed by the default setup.

GitHub documents these limits in [Code scanning merge protection](https://docs.github.com/en/code-security/concepts/code-scanning/merge-protection).

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
| Fuzzing of each new or changed parser | `cargo fuzz` | At least 10 minutes per target without a finding. Long runs are not an author gate: their evidence is in the nightly fuzzing workflow, described below |
| Differential tests against DSS | `sigillum-oracle` | No unexplained divergence |

Thresholds apply to the change under review. A shortfall is acceptable only with a written justification in the pull request, for example code that is unreachable by construction.

The fuzzing threshold applies to parsers in the library crates and in the Rust tools. The Java test tool `tools/dss-oracle` is covered instead by a deterministic JUnit mutation test of its inputs, run by `mvn verify`, because it is not distributed and reads only project fixtures and sigillum output. Its README describes the test.

## Nightly fuzzing

`.github/workflows/fuzz-nightly.yml` runs every `cargo fuzz` target of the repository each night, and when it is started by hand, for at least 10 minutes per target, one job per target. `.github/scripts/fuzz-targets.sh` lists the targets: every binary of every fuzz project under `crates/*/fuzz`, so a new target joins the run without a change to the workflow. Its tests, `.github/scripts/test-fuzz-targets.sh`, and those of the minimisation, `.github/scripts/test-fuzz-minimise.sh`, run in the fuzz targets build check of each pull request. The runs of this workflow, in the Actions tab of the repository, are where the evidence of long fuzzing runs lives.

- **Toolchain.** The workflow pins the nightly toolchain and `cargo-fuzz` to the versions of `tools/dev-image/versions.env`, `RUST_NIGHTLY` and `CARGO_FUZZ_VERSION`, which the development image versions check compares.
- **Findings.** A crash, leak, out-of-memory input, or an input that runs for more than 60 seconds, fails the job of its target, while fuzzing or while minimising, as does an inner process of the minimisation that dies without a report, for example when the kernel kills it for its memory. A minimisation counts as complete only when libFuzzer reports that an inner process succeeded. The failing input, named `merge-failure-<file>` for an inner process that died, is uploaded as the artefact `crash-<crate>-<target>` of the run, kept for 7 days. The time limit of one input is 60 seconds in the nightly run, against 1200 seconds by default, so that inputs that exhaust time are found. A finding is reproduced in the fuzz project with the pinned nightly, `cargo +<RUST_NIGHTLY> fuzz run --fuzz-dir . <target> <input>`, or in the development image, where `cargo +nightly` selects that nightly.
- **Triage of a finding.** A finding is first handled as a possible vulnerability, as [SECURITY.md](../../SECURITY.md) requires: the maintainer opens a draft security advisory of the repository, which stays private, records the input and the analysis there, and then deletes the run with `gh run delete <id>`, which removes its logs and artefacts. Deleting the run is a required step for every finding until it is judged not to be a security issue. It becomes a public issue of type Bug only once it is judged not to be a security issue. Otherwise it is fixed through the advisory, with coordinated disclosure.
- **Public findings.** The repository is public, so a failing run can be read by anyone until it is deleted. Its artefact holds the failing input for 7 days. Its log holds the stack trace and the input itself, which libFuzzer prints in hexadecimal and in Base64 and cargo fuzz prints in its `Debug` form, and logs are kept for 90 days, the retention of the repository. This is accepted as residual risk 9 of the [threat model](../design/threat-model.md), limited by the deletion of the run in the triage above. Failing inputs never reach the corpus branch, as the next item describes.
- **Corpus.** Each target starts from the corpus that earlier runs kept on the branch `fuzz-corpus`, under `<crate>/<target>/`, and from the seeds of its fuzz project. After fuzzing, the corpus of each target is reduced with `cargo fuzz cmin`, every night, which took from 1 to 29 seconds per target with corpora of up to 40,000 inputs. The corpus of a target is saved only when its fuzzing and its minimisation both succeed. After a finding, or any other failure, the corpus that the branch holds for the target stays as it is: libFuzzer writes no failing input to the corpus, but inputs derived on the way to it can be there, and neither belongs in the history of a public branch. A target with a crash that persists therefore keeps the corpus of its last good run until the crash is fixed. Each job checks out the last commit of the branch only, with the corpora of every target, so the cost of the checkout follows the size of the corpora, not the length of the history. The directory of a target that is removed from the repository stays on the branch, unused, until it is deleted there by hand.
- **Writing the corpus branch.** What the workflow enforces, and what the ruleset enforces, differ:
  - The workflow: only the job *Save the corpus* writes `fuzz-corpus`, once per run after every fuzzing job has ended, so the jobs of the matrix never push concurrently, and one run at a time is allowed for each branch. It has the workflow's only `contents: write` permission, uses the `GITHUB_TOKEN` of the run, runs no code of the repository, pushes only fast-forwards, and runs only for `main`. The other jobs can only read. These rules hold because changes to the workflow on `main` go through review; they bind no other workflow.
  - The ruleset *Protect fuzz-corpus* on `fuzz-corpus` blocks deleting the branch and force pushes, for everyone; it has no bypass. It does not restrict who pushes. A rule that restricts updates to GitHub Actions is not possible: GitHub refuses the GitHub Actions app as a bypass actor of a ruleset of this repository, and the alternative, a deploy key or the key of a GitHub App of our own, would be a long-lived credential. So who writes the branch is limited by the workflow and by the review of changes on `main`, as the previous item describes, and by the write access to the repository: a pull request from a fork gets a read-only token.
  - No personal access token or other long-lived credential is used, as threat S6 of the threat model requires. A push made with `GITHUB_TOKEN` starts no other workflow.
- **Scorecard.** The OpenSSF Scorecard check Token-Permissions reports the job-level `contents: write` of *Save the corpus*. It is accepted for the reasons above.

The workflow is not a required check: it does not run on pull requests, and a finding is fixed in its own pull request or advisory.

## Local runs

`tools/dev-image/` holds a container image with the tools of the workflows at the versions they pin: Ubuntu 24.04, Temurin 21, Maven, Rust stable, the minimum supported Rust version and a nightly for `cargo fuzz`, OpenSSL 3.5.9 and 4.0.3 built from source, and the tools of the author gates. `versions.env` records every version and digest. The compiler and download tools come from the Ubuntu archive when the image is built: snapshot.ubuntu.com serves no snapshot of the archive for `arm64`. The gates then run with the tools and versions of continuous integration, whatever the host has installed. The `linux/amd64` image is the closest match to the runners; results that depend on timing or on the architecture can still differ, as #99, #100 and #101 record.

```
tools/dev-image/run.sh cargo test --workspace
tools/dev-image/run.sh bash -c 'cd tools/dss-oracle && mvn -B verify'
tools/dev-image/run.sh cargo fetch --locked
tools/dev-image/run.sh --offline cargo run -p sigillum-testpki -- verify --openssl
tools/dev-image/run.sh --offline cargo run -p sigillum-testpki -- verify --dss
```

The first run builds the image, which takes several minutes. The worktree is mounted at `/work`, and commands run as the user of the host. Build outputs stay in Docker volumes, one set per worktree and architecture, so they do not mix with those of the host. The home directory, with the Maven dependencies that the image holds and the Cargo registry, is a volume of each image. `git` does not work in the container for a worktree, whose repository is outside the mounted directory, so a check such as "Check that nothing changed" of `signed-corpus.yml` runs on the host. `--offline` runs without network, as the workflows run the checks that must work offline; fetch dependencies first. The image runs natively on `linux/arm64` hosts. `--platform linux/amd64` selects the architecture of the workflows, emulated on such hosts, for a step that must match them byte for byte. In the image, `openssl` and `SIGILLUM_TESTPKI_OPENSSL` name OpenSSL 3.5.9, and `SIGILLUM_TESTPKI_OPENSSL_OTHER` names 4.0.3.

Docker needs about 8 GiB of memory for `cargo test` and `mvn -B verify` in the image. With 1 GiB, the linker and the compiler are killed.

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
7. The public API is consistent with existing crates and with [ADR-0005](../design/adr/0005-two-step-signing.md), [ADR-0006](../design/adr/0006-no-network-access-in-core.md) and the conventions of [ADR-0026](../design/adr/0026-public-api-conventions.md). External evidence is obtained through the request and response loop of ADR-0026, decision 2, and the core performs no network access.
8. New dependencies are justified and pass `cargo deny` and `cargo vet`.
9. The provenance rule in [CONTRIBUTING.md](../../CONTRIBUTING.md) is respected: no code or test data under incompatible licences.
10. Documentation and comments follow the [style guide](style-guide.md).
11. The change is consistent with the [threat model](../design/threat-model.md); a new interface, format or dependency class updates it.
