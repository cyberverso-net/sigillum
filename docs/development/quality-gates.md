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
| Line coverage of new and changed code | `cargo llvm-cov`, measured by the *Line coverage* job of `coverage.yml`, as described below | At least 90% |
| Mutation score in critical modules (signing, verification, parsers) | `cargo mutants --in-diff`, run by the *Mutation testing* job of `mutants.yml` on each pull request, and on all critical modules every night, as described below | At least 80% of mutants caught |
| Fuzzing of each new or changed parser | `cargo fuzz` | At least 10 minutes per target without a finding. Long runs are not an author gate: their evidence is in the nightly fuzzing workflow, described below |
| Differential tests against DSS | `sigillum-oracle` | No unexplained divergence |

Thresholds apply to the change under review. A shortfall is acceptable only with a written justification in the pull request, for example code that is unreachable by construction.

The fuzzing threshold applies to parsers in the library crates and in the Rust tools. The Java test tool `tools/dss-oracle` is covered instead by a deterministic JUnit mutation test of its inputs, run by `mvn verify`, because it is not distributed and reads only project fixtures and sigillum output. Its README describes the test.

## Coverage evidence

The *Line coverage* job of `.github/workflows/coverage.yml` runs on every pull request, on the merge group and on every push to `main`, on Linux. It is where the evidence for the coverage gate lives. The reviewer checks the threshold against its report; the job fails only when the tests or the report fail, never on the threshold.

- **What runs.** `cargo llvm-cov --workspace`, with the version pinned in the workflow, runs the tests of the workspace with default features, as the cross-platform test job does. The `dss` feature of `sigillum-oracle`, and the tests that need OpenSSL or `tools/dss-oracle`, are not run: they need Java, Maven and OpenSSL built from source, and run in their own workflows. Their tests only say that they did not run.
- **What is measured.** `cargo llvm-cov` leaves out of the report, by default, the files under `tests`, `examples` and `benches` directories and the files named `tests.rs` or ending in `_tests.rs` or `-tests.rs`, so test code does not count. Unit tests therefore live in their own file, `src/<module>/tests.rs`, declared with `#[cfg(test)] mod tests;`. In any other Rust file, `.github/scripts/check-test-modules.sh` allows a `cfg` attribute whose condition contains the word `test`, in any form, only on exactly `mod tests;`, with no visibility and no other attribute such as `#[path]`, and refuses an inner `#![cfg(...)]` with `test`, and any test or benchmark: `#[test]`, an attribute whose path ends in `::test`, such as `#[tokio::test]`, and `#[bench]`. Anything else would put test code in the report as covered code. Code built only with the `dss` feature is not in the report. A test process stopped at a deadline can leave a profile that cannot be read. The job skips such a profile, which can only lower the coverage, and says so in a warning and in the job summary.
- **Changed lines.** `.github/scripts/diff-coverage.sh` compares the lcov report with the lines added or changed since the merge base: for a pull request, the base side of its merge commit; for a merge group, its base; for a push to `main`, the tip of `main` before the push. `.github/scripts/coverage-base.sh` chooses the base. A changed line counts when the report measures it, and is covered when a test runs it. The percentage is truncated, never rounded up. The scripts are tested in `.github/scripts/test-diff-coverage.sh`.
- **Where to read it.** The job summary gives the total line coverage, the coverage of the changed lines, and for each changed file the lines not covered. It lists the changed Rust files, other than test files, that have no line in the report, such as fuzz targets. The lcov and HTML reports are in the artefact `coverage-<run number>-<attempt>` of the run, kept for 30 days.
- **Code the job does not measure.** For changed code reached only by the tests that need DSS or OpenSSL, the author measures the coverage locally with those tests on, for example in the development image, and gives the result in the pull request.

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

## Mutation testing

The critical modules are the code that signs, verifies or parses. `.cargo/mutants.toml` lists them as file globs, which `cargo mutants` reads:

- **Library crates.** All the code of `sigillum-pki`, `sigillum-cms`, `sigillum-cades`, `sigillum-pades` and `sigillum-jades`. They hold no code yet. Their mutants are tested from the first pull request that adds code to them, with the tests of their own crate, and they add to the run time of the jobs below. A new library crate that signs, verifies or parses, such as `sigillum-pdf` of [ADR-0015](../design/adr/0015-pdf-reader-and-incremental-writer.md), is added to the list in the pull request that creates it. `sigillum-ffi` holds bindings and is not listed. `sigillum-bench` holds only benchmarks, which neither sign, verify nor parse, and is not listed.
- **`sigillum-testpki`.** The issuance and signing of the test PKI, of timestamp tokens and of the signed corpus (`pki/keys.rs`, `pki/hierarchy.rs`, `pki/issue.rs`, `pki/crl.rs`, `pki/ocsp.rs`, `timestamp.rs`, `signed.rs`), the parsers of untrusted input (`manifest.rs`, `mutations.rs`, `mutations/pades.rs`, `timestamp/input.rs`), and the OpenSSL and DSS checks of the corpus (`openssl.rs`, `openssl/process.rs`, `dss.rs`).
- **`sigillum-oracle`.** The parser of `summary.json` (`summary.rs`), the comparison of results (`compare.rs`) and the validation runs (`validation.rs`).

The other source files of the two tool crates are not listed, for these reasons. Each is named on a line `# not critical: <path>` of `.cargo/mutants.toml`. Test modules, `tests.rs` and the files under `tests/`, are test code, which `cargo mutants` does not mutate.

- `sigillum-testpki/src/lib.rs` and `sigillum-oracle/src/lib.rs` hold only module declarations and re-exports, with no code to mutate.
- `sigillum-testpki/src/main.rs` dispatches the subcommands and maps their results to exit codes; it neither signs, verifies nor parses.
- `sigillum-testpki/src/tsa_cli.rs` declares the options of the `tsa` subcommand; the parsers of its untrusted text are in `timestamp/input.rs`, which is listed.
- `sigillum-testpki/src/verify_cli.rs` declares the options of the `verify` subcommand and formats its report; the checks themselves are in `openssl.rs` and `dss.rs`, which are listed.
- `sigillum-testpki/src/documents.rs` writes the fixed unsigned base documents of the corpus, from constants; it reads no input and signs nothing.
- `sigillum-testpki/src/pki.rs` names the files of the test PKI and writes them into the corpus; the certificates, CRLs and responses are made in the listed modules under `pki/`.
- `sigillum-testpki/src/pki/rng.rs` is the deterministic source of bytes for test keys; it neither signs nor parses, and any change to its output changes the committed corpus, which the *Signed corpus* check compares byte for byte.
- `sigillum-oracle/src/dss.rs` is compiled only with the `dss` feature. With the feature off, as in the jobs below, its code is not compiled, so its mutants would build and pass every test and would count as missed. With the feature on, its tests are the differential tests, which need Java and `tools/dss-oracle`.

`cargo mutants` reads `.cargo/mutants.toml` from the root of the workspace. A `-f` or `--file` option on the command line adds to its list and does not replace it: the cargo-mutants book states that list values from the configuration file are appended to those of the command line, which version 27.1.0 does in `src/options.rs`. To test other files alone, `--no-config` ignores the configuration file, for example `cargo mutants --no-config -f crates/sigillum-testpki/src/pki.rs`.

The author runs `cargo mutants --in-diff` on the diff of the change against `main`, for example `git diff origin/main... > change.diff` and then `cargo mutants --in-diff change.diff`, and gives the score in the pull request. The development image has the version of `cargo mutants` that the workflows pin.

The workflow `.github/workflows/mutants.yml` runs `cargo mutants` 27.1.0 in eight shards, each on its own runner with three jobs (`--jobs 3`), with round-robin sharding. The job *Mutation testing* adds up the shards:

- **Pull requests.** On each pull request, the shards test only the mutants of the critical modules that overlap the diff of the pull request with its base (`--in-diff`). On the diff of #154, a feature pull request with 192 such mutants, a run of this configuration took 24 minutes from the start of the shards to the end of the report, within the limit of 30 minutes that issue #80 sets for a run on the diff. The same diff without shards took 2 h 44 min with one job, and 1 h 44 min with three. On a pull request each shard has a time limit of 45 minutes, so that a run over its budget fails visibly instead of holding eight runners: a shard that reaches the limit is cancelled, and the report lists it as a shard that reported no result. If runs on pull requests regularly approach the limit, the number of shards is raised, or the job is left to the nightly run alone. The pull request that added the job changed no Rust source, so its own run tested no mutant; the first pull request that changes a critical module is the first to run `--in-diff` with mutants on a pull request.
- **Every night.** At 01:23 UTC on `main`, and on demand, the shards test all the mutants of the critical modules. The first run, with the list before `signed.rs`, `pki/hierarchy.rs` and `openssl/process.rs` were added, generated 1,076 mutants, of which 952 were viable, and took 1 h 35 min, the time of its slowest shard. The number of shards is raised when the slowest shard approaches the time limit of the nightly job, four hours, as the library crates grow.
- **Report.** The job writes to its summary the counts of each outcome, the score, and the missed and timed out mutants. It fails when the score is below the threshold, when a shard is missing, failed or ran on failing tests, and when a mutant had an outcome other than the four it counts; it then still reports the shards that completed. Each shard keeps its `mutants.out` directory in the artefact `mutants-out-shard-<n>`, with the log of every mutant. The score is the share of caught mutants among those the tests ran against: a timeout counts as not caught, and a mutant that does not build is left out.
- **Not required.** The check is not required, because a shortfall can be justified in the pull request, as stated above. The reviewer reads the score in the summary of the pull request run. Before treating a run below the threshold as a real shortfall, the reviewer reads the list of timeouts: a timeout counts as not caught, and with three jobs on each runner a slow test can time out under the load alone, which the log of the mutant in the artefact shows. A missed mutant reported by the nightly run is fixed, or justified, in a follow-up issue.

The workflow `.github/workflows/mutants-config.yml` runs on pull requests that change the configuration, its scripts or the sources under `crates/`. It runs the tests of the scripts and `.github/scripts/check-mutants-globs.sh`, which checks that every glob of `.cargo/mutants.toml` matches at least one source file, so that a renamed module cannot leave the list unnoticed, and that every source file of `sigillum-testpki` and `sigillum-oracle`, other than test modules, is either selected or named as not critical, so that a new file cannot be left out unnoticed.

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
