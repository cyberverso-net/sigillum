# Development process

This document describes how work is planned, tracked and delivered. It applies to every contributor, including the maintainer.

## Planning structure

| Level | GitHub feature | Purpose |
| --- | --- | --- |
| Phase | Milestone | A roadmap phase with exit criteria, as in [roadmap.md](../project/roadmap.md) |
| Epic | Issue of type *Epic* | A coherent capability, for example "CAdES baseline creation"; its stories are attached as sub-issues |
| Story | Issue of type *Story* | One user-visible increment that can be implemented, tested and reviewed on its own |
| Task | Issue of type *Task* | Technical work with no direct user-visible effect, for example CI or tooling |
| Bug | Issue of type *Bug* | A defect in released or merged behaviour |

The public project board, *sigillum roadmap*, shows every open item with its status, milestone and area.

## Writing stories

Every story uses the *Story* issue form and contains:

- a user story: "As a … I want … so that …";
- the context and any relevant ADR;
- numbered acceptance criteria, each one testable;
- the normative references (standard and clause) that the implementation must follow;
- a test plan: unit tests, known-answer vectors, differential tests against DSS, fuzz targets where a parser is involved;
- what is explicitly out of scope for the story.

A story should be small enough to be implemented and reviewed in a few days. A larger story is split before it is started.

## Definition of Ready

A story may move to *Ready* when:

- its acceptance criteria are complete and testable;
- its normative references are identified;
- any decision it depends on is recorded in an accepted ADR;
- the issues it depends on are done;
- if it performs elliptic-curve operations on secret values, it names #21 as a dependency in the issue;
- it fits within [scope.md](../project/scope.md).

[ADR-0020](../design/adr/0020-accepted-advisories-der-0-7.md) accepts RUSTSEC-2026-0387 only while no library code performs such operations. Such a story therefore cannot be ready until #21 is done.

## Workflow

| Status | Meaning |
| --- | --- |
| Backlog | Identified, not yet ready |
| Ready | Meets the Definition of Ready |
| In progress | Being implemented on a branch |
| In review | Pull request open |
| Done | Merged and meets the Definition of Done |

Branches are named `<type>/<issue>-<short-slug>`, for example `story/42-cades-signed-attributes`. Pull requests reference their issue with `Closes #42` and are merged by squash, with a commit message that follows [CONTRIBUTING.md](../../CONTRIBUTING.md).

`.github/CODEOWNERS` names the maintainer as owner of every file. While there is a single maintainer, the ruleset on `main` must not require code-owner review, because the only code owner cannot approve their own pull requests. The other rules on `main` are listed in [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Merging through the merge queue

Every pull request into `main` is merged through the merge queue, by squash. The bypass of the ruleset described in [CONTRIBUTING.md](../../CONTRIBUTING.md) is the only exception. The queue tests each change as it will land on `main`, so a pull request branch need not be updated with `main` before it is merged.

1. The pull request passes its required checks and the code scanning rule, both run on the pull request. The code scanning rule blocks a CodeQL security alert of high or critical severity whose lines are all in the pull request diff.
2. The maintainer adds the pull request to the queue with *Merge when ready*, or with `gh pr merge`. If the checks have not finished, GitHub enables auto-merge and queues the pull request once they pass.
3. The queue creates a merge group on a temporary branch. The merge group combines the latest `main`, the pull requests ahead in the queue and this pull request.
4. The required checks run again on the merge group, through the `merge_group` event.
5. If they pass, GitHub merges the group into `main`. If one fails or times out, the queue removes the pull request, and the pull request timeline gives the reason.

A queued merge does not change the pull request branch. The independent review of that branch therefore stays valid and is not repeated when the pull request is queued, or queued again after removal. A change pushed to the branch is a new state of the pull request, and its review is repeated as for any other update.

The checks "Developer Certificate of Origin" and "Verified commit signatures" read the commits of a pull request. In a merge group they pass without checking its commits, as `.github/workflows/ci.yml` states. The merge group holds commits that the queue creates, not the contributor's commits, and those were already checked on the pull request before it could be queued. The ruleset on `main` still requires a verified signature on every commit that reaches `main`.

Every workflow that reports a required check has the `merge_group` trigger. A check that is not reported for a merge group blocks the queue until the status check timeout. A new required check therefore needs the trigger, and it must not depend on a `paths` filter, before it is added to the ruleset.

## Definition of Done

A story is done when:

- every acceptance criterion is met and covered by a test;
- all [quality gates](quality-gates.md) pass;
- the change has been reviewed against the review checklist in [quality-gates.md](quality-gates.md);
- documentation, including rustdoc for public items, is updated;
- any significant decision is recorded in an ADR;
- any intentional divergence from DSS is recorded in [divergences.md](../design/divergences.md);
- a changelog fragment is added under `changelog.d/` where one is needed, as described in [changelog.d/README.md](../../changelog.d/README.md).

## Labels

| Label | Use |
| --- | --- |
| `area: pki`, `area: cms`, `area: cades`, `area: pades`, `area: ffi`, `area: oracle`, `area: docs`, `area: ci` | The crate or area concerned |
| `priority: high`, `priority: low` | Deviation from normal priority |
| `needs: adr` | A decision must be recorded before work can proceed |
| `needs: discussion` | Scope or approach not yet agreed |
| `blocked` | Waiting on another item, named in the issue |
| `good first issue` | Suitable for a new contributor |

Issue type, milestone and status are not duplicated as labels.

## Releases

Versions follow Semantic Versioning. Before 1.0, minor versions may contain breaking changes, which are listed in the changelog. A release is tagged `vX.Y.Z` from `main` once its milestone's exit criteria, or the subset planned for that release, are met. When a release is prepared, the changelog fragments in `changelog.d/` are compiled into [CHANGELOG.md](../../CHANGELOG.md).

## Dependency updates

Dependabot proposes version updates weekly, as configured in `.github/dependabot.yml`. Its pull requests pass the same checks as any other.

| Entry | Groups | Review |
| --- | --- | --- |
| `cargo` | `rustcrypto-dalek`, which moves the RustCrypto and dalek crates together within the generation that [ADR-0011](../design/adr/0011-asn1-x509-cms-foundations.md) pins | The normal checks, with `cargo vet` as described in [quality-gates.md](quality-gates.md) |
| `maven` | `dss` for the DSS artefacts, and `maven-routine` for the plugins and the other libraries | `dss`: an oracle change, as below. `maven-routine`: the normal checks, and the licence table in [tools/dss-oracle/README.md](../../tools/dss-oracle/README.md) |
| `github-actions` | None | The normal checks |

A DSS update is an oracle change, never a routine update ([ADR-0013](../design/adr/0013-dss-oracle-command-line-tool.md)). Its pull request reruns the whole corpus through the oracle, reviews every changed result against the predictions of `testdata/manifest.toml`, and updates `dss-version` in the header of the manifest. The steps are listed under "Dependency updates" in [tools/dss-oracle/README.md](../../tools/dss-oracle/README.md).

The `maven` entry lists every directory of the repository that holds a `pom.xml`. Dependabot's current implementation makes one pull request per group across all the directories of an entry, so the `dss` group is expected to move every DSS pin in the same pull request. GitHub's documentation does not state this, so any other build that pins DSS must have a test that its pin equals that of `tools/dss-oracle`. The check `.github/scripts/check-dependabot-lists.sh` fails when a `pom.xml` is added without its directory, or when the `maven-routine` group could take a DSS artefact.

## Raising the minimum supported Rust version

The minimum supported Rust version (MSRV) is raised only in a minor release, as stated in [architecture.md](../design/architecture.md). A raise follows these steps:

1. Open an issue that states the reason for the raise and the new version. The remaining steps are made in one pull request.
2. Change `rust-version` in the workspace `Cargo.toml`. The CI job for the minimum supported Rust version reads it from there.
3. Update the version stated in [architecture.md](../design/architecture.md).
4. Check that every pin of `dtolnay/rust-toolchain` in `.github/workflows/` is the current commit of its `v1` tag, and refresh it if not, keeping the `# v1` comment. A current commit keeps the action's handling of toolchain versions up to date when the CI job switches to the new version. The commit is given by `gh api repos/dtolnay/rust-toolchain/commits/v1 --jq .sha`. Dependabot may propose newer commits of this action at any time, taken from its default branch rather than from the tag.
5. Check that every CI job passes with the new version.
6. Record the raise under *Changed* in a changelog fragment.
