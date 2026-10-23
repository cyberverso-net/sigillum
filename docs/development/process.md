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
- the stories it depends on are done;
- it fits within [scope.md](../project/scope.md).

## Workflow

| Status | Meaning |
| --- | --- |
| Backlog | Identified, not yet ready |
| Ready | Meets the Definition of Ready |
| In progress | Being implemented on a branch |
| In review | Pull request open |
| Done | Merged and meets the Definition of Done |

Branches are named `<type>/<issue>-<short-slug>`, for example `story/42-cades-signed-attributes`. Pull requests reference their issue with `Closes #42` and are merged by squash, with a commit message that follows [CONTRIBUTING.md](../../CONTRIBUTING.md).

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

## Raising the minimum supported Rust version

The minimum supported Rust version (MSRV) is raised only in a minor release, as stated in [architecture.md](../design/architecture.md). A raise follows these steps:

1. Open an issue that states the reason for the raise and the new version. The remaining steps are made in one pull request.
2. Change `rust-version` in the workspace `Cargo.toml`. The CI job for the minimum supported Rust version reads it from there.
3. Update the version stated in [architecture.md](../design/architecture.md).
4. Check that every pin of `dtolnay/rust-toolchain` in `.github/workflows/` is the current commit of its `v1` tag, and refresh it if not, keeping the `# v1` comment. A current commit keeps the action's handling of toolchain versions up to date when the CI job switches to the new version. The commit is given by `gh api repos/dtolnay/rust-toolchain/commits/v1 --jq .sha`. Dependabot may propose newer commits of this action at any time, taken from its default branch rather than from the tag.
5. Check that every CI job passes with the new version.
6. Record the raise under *Changed* in a changelog fragment.
