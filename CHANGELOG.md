# Changelog

All notable changes to this project are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project charter, scope and roadmap.
- Architecture overview, conformance strategy and register of divergences from DSS.
- Architecture decision records 0001 to 0007.
- ADR-0008, bringing JAdES baseline (B-B to B-LT) into scope, and the `sigillum-jades` crate skeleton.
- ADR-0009, recording why XAdES remains deferred.
- Provision in the governance for the lead maintainer to shorten the comment period on charter, scope and roadmap changes, with the reason stated in the pull request.
- Development process, quality gates and writing style guide.
- Cargo workspace skeleton with the phase 1 crates.
- Contribution rules (Developer Certificate of Origin, provenance rule), security policy and governance.
- Issue forms for epics, stories, tasks and bugs, and a pull request template.
- Continuous integration for formatting, linting, tests on Linux, macOS and Windows, documentation, the minimum supported Rust version, WebAssembly and mobile targets, licence checks and commit sign-off; Dependabot updates.
- Requirement for signed commits, enforced by a continuous integration check on pull requests and by the ruleset on `main`, and documented in the contribution rules.

### Changed

- Regulation references in ADR-0008, ADR-0009 and the scope aligned with the Official Journal text, including the target versions of the standards.
- CAdES and PAdES crate documentation cites part 1 of each standard for the baseline levels.
