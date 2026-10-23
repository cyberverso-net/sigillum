# Changelog fragments

Every change that a user or integrator would notice adds one fragment to this directory, instead of editing `CHANGELOG.md` directly. Fragments avoid merge conflicts between pull requests that change the changelog at the same time.

- One file per issue, named after the issue number: `changelog.d/<issue>.md`, for example `changelog.d/42.md`. A later pull request for the same issue edits the existing fragment. A pull request without an issue uses its own number.
- The file contains the lines to add under *Unreleased*, grouped under the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) section headings that apply: `### Added`, `### Changed`, `### Deprecated`, `### Removed`, `### Fixed`, `### Security`.
- Each line is a complete entry in the style of `CHANGELOG.md`, written for a reader of the release notes.
- A pull request that needs no changelog entry, such as a fix to a typo, adds no fragment and says so in its description.

Fragments are compiled into `CHANGELOG.md` when a release is prepared, under the heading of the new version, and the compiled files are then removed. Until release tooling does this, the maintainer merges them by hand. This file stays.
