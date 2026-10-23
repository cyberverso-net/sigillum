# Architecture decision records

An architecture decision record (ADR) captures one significant decision: the context, the decision itself, and its consequences. ADRs explain *why* the project is the way it is, so that later contributors can understand a choice before proposing to change it.

## When to write an ADR

Write an ADR for any decision that:

- affects the public API or the crate structure;
- adds, replaces or removes a significant dependency (cryptographic backend, ASN.1, PDF or XML library, binding generator);
- changes what the project supports or how it reports results;
- changes licensing, provenance rules or the conformance strategy;
- would be costly to reverse.

Routine implementation choices do not need an ADR.

## Process

1. Copy [template.md](template.md) to `NNNN-short-title.md`, using the next free number.
2. Set the status to *Proposed* and open a pull request. Link the issue that prompted the decision.
3. Discussion happens on the pull request. When the maintainer approves, set the status to *Accepted* and merge.
4. An accepted ADR is not edited in substance. To change a decision, write a new ADR that supersedes it, and set the old one's status to *Superseded by ADR-NNNN*.

## Statuses

| Status | Meaning |
| --- | --- |
| Proposed | Under discussion |
| Accepted | In force |
| Rejected | Considered and not adopted; kept for the record |
| Superseded | Replaced by a later ADR, named in the status |

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-implement-in-rust.md) | Implement in Rust | Accepted |
| [0003](0003-licence-and-contribution-terms.md) | Licence under Apache-2.0 OR MIT with a Developer Certificate of Origin | Accepted |
| [0004](0004-dss-as-test-oracle.md) | Use DSS as a test oracle | Accepted |
| [0005](0005-two-step-signing.md) | Two-step signing with an external signer | Accepted |
| [0006](0006-no-network-access-in-core.md) | No network access in the core | Accepted |
| [0007](0007-asymmetric-scope.md) | Asymmetric scope and explicit unsupported results | Accepted |
| [0008](0008-include-jades-baseline.md) | Include JAdES baseline in scope | Accepted |
| [0009](0009-keep-xades-deferred.md) | Keep XAdES deferred | Proposed |
