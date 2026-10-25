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
5. An accepted ADR may be corrected for factual accuracy without a superseding ADR, provided the decision itself does not change. Examples are a version number, a reference or a statement about a third-party project. The pull request states what was corrected and why.

When the lead maintainer accepts an ADR directly, without a *Proposed* stage, the pull request states this and why. When the ADR also changes the charter, scope or roadmap, the comment period in GOVERNANCE.md applies, and it may be shortened only under the provision there.

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
| [0009](0009-keep-xades-deferred.md) | Keep XAdES deferred | Accepted |
| [0010](0010-cryptographic-backend.md) | Use RustCrypto as the cryptographic backend | Accepted |
| [0011](0011-asn1-x509-cms-foundations.md) | Build ASN.1, X.509 and CMS on the RustCrypto formats crates | Accepted |
| [0012](0012-certificate-path-validation.md) | Implement certificate path validation in sigillum | Accepted |
| [0013](0013-dss-oracle-command-line-tool.md) | Run DSS through a purpose-built command-line tool | Accepted |
| [0014](0014-test-pki-and-corpus.md) | Generate the test PKI and corpus, and verify them independently | Accepted |
| [0015](0015-pdf-reader-and-incremental-writer.md) | Implement a minimal PDF reader and an incremental-update writer | Accepted |
| [0016](0016-jades-implementation-basis.md) | Implement JAdES on sigillum's own foundations | Accepted |
| [0017](0017-defensive-api-rules.md) | Apply defensive rules to the signing and verification API | Accepted |
| [0018](0018-restrict-jades-payloads-and-detached-mechanisms.md) | Exclude unencoded JAdES payloads and restrict detached mechanisms | Accepted |
| [0019](0019-divergence-classes-and-intentional-restrictions.md) | Divergence classes and intentional restrictions | Accepted |
| [0020](0020-accepted-advisories-der-0-7.md) | Accepted advisories on the der 0.7 generation | Accepted |
| [0021](0021-x509-cert-builder-for-test-certificates.md) | Assemble test certificates with the x509-cert builder only | Accepted |
| [0022](0022-x509-cert-structures-for-test-crls.md) | Build test CRLs from x509-cert structures only | Accepted |
| [0024](0024-bounded-decoding-of-untrusted-input.md) | Bounded decoding of untrusted input | Accepted |
