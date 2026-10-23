# sigillum

A portable, memory-safe Rust implementation of the core of European advanced electronic signatures (AdES), designed for mobile, desktop and browser environments where the Java-based [DSS](https://github.com/esig/dss) library cannot run.

> **Status: pre-alpha.** No release has been published. The code base is a skeleton and nothing in it is fit for production use. This README describes intent, not capability.

## Why

DSS (Digital Signature Service) is the reference open-source library for creating and validating AdES signatures in line with the eIDAS Regulation and the related ETSI standards. It is mature, comprehensive and well suited to JVM servers. It does not run on iOS, in a browser, or in-process within applications written in other languages.

As a result, mobile wallets, native desktop applications and browser-based tools rely on thin, creation-only stacks that typically stop at PAdES-B, embed no revocation data and perform no validation. sigillum aims to fill that gap with a single core that can be embedded everywhere, without attempting to replace DSS where DSS already serves its users well.

## What sigillum is

- A **narrow core**: CAdES, PAdES and JAdES signature creation up to baseline -LT, CMS EnvelopedData, and, in a second stage, basic signature verification.
- **Portable**: one Rust code base for Android, iOS, macOS, Windows, Linux and `wasm32`, with bindings for Kotlin, Swift and JavaScript.
- **Memory-safe**: no `unsafe` code outside the binding layer; every parser is fuzzed.
- **Verified against DSS**: every signature sigillum produces is validated by DSS in continuous integration; DSS is used as an external test oracle, never linked or copied.
- **Honest about its limits**: anything outside the supported scope produces an explicit "not supported" result, never a silent pass.

## What sigillum is not

- Not a port or a fork of DSS, and not a replacement for it.
- Not a qualified validation service, nor a substitute for one.
- Not, in its first phases, an implementation of XAdES, ASiC, archival (-LTA) signatures, legacy signature forms, or configurable validation policies.

The full scope, including what is deliberately left out, is set out in [docs/project/scope.md](docs/project/scope.md).

## Documents

The full documentation index is in [docs/README.md](docs/README.md). The main entry points are:

| Document | Purpose |
| --- | --- |
| [Charter](docs/project/charter.md) | Mission, goals and guiding principles |
| [Scope](docs/project/scope.md) | What is in scope, deferred, and excluded |
| [Roadmap](docs/project/roadmap.md) | Phases, deliverables and exit criteria |
| [Architecture](docs/design/architecture.md) | Workspace layout and design overview |
| [Architecture decision records](docs/design/adr/README.md) | The reasoning behind each key decision |
| [Conformance strategy](docs/design/conformance.md) | How equivalence with DSS and the ETSI standards is demonstrated |
| [Development process](docs/development/process.md) | How work is planned, tracked and accepted |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute, including the provenance rule |
| [SECURITY.md](SECURITY.md) | How to report vulnerabilities |
| [GOVERNANCE.md](GOVERNANCE.md) | How decisions are made |

## Licence

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT licence ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 licence, shall be dual licensed as above, without any additional terms or conditions.

## Disclaimer

sigillum is an independent open-source project developed in a personal capacity. It is not affiliated with, endorsed by, or maintained on behalf of the European Commission, the maintainers of DSS, or any trust service provider. References to DSS, eIDAS and ETSI specifications identify the works and standards concerned and imply no endorsement.
