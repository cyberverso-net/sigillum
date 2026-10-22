# ADR-0002: Implement in Rust

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

The project must run on Android, iOS, macOS, Windows, Linux and in browsers, and be callable from Kotlin, Swift and JavaScript. A signature library parses hostile input (ASN.1, PDF) by design, and its worst failure is accepting a forged signature. Memory-safety defects in parsers are a recurring source of such failures in signature software.

## Decision

sigillum is implemented in Rust. Bindings are generated with UniFFI for Kotlin and Swift and with `wasm-bindgen` for JavaScript. `unsafe` code is forbidden in every crate except the binding layer.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Java with GraalVM native image | Mature libraries (BouncyCastle, PDFBox) | No iOS and no WebAssembly support in practice |
| Kotlin Multiplatform | Natural for Android wallets; reaches iOS | No CMS, PDF or XML signature support on Kotlin/Native; no route to browsers or other languages |
| Go | Strong standard cryptography | Heavy runtime on mobile; large WebAssembly output; weak XML canonicalisation |
| Swift | Natural on iOS | Apple platforms only in practice |
| C or C++ | Available everywhere; existing libraries | No memory safety; repeats the parser risk |
| Rust | Reaches every target from one code base; memory-safe; good ASN.1 and X.509 foundations | AdES-level components (CMS signing, timestamps, revocation, PDF incremental signing) must be built |

## Consequences

Generic building blocks missing from the Rust ecosystem are built in this project or contributed upstream. Bindings must be maintained for each target language. The minimum supported Rust version is stated in [architecture.md](../architecture.md).
