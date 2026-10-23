# ADR-0010: Use RustCrypto as the default cryptographic backend

- **Status:** Accepted
- **Date:** 2026-10-23

## Context

sigillum needs digests (SHA-2, SHA-3), signature verification (RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA on P-256, P-384 and P-521, Ed25519), key transport and key agreement for CMS EnvelopedData, and random numbers. It must build for Android, iOS, macOS, Windows, Linux and `wasm32-unknown-unknown` ([ADR-0002](0002-implement-in-rust.md)). Some deployments may require a cryptographic module validated under FIPS 140-3.

Private-key operations for signing are performed outside the library ([ADR-0005](0005-two-step-signing.md)), so the library itself mostly performs public-key operations.

## Decision

The default backend is the RustCrypto family of crates (`sha2`, `sha3`, `rsa`, `p256`, `p384`, `p521`, `ed25519-dalek`, `aes`, `aes-gcm` and related crates). All cryptographic calls go through a small internal provider interface in `sigillum-pki`, so that an alternative backend can be selected at build time. A second provider based on `aws-lc-rs` is offered behind a Cargo feature for deployments that need a validated module; it is not required for any target and is not built for `wasm32`.

The `rsa` crate carries an unpatched advisory, RUSTSEC-2023-0071 (Marvin attack), on timing side channels in private-key operations. sigillum uses `rsa` for public-key operations only: signature verification and encryption to recipients. The advisory is therefore listed as an accepted exception in `deny.toml`, with this ADR as the justification. Any future feature that performs RSA private-key operations inside the library, such as local decryption of EnvelopedData, must use the `aws-lc-rs` provider or a key held by the caller, and must not rely on `rsa`.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| RustCrypto only | Pure Rust; builds for every target including `wasm32`; small binaries | No validated module; some crates pre-1.0; the `rsa` advisory |
| `aws-lc-rs` only | Validated module available; constant-time RSA | C toolchain needed for every target; no `wasm32` support; larger binaries |
| `ring` | Mature, fast | Limited algorithm set: no P-521 and no SHA-3; C and assembly code complicates some targets |
| RustCrypto by default, `aws-lc-rs` as an option | Portability by default; validated module when needed | Two providers to test |

## Consequences

The provider interface is designed in phase 1 together with `sigillum-pki`. Continuous integration tests both providers on the targets where `aws-lc-rs` builds. `deny.toml` gains an `ignore` entry for RUSTSEC-2023-0071 with a comment pointing to this ADR, added in the same change that introduces the `rsa` dependency.
