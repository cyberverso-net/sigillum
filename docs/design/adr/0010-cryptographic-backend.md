# ADR-0010: Use RustCrypto as the cryptographic backend

- **Status:** Accepted
- **Date:** 2026-10-23
- **Issue:** #19

## Context

sigillum needs digests (SHA-2, SHA-3), signature verification (RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA on P-256, P-384 and P-521, Ed25519), key transport and key agreement for CMS EnvelopedData, and random numbers. It must build for Android, iOS, macOS, Windows, Linux and `wasm32-unknown-unknown` ([ADR-0002](0002-implement-in-rust.md)).

Private-key operations for signing are performed outside the library ([ADR-0005](0005-two-step-signing.md)). The library itself mostly performs public-key operations.

## Decision

The backend is the RustCrypto family of crates (`sha2`, `sha3`, `rsa`, `p256`, `p384`, `p521`, `aes`, `aes-gcm` and related crates), together with `ed25519-dalek` from the dalek-cryptography project for Ed25519. All cryptographic calls go through a small internal provider interface in `sigillum-pki`. A second provider can therefore be added later without changing the format crates.

A provider based on a validated module, such as `aws-lc-rs` in FIPS mode, is not part of this decision. Its licence terms (which include the OpenSSL licence), its build requirements and its platform coverage on Android and iOS need their own assessment. It will be the subject of a separate ADR if a user needs it.

The `rsa` crate carries an unpatched advisory, RUSTSEC-2023-0071 (Marvin attack), on timing side channels in private-key operations. Library crates use `rsa` for public-key operations only: signature verification and encryption to recipients. The rule is enforced in two ways:

1. `clippy.toml` lists `rsa::RsaPrivateKey` and every type built on it under `disallowed-types`: `rsa::pkcs1v15::SigningKey`, `rsa::pss::SigningKey`, `rsa::pss::BlindedSigningKey`, `rsa::pkcs1v15::DecryptingKey` and `rsa::oaep::DecryptingKey`. It lists the private-key functions of `rsa::hazmat`, `rsa_decrypt` and `rsa_decrypt_and_check`, under `disallowed-methods`. Library crates deny `clippy::disallowed_types` and `clippy::disallowed_methods`. Test code, `sigillum-testpki` and examples may allow these lints locally, because timing attacks do not apply to test keys.
2. `deny.toml` lists RUSTSEC-2023-0071 as an accepted advisory, with a comment pointing to this ADR.

Any future feature that performs RSA private-key operations inside the library, such as local decryption of EnvelopedData, needs a constant-time provider and a new ADR.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| RustCrypto | Pure Rust; builds for every target including `wasm32`; small binaries | No validated module; some crates pre-1.0; the `rsa` advisory |
| `aws-lc-rs` | Validated module available; constant-time RSA | C toolchain for every target; no `wasm32`; licence of the FIPS build and platform coverage to assess |
| `ring` | Mature, fast | No P-521, no SHA-3, no RSA encryption, which EnvelopedData needs |

## Consequences

The provider interface is designed in phase 1 together with `sigillum-pki`. The `clippy.toml` rule and the `deny.toml` entry are added in the same change that introduces the `rsa` dependency.
