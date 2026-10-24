# ADR-0021: Assemble test certificates with the x509-cert builder only

- **Status:** Accepted
- **Date:** 2026-10-24
- **Issue:** #27

## Context

[ADR-0014](0014-test-pki-and-corpus.md) chose two tools to assemble the certificates of the test PKI: `rcgen` for the algorithms it supports, and the `x509-cert` certificate builder for the others, such as RSASSA-PSS, SHA-3 and P-521.

The implementation of #27 encodes the extensions once and gives them to both tools. Mutation testing showed that the `x509-cert` builder alone produces byte-identical certificates for every case that `rcgen` handled: when the `rcgen` path is removed, every certificate in the corpus is reproduced unchanged. `rcgen` therefore adds a second assembly path, more code and three dependencies (`rcgen`, `yasna`, `rustls-pki-types`) without any effect on the output.

## Decision

The test PKI assembles every certificate with the `x509-cert` certificate builder, signing through the generator's own signer wrappers. `rcgen` is not used for certificates. This changes the certificate part of ADR-0014. The choice of tools for CRLs in ADR-0014 is unchanged and is decided with #28.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Keep both paths, as ADR-0014 states | Follows ADR-0014 to the letter | Two paths that produce the same bytes; a test can only prove that the second path is redundant |
| Use `rcgen` only | Higher-level interface | Has no RSASSA-PSS or SHA-3 algorithm identifiers, and supports P-521 only with its aws-lc-rs backend |
| Use the `x509-cert` builder only | One path, fewer dependencies, every algorithm in scope | Lower-level interface; extensions are encoded by the generator |

## Consequences

`sigillum-testpki` drops the `rcgen` dependency and its cargo vet exemptions. ADR-0014 carries a cross-reference to this ADR. If #28 finds that `rcgen` is needed for CRLs, that story records the choice.
