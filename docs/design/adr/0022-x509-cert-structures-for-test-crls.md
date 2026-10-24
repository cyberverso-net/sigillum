# ADR-0022: Build test CRLs from x509-cert structures only

- **Status:** Accepted
- **Date:** 2026-10-24
- **Issue:** #28

## Context

[ADR-0014](0014-test-pki-and-corpus.md) chose `rcgen` for the CRLs it can sign, and `x509-cert` CRL structures signed by the generator for the others, because `x509-cert` 0.2 has no CRL builder. [ADR-0021](0021-x509-cert-builder-for-test-certificates.md) dropped `rcgen` for certificates, after showing that the `x509-cert` builder alone produced the same bytes, and left the choice for CRLs to #28.

The test PKI has issuing CAs that sign with RSASSA-PSS and with P-521. `rcgen` has no RSASSA-PSS algorithm identifier and supports P-521 only with its aws-lc-rs backend, so `x509-cert` structures are needed for some CRLs in any case. The generator already has signer wrappers for every algorithm in the test PKI.

## Decision

The test PKI builds every CRL from `x509-cert` CRL structures, encoded with `der` and signed through the generator's own signer wrappers. `rcgen` is not used for CRLs. This changes the CRL part of ADR-0014. With ADR-0021, `rcgen` is no longer used by the test PKI.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Follow ADR-0014: `rcgen` where it can sign, `x509-cert` structures for the rest | Higher-level interface for some CRLs | Two paths again; `rcgen` and its dependencies return for a subset of CRLs that the structures already cover |
| `x509-cert` structures only | One path, the same signer wrappers as the certificates, no new dependency | The generator encodes the CRL fields and extensions itself |

## Consequences

`sigillum-testpki` builds CRLs without `rcgen`. ADR-0014 carries a cross-reference to this ADR.
