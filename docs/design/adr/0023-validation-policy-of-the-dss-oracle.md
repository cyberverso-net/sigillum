# ADR-0023: Validation policy of the DSS oracle

- **Status:** Accepted
- **Date:** 2026-10-25
- **Issue:** #75

## Context

The corpus predictions in `testdata/manifest.toml` follow [ETSI EN 319 102-1 V1.4.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf). The `validate-certificate` mode of `tools/dss-oracle` ([ADR-0013](0013-dss-oracle-command-line-tool.md)) ran DSS 6.5.1 with its default certificate validation policy. On the corpus, 15 results differed from the predictions. [ADR-0019](0019-divergence-classes-and-intentional-restrictions.md) requires each difference to be a corrected prediction or a recorded divergence.

Seven of the differences come from four parameters of the default policy. ETSI EN 319 102-1 V1.4.1 leaves each of them to the validation policy, through the X.509 validation constraints and the cryptographic constraints (clause 5.2.6.2, Table 12):

| Parameter | Default policy of DSS 6.5.1 | Cases |
| --- | --- | --- |
| Signature algorithms | EdDSA is not an acceptable algorithm | `pki/signer-ed25519`, `crl/ca-ed25519`, `ocsp/signer-ed25519`: INDETERMINATE with CRYPTO_CONSTRAINTS_FAILURE_NO_POE |
| Revocation freshness | Not checked | `crl/ca-ecdsa-expired`: PASSED, while clause 5.2.5.4 and clause 5.2.6.4, step 4 a), give TRY_LATER |
| Unknown critical extensions | A warning only | `pki/signer-unknown-critical-extension`, `ocsp/signer-unknown-critical-extension`: PASSED, while [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280), sections 6.1.4 (o) and 6.1.5 (f), require the path to fail |
| `id-pkix-ocsp-nocheck` | Not a reason to skip revocation checking of the certificate under validation | `pki/ocsp-responder`: INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE, while [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960), section 4.2.2.2.1, and clause 5.2.6.4, step 4, EXAMPLE 2, let a client trust such a responder without checking its revocation |

The comparisons need a policy that is stated, versioned and reproducible, and that differs from what DSS ships only where the standard leaves the choice to the policy. The policy that DSS ships is DSS material under LGPL-2.1 and is not copied into the repository.

## Decision

The oracle validates with an **aligned policy**, defined in `tools/dss-oracle`. It is built at run time from the default policy that DSS ships in `dss-policy-jaxb`: `policy/certificate-constraint.xml` for `validate-certificate`, and `policy/constraint.xml` for `validate-timestamp` and the planned `validate-document`. The tool reads that policy through the public policy API of DSS (`ValidationPolicyFacade`), applies the deltas below in code (`AlignedPolicy`), and validates with the result. It copies no policy file of DSS.

The deltas change only parameters that ETSI EN 319 102-1 V1.4.1 leaves to the validation policy. Each is exposed as a constraint of the DSS 6.5.1 policy schema (`xsd/policy.xsd` in `dss-policy-jaxb`):

| Delta | Reason | DSS constraint | Effect on the corpus |
| --- | --- | --- | --- |
| 1. Accept Ed25519 | sigillum supports Ed25519 ([scope](../../project/scope.md), [ADR-0010](0010-cryptographic-backend.md)), and the corpus has an Ed25519 family. The cryptographic constraints are an input of clause 5.2.6.4, step 6 | `Cryptographic/AcceptableEncryptionAlgo/Algo` with the value `EdDSA`; `Cryptographic/MiniPublicKeySize/Algo` and `Cryptographic/AlgoExpirationDate/Algo` with `EdDSA`, a size of 32 and no expiry date. DSS 6.5.1 measures an EdDSA key in octets, 32 for Ed25519 | `pki/signer-ed25519`, `crl/ca-ed25519`, `ocsp/signer-ed25519`: PASSED, as predicted |
| 2. Check revocation freshness | Clause 5.2.5.4, step 1: without a maximum freshness in the constraints, the interval from `thisUpdate` to `nextUpdate` is the maximum. Clause 5.2.6.4, step 4 a), gives TRY_LATER when the checker fails | In every `CertificateConstraints`: `RevocationFreshness` removed, so that DSS falls back to `nextUpdate` minus `thisUpdate`, and `RevocationFreshnessNextUpdate` at level `FAIL` | `crl/ca-ecdsa-expired`: INDETERMINATE with TRY_LATER, as predicted |
| 3. Fail on unknown critical extensions | RFC 5280, sections 6.1.4 (o) and 6.1.5 (f): a critical extension that is not recognised and processed makes the path invalid. Clause 5.2.6.4, step 4, follows RFC 5280, section 6.1 | In every `CertificateConstraints`: `SupportedCriticalExtensions` at level `FAIL`, with the list of DSS unchanged. That list lacks policyMappings (2.5.29.33), which RFC 5280, section 6.1.4, processes and DSS 6.5.1 does not, so a CA certificate with a critical policyMappings extension fails under this delta, a limitation of DSS | `pki/signer-unknown-critical-extension`, `ocsp/signer-unknown-critical-extension`: INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE, as predicted |
| 4. Honour `id-pkix-ocsp-nocheck` | RFC 6960, section 4.2.2.2.1: a CA may let clients trust a responder for the lifetime of its certificate. Clause 5.2.6.4, step 4, exempts the certificates for which the constraints state that revocation checking is not performed, with this case as EXAMPLE 2 | In the `CertificateConstraints` of every signing certificate: `RevocationDataSkip/CertificateExtensions/Id` with `1.3.6.1.5.5.7.48.1.5`. Where the default policy has no `RevocationDataSkip`, as for timestamps, one is added at level `INFORM`. In `constraint.xml`, the signing certificates of signatures, counter-signatures and timestamps also have `ForbiddenExtensions` with `id-pkix-ocsp-nocheck` at level `FAIL`, so the skip has no effect there. In `certificate-constraint.xml`, the delta applies the exemption that RFC 6960 gives OCSP responders to any certificate under validation that carries the extension, not only to responders | `pki/ocsp-responder`: PASSED, as predicted |

The aligned policy has a version, now 1. A change to the deltas takes the next version. `summary.json` names the policy of each run in its member `policy`: `aligned-1`, `default` for the policy of DSS unchanged, or, for a policy file, an object with the file as named on the command line and the SHA-256 digest of its content. The simple report of DSS names the aligned policy "sigillum aligned policy 1, from" followed by the name of the policy of DSS.

Every validation mode takes the option `--policy aligned|default|<file>`, and uses the aligned policy without it; `validate-document` (#37) takes the same option and the same default. Any value other than the two names is the path of a DSS policy file, which the tool loads through the public policy API of DSS (`ValidationPolicyLoader`), checked against the policy schema of DSS. A file named `aligned` or `default` is given with a path, such as `./aligned`. A policy file is an input like the others, under the rules of [ADR-0013](0013-dss-oracle-command-line-tool.md): a missing file is a failure of the tool, and a file that DSS cannot load, or with which DSS cannot complete a validation that the aligned policy completes, gives the result `rejected`. One class of the tool, `PolicySelection`, selects the policy for every mode.

Comparisons with the corpus predictions, and later with sigillum, use the aligned policy. A run with the default policy of DSS is recorded for information only and does not gate. The test `ValidateCertificateTest` runs both and prints a table; the README of the tool records it.

The differences that remain under the aligned policy are recorded in [divergences.md](../divergences.md). One property needed a fifth delta that the schema cannot express: RFC 6960, section 4.2.2.2, requires `id-kp-OCSPSigning` in the certificate of a delegated responder. The schema has an `ExtendedKeyUsage` constraint, but its one set of constraints for revocation data (`Revocation/BasicSignatureConstraints/SigningCertificate`) applies to the signers of CRLs and of OCSP responses alike, and to a CA that signs its own responses. Requiring `id-kp-OCSPSigning` there would reject valid CRLs and responses. It is recorded as a divergence of the first class instead.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| The default policy of DSS only | Nothing to maintain; the oracle is DSS as shipped | Seven cases of the corpus become divergences that reflect choices of DSS's policy, not of the standard. sigillum would need its own Ed25519 results recorded as divergences, although the standard leaves the algorithms to the policy |
| A fully custom policy, written for sigillum | Every constraint chosen deliberately | Hundreds of constraints to choose and maintain at each DSS upgrade, most of them irrelevant to the corpus; differences from DSS behaviour would be hard to tell from differences of policy; a policy file derived from DSS's would bring LGPL-2.1 material into the repository |
| The default policy of DSS with documented deltas, built at run time | Each difference from DSS as shipped is listed with its basis; nothing of DSS is copied; a DSS upgrade brings its new defaults automatically | The deltas depend on the policy schema of DSS, and a change to it at an upgrade must be checked |

## Consequences

`tools/dss-oracle` has the option `--policy`, and `summary.json` has the member `policy` (format version 2). Policy files join the inputs of the mutation test of the tool. The corpus test of `validate-certificate` compares every case with its prediction under the aligned policy and fails on any difference that divergences.md does not record. A DSS upgrade, or a change of the default policy of DSS, requires the deltas to be checked against the new schema and policy. #37 uses the same option and default for `validate-document`.
