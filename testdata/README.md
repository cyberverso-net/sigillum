# Test corpus

This directory holds the test corpus of sigillum: certificates, CRLs, OCSP responses, timestamp tokens and signed documents, generated as described in [ADR-0014](../docs/design/adr/0014-test-pki-and-corpus.md). Every artefact is listed in `manifest.toml`, with its purpose and the results expected from OpenSSL and DSS. The program `sigillum-testpki` (in `crates/sigillum-testpki`) generates the artefacts and checks them against the manifest. Its `tsa` subcommand issues timestamp tokens with a time, key and certificate given explicitly, and does not read the manifest.

Seven generators write the corpus, in this order: `generate pki`, then `generate crls`, `generate timestamps` and `generate ocsp`, which link the certificates that `generate pki` records, then `generate documents`, which writes the unsigned base documents, then `generate signed`, which has DSS sign them, and last `generate mutations`, which derives malformed variants from the signatures. Each owns the entries described in its section below, keeps every other entry, and follows the regeneration rules of the test PKI.

## Manifest format

`manifest.toml` is a TOML file with one required `[header]` table and one `[[artefact]]` table per artefact, possibly none. Unknown fields are rejected, and a text field that holds only spaces counts as empty. Paths are relative to the directory that contains the manifest. The generators write it with one field per line, in the order below, and inline tables on one line. The tests of `tools/dss-oracle` read it with a reader of that layout, not a TOML parser, which refuses a `dss-divergence` in any other layout; a manifest edited by hand keeps that layout.

### Header

| Field | Content |
| --- | --- |
| `format-version` | The version of this format, currently `3`. Other versions are rejected. Version 2 added `dss-divergence`, and version 3 added `attack-class`. |
| `validation-time` | The fixed validation time of the corpus, of the exact form `YYYY-MM-DDTHH:MM:SSZ`, for example `"2030-01-15T10:00:00Z"`: UTC, whole seconds, no leap second. Every time field of every artefact is chosen relative to it, and the subcommands `generate` and `verify` of `sigillum-testpki` read it from here. |
| `openssl-version` | The OpenSSL version whose results the manifest records, written as the version number only, for example `"3.5.9"` (`openssl version` prints `OpenSSL 3.5.9 29 Sep 2026`). The parser checks only that it is not empty. `verify --openssl` runs only with this release, as described under Verification with OpenSSL. |
| `dss-version` | The DSS version whose results the manifest records, for example `"6.5.1"`. It is the version that `tools/dss-oracle` is built against. The parser checks only that it is not empty. `verify --dss` runs only with a tool built against this version, as described under Verification with DSS. |

### Artefact

| Field | Content |
| --- | --- |
| `id` | Unique identifier, for example `"pki/root-ca"`, with the same character rules as `path`. |
| `path` | Path of the file. Parts are separated by `/`. Each part is non-empty, contains only letters, digits, `.`, `_` and `-`, and is not `.`, `..` or a name that Windows reserves for devices: `CON`, `PRN`, `AUX`, `NUL`, `COM1` to `COM9` or `LPT1` to `LPT9`, with or without an extension. `COM0` and `LPT0` are refused as well, to be safe. A part does not end with `.`. The root files `manifest.toml` and `README.md` are reserved. Ignoring letter case, two artefacts may not name the same file, a file may not also be a directory, and a directory is spelt the same way in every path. |
| `sha256` | SHA-256 digest of the file, as 64 lower-case hexadecimal digits. |
| `kind` | One of `certificate`, `private-key`, `crl`, `ocsp-response`, `timestamp-token`, `signed-document`, `document`. |
| `purpose` | Why the artefact exists, in one sentence. |
| `expected-openssl` | The result expected from OpenSSL: `verified`, `parsed` (parsing only, as for private keys), `rejected`, or `not-applicable` (OpenSSL does not process this kind of artefact). Where OpenSSL can check part of an artefact only against the current time, `verified` covers the rest, and the notes of the entry say so, as for the OCSP responses. |
| `expected-dss` | The result expected from DSS: `"not-applicable"` when DSS does not process this kind of artefact, such as a private key or an unsigned document; `"rejected"` when DSS cannot parse it; otherwise a table `{ indication = "...", sub-indication = "..." }` with the result of a validation that DSS could run. |
| `dss-divergence` | Optional table for an artefact on which DSS gives another result than `expected-dss` predicts, a divergence recorded in `docs/design/divergences.md`: `{ entry = "DIV-5", indication = "...", sub-indication = "..." }`. `entry` names the row of the register, as `DIV-` followed by a number from 1 without leading zeros. `indication` and the optional `sub-indication` give the result that DSS gives, with the rules of `expected-dss`. That result must differ from `expected-dss`, which may not be `"not-applicable"`. The field always holds an indication; see the known limitation below. A test of `sigillum-testpki` checks that the row exists and names the artefact. |
| `attack-class` | Optional, for a malformed PAdES document: the class of attack on PDF signatures that it carries, one of `incremental-saving` (threat D1 of the [threat model](../docs/design/threat-model.md)), `shadow-hide`, `shadow-replace`, `shadow-hide-and-replace` (D2), `signature-wrapping` (D3) and `universal-signature-forgery` (D4). Allowed only on a PAdES signed document: an artefact of kind `signed-document` whose path ends with `.pdf`, ignoring letter case, since the manifest records no format. |
| `links` | Optional table of other artefacts, by identifier, needed to check this one. `issuer` names the issuer's certificate. `chain` lists the certificates above this artefact, from its issuer up to the trust anchor; when both are given, `chain` starts with `issuer`. `revocation` lists CRLs and OCSP responses. `content` names the signed content of a detached signature, or the data a timestamp covers, of any kind. `timestamp-chain`, for a signed document with a signature timestamp, lists the certificate of the timestamping authority and the certificates above it, up to the trust anchor, because a token may hold only the certificate of its authority. For a timestamp token and a signed document, `issuer` names the certificate that signed it, and `chain` starts with that certificate. Every identifier must name another artefact of the manifest; `issuer`, `chain` and `timestamp-chain` must name certificates, and `revocation` CRLs or OCSP responses. A list may not name one artefact twice. |
| `notes` | Optional remarks; not empty when present. |

The indication is one of `TOTAL-PASSED`, `TOTAL-FAILED`, `INDETERMINATE` (ETSI EN 319 102-1 V1.4.1, clause 5.1.3), or `PASSED`, `FAILED` for building blocks such as certificate validation. The sub-indication is optional and must be one that Table 6 of that standard defines for the indication. `TOTAL-PASSED` and `PASSED` take none, `TOTAL-FAILED` takes the `TOTAL-FAILED` list, and `INDETERMINATE` takes its own list, which includes `CUSTOM`. Table 6 defines no list for the building-block indications. This project gives `FAILED` the `TOTAL-FAILED` list, and uses the `INDETERMINATE` list for building blocks too. Indications are written with hyphens, as in the standard; DSS reports them with underscores, and `verify` maps one to the other.

Later stories add the fields they need, such as the format of signed documents. A new format version is introduced where a change alters the meaning of an existing manifest.

Known limitation of format versions 2 and 3: `dss-divergence` cannot express a divergence in which DSS rejects an artefact for which the manifest predicts an indication, because the field always holds an indication. The first fixture that needs it changes the format in its own story.

Example:

```toml
[[artefact]]
id = "pki/signer-p256"
path = "pki/signer-p256.pem"
sha256 = "<64 hexadecimal digits>"
kind = "certificate"
purpose = "End-entity signing certificate with an ECDSA P-256 key."
expected-openssl = "verified"
expected-dss = { indication = "PASSED" }
links = { issuer = "pki/ca-ecdsa", chain = ["pki/ca-ecdsa", "pki/root-ca"] }
```

## Test PKI

`sigillum-testpki generate pki` writes the test PKI under `pki/` and records each file in `manifest.toml`. Regeneration is an explicit step, not part of the build. A test checks that the committed files are what the generator produces. Every certificate is assembled by the `x509-cert` certificate builder, as [ADR-0021](../docs/design/adr/0021-x509-cert-builder-for-test-certificates.md) decides.

Regeneration works as follows:

- Entries with the same identifiers are replaced, and new ones are appended. The `revocation` links of a replaced entry are kept, because `generate crls` and later generators set them.
- `generate pki` owns every certificate and private-key entry under `pki/`. Those that the generator no longer produces are removed from the manifest, and their files are left in place. Certificates and keys made by other means, such as the mutated variants that ADR-0014 plans, must therefore live outside `pki/`. Entries of other kinds, and entries outside `pki/`, are kept.
- Files under `pki/` that no manifest entry names are reported on standard error, and left in place.
- The manifest is written anew, so comments added to it by hand are lost.
- The artefact files are written first, and the files under the generator's own directory are then listed: `pki/` for `generate pki`, `crl/` for `generate crls`, `timestamps/` for `generate timestamps`, `ocsp/` for `generate ocsp`. Every generator writes the corpus through the same steps, so these guarantees hold for all four. The manifest is written last, through a temporary file renamed over it, so a failure at any step, including a directory of the generator that cannot be read, leaves the previous manifest in place, possibly beside some new artefact files. Running the command again brings them back in step.

| Certificates | Content |
| --- | --- |
| `pki/root-ca` | Self-signed root CA, RSA 3072-bit key, the trust anchor of every chain |
| `pki/ca-rsa`, `pki/ca-rsa-pss`, `pki/ca-ecdsa`, `pki/ca-ed25519` | One issuing CA per signature family: RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA (P-384 key, SHA-384) and Ed25519 |
| `pki/ca-ecdsa-p521` | A second ECDSA issuing CA, with a P-521 key that signs with SHA-512 |
| `pki/signer-*` | End-entity signing certificates: RSA PKCS#1 v1.5 with 2048-bit and 3072-bit keys, RSASSA-PSS with SHA-256 and SHA-384, ECDSA with P-256 and P-384 keys (issued by `pki/ca-ecdsa`) and a P-521 key (issued by `pki/ca-ecdsa-p521`), Ed25519, and RSA PKCS#1 v1.5 with SHA3-256 |
| `pki/tsa` | Timestamping authority, with the critical extended key usage `id-kp-timeStamping` (RFC 3161, section 2.3) |
| `pki/ocsp-responder` | Delegated OCSP responder of `pki/ca-ecdsa`, with `id-kp-OCSPSigning` and `id-pkix-ocsp-nocheck` (RFC 6960, section 4.2.2.2) |
| `pki/signer-expired`, `pki/signer-not-yet-valid` | Expired one day before, and valid from one day after, the validation time |
| `pki/ca-expired`, `pki/signer-under-expired-ca` | An intermediate CA that expired one day before the validation time, and an end entity it issued that is still valid |
| `pki/signer-without-non-repudiation` | End entity whose key usage lacks `nonRepudiation` |
| `pki/ca-without-ca-flag`, `pki/signer-under-ca-without-ca-flag` | A CA certificate whose basic constraints leave `cA` at its default, FALSE, and an end entity it issued |
| `pki/ca-without-basic-constraints`, `pki/signer-under-ca-without-basic-constraints` | A CA certificate without the basic constraints extension, and an end entity it issued |
| `pki/signer-unknown-critical-extension` | End entity with the critical extension `1.3.6.1.4.1.32473.1.1`, which no implementation recognises, and a DER NULL as its value |
| `pki/signer-rsa-revoked`, `pki/signer-rsa-pss-revoked`, `pki/signer-p256-revoked`, `pki/signer-ed25519-revoked` | One end entity per signature family, revoked for key compromise 60 days before the validation time, before the planned signing time |
| `pki/signer-p256-revoked-after-signing` | End entity of the ECDSA family, revoked for key compromise 10 days before the validation time, after the planned signing time |

The certificates follow RFC 5280, sections 4.1 and 4.2:

- Every time is a fixed offset from the validation time: the root is valid from three years before to ten years after it, the issuing CAs from two years before to five years after, and the end entities from one year before to two years after, except the validity cases.
- Serial numbers are fixed and unique in the test PKI.
- Subject key identifiers use method 1 of RFC 7093, section 2. Every certificate but the root carries the authority key identifier of its issuer.
- The planned signing time of the signed corpus is 30 days before the validation time, 2029-12-16T10:00:00Z. The revoked end entities are separate certificates, so that the other signers stay valid for the fixtures that use them. Their revocations are recorded in the CRLs below.
- Every certificate but the root carries a CRL distribution point and authority information access URIs under `http://example.invalid/`, a domain reserved by RFC 2606 that never resolves. End entities other than the OCSP responder also name an OCSP responder.
- Algorithm identifiers follow RFC 4055 for RSA, RFC 5758 for ECDSA and RFC 8410 for Ed25519. SHA3-256 with RSA PKCS#1 v1.5 uses the identifier of the NIST Computer Security Objects Register, `2.16.840.1.101.3.4.3.14`, with NULL parameters, as OpenSSL encodes it; the register does not specify the parameters.

### Timeline

Every time of the test PKI, in order, for the validation time `2030-01-15T10:00:00Z`. All times are at 10:00:00 UTC. Stories that sign at the planned signing time, or timestamp or validate later, refer to this list. A test checks that the planned signing time falls inside the validity of every certificate that valid fixtures use, and of the CAs above it.

| Time | Offset | Event |
| --- | --- | --- |
| 2027-01-15 | 3 years before | `notBefore` of `pki/root-ca` and `pki/ca-expired` |
| 2028-01-15 | 2 years before | `notBefore` of the other CA certificates |
| 2029-01-15 | 1 year before | `notBefore` of the end entities, except `pki/signer-not-yet-valid` |
| 2029-11-16 | 60 days before | Revocation of `pki/signer-rsa-revoked`, `pki/signer-rsa-pss-revoked`, `pki/signer-p256-revoked` and `pki/signer-ed25519-revoked` |
| 2029-12-16 | 30 days before | Planned signing time |
| 2030-01-01 | 14 days before | `thisUpdate` of `crl/ca-ecdsa-expired` |
| 2030-01-05 | 10 days before | Revocation of `pki/signer-p256-revoked-after-signing` |
| 2030-01-08 | 7 days before | `nextUpdate` of `crl/ca-ecdsa-expired` |
| 2030-01-13 | 2 days before | `producedAt` and `thisUpdate` of `ocsp/signer-expired-before-expiry` |
| 2030-01-14 | 1 day before | `thisUpdate` of the other CRLs; `producedAt` and `thisUpdate` of the other OCSP responses, except the `producedAt` of `ocsp/produced-at-after-validation-time`; `notAfter` of `pki/signer-expired` and `pki/ca-expired` |
| 2030-01-15 | 0 | Validation time; `thisUpdate` of `crl/ca-ecdsa-expired-certs` |
| 2030-01-16 | 1 day after | `notBefore` of `pki/signer-not-yet-valid`; `producedAt` of `ocsp/produced-at-after-validation-time` |
| 2030-01-20 | 5 days after | `nextUpdate` of `ocsp/signer-expired-before-expiry` |
| 2030-01-21 | 6 days after | `nextUpdate` of the other CRLs, except `crl/ca-ecdsa-expired` and `crl/ca-ecdsa-expired-certs`, and of the other OCSP responses |
| 2030-01-22 | 7 days after | `nextUpdate` of `crl/ca-ecdsa-expired-certs` |
| 2031-01-15 | 1 year after | `notAfter` of `pki/signer-not-yet-valid` |
| 2032-01-15 | 2 years after | `notAfter` of the other end entities. Horizon of the signed corpus: while DSS 6.5.1 adds the B-LT validation data, it checks certificates at the time of the clock, which no public setting of DSS changes, so `generate signed` may fail after this date |
| 2035-01-15 | 5 years after | `notAfter` of the CA certificates, except `pki/ca-expired` |
| 2040-01-15 | 10 years after | `notAfter` of `pki/root-ca` |

### Test object identifiers

Object identifiers that the test corpus needs, and that no standard defines, sit under the sigillum test arc `1.3.6.1.4.1.32473.1`. The arc uses Enterprise Number 32473, which RFC 5612, section 2, allocates for use in examples and documentation. New test object identifiers are added to this table only.

| Object identifier | Use |
| --- | --- |
| `1.3.6.1.4.1.32473.1` | The sigillum test arc |
| `1.3.6.1.4.1.32473.1.1` | The unknown critical extension of `pki/signer-unknown-critical-extension` |
| `1.3.6.1.4.1.32473.1.2` | The policy of the test timestamping authority, in the `TSTInfo` of every token that `sigillum-testpki` issues |

Generation is reproducible byte for byte with the same validation time and the same `Cargo.lock`. Each key is derived from its name by a deterministic generator, SHA-256 in counter mode, so the keys are public by construction. RSA PKCS#1 v1.5, ECDSA on P-256 and P-384 (RFC 6979) and Ed25519 signatures are deterministic. Each RSASSA-PSS salt is derived from the signed data by the same generator. ECDSA signatures on P-521 are reproducible too: the `p521` crate offers no RFC 6979 signer, so each nonce is derived by the same generator from the private key and the signed data, as RFC 6979 derives it from both. A change of the RSA or elliptic-curve crates may change the keys, and then every certificate.

The expected OpenSSL results are those of `openssl verify` at the validation time (`-attime`), with the chain of the manifest and default flags. When the certificate links a CRL in `revocation`, the check adds `-crl_check_all` and every CRL linked by the certificate and by the certificates of its chain, each given with `-CRLfile`. `openssl verify` takes no OCSP responses, so the responses that a certificate links are checked on their own, as described under OCSP responses. `pki/ca-without-ca-flag` and `pki/ca-without-basic-constraints` verify with default flags and fail with `-x509_strict`. Private keys are expected to parse. The expected DSS results are those of the X.509 certificate validation of ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, given the CRLs and OCSP responses that the certificates link. The `validate-certificate` mode of `tools/dss-oracle` confirms them with DSS 6.5.1 under the aligned validation policy of [ADR-0023](../docs/design/adr/0023-validation-policy-of-the-dss-oracle.md), except for the divergences recorded in [divergences.md](../docs/design/divergences.md). The revoked end entities are predicted INDETERMINATE with REVOKED_NO_POE, from clause 5.2.6.4, step 4 b). The validity cases are predicted as follows:

- `pki/signer-expired` and `pki/ca-expired`: INDETERMINATE with OUT_OF_BOUNDS_NO_POE, from step 7. Their revocation data were issued at the instant they expired, within their validity, because `notAfter` is inclusive (RFC 5280, section 4.1.2.5). No CRL carries `expiredCertsOnCRL` and no response `archiveCutoff`, so no status after expiry is shown. NOTE 8 of clause 5.2.6.4, which is informative, describes a certificate known not to have been revoked as one whose CA keeps providing status after expiry, checked, or whose CA assures that it was not revoked at signing time. DSS 6.5.1 reports OUT_OF_BOUNDS_NOT_REVOKED, the divergence DIV-5. Two fixtures separate the readings: `ocsp/signer-expired-before-expiry` and `crl/ca-ecdsa-expired-certs`, described below.
- `pki/signer-not-yet-valid`: INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE, from step 4 e). Its revocation data were issued two days before its `notBefore`, which the standard takes as its issuance date (clauses 5.5.4 and 5.6.2.4.4), so they are not known to contain revocation status information about it, as step 4 requires. DSS 6.5.1 reaches the same result through its `RevocationAfterCertificateIssuance` constraint. The path validation cannot show that it is not revoked (RFC 5280, section 6.1.3, step (a)(3)), and step 4 fails before step 7 checks the validity period.
- `pki/signer-under-expired-ca`: INDETERMINATE with REVOCATION_OUT_OF_BOUNDS_NO_POE, from step 8. Its CA, `pki/ca-expired`, has expired and also issued its revocation data. Step 4 does not check the validity of the issuer of the revocation data at the validation time, which NOTE 6 defers to step 8, and clause 5.6.2.4.4 handles that result with proofs of existence.

## CRLs

`sigillum-testpki generate crls` writes the CRLs of the test PKI under `crl/` and records each in `manifest.toml`. It reads the validation time from the manifest, like `generate pki`, and runs after it, because the CRL entries link the certificates. Every CRL is built from the `x509-cert` CRL structures, encoded with `der` and signed by the generator, as [ADR-0022](../docs/design/adr/0022-x509-cert-structures-for-test-crls.md) decides. A test checks that the committed files are what the generator produces.

Regeneration follows the rules of `generate pki`, with these differences:

- `generate crls` owns every CRL entry under `crl/`. The `revocation` links of a replaced CRL entry are kept. Those it no longer produces are removed from the manifest, with every `revocation` link to them, and their files are left in place. Files under `crl/` that no manifest entry names are reported.
- It also owns the links to its CRLs in the `revocation` lists of the certificate entries under `pki/`. Each certificate whose issuer has a current CRL links that CRL, in first place. Other `revocation` links, such as OCSP responses, are kept.

Each CRL is a DER file named after the CRL distribution point of the certificates it covers: `http://example.invalid/crl/ca-ecdsa.crl` is `crl/ca-ecdsa.crl`. RFC 5280, section 4.2.1.13, requires a DER-encoded CRL behind an HTTP distribution point. The CRLs follow RFC 5280, section 5:

- Every CRL is a version 2 CRL, signed with an algorithm its issuer uses for certificates, with the issuer name of the issuer's certificate.
- It carries two non-critical extensions: the authority key identifier of its issuer (section 5.2.1) and a CRL number (section 5.2.3), 2 for the current CRLs, 1 for the expired one and 3 for `crl/ca-ecdsa-expired-certs`, which also carries expiredCertsOnCRL.
- It lists the certificates of its issuer revoked on or before its `thisUpdate`, by serial number, each with a non-critical reason code (section 5.3.1). When none is revoked, the list is absent (section 5.1.2.6).
- Times are UTCTime through 2049 and GeneralizedTime from 2050 (section 5.1.2.4).
- Delta CRLs and indirect CRLs are out of scope.

| CRLs | Content |
| --- | --- |
| `crl/root-ca` | Current CRL of the root CA, linked by every CA certificate it issued; it revokes none |
| `crl/ca-rsa`, `crl/ca-rsa-pss`, `crl/ca-ecdsa`, `crl/ca-ecdsa-p521`, `crl/ca-ed25519` | Current CRL of each issuing CA of a signature family, with `thisUpdate` one day before and `nextUpdate` six days after the validation time. Each lists the revoked end entities of its CA; `crl/ca-ecdsa-p521` lists none |
| `crl/ca-expired`, `crl/ca-without-ca-flag`, `crl/ca-without-basic-constraints` | Current CRL of each misconfigured CA, with the same times; none revokes a certificate. `crl/ca-expired` is issued at the instant its CA expires, still within the CA's validity, because `notAfter` is inclusive (RFC 5280, section 4.1.2.5). Their end entities link them, so that they fail only for the defect of their CA |
| `crl/ca-ecdsa-expired` | An earlier CRL of `pki/ca-ecdsa`, with `thisUpdate` 14 days and `nextUpdate` 7 days before the validation time. It lists `pki/signer-p256-revoked` only |
| `crl/ca-ecdsa-wrong-key` | The current CRL of `pki/ca-ecdsa`, signed with the key of `pki/signer-p384` |
| `crl/ca-ecdsa-wrong-issuer` | The current CRL of `pki/ca-ecdsa`, with the issuer name `O=sigillum test PKI, CN=sigillum test unknown CA`, which no certificate has as subject |
| `crl/ca-ecdsa-expired-certs` | A later CRL of `pki/ca-ecdsa`, number 3, with `thisUpdate` at the validation time and `nextUpdate` seven days after it. It carries a third non-critical extension, expiredCertsOnCRL, which RFC 5280 does not define: ITU-T X.509 (10/2019), clause 9.5.2.8, extends the scope of the CRL to the certificates that expired on or after its date, here one year before the validation time. It lists what the current CRL lists |

The expected OpenSSL result of a CRL is `verified` when these checks pass, and `rejected` otherwise:

- `openssl crl -inform DER -verify -lastupdate -nextupdate -CAfile` with the certificate of the issuer, which finds the issuer by name, checks the signature and prints `thisUpdate` and `nextUpdate`;
- `thisUpdate` is at or before the validation time, and `nextUpdate` after it, which `verify` compares itself, because `openssl crl` has no `-attime`. RFC 5280, section 5.1.2.4, makes `thisUpdate` the issue date of the CRL, and section 5.1.2.5 makes `nextUpdate` the date by which the next CRL will be issued and requires conforming issuers to include it, so a CRL without `nextUpdate` is rejected. The RFC fixes no boundary for the comparison: the boundaries are those of the CRL time check of OpenSSL, `X509_cmp_time`, under which a `thisUpdate` equal to the validation time is current and a `nextUpdate` equal to it is not. Times that `verify` cannot read stop the check of the CRL;
- `openssl verify -attime` at the validation time, with `-crl_check_all`, this CRL and the CRLs linked by the chain, for each certificate that its issuer issued and that is expected to verify.

`crl/ca-expired`, `crl/ca-without-ca-flag` and `crl/ca-without-basic-constraints` have no certificate that is expected to verify, so the first two checks decide their result.

The expected DSS result of a CRL is the result of the X.509 certificate validation of ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, at the validation time, of one certificate that the CRL covers, with this CRL as its revocation data. The CA certificates above it use the current CRLs that they link. It is a prediction from the standard. The `validate-certificate` mode of `tools/dss-oracle` gives the result of DSS for that certificate and CRL, under the aligned policy of ADR-0023, and the cases where DSS 6.5.1 differs from the prediction are recorded in [divergences.md](../docs/design/divergences.md). The covered certificate is issued by the issuer of the CRL and not revoked, and the notes of the CRL entry name it in their first sentence, of the form `Covered certificate: pki/<name>.`

| CRLs | Covered certificate | Predicted result |
| --- | --- | --- |
| `crl/root-ca` | `pki/ca-ecdsa` | PASSED (step 9) |
| `crl/ca-rsa`, `crl/ca-rsa-pss`, `crl/ca-ecdsa`, `crl/ca-ecdsa-p521`, `crl/ca-ed25519` | `pki/signer-rsa-2048`, `pki/signer-rsa-pss-sha256`, `pki/signer-p256`, `pki/signer-p521`, `pki/signer-ed25519` | PASSED (step 9) |
| `crl/ca-expired` | `pki/signer-under-expired-ca` | INDETERMINATE with REVOCATION_OUT_OF_BOUNDS_NO_POE, from step 8, the result predicted for the certificate itself: the CA that issued the CRL has expired |
| `crl/ca-without-ca-flag`, `crl/ca-without-basic-constraints` | The end entity of each CA | INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE, from step 4 e), the result predicted for the certificate itself: its path fails for the defect of its CA, not for want of revocation data |
| `crl/ca-ecdsa-expired` | `pki/signer-p256` | INDETERMINATE with TRY_LATER, from step 4 a): the revocation freshness checker of clause 5.2.5.4 takes the seven days from `thisUpdate` to `nextUpdate` as the maximum accepted freshness, and the CRL was issued 14 days before the validation time |
| `crl/ca-ecdsa-wrong-key` | `pki/signer-p256` | INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE, from step 4 e): the signature of the CRL does not verify with the key of the CA, so the CRL cannot be used (RFC 5280, section 6.3.3, step (g)). The path validation cannot show that the certificate is not revoked (RFC 5280, section 6.1.3, step (a)(3)), and fails |
| `crl/ca-ecdsa-wrong-issuer` | `pki/signer-p256` | INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE, from step 4 e): the issuer name of the CRL differs from the issuer of the certificate, so the CRL does not apply to it (RFC 5280, section 6.3.3, step (b)). The path validation cannot show that the certificate is not revoked, and fails |
| `crl/ca-ecdsa-expired-certs` | `pki/signer-expired` | INDETERMINATE with OUT_OF_BOUNDS_NOT_REVOKED, from step 7: the CRL, issued after the certificate expired and covering it through expiredCertsOnCRL, shows it not revoked after expiry, as NOTE 8 describes |

These are predictions from the text of the standard. DSS 6.5.1 gives them under the aligned policy and under its default policy, `crl/ca-ecdsa-expired-certs` included, except for `crl/ca-ed25519` and `crl/ca-ecdsa-expired` under the default policy, which the table of the default policy in `tools/dss-oracle/README.md` lists. Step 4 a), which gives TRY_LATER, applies only when the path validation succeeds, as it does with the expired CRL. The default policy of DSS does not check revocation freshness and gives PASSED for `crl/ca-ecdsa-expired`; the aligned policy checks it.

## Timestamp tokens

`sigillum-testpki generate timestamps` writes standalone RFC 3161 timestamp tokens under `timestamps/`, with the data they cover, and records each file in `manifest.toml`. It regenerates the test PKI of the validation time in memory and signs with it, so the tokens always match `generate pki`. A test checks that the committed files are what the generator produces, byte for byte. Regeneration follows the rules of the test PKI, with one difference: `generate timestamps` owns every entry whose identifier is under `timestamps/`, whatever its kind. The manifest must already list the test PKI, because the tokens link to it, so `generate pki` runs first. The content of its entries does not depend on `generate crls`, whose links it neither reads nor changes. The committed manifest assumes the order `generate pki`, then `generate crls`, then `generate timestamps`, then `generate ocsp`, and lists the entries in that order; a test checks that this order reproduces it byte for byte. Otherwise `generate timestamps` writes nothing, leaves the manifest unchanged and says so.

| Artefact | Content |
| --- | --- |
| `timestamps/content` | The data that every token covers, a line of text |
| `timestamps/valid` | A valid token from `pki/tsa`, with a `genTime` one day before the validation time |
| `timestamps/signer-without-time-stamping` | A token signed by `pki/signer-p256`, whose certificate lacks the extended key usage `id-kp-timeStamping` that RFC 3161, section 2.3, requires |
| `timestamps/imprint-mismatch` | A token from `pki/tsa` whose message imprint is the SHA-256 digest of the content with its last octet inverted |
| `timestamps/gen-time-after-validation-time` | A token from `pki/tsa` with a `genTime` one day after the validation time |

Every token, from `generate timestamps` or from the `tsa` subcommand, has the same structure:

- A CMS `SignedData` (RFC 5652, section 5), assembled by the `cms` builder, whose encapsulated content is a `TSTInfo` of type `id-ct-TSTInfo` (RFC 3161, section 2.4.2).
- The `TSTInfo` has version 1, the policy `1.3.6.1.4.1.32473.1.2`, the message imprint with the algorithm's parameters absent (RFC 5754, section 2), a serial number and the `genTime` in whole seconds. It has no accuracy, nonce, TSA name or extensions, and `ordering` is FALSE.
- One signer, identified by issuer and serial number, with the signed attributes content type, message digest and the ESS `signingCertificateV2` (RFC 5816, section 2.2.1; RFC 5035, sections 3 and 4). The `ESSCertIDv2` holds the SHA-256 hash of the certificate, the default algorithm and so not encoded, and the issuer and serial number of the certificate. There is no `signingTime` attribute, and no time is read from the system clock.
- The signing certificate is included in `certificates`, as RFC 3161, section 2.4.1, requires when a request sets `certReq`. The chain above it is not.
- A P-256 key, such as that of `pki/tsa`, signs with ECDSA and SHA-256. Other key types of the test PKI sign with RSA PKCS#1 v1.5 and SHA-256, ECDSA with SHA-384 on P-384 and with SHA-512 on P-521, or Ed25519 with SHA-512 as the digest of the signed attributes (RFC 8419, section 3).

RFC 3161, section 2.4.2, requires serial numbers unique among the tokens of one authority. No counter or clock is used, so that generation stays reproducible and each run of `tsa` stands alone. The serial number is 16 octets of SHA-256 over a fixed label, the hash of the authority's certificate, the digest algorithm, the digest and the `genTime`, with the two top bits set to `01`. Two requests that differ in any of these get different serial numbers, except with a probability of about 2^-126. Two identical requests get the same token, byte for byte, which is one token rather than two. The four tokens of the corpus have distinct serial numbers, as a test checks.

### The `tsa` subcommand

`sigillum-testpki tsa` issues one token and writes it to standard output in DER. `tools/dss-oracle` calls it in its `sign` mode, once per token ([ADR-0013](../docs/design/adr/0013-dss-oracle-command-line-tool.md)). It does not read the manifest.

| Option | Content |
| --- | --- |
| `--digest-algorithm` | `SHA-256`, `SHA-384` or `SHA-512`, in any letter case and with or without the hyphen, or their object identifiers `2.16.840.1.101.3.4.2.1`, `2.16.840.1.101.3.4.2.2` and `2.16.840.1.101.3.4.2.3`, written exactly so: an arc with leading zeros is refused |
| `--digest` | The digest, in hexadecimal digits of either case, as long as the algorithm's output |
| `--time` | The `genTime`, of the exact form of `validation-time`, `YYYY-MM-DDTHH:MM:SSZ`, from 1970. Offsets, fractions of a second, lower-case `t` or `z` and missing seconds are refused |
| `--tsa-key` | The authority's private key, a PKCS#8 PEM file. A DER or non-UTF-8 file is refused. An RSA key must pass its own consistency check and have exactly two primes, each half the modulus length within one bit, and a modulus of 2048 to 4096 bits. RFC 8017, section 3.2, allows other forms, but rsa 0.9.10 may take practically forever to sign with very unequal primes, such as 3 and 2^607 - 1, so they are refused before anything is signed |
| `--tsa-cert` | The authority's certificate, which must match the key. A DER file holds one certificate and nothing after it. A PEM file holds a single `CERTIFICATE` block, with nothing after the END line but its line ending. Chain files and the output of `openssl x509 -text` are refused. The key matches when the public keys are equal once decoded, so an elliptic-curve point may be compressed or not |

Before the encapsulation boundary of a PEM document, only a UTF-8 byte order mark and white space are skipped. RFC 7468, section 2, permits data there, and the production `W` of its section 3 defines the white space. Any other text before the boundary is refused. Each file is read up to 64 KiB, which is generous for the keys and certificates of the test PKI; a larger file is refused with exit code 1 before it is parsed, so that an oversized file cannot exhaust memory. The parsers of these options are in the module `timestamp::input` of the library, and the fuzz target `tsa_input` exercises them.

It exits with 0 on success, 2 on a usage error, including an invalid time, algorithm or digest and a digest of the wrong length, and 1 when the key or certificate cannot be read, is not valid or does not match. Every error is reported on standard error, and nothing is written to standard output.

### Expected results

The expected OpenSSL results are those of `openssl ts -verify -in <token> -token_in -data timestamps/content.txt -CAfile <bundle> -untrusted <certificates> -crl_check_all -attime <validation time>`, where the bundle holds `pki/root-ca.pem` and, in PEM, the CRLs that the chain of the signing certificate links (`crl/ca-ecdsa` and `crl/root-ca`), because `openssl ts` has no `-CRLfile` option. The untrusted certificates are the signing certificate and the rest of the chain but the trust anchor (`pki/tsa.pem` and `pki/ca-ecdsa.pem`), because a token carries no certificates when its request did not set `certReq` (RFC 3161, section 2.4.1). The signing certificate is among them even when it is itself the trust anchor, because `openssl ts` looks for the signer only there and in the token. The results are the same without `-crl_check_all` and the CRLs. OpenSSL rejects the token without `id-kp-timeStamping` with "unsuitable certificate purpose" and the mismatched imprint with "message imprint mismatch". It verifies the token whose `genTime` follows the validation time, because it does not compare `genTime` with the verification time.

The expected DSS results are predictions from ETSI EN 319 102-1 V1.4.1. DSS 6.5.1 gives them in the `validate-timestamp` mode of `tools/dss-oracle`, under the aligned policy of ADR-0023, with the content:

- the valid token and the token with a later `genTime` pass the time-stamp validation building block, clause 5.4.4, which does not compare `genTime` with the validation time. A verifier that uses a token as time evidence must still reject a `genTime` after the validation time. Step 1 of that clause runs the basic signature validation, whose X.509 validation checks revocation (clause 5.2.6.4, step 4), and `pki/tsa` has no `id-pkix-ocsp-nocheck`. The chain of `pki/tsa` has its CRLs linked: `pki/tsa` links `crl/ca-ecdsa` and `pki/ca-ecdsa` links `crl/root-ca`, and neither revokes a certificate of the chain, so step 4 passes. `pki/tsa` also links `ocsp/tsa`, which gives `good`;
- the token without `id-kp-timeStamping` fails the X.509 validation constraints, clause 5.2.6.4, step 5, INDETERMINATE with CHAIN_CONSTRAINTS_FAILURE;
- the token with the mismatched imprint is itself intact. FAILED with HASH_FAILURE is this project's mapping for a message imprint that does not match the data supplied to the validation, as the `validate-timestamp` mode of `tools/dss-oracle` compares it. It does not follow from clause 5.2.7.4, whose integrity check covers the token's own signed data.

## OCSP responses

`sigillum-testpki generate ocsp` writes the OCSP responses of the test PKI under `ocsp/` and records each in `manifest.toml`. It reads the validation time from the manifest and regenerates the test PKI of that time in memory, so the responses always match `generate pki`. Every successful response is assembled by the `x509-ocsp` response builder with an explicit `producedAt`, as [ADR-0014](../docs/design/adr/0014-test-pki-and-corpus.md) decides, and signed by the generator with the key of its responder. No time is read from the system clock. A test checks that the committed files are what the generator produces, byte for byte.

Regeneration follows the rules of `generate crls`, with these differences:

- `generate ocsp` owns every OCSP response entry under `ocsp/`. The `revocation` links of a replaced entry are kept. Those it no longer produces are removed from the manifest, with every `revocation` link to them, and their files are left in place. Files under `ocsp/` that no manifest entry names are reported.
- It also owns the links to its responses in the `revocation` lists of the certificate entries under `pki/`. Each certificate that has a response links it, in last place. Other `revocation` links are kept. `generate crls` puts its CRL in first place, so the links are the same whichever of the two runs last.
- It runs after `generate pki`, because the response entries link the certificates of the test PKI. Without them the updated manifest is not valid, and nothing is written. Its content does not depend on `generate crls` or `generate timestamps`, but the committed manifest lists the entries in the order of the generators given above.

Each response is a DER file named after the certificate it covers, or after its case: `ocsp/<name>.der`. The responses follow RFC 6960:

- Every end entity has a response, except `pki/ocsp-responder`, which carries `id-pkix-ocsp-nocheck` (section 4.2.2.2.1). Section 4.2.2.2 allows two signers, and the corpus has both. `pki/ocsp-responder` is a delegated responder of `pki/ca-ecdsa`, with `id-kp-OCSPSigning`, so it may answer only for the certificates of that CA, and it signs their responses. Every other CA signs the responses for its own certificates, the misconfigured CAs included, as they have CRLs: their end entities then fail only for the defect of their CA.
- A successful response holds one `SingleResponse`. Its `CertID` uses SHA-1 with NULL parameters, the algorithm that `openssl ocsp` uses by default and that RFC 5019, section 2.1.1, requires of lightweight clients; RFC 6960, section 4.1.1, leaves it open.
- The status is that of the CRL of the same CA at `thisUpdate`: `revoked`, with the revocation date and the reason code of the CRL entry, when the certificate is revoked on or before `thisUpdate`, and `good` otherwise. The responses therefore agree with the current CRL of each CA, as a test checks.
- `producedAt` and `thisUpdate` are one day before the validation time, and `nextUpdate` six days after it, as for the current CRLs, except for `ocsp/signer-expired-before-expiry` and `ocsp/produced-at-after-validation-time`. Every time is a GeneralizedTime in whole seconds (section 4.2.2.1).
- The signer is identified by the SHA-1 hash of its key, `byKey` (section 4.2.2.3). A delegated responder includes its certificate alone in `certs` (section 4.2.1). A CA includes none, and `certs` is absent: a client already holds the CA certificate, to build the path of the certificate and to compute the `CertID`.
- A CA signs with the algorithm of its CRL: RSA PKCS#1 v1.5 with SHA-256, RSASSA-PSS with SHA-256, ECDSA with SHA-512 on P-521, Ed25519, or ECDSA with SHA-256 for the misconfigured CAs. Another signer signs with the algorithm of its key: ECDSA with SHA-256 on P-256 and with SHA-384 on P-384, the pairs of RFC 5480, section 4, with the identifiers of RFC 5758, section 3.2.
- `pki/ca-expired` signs one day before the validation time, at the instant it expires, so within its validity, because `notAfter` is inclusive (RFC 5280, section 4.1.2.5), as for its CRL.
- There are no extensions, except the nonce of `ocsp/nonce`.

| Responses | Content |
| --- | --- |
| `ocsp/signer-p256`, `ocsp/signer-p384`, `ocsp/tsa`, `ocsp/signer-expired`, `ocsp/signer-not-yet-valid`, `ocsp/signer-without-non-repudiation`, `ocsp/signer-unknown-critical-extension` | The status `good` from `pki/ocsp-responder` for each end entity of `pki/ca-ecdsa` that is not revoked |
| `ocsp/signer-p256-revoked`, `ocsp/signer-p256-revoked-after-signing` | The status `revoked` from `pki/ocsp-responder` for key compromise, 60 and 10 days before the validation time |
| `ocsp/signer-rsa-2048`, `ocsp/signer-rsa-3072`, `ocsp/signer-rsa-sha3-256`, `ocsp/signer-rsa-pss-sha256`, `ocsp/signer-rsa-pss-sha384`, `ocsp/signer-p521`, `ocsp/signer-ed25519` | The status `good`, signed by the CA of each end entity |
| `ocsp/signer-rsa-revoked`, `ocsp/signer-rsa-pss-revoked`, `ocsp/signer-ed25519-revoked` | The status `revoked` for key compromise, 60 days before the validation time, signed by the CA of each end entity |
| `ocsp/signer-under-expired-ca`, `ocsp/signer-under-ca-without-ca-flag`, `ocsp/signer-under-ca-without-basic-constraints` | The status `good`, signed by the misconfigured CA of each end entity |
| `ocsp/unknown` | The status `unknown` for `pki/signer-p256` (section 2.2) |
| `ocsp/responder-without-ocsp-signing` | The status `good` for `pki/signer-p256`, signed by `pki/signer-p384`, which `pki/ca-ecdsa` issued without `id-kp-OCSPSigning` |
| `ocsp/produced-at-after-validation-time` | The status `good` for `pki/signer-p256`, with a `producedAt` one day after the validation time and the usual `thisUpdate` and `nextUpdate` |
| `ocsp/nonce` | The status `good` for `pki/signer-p256`, with a non-critical nonce extension (section 4.4.1) of 32 octets, the most that RFC 8954, section 2.1, allows. The nonce is the SHA-256 hash of a fixed label, so that the response is reproducible |
| `ocsp/try-later`, `ocsp/unauthorized` | The response statuses `tryLater` and `unauthorized`, without `responseBytes` (section 4.2.1) |
| `ocsp/cert-id-wrong-issuer-name-hash`, `ocsp/cert-id-wrong-issuer-key-hash` | The fixtures of threat K10 of the [threat model](../docs/design/threat-model.md): the response for `pki/signer-p256`, whose `CertID` carries the issuer name hash, or the issuer key hash, of `pki/ca-ecdsa` with its last octet inverted. The other fields are those of `ocsp/signer-p256`. The `CertID` identifies no certificate of the test PKI, so the response does not apply to `pki/signer-p256` (sections 3.2 and 4.1.1). A verifier that checks the delegation of the responder against the CA that the `CertID` names also rejects them for that reason (section 4.2.2.2), so the tests of sigillum should assert the specific reason, that the response does not apply to the certificate |
| `ocsp/signer-expired-before-expiry` | The status `good` for `pki/signer-expired`, from `pki/ocsp-responder`, with `producedAt` and `thisUpdate` two days before the validation time, before the certificate expired, and `nextUpdate` five days after it, so that the response is fresh at the validation time |

### Expected results

The expected OpenSSL result of a response is `verified` when `openssl ocsp -respin <response> -no_nonce -issuer <issuer> -cert <certificate> -no-CApath -no-CAstore -CAfile <trust anchor> -verify_other <intermediate CAs> -attime <validation time>` exits with 0, prints `Response verify OK` and gives a status for the covered certificate, and `rejected` otherwise. The certificate is the covered certificate defined below, the issuer its issuer, which also signs the CA-signed responses, the trust anchor the last certificate of the chain of the covered certificate, `pki/root-ca`, and the intermediate CAs the other certificates of that chain, so that a chain with several intermediate CAs verifies, followed by the responder that the entry links in `issuer` and the certificates of its chain but the trust anchor, so that a delegated response without the optional `certs` field (RFC 6960, section 4.2.1) verifies. The trust anchor and the intermediate CAs are given in files that `verify` writes, as described under Verification with OpenSSL. The status itself, `good`, `revoked` or `unknown`, is recorded in the purpose of the entry, not in the OpenSSL result. Without `-no_nonce`, `openssl ocsp` puts a nonce in the request it builds from `-issuer` and `-cert`, and then rejects `ocsp/nonce`, whose nonce differs. OpenSSL rejects `ocsp/responder-without-ocsp-signing` with "missing ocspsigning usage", and reports the two unsuccessful responses with "Responder Error". It rejects `ocsp/signer-under-expired-ca` with "certificate has expired", because it checks the signer at the time of `-attime`, after `pki/ca-expired` expired. For the two fixtures of threat K10 it finds no status for the certificate ("No Status found"). It also fails to verify them ("root ca not trusted"): the `CertID` does not name `pki/ca-ecdsa`, so `pki/ocsp-responder` is not a delegated responder of the CA it names (section 4.2.2.2). It compares `thisUpdate` and `nextUpdate` only with the system clock, not with `-attime`, and prints "WARNING: Status times invalid" for every response while the system clock is before its `thisUpdate` or after its `nextUpdate`, which does not change the result. The expected result therefore covers the parsing of a response, its signature and the path of its signer at the validation time, and not its freshness. The notes of every response with a status end with a sentence that says so. It does not compare `producedAt` with the verification time, so it verifies `ocsp/produced-at-after-validation-time`.

The expected DSS result of a response is the result of the X.509 certificate validation of ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, at the validation time, of the covered certificate, with this response as its revocation data. The CA certificates above it use the CRLs that they link. It is a prediction from the standard. The `validate-certificate` mode of `tools/dss-oracle` gives the result of DSS for that certificate and response, under the aligned policy of ADR-0023, and the cases where DSS 6.5.1 differs from the prediction are recorded in [divergences.md](../docs/design/divergences.md). The covered certificate is the certificate whose status the response gives, and for an unsuccessful response the certificate that a request would have named. The notes of each entry name it in their first sentence, of the form `Covered certificate: pki/<name>.`, as for the CRLs.

| Responses | Covered certificate | Predicted result |
| --- | --- | --- |
| The response for each end entity | The end entity itself | The result predicted for the certificate itself, whose entry links this response: PASSED for the valid end entities, INDETERMINATE with REVOKED_NO_POE for the revoked ones, and the results given under Test PKI for the others. `ocsp/signer-expired` has a `thisUpdate` equal to the `notAfter` of its certificate, so it shows no status after the certificate expired (clause 5.2.6.4, step 7 and NOTE 8) |
| `ocsp/unknown` | `pki/signer-p256` | INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE, from step 4 e): the response shows neither `good` nor `revoked`, so the path validation cannot show that the certificate is not revoked (RFC 5280, section 6.1.3, step (a)(3)) |
| `ocsp/responder-without-ocsp-signing` | `pki/signer-p256` | INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE, from step 4 e): a client must reject the response (RFC 6960, section 4.2.2.2), and the path validation then fails as for `ocsp/unknown` |
| `ocsp/produced-at-after-validation-time` | `pki/signer-p256` | PASSED (step 9): the revocation freshness checker of clause 5.2.5.4 uses `thisUpdate` (NOTE 3), and step 4 checks only that `producedAt` falls within the validity of the responder certificate |
| `ocsp/nonce` | `pki/signer-p256` | PASSED (step 9) |
| `ocsp/try-later`, `ocsp/unauthorized` | `pki/signer-p256` | `rejected`: the response holds no revocation data that DSS can load |
| `ocsp/cert-id-wrong-issuer-name-hash`, `ocsp/cert-id-wrong-issuer-key-hash` | `pki/signer-p256` | INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE, from step 4 e): the response does not apply to the certificate (RFC 6960, sections 3.2 and 4.1.1), so the path validation cannot show that it is not revoked |
| `ocsp/signer-expired-before-expiry` | `pki/signer-expired` | INDETERMINATE with OUT_OF_BOUNDS_NO_POE, from step 7 and NOTE 8: the response is fresh (clause 5.2.5.4) but was issued before the certificate expired, so it shows no status after expiry |

These are predictions from the text of the standard. DSS 6.5.1 gives them under the aligned policy, except for `ocsp/signer-expired` and `ocsp/signer-expired-before-expiry`, for which it reports OUT_OF_BOUNDS_NOT_REVOKED, the divergence DIV-5. It gives the predicted result for `ocsp/responder-without-ocsp-signing` for another reason: it finds no revocation data for `pki/signer-p384`, the signer of the response, and does not check `id-kp-OCSPSigning`. Given `crl/ca-ecdsa` as well, which covers that signer, DSS accepts the response, the divergence DIV-3. DSS 6.5.1 gives PASSED for `ocsp/produced-at-after-validation-time`; a verifier that uses it as evidence at the validation time must reject it, because it did not exist then. The `validate-certificate` mode rejects the two unsuccessful responses, because DSS cannot load them.

## Base documents

`sigillum-testpki generate documents` writes the unsigned base documents of the signed corpus under `documents/` and records each in `manifest.toml`, with the kind `document` and no expected result from OpenSSL or DSS. It owns every entry under `documents/` and follows the regeneration rules of the test PKI. The documents depend neither on the validation time nor on any other entry, and a test checks that the committed files are what the generator produces, byte for byte.

| Artefact | Content |
| --- | --- |
| `documents/simple` | A PDF 1.7 file of one A4 page with one line of text in Helvetica, the base document of the PAdES signatures |
| `documents/signature-field` | The same page with an interactive form holding one empty signature field, `Signature1`, merged with an invisible widget annotation. It is an unsigned input reserved for signing into an existing field, by sigillum's PAdES creation, the epic #120 |
| `documents/text` | A line of text, the signed content of the CAdES signatures |
| `documents/payload` | A JSON object on one line (RFC 8259), the payload of the JAdES signatures |

The PDF files are written byte by byte from ISO 32000-1:2008, without a PDF library: the header and a binary comment (clause 7.5.2), the objects (clauses 7.7.2, 7.7.3 and 7.3.8), a cross-reference table of one subsection whose entries are 20 bytes long (clause 7.5.4), and a trailer whose two file identifiers (clause 14.4) are derived from the name of the document. The signature field follows clauses 12.7.2 and 12.7.4.5. A test checks the structure, including every offset of the cross-reference table. No signature of the corpus uses `documents/signature-field`.

## Signed corpus

`sigillum-testpki generate signed` creates the signed corpus under `signed/` with the `sign` mode of `tools/dss-oracle` ([ADR-0013](../docs/design/adr/0013-dss-oracle-command-line-tool.md)), and records each signature in `manifest.toml`. It runs `java -XX:+UnlockExperimentalVMOptions -XX:hashCode=2 -jar <jar> sign ...` once per signature, without a shell. The two options make every identity hash code of the JVM 1. DSS 6.5.1 embeds the validation data of B-LT in an order that depends on these hash codes, so without the options the order, and the bytes, change between JVMs. `--dss-oracle` names the JAR, by default `tools/dss-oracle/target/dss-oracle.jar`, and `--java` the Java launcher, by default `java` from the `PATH`. For the timestamps, it gives `tools/dss-oracle` its own executable as `--tsa-program`. It runs last, because the signatures read the test PKI, its OCSP responses and CRLs, and the base documents, and link them; when the manifest does not list one of them, nothing is signed or written. It owns every entry under `signed/` and follows the regeneration rules of the test PKI.

| Artefacts | Content |
| --- | --- |
| `signed/cades-enveloping-<level>-<signer>` | CAdES with the content of `documents/text` inside, `.p7m` |
| `signed/cades-detached-<level>-<signer>` | CAdES over `documents/text`, without the content, `.p7s`, which links `documents/text` as its content |
| `signed/pades-<level>-<signer>` | An invisible PAdES signature of `documents/simple`, `.pdf` |
| `signed/jades-compact-b-b-<signer>` | JAdES over `documents/payload` in the JWS compact serialisation, `.jws`, at B-B only: the compact serialisation has no unprotected header for unsigned properties (RFC 7515, section 7.1) |
| `signed/jades-flattened-<level>-<signer>`, `signed/jades-general-<level>-<signer>` | JAdES over `documents/payload` in the flattened and general JWS JSON serialisations, `.json` |

The level is `b-b`, `b-t` or `b-lt`. The signers are `rsa` (`pki/signer-rsa-2048`, RSA PKCS#1 v1.5 with SHA-256), `rsa-pss` (`pki/signer-rsa-pss-sha256`, RSASSA-PSS with SHA-256), `p256` (`pki/signer-p256`, ECDSA with SHA-256) and `ed25519` (`pki/signer-ed25519`). That is 64 signatures. DSS 6.5.1 creates every combination of the story, Ed25519 included, so none is left out for want of support.

Every signature is made as follows:

- The signing time is the planned signing time, 2029-12-16T10:00:00Z. The certificate chain of the signer, up to `pki/root-ca`, is included.
- At B-T and B-LT, the signature timestamp is issued by `sigillum-testpki tsa` with `pki/tsa`, for the digest that DSS asks for, with the planned signing time as its genTime.
- At B-LT, DSS embeds the OCSP response of the signer, `ocsp/tsa` and `crl/root-ca`, with the certificates of both chains. It selects and checks the revocation data at the validation time, under the cryptographic constraints of the aligned policy of `tools/dss-oracle`, which authorises EdDSA. A CRL or OCSP response that fails the checks is never embedded; the run fails when no accepted revocation data remains for a certificate that needs it.
- Every JAdES signature carries `x5c` in its protected header. Annex I of [Commission Implementing Regulation (EU) 2026/248 of 2 February 2026](http://data.europa.eu/eli/reg_impl/2026/248/oj) replaces clause 5.1.8 of ETSI TS 119 182-1 V1.2.1 and requires `x5c` "either as a signed or unsigned header parameter".
- Every signature algorithm is deterministic, and no clock is read, so the corpus is reproduced byte for byte with the same DSS version, on any JVM that accepts the options above, such as HotSpot 21 to 27. The workflow `signed-corpus.yml` regenerates it without network access and fails on any difference. Without Java, the tests of `sigillum-testpki` check that each committed signature has its manifest entry.

The links of each entry name the signing certificate as `issuer`, the chain from it to `pki/root-ca` as `chain`, and revocation data: at B-B the OCSP response of the signer and `crl/root-ca`, at B-T also `ocsp/tsa`, and at B-LT none, since the signature holds them. At B-T and B-LT, `timestamp-chain` links `pki/tsa`, `pki/ca-ecdsa` and `pki/root-ca`: the token holds the certificate of `pki/tsa` only, so a validation of a B-T signature needs `pki/ca-ecdsa` from the links. A B-LT signature also holds it among its validation data. A validation uses the linked files only: the certificates of `chain` and `timestamp-chain`, with `pki/root-ca` as trust anchor, the revocation data of `revocation`, and the content of `content`. A test checks that every signed entry links the chain of its signer and, from B-T on, the chain of `pki/tsa`.

The expected OpenSSL result of a CAdES signature is that of `openssl cms -verify`, as `verify --openssl` runs it (see below): `verified` for every signature, with OpenSSL 3.5.9 and with OpenSSL 4.0.3. OpenSSL does not process PAdES or JAdES, whose entries are `not-applicable`.

The expected DSS result is TOTAL-PASSED for every signature: a prediction from ETSI EN 319 102-1 V1.4.1. The signature value and the signed attributes verify (clause 5.2.7), the chain builds to `pki/root-ca` (clause 5.2.6), and no certificate of the chain is revoked (clause 5.2.6.4, step 4). With the linked files, the signature timestamp passes the time-stamp validation building block (clause 5.4). DSS 6.5.1 gives this result for all 64 signatures in the `validate-document` mode of `tools/dss-oracle`, under the aligned policy of [ADR-0023](../docs/design/adr/0023-validation-policy-of-the-dss-oracle.md), with the linked files only and the root CA as trust anchor. Under its default validation policy, DSS 6.5.1 reports the 16 Ed25519 signatures INDETERMINATE with CRYPTO_CONSTRAINTS_FAILURE_NO_POE instead, because that policy does not authorise EdDSA; the notes of those entries say so.

## Malformed variants

`sigillum-testpki generate mutations` derives malformed variants from signatures of the signed corpus, as [ADR-0014](../docs/design/adr/0014-test-pki-and-corpus.md) decides, writes them under `mutations/` and records each in `manifest.toml`. Each mutation changes bytes of one committed signature and computes no new signature value. The generator reads only the committed corpus, so it needs neither Java nor DSS. It runs after `generate signed`, and checks the digest of each source against its entry first; when the manifest does not list a source, or its file differs from its entry, nothing is written. It owns every entry under `mutations/` and follows the regeneration rules of the test PKI. The mutations are pure functions of their sources, so the variants are reproduced byte for byte: a test checks the committed files without Java, and the workflow `signed-corpus.yml` derives them again after the signed corpus.

| Artefact | Source | Change | Expected result |
| --- | --- | --- | --- |
| `mutations/cades-modified-signed-attribute` | `signed/cades-enveloping-b-b-p256` | The signing-time attribute (RFC 5652, section 11.3) moves one second later, by its last digit | OpenSSL `rejected`; DSS TOTAL-FAILED with SIG_CRYPTO_FAILURE |
| `mutations/cades-modified-content` | `signed/cades-enveloping-b-b-p256` | The first octet of the encapsulated content, `eContent`, changes from `s` to `S`; the signed attributes are intact | OpenSSL `rejected`; DSS TOTAL-FAILED with HASH_FAILURE |
| `mutations/jades-tampered-header` | `signed/jades-compact-b-b-p256` | `iat` in the protected header moves one second later | DSS TOTAL-FAILED with SIG_CRYPTO_FAILURE predicted; DSS 6.5.1 gives HASH_FAILURE, the divergence DIV-6 |
| `mutations/jades-duplicate-header-parameter` | `signed/jades-compact-b-b-p256` | A second `iat`, one day later, ends the protected header | DSS `rejected` |

Each variant keeps the links of its source, so DSS validates it with the same files. The notes of each entry give the reasoning. ETSI EN 319 102-1 V1.4.1 predicts HASH_FAILURE for the changed content: the signature value over the signed attributes still verifies, but the message-digest attribute (RFC 5652, section 11.2) no longer matches the digest of the content, the hash of a signed data item (clause 5.2.7.3, Table 15, and Table 6; clause 5.2.7.4, step 2). It predicts SIG_CRYPTO_FAILURE for the changed signing time and the changed protected header. In the CAdES variant with the changed signing time, the content still matches the message-digest attribute (clause 5.2.7.4, step 2), and the signature value no longer verifies (step 4). HASH_FAILURE means that the hash of a signed data item does not match the corresponding hash value in the signature (clause 5.2.7.3, Table 15, and Table 6). The JAdES variant carries no hash value of its unchanged payload: its signature value covers the JWS Signing Input, protected header included (RFC 7515, section 5.2, step 8), so only step 4 fails. Clause 5.2.7.4 leaves its first two steps to the signature type, and refers to the CAdES, XAdES and PAdES standards and RFC 3852, not to ETSI TS 119 182-1. A failed step returns FAILED with its sub-indication from the cryptographic verification building block. The validation process for basic signatures returns that result (clause 5.3.4, step 5), and the main indication is then TOTAL-FAILED with the same sub-indication (clause 5.1.3, Table 6). RFC 7515, section 4, lets a JWS parser reject duplicate Header Parameter names, as DSS 6.5.1 does. The duplicate variant also breaks the signature value, which was not computed again, so the fixture alone does not show that a verifier checks for duplicate names.

The PAdES variants, which carry an `attack-class`, are added by #112.

## Verification with OpenSSL

`sigillum-testpki verify --openssl` checks every artefact of the manifest with OpenSSL, as [ADR-0014](../docs/design/adr/0014-test-pki-and-corpus.md) decides, and compares the result with `expected-openssl`. It reports each artefact without its expected result on standard error, with the commands that decided the result and the start of their output, and then prints a summary. It exits with 0 when every artefact has its expected result, and with 1 otherwise or when the checks cannot run.

Before any check, it runs `openssl version`. The program and the library it uses must both be the release that `openssl-version` names in the header, so the results are those recorded. Otherwise `verify` stops with exit code 1 and names both versions. `--openssl-program` names the program, by path or by a name looked up in `PATH`; the default is `openssl`. `--openssl-version` names another release, which then takes the place of the header for this run only: the program must be that release, and the expected results stay those of the manifest. `verify` says so on standard error before any check. It serves to show that a second release agrees with the recorded results, and changes neither the manifest nor the run without the option.

Each command runs the program directly, with explicit arguments and never through a shell, with an empty standard input, in the temporary directory described below. Corpus files are given by their absolute paths, which cannot be read as options, and the files that `verify` writes by bare names such as `bundle-1.pem`: `openssl ts` splits the file names of `-untrusted` at commas and white space, and a bare name holds neither, whatever the path of the temporary directory. A run longer than 60 seconds, or that writes more than 1 MiB to either output, is stopped and reported. The 60 seconds include the reading of the outputs, so a process that the program starts and that keeps them open cannot hold `verify` past the limit. On Unix the program runs in a process group of its own, which is killed with every process in it when the limit passes; on other platforms only the program is killed. `OPENSSL_CONF` names an empty configuration file, so that the configuration of the system does not change the results. The trusted certificates come only from the files that `verify` writes for each command: `-no-CApath` and `-no-CAstore` keep out the default trust stores, and `openssl ts` loads none. These files hold certificates and CRLs in PEM form, in a temporary directory removed at the end. No command uses the network.

| Kind | Command | Result |
| --- | --- | --- |
| `certificate` | `openssl verify -attime`, with the trust anchor of the chain as `-CAfile`, the certificates between it and the certificate as `-untrusted` and, when the certificate or its chain links CRLs, `-crl_check_all` and each CRL with `-CRLfile`, as described under Test PKI | `verified` when it exits with 0 and prints the line `<path>: OK`, and `rejected` otherwise |
| `private-key` | `openssl pkey -in <path> -noout` | `parsed` when it exits with 0, and `rejected` otherwise |
| `crl` | `openssl crl -verify -lastupdate -nextupdate` with the certificate of the issuer, then `openssl verify -attime` for each certificate of the issuer that is expected to verify, with this CRL and the CRLs of its chain, as described under CRLs | `verified` when `openssl crl` exits with 0 and prints `verify OK`, the CRL is current at the validation time, and every `openssl verify` passes; `rejected` otherwise. A vanilla build of OpenSSL 3.0.13 exits with 0 even when the signature fails, so the message decides |
| `ocsp-response` | `openssl ocsp -respin -attime` for the covered certificate, as described under OCSP responses | `verified` when it exits with 0, prints `Response verify OK` and gives a status for the covered certificate, and `rejected` otherwise |
| `timestamp-token` | `openssl ts -verify -attime` with the data it covers, as described under Timestamp tokens | `verified` when it exits with 0 and prints `Verification: OK`, and `rejected` otherwise |
| `document` | None | `not-applicable` |
| `signed-document` | A CMS `SignedData`, a CAdES signature: `openssl cms -verify -binary -inform DER` at the validation time, with `-no-CApath -no-CAstore`, the trust anchor of the chain as `-CAfile`, the certificates between the signer and the anchor as `-certfile`, and `-content` with the linked content of a detached signature. Revocation is not checked, because the signatures link OCSP responses, which `openssl cms` does not take. Any other signed document: none | `verified` when it exits with 0 and prints `CMS Verification successful`, and `rejected` otherwise. Another signed document is `not-applicable`, and must be recorded so. A CMS signature recorded as `not-applicable` is refused as a check that cannot run, so that no CAdES entry escapes the check |

Before any command, `verify` reads every corpus file that the command takes. A missing, unreadable or oversized file stops the check of the artefact with the reason, which never counts as a result of OpenSSL: otherwise a missing file expected to be rejected would pass.

Every command that validates a certificate path takes the validation time with `-attime`, in seconds since 1970-01-01T00:00:00Z. `openssl crl` has no `-attime`, so `verify` compares the `thisUpdate` and `nextUpdate` that it prints with the validation time itself. `openssl ocsp` cannot compare the times of a response with the validation time, as described under OCSP responses.

The check has known limits. A `rejected` result matches any failure of OpenSSL, whatever its reason, so a fixture that fails for another reason than its purpose still matches. The status of an OCSP response, `good`, `revoked` or `unknown`, must be present but is not compared with an expected status, which only the purpose of the entry records. A manifest field for the reason or the status would be a change of the format, left for later.

The workflow `.github/workflows/fixtures-openssl.yml` runs `verify --openssl` on Linux for every pull request and every push to `main`, in two jobs. Each builds its release from the published source, checked against a SHA-256 digest recorded in the workflow, and runs the checks in a network namespace without network. The first job builds the release that the header names, OpenSSL 3.5.9, a long-term support release, and runs `verify --openssl` without `--openssl-version`, then the tests of `tests/openssl.rs`. The second builds OpenSSL 4.0.3 and runs `verify --openssl --openssl-version 4.0.3`, so that a result that depends on the release shows up. A change of release changes `openssl-version` and the digests in the workflow. Results that differ with the new release are changed in the generators, with the reason in the notes.

The tests in `crates/sigillum-testpki/tests/openssl.rs` run `verify --openssl` on the corpus, on a copy whose manifest expects a wrong result and on a manifest that names another release. They run OpenSSL only when the environment variable `SIGILLUM_TESTPKI_OPENSSL` names the program of the release in the header, and otherwise say so and pass. When `SIGILLUM_TESTPKI_OPENSSL_REQUIRED` is `1`, as the workflow sets it with the program, a missing program fails them instead. To run them locally, build that release as the workflow does and set the variable to its `apps/openssl`. The unit tests of the module `openssl` cover the commands and the reading of their output on every platform, with a program that stands in for OpenSSL.

## Verification with DSS

`sigillum-testpki verify --dss` checks every artefact of the manifest with DSS, through the validation modes of `tools/dss-oracle` ([ADR-0013](../docs/design/adr/0013-dss-oracle-command-line-tool.md)), as [ADR-0014](../docs/design/adr/0014-test-pki-and-corpus.md) decides, and compares the result with `expected-dss`. It reports each artefact without its expected result on standard error, with the run that decided the result and the start of its `summary.json`, and then prints a summary. It exits with 0 when every artefact has its expected result, and with 1 otherwise or when the checks cannot run.

`verify` without `--openssl` or `--dss` runs both checks, OpenSSL first, and exits with 1 when either fails. An option of a check that does not run, such as `--java` with `--openssl` alone, is a usage error.

`--dss-oracle` names the executable JAR of the tool, by default `tools/dss-oracle/target/dss-oracle.jar`, which `mvn -B package` builds in `tools/dss-oracle`. `--java` names the Java launcher, by default `java` from the `PATH`. Before any check, `verify` runs the tool with `--version`, which prints the DSS version that the tool is built against. That version must be the `dss-version` of the header. Otherwise `verify` stops with exit code 1 and names both versions. Every `summary.json` must also name that DSS version, the mode of the run, the validation time of the header and the aligned policy of [ADR-0023](../docs/design/adr/0023-validation-policy-of-the-dss-oracle.md), `aligned-1`, or the check of the artefact cannot run.

Each validation runs `java -Xmx512m -XX:+UseSerialGC -jar <jar> <mode> ... --timeout 120` directly, with explicit arguments and never through a shell, with an empty standard input. The heap limit, the garbage collector and the time limit of the validation are those of the continuous integration of the tool, so that a run near a resource limit has the same outcome on every host with the same JVM, as "Resource limits" in the README of the tool describes. It writes its reports to a directory of its own, in a temporary directory removed at the end. Corpus files are given by their absolute paths. A run longer than 180 seconds, the time limit of the validation and one minute for the JVM, or that writes more than 1 MiB to either output, is stopped and reported. On Unix its process group is then killed, as for OpenSSL. Up to one validation per processor of the machine runs at once.

| Kind | Mode and inputs | Result |
| --- | --- | --- |
| `certificate` | `validate-certificate` with the certificate, the certificates between it and the trust anchor of its `chain`, the trust anchor, the CRLs and OCSP responses that the certificate links in `revocation`, and those that the certificates between it and the trust anchor link | The `indication` and `sub-indication` of `summary.json`: the conclusion of the X.509 certificate validation of the certificate and its chain |
| `crl`, `ocsp-response` | `validate-certificate` with the covered certificate named in the notes, as for a certificate, but with this CRL or response as its own revocation data | As for a certificate |
| `timestamp-token` | `validate-timestamp` with the token, the data it covers (`content`) as `--data`, the certificates of its `chain` but the trust anchor, the trust anchor, and the CRLs that those certificates link, with which the notes of the tokens predict their results | The indication of the token |
| `signed-document` | `validate-document` with the linked files only: the document, its `content` as `--detached`, the certificates of `chain` and `timestamp-chain` but the trust anchor, the last certificate of `chain` as trust anchor, and the revocation data of `revocation` | The indication of its signature. A document with no signature, or with more than one, has no indication, and its check cannot run |
| `private-key`, `document` | None | `not-applicable` |

These are the inputs with which the expected results above were predicted and confirmed. `ValidateCertificateTest` of `tools/dss-oracle` gives the certificates, CRLs and OCSP responses the same inputs, and `ValidateTimestampTest` gives the tokens the same, without the signing certificate, which `verify` also gives. A summary with the result `rejected` gives `rejected`. DSS writes indications with underscores, and `verify` reads them with hyphens. A run that fails, exceeds a resource limit of the tool or writes no summary stops the check of the artefact with the reason, which never counts as a result of DSS.

DSS 6.5.1 gives another result than the manifest predicts for four artefacts, the divergence DIV-5 of [divergences.md](../docs/design/divergences.md): `pki/signer-expired`, `pki/ca-expired`, `ocsp/signer-expired` and `ocsp/signer-expired-before-expiry`. DSS reports them INDETERMINATE with OUT_OF_BOUNDS_NOT_REVOKED, and the manifest keeps the prediction from the standard, OUT_OF_BOUNDS_NO_POE. Their entries name the divergence and the result of DSS in `dss-divergence`, which `generate pki` and `generate ocsp` write. `verify` expects that result for them, as `ValidateCertificateTest` of `tools/dss-oracle` and the differential tests of `sigillum-oracle` do, all three reading the field. A fifth artefact, `mutations/jades-tampered-header`, has the divergence DIV-6: DSS reports TOTAL-FAILED with HASH_FAILURE where the manifest predicts SIG_CRYPTO_FAILURE, as described under Malformed variants. `generate mutations` writes its `dss-divergence`, which `verify` and the differential tests read in the same way. The summary of `verify` counts these artefacts. When DSS gives the prediction for one of them, the artefact is not as expected. A manifest whose `dss-divergence` gives the result that `expected-dss` predicts is not valid, so the field changes with the divergence.

The check has known limits. It compares the indication and the sub-indication only, not the errors and warnings of the reports. When a certificate links both a CRL and an OCSP response, its result depends on the one that DSS uses, which `summary.json` names. Each CRL and response is still checked on its own, as the revocation data of its covered certificate.

The workflow `.github/workflows/fixtures-dss.yml` builds `tools/dss-oracle` with Java 21. It then runs `verify --dss` on Linux for every pull request and every push to `main`, in a network namespace without network, followed by the tests of `tests/dss.rs`. The DSS version changes only with the version that `tools/dss-oracle/pom.xml` pins, through a pull request that reviews the changes in results (ADR-0013), and `dss-version` changes with it.

The tests in `crates/sigillum-testpki/tests/dss.rs` run `verify --dss` on part of the corpus: a certificate, a CRL, a recorded divergence, a timestamp token and a signed document, with the artefacts that they link. They run it again with a wrong expected result for each validation mode, and on a manifest that names another DSS version. They run DSS only when the environment variable `SIGILLUM_TESTPKI_DSS_ORACLE` names the JAR, and otherwise say so and pass. `SIGILLUM_TESTPKI_JAVA` names the Java launcher, `java` by default. When `SIGILLUM_TESTPKI_DSS_REQUIRED` is `1`, as the workflow sets it with the JAR, a missing JAR fails them instead. The unit tests of the module `dss` cover the runs and the reading of their summaries on every platform, with an oracle that stands in for the tool.

## Test keys

Private keys in this directory are test keys with no value outside the test suite. They are never used for anything else. The keys of the test PKI are PKCS#8 files under `pki/keys/`, each named after its certificate with the suffix `.test-key.pem`, as `pki/keys/README.md` states.
