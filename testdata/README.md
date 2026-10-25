# Test corpus

This directory holds the test corpus of sigillum: certificates, CRLs, OCSP responses, timestamp tokens and signed documents, generated as described in [ADR-0014](../docs/design/adr/0014-test-pki-and-corpus.md). Every artefact is listed in `manifest.toml`, with its purpose and the results expected from OpenSSL and DSS. The program `sigillum-testpki` (in `crates/sigillum-testpki`) generates the artefacts and checks them against the manifest. Its `tsa` subcommand issues timestamp tokens with a time, key and certificate given explicitly, and does not read the manifest.

Four generators write the corpus, in this order: `generate pki`, then `generate crls`, `generate timestamps` and `generate ocsp`, which link the certificates that `generate pki` records. Each owns the entries described in its section below, keeps every other entry, and follows the regeneration rules of the test PKI.

## Manifest format

`manifest.toml` is a TOML file with one required `[header]` table and one `[[artefact]]` table per artefact, possibly none. Unknown fields are rejected, and a text field that holds only spaces counts as empty. Paths are relative to the directory that contains the manifest.

### Header

| Field | Content |
| --- | --- |
| `format-version` | The version of this format, currently `1`. Other versions are rejected. |
| `validation-time` | The fixed validation time of the corpus, of the exact form `YYYY-MM-DDTHH:MM:SSZ`, for example `"2030-01-15T10:00:00Z"`: UTC, whole seconds, no leap second. Every time field of every artefact is chosen relative to it, and the subcommands `generate` and `verify` of `sigillum-testpki` read it from here. |
| `openssl-version` | The OpenSSL version whose results the manifest records, written as the version number only, for example `"3.0.13"` (`openssl version` prints `OpenSSL 3.0.13 30 Jan 2024`). The parser checks only that it is not empty. |
| `dss-version` | The DSS version whose results the manifest records, for example `"6.5.1"`. It is the version that `tools/dss-oracle` is built against. The parser checks only that it is not empty. |

### Artefact

| Field | Content |
| --- | --- |
| `id` | Unique identifier, for example `"pki/root-ca"`, with the same character rules as `path`. |
| `path` | Path of the file. Parts are separated by `/`. Each part is non-empty, contains only letters, digits, `.`, `_` and `-`, and is not `.`, `..` or a name that Windows reserves for devices: `CON`, `PRN`, `AUX`, `NUL`, `COM1` to `COM9` or `LPT1` to `LPT9`, with or without an extension. `COM0` and `LPT0` are refused as well, to be safe. A part does not end with `.`. The root files `manifest.toml` and `README.md` are reserved. Ignoring letter case, two artefacts may not name the same file, a file may not also be a directory, and a directory is spelt the same way in every path. |
| `sha256` | SHA-256 digest of the file, as 64 lower-case hexadecimal digits. |
| `kind` | One of `certificate`, `private-key`, `crl`, `ocsp-response`, `timestamp-token`, `signed-document`, `document`. |
| `purpose` | Why the artefact exists, in one sentence. |
| `expected-openssl` | The result expected from OpenSSL: `verified`, `parsed` (parsing only, for example where OpenSSL can check freshness only against the current time), `rejected`, or `not-applicable` (OpenSSL does not process this kind of artefact). |
| `expected-dss` | The result expected from DSS: `"not-applicable"` when DSS does not process this kind of artefact, such as a private key or an unsigned document; `"rejected"` when DSS cannot parse it; otherwise a table `{ indication = "...", sub-indication = "..." }` with the result of a validation that DSS could run. |
| `links` | Optional table of other artefacts, by identifier, needed to check this one. `issuer` names the issuer's certificate. `chain` lists the certificates above this artefact, from its issuer up to the trust anchor; when both are given, `chain` starts with `issuer`. `revocation` lists CRLs and OCSP responses. `content` names the signed content of a detached signature, or the data a timestamp covers, of any kind. For a timestamp token, `issuer` names the certificate that signed it, and `chain` starts with that certificate. Every identifier must name another artefact of the manifest; `issuer` and `chain` must name certificates, and `revocation` CRLs or OCSP responses. A list may not name one artefact twice. |
| `notes` | Optional remarks; not empty when present. |

The indication is one of `TOTAL-PASSED`, `TOTAL-FAILED`, `INDETERMINATE` (ETSI EN 319 102-1 V1.4.1, clause 5.1.3), or `PASSED`, `FAILED` for building blocks such as certificate validation. The sub-indication is optional and must be one that Table 6 of that standard defines for the indication. `TOTAL-PASSED` and `PASSED` take none, `TOTAL-FAILED` takes the `TOTAL-FAILED` list, and `INDETERMINATE` takes its own list, which includes `CUSTOM`. Table 6 defines no list for the building-block indications. This project gives `FAILED` the `TOTAL-FAILED` list, and uses the `INDETERMINATE` list for building blocks too. Indications are written with hyphens, as in the standard; DSS reports them with underscores, and `verify` maps one to the other.

Later stories add the fields they need, such as the format of signed documents or the attack class of malformed variants. A new format version is introduced where a change alters the meaning of an existing manifest.

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
| 2030-01-14 | 1 day before | `thisUpdate` of the other CRLs; `producedAt` and `thisUpdate` of the OCSP responses, except the `producedAt` of `ocsp/produced-at-after-validation-time`; `notAfter` of `pki/signer-expired` and `pki/ca-expired` |
| 2030-01-15 | 0 | Validation time |
| 2030-01-16 | 1 day after | `notBefore` of `pki/signer-not-yet-valid`; `producedAt` of `ocsp/produced-at-after-validation-time` |
| 2030-01-21 | 6 days after | `nextUpdate` of the CRLs other than `crl/ca-ecdsa-expired`, and of the OCSP responses |
| 2031-01-15 | 1 year after | `notAfter` of `pki/signer-not-yet-valid` |
| 2032-01-15 | 2 years after | `notAfter` of the other end entities |
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

The expected OpenSSL results are those of `openssl verify` at the validation time (`-attime`), with the chain of the manifest and default flags. When the certificate links a CRL in `revocation`, the check adds `-crl_check_all` and every CRL linked by the certificate and by the certificates of its chain, each given with `-CRLfile`. `openssl verify` takes no OCSP responses, so the responses that a certificate links are checked on their own, as described under OCSP responses. `pki/ca-without-ca-flag` and `pki/ca-without-basic-constraints` verify with default flags and fail with `-x509_strict`. Private keys are expected to parse. The expected DSS results are those of the X.509 certificate validation of ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, given the CRLs and OCSP responses that later stories link. They are confirmed once `verify` runs DSS. The predictions most likely to change are CERTIFICATE_CHAIN_GENERAL_FAILURE for the end entities under the expired CA and under the CA certificates without cA, and OUT_OF_BOUNDS_NO_POE for the expired and not yet valid certificates. The linked CRLs do not show that `pki/signer-expired` was not revoked after it expired, as clause 5.2.6.4, step 7 and NOTE 8, would require for OUT_OF_BOUNDS_NOT_REVOKED. DSS may still report OUT_OF_BOUNDS_NOT_REVOKED for `pki/signer-not-yet-valid`, which the current CRL of its issuer does not list. The revoked end entities are predicted INDETERMINATE with REVOKED_NO_POE, from clause 5.2.6.4, step 4 b).

## CRLs

`sigillum-testpki generate crls` writes the CRLs of the test PKI under `crl/` and records each in `manifest.toml`. It reads the validation time from the manifest, like `generate pki`, and runs after it, because the CRL entries link the certificates. Every CRL is built from the `x509-cert` CRL structures, encoded with `der` and signed by the generator, as [ADR-0022](../docs/design/adr/0022-x509-cert-structures-for-test-crls.md) decides. A test checks that the committed files are what the generator produces.

Regeneration follows the rules of `generate pki`, with these differences:

- `generate crls` owns every CRL entry under `crl/`. The `revocation` links of a replaced CRL entry are kept. Those it no longer produces are removed from the manifest, with every `revocation` link to them, and their files are left in place. Files under `crl/` that no manifest entry names are reported.
- It also owns the links to its CRLs in the `revocation` lists of the certificate entries under `pki/`. Each certificate whose issuer has a current CRL links that CRL, in first place. Other `revocation` links, such as OCSP responses, are kept.

Each CRL is a DER file named after the CRL distribution point of the certificates it covers: `http://example.invalid/crl/ca-ecdsa.crl` is `crl/ca-ecdsa.crl`. RFC 5280, section 4.2.1.13, requires a DER-encoded CRL behind an HTTP distribution point. The CRLs follow RFC 5280, section 5:

- Every CRL is a version 2 CRL, signed with an algorithm its issuer uses for certificates, with the issuer name of the issuer's certificate.
- It carries two non-critical extensions: the authority key identifier of its issuer (section 5.2.1) and a CRL number (section 5.2.3), 2 for the current CRLs and 1 for the expired one.
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

The expected OpenSSL result of a CRL is `verified` when two checks pass, and `rejected` otherwise:

- `openssl crl -inform DER -verify -CAfile` with the certificate of the issuer, which finds the issuer by name and checks the signature;
- `openssl verify -attime` at the validation time, with `-crl_check_all`, this CRL and the CRLs linked by the chain, for each certificate that its issuer issued and that is expected to verify.

For `crl/ca-expired`, `crl/ca-without-ca-flag` and `crl/ca-without-basic-constraints`, `verified` rests only on `openssl crl -verify`, because no certificate of those CAs is expected to verify.

The expected DSS result of a CRL is the result of the X.509 certificate validation of ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, at the validation time, of one certificate that the CRL covers, with this CRL as its revocation data. The CA certificates above it use the current CRLs that they link. It is a prediction from the standard. The `validate-certificate` mode of `tools/dss-oracle` gives the result of DSS for that certificate and CRL, and the cases where DSS 6.5.1 differs from the prediction are tracked in issue #75. The covered certificate is issued by the issuer of the CRL and not revoked, and the notes of the CRL entry name it in their first sentence, of the form `Covered certificate: pki/<name>.`

| CRLs | Covered certificate | Predicted result |
| --- | --- | --- |
| `crl/root-ca` | `pki/ca-ecdsa` | PASSED (step 9) |
| `crl/ca-rsa`, `crl/ca-rsa-pss`, `crl/ca-ecdsa`, `crl/ca-ecdsa-p521`, `crl/ca-ed25519` | `pki/signer-rsa-2048`, `pki/signer-rsa-pss-sha256`, `pki/signer-p256`, `pki/signer-p521`, `pki/signer-ed25519` | PASSED (step 9) |
| `crl/ca-expired`, `crl/ca-without-ca-flag`, `crl/ca-without-basic-constraints` | The end entity of each CA | INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE, from step 4 e), the result predicted for the certificate itself: its path fails for the defect of its CA, not for want of revocation data |
| `crl/ca-ecdsa-expired` | `pki/signer-p256` | INDETERMINATE with TRY_LATER, from step 4 a): the revocation freshness checker of clause 5.2.5.4 takes the seven days from `thisUpdate` to `nextUpdate` as the maximum accepted freshness, and the CRL was issued 14 days before the validation time |
| `crl/ca-ecdsa-wrong-key` | `pki/signer-p256` | INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE, from step 4 e): the signature of the CRL does not verify with the key of the CA, so the CRL cannot be used (RFC 5280, section 6.3.3, step (g)). The path validation cannot show that the certificate is not revoked (RFC 5280, section 6.1.3, step (a)(3)), and fails |
| `crl/ca-ecdsa-wrong-issuer` | `pki/signer-p256` | INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE, from step 4 e): the issuer name of the CRL differs from the issuer of the certificate, so the CRL does not apply to it (RFC 5280, section 6.3.3, step (b)). The path validation cannot show that the certificate is not revoked, and fails |

These are predictions from the text of the standard, confirmed once `verify` runs DSS. For the wrong-key and wrong-issuer CRLs, DSS is likely to report TRY_LATER instead, from its check for acceptable revocation data; the notes of both entries say so. Step 4 a), which gives TRY_LATER in the standard, applies only when the path validation succeeds, as it does with the expired CRL.

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

The expected OpenSSL results are those of `openssl ts -verify -in <token> -token_in -data timestamps/content.txt -CAfile <bundle> -untrusted pki/ca-ecdsa.pem -crl_check_all -attime <validation time>`, where the bundle holds `pki/root-ca.pem` and, in PEM, the CRLs that the chain of the signing certificate links (`crl/ca-ecdsa` and `crl/root-ca`), because `openssl ts` has no `-CRLfile` option. The results are the same without `-crl_check_all` and the CRLs. OpenSSL rejects the token without `id-kp-timeStamping` with "unsuitable certificate purpose" and the mismatched imprint with "message imprint mismatch". It verifies the token whose `genTime` follows the validation time, because it does not compare `genTime` with the verification time.

The expected DSS results are predictions from ETSI EN 319 102-1 V1.4.1, confirmed once `verify` runs DSS in its `validate-timestamp` mode with the content:

- the valid token and the token with a later `genTime` pass the time-stamp validation building block, clause 5.4.4, which does not compare `genTime` with the validation time. A verifier that uses a token as time evidence must still reject a `genTime` after the validation time. Step 1 of that clause runs the basic signature validation, whose X.509 validation checks revocation (clause 5.2.6.4, step 4), and `pki/tsa` has no `id-pkix-ocsp-nocheck`. The chain of `pki/tsa` has its CRLs linked: `pki/tsa` links `crl/ca-ecdsa` and `pki/ca-ecdsa` links `crl/root-ca`, and neither revokes a certificate of the chain, so step 4 passes. `pki/tsa` also links `ocsp/tsa`, which gives `good`;
- the token without `id-kp-timeStamping` fails the X.509 validation constraints, clause 5.2.6.4, step 5, INDETERMINATE with CHAIN_CONSTRAINTS_FAILURE;
- the token with the mismatched imprint is itself intact. FAILED with HASH_FAILURE is this project's mapping for a message imprint that does not match the data supplied to the validation, as the `validate-timestamp` mode of `tools/dss-oracle` will compare it. It does not follow from clause 5.2.7.4, whose integrity check covers the token's own signed data.

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
- `producedAt` and `thisUpdate` are one day before the validation time, and `nextUpdate` six days after it, as for the current CRLs. Every time is a GeneralizedTime in whole seconds (section 4.2.2.1).
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

### Expected results

The expected OpenSSL result of a response is `verified` when `openssl ocsp -respin <response> -no_nonce -issuer <issuer> -cert <certificate> -CAfile pki/root-ca.pem -verify_other <issuer> -attime <validation time>` exits with 0, prints `Response verify OK` and gives a status for the covered certificate, and `rejected` otherwise. The certificate is the covered certificate defined below, and the issuer its issuer, which also signs the CA-signed responses. The status itself, `good`, `revoked` or `unknown`, is recorded in the purpose of the entry, not in the OpenSSL result. Without `-no_nonce`, `openssl ocsp` puts a nonce in the request it builds from `-issuer` and `-cert`, and then rejects `ocsp/nonce`, whose nonce differs. OpenSSL rejects `ocsp/responder-without-ocsp-signing` with "missing ocspsigning usage", and reports the two unsuccessful responses with "Responder Error". It rejects `ocsp/signer-under-expired-ca` with "certificate has expired", because it checks the signer at the time of `-attime`, after `pki/ca-expired` expired. For the two fixtures of threat K10 it finds no status for the certificate ("No Status found"). It also fails to verify them ("root ca not trusted"): the `CertID` does not name `pki/ca-ecdsa`, so `pki/ocsp-responder` is not a delegated responder of the CA it names (section 4.2.2.2). It compares `thisUpdate` and `nextUpdate` only with the system clock, not with `-attime`, and prints "WARNING: Status times invalid" for every response until 2030-01-14, which does not change the result. It does not compare `producedAt` with the verification time, so it verifies `ocsp/produced-at-after-validation-time`.

The expected DSS result of a response is the result of the X.509 certificate validation of ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, at the validation time, of the covered certificate, with this response as its revocation data. The CA certificates above it use the CRLs that they link. It is a prediction from the standard. The `validate-certificate` mode of `tools/dss-oracle` gives the result of DSS for that certificate and response, and the cases where DSS 6.5.1 differs from the prediction are tracked in issue #75. The covered certificate is the certificate whose status the response gives, and for an unsuccessful response the certificate that a request would have named. The notes of each entry name it in their first sentence, of the form `Covered certificate: pki/<name>.`, as for the CRLs.

| Responses | Covered certificate | Predicted result |
| --- | --- | --- |
| The response for each end entity | The end entity itself | The result predicted for the certificate itself, whose entry links this response: PASSED for the valid end entities, INDETERMINATE with REVOKED_NO_POE for the revoked ones, and the results given under Test PKI for the others. `ocsp/signer-expired` has a `thisUpdate` equal to the `notAfter` of its certificate, so it does not show that the certificate was not revoked after it expired (clause 5.2.6.4, step 7 and NOTE 8) |
| `ocsp/unknown` | `pki/signer-p256` | INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE, from step 4 e): the response shows neither `good` nor `revoked`, so the path validation cannot show that the certificate is not revoked (RFC 5280, section 6.1.3, step (a)(3)) |
| `ocsp/responder-without-ocsp-signing` | `pki/signer-p256` | INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE, from step 4 e): a client must reject the response (RFC 6960, section 4.2.2.2), and the path validation then fails as for `ocsp/unknown` |
| `ocsp/produced-at-after-validation-time` | `pki/signer-p256` | PASSED (step 9): the revocation freshness checker of clause 5.2.5.4 uses `thisUpdate` (NOTE 3), and step 4 checks only that `producedAt` falls within the validity of the responder certificate |
| `ocsp/nonce` | `pki/signer-p256` | PASSED (step 9) |
| `ocsp/try-later`, `ocsp/unauthorized` | `pki/signer-p256` | `rejected`: the response holds no revocation data that DSS can load |
| `ocsp/cert-id-wrong-issuer-name-hash`, `ocsp/cert-id-wrong-issuer-key-hash` | `pki/signer-p256` | INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE, from step 4 e): the response does not apply to the certificate (RFC 6960, sections 3.2 and 4.1.1), so the path validation cannot show that it is not revoked |

These are predictions from the text of the standard, confirmed once `verify` runs DSS. For `ocsp/unknown`, `ocsp/responder-without-ocsp-signing` and the fixtures of threat K10, DSS is likely to report TRY_LATER instead, from its check for acceptable revocation data, as for the wrong-key and wrong-issuer CRLs. DSS may reject `ocsp/produced-at-after-validation-time` as revocation data produced after the validation time; a verifier that uses it as evidence at the validation time must reject it, because it did not exist then. If the `validate-certificate` mode loads an unsuccessful response and ignores it instead of rejecting it, the result is that of `pki/signer-p256` without revocation data. The notes of the entries say so.

## Test keys

Private keys in this directory are test keys with no value outside the test suite. They are never used for anything else. The keys of the test PKI are PKCS#8 files under `pki/keys/`, each named after its certificate with the suffix `.test-key.pem`, as `pki/keys/README.md` states.
