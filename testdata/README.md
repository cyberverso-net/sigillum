# Test corpus

This directory holds the test corpus of sigillum: certificates, CRLs, OCSP responses, timestamp tokens and signed documents, generated as described in [ADR-0014](../docs/design/adr/0014-test-pki-and-corpus.md). Every artefact is listed in `manifest.toml`, with its purpose and the results expected from OpenSSL and DSS. The program `sigillum-testpki` (in `crates/sigillum-testpki`) generates the artefacts and checks them against the manifest. Its `tsa` subcommand issues timestamp tokens with a time, key and certificate given explicitly, and does not read the manifest.

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

- Entries with the same identifiers are replaced, and new ones are appended.
- `generate pki` owns every certificate and private-key entry under `pki/`. Those that the generator no longer produces are removed from the manifest, and their files are left in place. Certificates and keys made by other means, such as the mutated variants that ADR-0014 plans, must therefore live outside `pki/`. Entries of other kinds, and entries outside `pki/`, are kept.
- Files under `pki/` that no manifest entry names are reported on standard error, and left in place.
- The manifest is written anew, so comments added to it by hand are lost.
- The artefact files are written first, and the files under `pki/` are then listed. The manifest is written last, through a temporary file renamed over it, so a failure at any step, including a directory under `pki/` that cannot be read, leaves the previous manifest in place, possibly beside some new artefact files. Running the command again brings them back in step.

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

The certificates follow RFC 5280, sections 4.1 and 4.2:

- Every time is a fixed offset from the validation time: the root is valid from three years before to ten years after it, the issuing CAs from two years before to five years after, and the end entities from one year before to two years after, except the validity cases.
- Serial numbers are fixed and unique in the test PKI.
- Subject key identifiers use method 1 of RFC 7093, section 2. Every certificate but the root carries the authority key identifier of its issuer.
- Every certificate but the root carries a CRL distribution point and authority information access URIs under `http://example.invalid/`, a domain reserved by RFC 2606 that never resolves. End entities other than the OCSP responder also name an OCSP responder.
- Algorithm identifiers follow RFC 4055 for RSA, RFC 5758 for ECDSA and RFC 8410 for Ed25519. SHA3-256 with RSA PKCS#1 v1.5 uses the identifier of the NIST Computer Security Objects Register, `2.16.840.1.101.3.4.3.14`, with NULL parameters, as OpenSSL encodes it; the register does not specify the parameters.

### Test object identifiers

Object identifiers that the test corpus needs, and that no standard defines, sit under the sigillum test arc `1.3.6.1.4.1.32473.1`. The arc uses Enterprise Number 32473, which RFC 5612, section 2, allocates for use in examples and documentation. New test object identifiers are added to this table only.

| Object identifier | Use |
| --- | --- |
| `1.3.6.1.4.1.32473.1` | The sigillum test arc |
| `1.3.6.1.4.1.32473.1.1` | The unknown critical extension of `pki/signer-unknown-critical-extension` |
| `1.3.6.1.4.1.32473.1.2` | The policy of the test timestamping authority, in the `TSTInfo` of every token that `sigillum-testpki` issues |

Generation is reproducible byte for byte with the same validation time and the same `Cargo.lock`. Each key is derived from its name by a deterministic generator, SHA-256 in counter mode, so the keys are public by construction. RSA PKCS#1 v1.5, ECDSA on P-256 and P-384 (RFC 6979) and Ed25519 signatures are deterministic. Each RSASSA-PSS salt is derived from the signed data by the same generator. ECDSA signatures on P-521 are reproducible too: the `p521` crate offers no RFC 6979 signer, so each nonce is derived by the same generator from the private key and the signed data, as RFC 6979 derives it from both. A change of the RSA or elliptic-curve crates may change the keys, and then every certificate.

The expected OpenSSL results are those of `openssl verify` at the validation time (`-attime`), with the chain of the manifest and default flags. `pki/ca-without-ca-flag` and `pki/ca-without-basic-constraints` verify with default flags and fail with `-x509_strict`. Private keys are expected to parse. The expected DSS results are those of the X.509 certificate validation of ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, given the CRLs and OCSP responses that later stories link. They are confirmed once `verify` runs DSS. The predictions most likely to change are CERTIFICATE_CHAIN_GENERAL_FAILURE for the end entities under the expired CA and under the CA certificates without cA, and OUT_OF_BOUNDS_NO_POE for the expired and not yet valid certificates, which becomes OUT_OF_BOUNDS_NOT_REVOKED once a CRL that proves non-revocation is linked.

## Timestamp tokens

`sigillum-testpki generate timestamps` writes standalone RFC 3161 timestamp tokens under `timestamps/`, with the data they cover, and records each file in `manifest.toml`. It regenerates the test PKI of the validation time in memory and signs with it, so the tokens always match `generate pki`. A test checks that the committed files are what the generator produces, byte for byte. Regeneration follows the rules of the test PKI, with one difference: `generate timestamps` owns every entry whose identifier is under `timestamps/`, whatever its kind. The manifest must already list the test PKI, because the tokens link to it, so `generate pki` runs first. Otherwise `generate timestamps` writes nothing, leaves the manifest unchanged and says so.

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
| `--tsa-key` | The authority's private key, a PKCS#8 PEM file. A DER or non-UTF-8 file is refused |
| `--tsa-cert` | The authority's certificate, which must match the key. A DER file holds one certificate and nothing after it. A PEM file holds a single `CERTIFICATE` block, with nothing after the END line but its line ending. Chain files and the output of `openssl x509 -text` are refused. The key matches when the public keys are equal once decoded, so an elliptic-curve point may be compressed or not |

Before the encapsulation boundary of a PEM document, only a UTF-8 byte order mark and white space are skipped. RFC 7468, section 2, permits data there, and the production `W` of its section 3 defines the white space. Any other text before the boundary is refused. Each file is read up to 64 KiB, which is generous for the keys and certificates of the test PKI; a larger file is refused with exit code 1 before it is parsed, so that an oversized file cannot exhaust memory. The parsers of these options are in the module `timestamp::input` of the library, and the fuzz target `tsa_input` exercises them.

It exits with 0 on success, 2 on a usage error, including an invalid time, algorithm or digest and a digest of the wrong length, and 1 when the key or certificate cannot be read, is not valid or does not match. Every error is reported on standard error, and nothing is written to standard output.

### Expected results

The expected OpenSSL results are those of `openssl ts -verify -in <token> -token_in -data timestamps/content.txt -CAfile pki/root-ca.pem -untrusted pki/ca-ecdsa.pem -attime <validation time>`. OpenSSL rejects the token without `id-kp-timeStamping` with "unsuitable certificate purpose" and the mismatched imprint with "message imprint mismatch". It verifies the token whose `genTime` follows the validation time, because it does not compare `genTime` with the verification time.

The expected DSS results are predictions from ETSI EN 319 102-1 V1.4.1, confirmed once `verify` runs DSS in its `validate-timestamp` mode with the content:

- the valid token and the token with a later `genTime` pass the time-stamp validation building block, clause 5.4.4, which does not compare `genTime` with the validation time. A verifier that uses a token as time evidence must still reject a `genTime` after the validation time. Step 1 of that clause runs the basic signature validation, whose X.509 validation checks revocation (clause 5.2.6.4, step 4), and `pki/tsa` has no `id-pkix-ocsp-nocheck`. PASSED therefore assumes the revocation data for the chain of `pki/tsa` that later stories link, as for the certificates above. Without it, DSS would likely report INDETERMINATE;
- the token without `id-kp-timeStamping` fails the X.509 validation constraints, clause 5.2.6.4, step 5, INDETERMINATE with CHAIN_CONSTRAINTS_FAILURE;
- the token with the mismatched imprint is itself intact. FAILED with HASH_FAILURE is this project's mapping for a message imprint that does not match the data supplied to the validation, as the `validate-timestamp` mode of `tools/dss-oracle` will compare it. It does not follow from clause 5.2.7.4, whose integrity check covers the token's own signed data.

## Test keys

Private keys in this directory are test keys with no value outside the test suite. They are never used for anything else. The keys of the test PKI are PKCS#8 files under `pki/keys/`, each named after its certificate with the suffix `.test-key.pem`, as `pki/keys/README.md` states.
