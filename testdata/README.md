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
| `links` | Optional table of other artefacts, by identifier, needed to check this one. `issuer` names the issuer's certificate. `chain` lists the certificates above this artefact, from its issuer up to the trust anchor; when both are given, `chain` starts with `issuer`. `revocation` lists CRLs and OCSP responses. `content` names the signed content of a detached signature, or the data a timestamp covers, of any kind. Every identifier must name another artefact of the manifest; `issuer` and `chain` must name certificates, and `revocation` CRLs or OCSP responses. A list may not name one artefact twice. |
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
| `1.3.6.1.4.1.32473.1.2` | Reserved for the policy of the test timestamping authority (#30) |

Generation is reproducible byte for byte with the same validation time and the same `Cargo.lock`. Each key is derived from its name by a deterministic generator, SHA-256 in counter mode, so the keys are public by construction. RSA PKCS#1 v1.5, ECDSA on P-256 and P-384 (RFC 6979) and Ed25519 signatures are deterministic. Each RSASSA-PSS salt is derived from the signed data by the same generator. ECDSA signatures on P-521 are reproducible too: the `p521` crate offers no RFC 6979 signer, so each nonce is derived by the same generator from the private key and the signed data, as RFC 6979 derives it from both. A change of the RSA or elliptic-curve crates may change the keys, and then every certificate.

The expected OpenSSL results are those of `openssl verify` at the validation time (`-attime`), with the chain of the manifest and default flags. `pki/ca-without-ca-flag` and `pki/ca-without-basic-constraints` verify with default flags and fail with `-x509_strict`. Private keys are expected to parse. The expected DSS results are those of the X.509 certificate validation of ETSI EN 319 102-1 V1.4.1, clause 5.2.6.4, given the CRLs and OCSP responses that later stories link. They are confirmed once `verify` runs DSS. The predictions most likely to change are CERTIFICATE_CHAIN_GENERAL_FAILURE for the end entities under the expired CA and under the CA certificates without cA, and OUT_OF_BOUNDS_NO_POE for the expired and not yet valid certificates, which becomes OUT_OF_BOUNDS_NOT_REVOKED once a CRL that proves non-revocation is linked.

## Test keys

Private keys in this directory are test keys with no value outside the test suite. They are never used for anything else. The keys of the test PKI are PKCS#8 files under `pki/keys/`, each named after its certificate with the suffix `.test-key.pem`, as `pki/keys/README.md` states.
