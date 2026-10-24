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
links = { issuer = "pki/issuing-ca-ec", chain = ["pki/issuing-ca-ec", "pki/root-ca"] }
```

## Test keys

Private keys in this directory are test keys with no value outside the test suite. They are never used for anything else.
