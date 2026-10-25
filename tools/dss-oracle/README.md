# dss-oracle

A small Java command-line tool that runs [DSS](https://github.com/esig/dss), the European Commission's Digital Signature Service library, offline and deterministically. sigillum uses it as an external test oracle: `sigillum-oracle` and `sigillum-testpki` run it as a separate process to validate signatures and test PKI artefacts and to produce signed fixtures. The design is recorded in [ADR-0013](../../docs/design/adr/0013-dss-oracle-command-line-tool.md).

## Licensing

The code of this tool is written for sigillum and licensed like the rest of the repository, under Apache-2.0 OR MIT. It is not adapted from the DSS cookbook or demonstration code.

DSS is licensed under LGPL-2.1. It is a build-time and test-time dependency, resolved by Maven from Maven Central at the version pinned in `pom.xml` (property `dss.version`). No artefact that contains DSS, including the executable JAR built here, is committed, published or distributed, so the distribution conditions of LGPL-2.1 do not arise. The Maven dependencies fall outside the licence policy that `cargo deny` enforces for Rust, so they are listed below and checked by hand whenever they change.

## Building and running

The tool needs Java 21 or later and Maven.

```
mvn -B verify
java -jar target/dss-oracle.jar --version
```

Usage: `dss-oracle <mode> [options]`, or `dss-oracle --version` or `--help` on their own, with the modes `validate-document`, `validate-certificate`, `validate-timestamp` and `sign`, and the common options:

| Option | Meaning |
| --- | --- |
| `--validation-time <time>` | Fixed validation or signing time, as an RFC 3339 time with an offset |
| `--trust-anchor <file>` | Trust anchor certificate; repeatable |
| `--certificate <file>` | Certificate supplied offline; repeatable |
| `--crl <file>` | CRL supplied offline; repeatable |
| `--ocsp <file>` | OCSP response supplied offline; repeatable |
| `--out <directory>` | Output directory, which must not exist or be empty |
| `--policy aligned\|default\|<file>` | Validation policy of a validation mode, described below; `aligned` when absent. Refused in `sign` |
| `--timeout <seconds>` | Time limit of the validation, from 1 to 86400 seconds; 300 by default (see "Resource limits"). Refused in `sign` |

Exit codes: 0 success, 1 failure, 2 usage error, 3 mode not implemented yet, 4 network access attempted. A missing or unreadable input file, or an output directory that is not empty, is a failure. `sign` is not implemented yet.

## Network access

No mode may access the network, and three layers enforce it:

1. **Proxy selector.** The tool replaces the JVM's default proxy selector, which `java.net.URLConnection`, plain sockets and `java.net.http.HttpClient` consult before connecting unless a proxy is given explicitly.
2. **Name resolution.** A resolver registered as a `java.net.spi.InetAddressResolverProvider` service refuses every name lookup made through `java.net.InetAddress`, forward or reverse, during a run.
3. **No network in CI.** Continuous integration builds the tool with network access, then runs it in a network namespace without any. This covers only the jobs that run the tool that way: the check of this tool does, and the planned differential-test and fixture-verification jobs must do the same. The Maven tests run with network access.

The first two layers record every attempt, and a run with any attempt fails with exit code 4, even if the code that made the attempt ignored the error. In process, they do not see:

- NIO socket channels and UDP datagram sockets to an IP address;
- the JNDI DNS provider, which sends its own queries;
- connections to an IP address opened with an explicit `Proxy.NO_PROXY`;
- a `java.net.http.HttpClient` built with its own proxy selector, or built before the guard, connecting to an IP address.

Connections to a host name are caught by the second layer. The third layer covers the remaining gaps in the jobs that run the tool without network. The modes configure DSS with offline sources only, as described in the next section. A run of `validate-timestamp` on the timestamp corpus, of `validate-certificate` on the certificates, CRLs and OCSP responses of the corpus, or of `validate-document` on the documents that its tests sign, makes no name lookup, not even of the local host name, so the guard makes no exception.

## Validation modes

The validation modes run DSS at the fixed validation time, with the validation policy chosen by `--policy` (see [Validation policy](#validation-policy)) and English report messages. DSS sees only the files named on the command line:

- `--trust-anchor` gives the trust anchors;
- `--certificate` gives other certificates, such as intermediate CAs, which DSS may use to build a chain;
- `--crl` and `--ocsp` give revocation data, which DSS uses in place of retrieving any.

DSS has no source that fetches certificates through the authority information access extension, CRLs or OCSP responses. Certificates and CRLs are read in DER or PEM, as DSS reads them. OCSP responses are read in DER only, because DSS does not read them in PEM.

### validate-certificate

```
dss-oracle validate-certificate --certificate <file> [--certificate <file>]... --trust-anchor <file>
    [--crl <file>] [--ocsp <file>] --validation-time <time> --out <directory>
```

It validates a certificate as DSS validates one on its own: the X.509 certificate validation of [ETSI EN 319 102-1 V1.4.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf), clause 5.2.6, for the certificate and the chain that DSS builds to a trust anchor. The policy derives from the default certificate validation policy of DSS, "Certificate policy TL based" (`policy/certificate-constraint.xml` in `dss-policy-jaxb`), not from the policy it applies to signatures and timestamps. That policy also asks for the qualification of the certificate under the EU trusted lists. The tool supplies none, so the qualification process in the detailed report fails; `summary.json` does not report it.

The first `--certificate` names the certificate to validate. Every further `--certificate` is supplied for its chain only, such as an intermediate CA. The certificate to validate may also be a trust anchor, as `pki/root-ca` is. `--certificate`, `--trust-anchor`, `--validation-time` and `--out` are required.

DSS chooses the revocation data of each certificate in the chain among the CRLs and OCSP responses supplied. When an OCSP response covers a certificate, DSS 6.5.1 has been observed to take it and not to load the CRL in two cases where the response is not acceptable: when its status is unknown, and when its signer cannot be validated because the certificate of the responder carried in the response has an altered signature. When the response's own signature does not verify, DSS sets it aside and uses the CRL. DSS loads the CRL when no supplied OCSP response covers the certificate, for example when the CertID of the response names another issuer. The missing fallback is recorded as the divergence DIV-4 in [divergences.md](../../docs/design/divergences.md). `summary.json` names the file that DSS used for the certificate itself.

For a certificate of the corpus, the chain is supplied as follows, with the CRL of its issuer and the CRL that its CA certificate links:

```
java -jar target/dss-oracle.jar validate-certificate \
    --certificate ../../testdata/pki/signer-p256.pem --certificate ../../testdata/pki/ca-ecdsa.pem \
    --trust-anchor ../../testdata/pki/root-ca.pem \
    --crl ../../testdata/crl/ca-ecdsa.crl --crl ../../testdata/crl/root-ca.crl \
    --validation-time 2030-01-15T10:00:00Z --out results/signer-p256
```

The expected DSS result of a CRL or an OCSP response in `testdata/manifest.toml` is a prediction of the result of this mode for the certificate that it covers, given that CRL or response and the revocation data that the CA certificates of the chain link, as `testdata/README.md` describes. The test `ValidateCertificateTest` runs every certificate, CRL and OCSP response of the corpus so, under the aligned policy, and requires the predicted result. The only exceptions are the divergences recorded in [divergences.md](../../docs/design/divergences.md), whose results the test pins. It also runs `ocsp/responder-without-ocsp-signing` with the CRL of `pki/ca-ecdsa`, which covers the signer of the response: DSS then uses the response, the divergence DIV-3.

### Validation policy

The validation policy is decided in [ADR-0023](../../docs/design/adr/0023-validation-policy-of-the-dss-oracle.md). `--policy` takes one of two names, or the path of a policy file:

- `aligned`, the default: the default policy of DSS 6.5.1 for the kind of validation, with four deltas that ETSI EN 319 102-1 V1.4.1 leaves to the policy. The class `AlignedPolicy` builds it at run time from the policy that DSS ships, which is not copied into the repository. It accepts Ed25519, checks revocation freshness against `nextUpdate` (clause 5.2.5.4), fails on a critical extension that DSS does not support (RFC 5280, section 6.1.5 (f)), and skips revocation checking of a signing certificate with `id-pkix-ocsp-nocheck` (RFC 6960, section 4.2.2.2.1). Its version is 1, and `summary.json` names it `aligned-1`. Two limits follow from the policies of DSS. The list of supported critical extensions lacks policyMappings (2.5.29.33), which DSS does not process, so a CA certificate with that extension critical fails. In the policy for signatures and timestamps, the signing certificates forbid `id-pkix-ocsp-nocheck` at level FAIL, so the fourth delta has no effect there; in the certificate policy it applies to any certificate under validation that carries the extension, not only to OCSP responders.
- `default`: the default policy of DSS 6.5.1, unchanged, named `default` in `summary.json`.
- any other value: a DSS policy file, in the format of the policy schema of DSS (`xsd/policy.xsd` in `dss-policy-jaxb`). A file named `aligned` or `default` is given with a path, such as `./aligned`. `summary.json` names the file and the SHA-256 digest of its content.

The class `PolicySelection` selects the policy for every validation mode, so that a mode only states its kind of validation, certificate or document, and passes its validation to `PolicySelection.validate`. `validate-document` uses it as a validation of the document kind.

A policy file is an input. A missing or unreadable file is a failure of the tool. DSS loads the file through `ValidationPolicyLoader`, which checks it against the policy schema; a file that it cannot load is rejected, with the message of DSS. DSS reports such a file with unchecked exceptions, so the tool catches every exception at that call, as it does for the CRL parser. If the validation then fails with the file, the tool runs it again with the aligned policy: when that run succeeds, the failure belongs to the file, which is rejected; otherwise the first failure is a failure of the tool, with the second suppressed. The rerun needs no knowledge of which part of the file failed, which matters for documents: DSS reads the parts that the document needs, as described under `validate-document`. A file whose `AlgoExpirationDate` has a date `Format` that DSS cannot use is valid against the schema but makes the validation fail, and is rejected so.

Comparisons with the corpus predictions and with sigillum use the aligned policy. The default policy is run for information only. `ValidateCertificateTest` runs the corpus under both and prints the results. Under the default policy of DSS 6.5.1, these cases give another result than under the aligned policy; every other case gives the same result under both:

| Case | Aligned policy | Default policy |
| --- | --- | --- |
| `pki/signer-ed25519`, `crl/ca-ed25519`, `ocsp/signer-ed25519` | PASSED | INDETERMINATE with CRYPTO_CONSTRAINTS_FAILURE_NO_POE |
| `crl/ca-ecdsa-expired` | INDETERMINATE with TRY_LATER | PASSED |
| `pki/signer-unknown-critical-extension`, `ocsp/signer-unknown-critical-extension` | INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE | PASSED, with a warning |
| `pki/ocsp-responder` | PASSED | INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE |

### validate-timestamp

```
dss-oracle validate-timestamp --timestamp <file> [--data <file> | --digest <hex> --digest-algorithm <name>]
    --trust-anchor <file> [--certificate <file>] [--crl <file>] [--ocsp <file>]
    --validation-time <time> --out <directory>
```

It validates a standalone RFC 3161 timestamp token, in DER, as DSS validates a detached timestamp. With `--data`, DSS also checks that the message imprint of the token is the digest of the file. With `--digest` and `--digest-algorithm`, it checks the message imprint against that digest instead. The digest is in hexadecimal, and the algorithm is named as DSS names it. The names accepted are those that DSS 6.5.1 defines and that the JVM or Bouncy Castle, which DSS registers, can compute: `SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`, `SHA3-224`, `SHA3-256`, `SHA3-384`, `SHA3-512`, `SHAKE256-512`, `RIPEMD160`, `WHIRLPOOL`, `MD2` and `MD5`. `SHAKE-128` and `SHAKE-256` are refused with the usage error `--digest-algorithm: SHAKE-128 is not available.` (or `SHAKE-256`), because no provider computes them under those names. A token whose message imprint uses one of them is rejected when `--data` is given, since DSS cannot hash the data, and validated otherwise. The algorithm must be that of the message imprint, or the run is a usage error. Without data or a digest, the message imprint is not checked, `data-found` is false in the summary, and DSS 6.5.1 reports INDETERMINATE with SIGNED_DATA_NOT_FOUND.

`--timestamp`, `--trust-anchor`, `--validation-time` and `--out` are required. `--data` and `--digest` are mutually exclusive. The options `--timestamp`, `--data`, `--digest` and `--digest-algorithm` are refused in the other modes.

For the timestamp corpus of `testdata/timestamps/`, the chain of `pki/tsa` is supplied as follows:

```
java -jar target/dss-oracle.jar validate-timestamp \
    --timestamp ../../testdata/timestamps/valid.tst --data ../../testdata/timestamps/content.txt \
    --trust-anchor ../../testdata/pki/root-ca.pem --certificate ../../testdata/pki/ca-ecdsa.pem \
    --crl ../../testdata/crl/ca-ecdsa.crl --crl ../../testdata/crl/root-ca.crl \
    --validation-time 2030-01-15T10:00:00Z --out results/valid
```

### validate-document

```
dss-oracle validate-document --document <file> [--detached <file>] [--policy aligned|default|<file>]
    --trust-anchor <file> [--certificate <file>] [--crl <file>] [--ocsp <file>]
    --validation-time <time> --out <directory>
```

It validates the signatures of a signed document as DSS validates one: the validation of [ETSI EN 319 102-1 V1.4.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf) as DSS implements it, reported in the format of [ETSI TS 119 102-2 V1.4.1](https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf) among the reports of DSS. DSS recognises the format of the document from its content:

- CAdES: a CMS signed-data structure, enveloping or detached, through `dss-cades`;
- PAdES: a PDF document, through `dss-pades` with the PDF backend of DSS built on Apache PDFBox, `dss-pades-pdfbox`;
- JAdES: a JWS in the compact or JSON serialisation, through `dss-jades`.

DSS offers a second PDF backend, built on OpenPDF. The tool uses the PDFBox backend, whose libraries are under Apache-2.0. DSS takes the first implementation that the service registration of `dss-pades-pdfbox` lists, `PdfBoxNativeObjectFactory`. The PDF backend changes how DSS reads a PDF, and so the results; the choice is part of the pinned configuration, like the DSS version.

`--detached` gives the content of a detached signature, such as a CAdES signature without encapsulated content. It takes one content only: a signature over several detached documents, such as a JAdES signature with several `ObjectIdByURIHash` references, cannot be validated with all of them yet. Without it, DSS reports such a signature INDETERMINATE with SIGNED_DATA_NOT_FOUND. A file given with `--detached` is never rejected: any content can be hashed, and content that does not match the signature makes it fail with HASH_FAILURE. DSS receives the document and the detached content named after their files, without the directory, so that the reports do not depend on where the files are.

`--policy` selects the policy as described under [Validation policy](#validation-policy): the aligned policy by default. The default policy of DSS for signatures, "QES AES/QC AES TL based" (`policy/constraint.xml` in `dss-policy-jaxb`), on which the aligned policy is built, also asks for the qualification of the signing certificate under the EU trusted lists. The tool supplies none, so the qualification details of the reports carry an error; `summary.json` does not report qualification.

DSS reads part of a policy file only during the validation, and only the parts that the document needs. It parses the algorithm expiration dates of the cryptographic constraints of a context when it first needs them, and fails then on a date format that is not a pattern. Which contexts it needs depends on the document and its certificates: DSS 6.5.1 was observed, for example, to read the constraints of the CA certificates of a CRL but not those of its signing certificate, when the signer of the CRL is a CA of the chain. Reading the constraints before the validation would therefore reject files that DSS can use. The rerun with the aligned policy described under [Validation policy](#validation-policy) attributes such a failure to the file instead, and needs no knowledge of which part failed. `ValidateDocumentTest` puts a bad date format in each of the 14 places of the default policy that hold cryptographic constraints, and compares the result of the tool with that of DSS alone for a signature, a signature with a timestamp and an unsigned PDF.

The certificates supplied with `--trust-anchor` and `--certificate` are also given to DSS as its signing certificate source, so that a signature that does not hold its signing certificate, such as a CMS signature without certificates, finds it among them. `validate-timestamp` needs no such source: DSS looks for the signer of a standalone token among the supplied certificates already.

The tool gives DSS a signature policy provider without a data loader, so that the document of an explicit signature policy (EPES) is never retrieved from the URL that the signature names. DSS 6.5.1 retrieves none for these formats without a provider either.

Apache PDFBox looks among the fonts of the host for a substitute when a page that DSS renders uses a font that the PDF does not embed, so the rendering, and the comparison of revisions that uses it, may depend on the fonts installed. PDFBox writes the list of those fonts to a cache file, by default in the home directory. The tool points the system property `pdfbox.fontcache` to a temporary directory, removed when the JVM exits, unless the property is set already.

`--document`, `--trust-anchor`, `--validation-time` and `--out` are required. The options `--document` and `--detached` may be given once, and are refused in the other modes.

DSS validates a standalone timestamp token given as the document as a detached timestamp, with no signature: the summary then lists none. Use `validate-timestamp` for timestamp tokens.

For a document signed by `pki/signer-p256`, the chain is supplied as follows:

```
java -jar target/dss-oracle.jar validate-document --document signed.pdf \
    --trust-anchor ../../testdata/pki/root-ca.pem --certificate ../../testdata/pki/ca-ecdsa.pem \
    --crl ../../testdata/crl/ca-ecdsa.crl --crl ../../testdata/crl/root-ca.crl \
    --validation-time 2030-01-15T10:00:00Z --out results/signed
```

Until the corpus holds signed documents, the tests sign their own with DSS, the key of `pki/signer-p256` and the chain of `pki/ca-ecdsa`, at the planned signing time 2029-12-16T10:00:00Z: a CAdES baseline B signature, enveloping and detached, a CAdES baseline T signature with a timestamp issued by `pki/tsa`, a PAdES baseline B signature of a one-page PDF, and JAdES baseline B signatures in the compact and flattened JSON serialisations. The ECDSA random numbers come from a seeded generator, so every document is the same on every run. `mvn verify` writes four of them, with the detached content, to `target/test-documents`, where continuous integration validates them with the JAR without network.

### Output

A validation mode writes the reports that DSS gives for its kind of validation, then `summary.json`, to the output directory, which it creates if needed. The set of reports belongs to the mode. `validate-timestamp` writes these files:

| File | Content |
| --- | --- |
| `diagnostic-data.xml` | The DSS diagnostic data |
| `detailed-report.xml` | The DSS detailed report |
| `simple-report.xml` | The DSS simple report |
| `etsi-validation-report.xml` | The validation report in the format of [ETSI TS 119 102-2 V1.4.1 (2023-06)](https://www.etsi.org/deliver/etsi_ts/119100_119199/11910202/01.04.01_60/ts_11910202v010401p.pdf), as DSS produces it |
| `summary.json` | The summary described below, written last |

`validate-document` writes the same files. `validate-certificate` writes `diagnostic-data.xml`, `detailed-report.xml`, `simple-report.xml`, which is the DSS simple certificate report, and `summary.json`. DSS gives a certificate validation no report in the format of ETSI TS 119 102-2.

The reports are written as DSS produces them, unchanged. Their content is the same on every run with the same inputs. The namespace prefixes in `etsi-validation-report.xml` may differ from one run to the next, because the XML binding of DSS chooses them; the elements, attributes and values do not. Exclusive XML canonicalisation does not remove the difference, because it keeps the prefixes of the document. Comparisons therefore use `summary.json`. The tests compare that report by its content with the prefixes resolved.

When DSS cannot use an input file, the mode writes only `summary.json`, with the result `rejected`, and exits with code 0. This is a result, as ADR-0013 requires, not a failure of the tool.

### Resource limits

Every validation mode runs DSS on a worker thread within three limits. A run that exceeds one writes only `summary.json`, with the result `resource-limit`, the limit exceeded and the values of the three limits, and exits with code 0. Reports written before are removed.

| Limit | Value | Exceeded when |
| --- | --- | --- |
| `heap` | The maximum heap of the JVM, set with `-Xmx`, with the garbage collector of the JVM | DSS runs out of memory: an `OutOfMemoryError` on the worker |
| `stack` | 64 MiB, fixed, whatever the default of the host | The stack of the worker overflows: a `StackOverflowError` |
| `time` | `--timeout`, 300 seconds by default | The worker is still running |

The outcome of a run that comes near a limit depends on it, so the limits are part of a result, and `limits` records them with the names of the garbage collectors of the JVM. How close to the heap limit a run comes also depends on the collector, so the invocation pins it: continuous integration runs the JAR with `java -Xmx512m -XX:+UseSerialGC -jar target/dss-oracle.jar ... --timeout 120`, and the differential-test and fixture-verification jobs must give the limits and collector they use. An outcome near a limit is then reproducible on the same JVM with the same heap, collector and time limit, not across hosts with others. A worker past its time limit is interrupted and left to end, since Java cannot stop a thread safely; nothing more is written to the output, and the tool exits. A caller that runs the tool in its own JVM, as the tests do, keeps such a worker running after the network guard is closed, so its network attempts are no longer recorded.

The memory of some inputs grows with sizes that they declare. DSS compares the pages of a PDF that has revisions after a signature by rendering up to 10 pages of each, at a size that the PDF declares; a page of 40,000 by 40,000 units ends with `resource-limit` in a heap of 256 MiB, as a test checks. The tool does not reject such a PDF: DSS can use it with a larger heap, so a bound on the declared size would reject documents that DSS can use. The limit `heap`, with its value recorded, makes the outcome reproducible instead.

The stack is fixed for JSON. DSS 6.5.1 validates the JSON of a JWS against the JAdES schema with json-sKema 0.32.0, whose parser refuses a value nested more than 100,000 levels deep, and DSS then fails. With the stack of 64 MiB, DSS was observed to parse JSON nested 99,999 levels deep in the document, its unprotected header, its protected header and the header of the compact serialisation, also with the JIT compiler disabled (`-Xint`), where frames are largest. With the default stack of 1 MiB, it overflowed at depths from about 1,700. These observations were made with Temurin 27+35 on macOS, aarch64; frame sizes differ with the JVM and the architecture.

Before DSS parses a JWS, the tool walks its JSON and rejects a document nested deeper than DSS accepts, on which DSS fails. It reads the parts that DSS parses, at the places that the JWS structure gives them:

- the document, in the JSON serialisation (RFC 7515, section 7.2);
- the JWS Protected Header: the member `protected` of each element of `signatures` in the general syntax (section 7.2.1), or, when the document has no `signatures`, the member `protected` of the document in the flattened syntax (section 7.2.2). When `signatures` is present, DSS uses it only, and ignores the members `protected` and `header` of the document;
- the components of `etsiU` (ETSI TS 119 182-1 V1.2.1, clause 5.3.1) in the JWS Unprotected Header, `header`, at the same places, when every component of the array is a string of base64url characters only. DSS then decodes the components, builds the object `{"etsiU":[...]}` of the decoded components and validates that object against the schema (`DSSJsonUtils.validateAgainstJAdESSchema`), so a component counts two levels deeper. When a component is not such a string, DSS does not validate the components against the schema, and the tool does not count them;
- the counter signatures (`cSig`, clause 5.3.2) in the etsiU components, encoded or clear, as a string or an object: DSS parses each as a JWS of its own, an object as its JSON text, and validates it against the schema, with its own counter signatures in turn. DSS selects components as `DSSJsonUtils.parseEtsiUComponent` does: a clear component counts only when it has one member, and an encoded one only by its first member, so a `cSig` elsewhere in a component is not parsed. The tool checks each counter signature as a document, from a work list, so chains of counter signatures are followed without recursion;
- the JWS Protected Header of the compact serialisation (section 7.1), the part before the first full stop, also when line breaks end the document, as DSS allows.

Member names and values are read with their JSON escapes decoded (RFC 8259, section 7), and the encoded parts are decoded from base64url with the function of DSS, `DSSJsonUtils.fromBase64Url` (jose4j), which skips characters outside the alphabet. Places are matched by their path of member names and array elements, not by a name alone: a member of the same name elsewhere, such as a `protected` member of a header parameter, or a member whose name spells a path, such as `etsiU/#/cSig`, is not taken for one.

The walk follows the places listed above. DSS may parse JSON elsewhere that the walk does not foresee. In a JWS, the document is the only input that holds JSON, so the tool attributes to it any refusal of json-sKema to parse JSON nested too deep, a `TooDeeplyNestedValueException`, thrown during the checks or the validation, and reports `rejected` for `--document`. It does so only for a document that DSS reads as a JWS. With this, JSON nested too deep in a JWS ends in `rejected`, never in exit code 1. A test runs crafted JWS documents, with counter signatures, mixed and lenient etsiU arrays, ignored members, duplicate members and escapes, and requires the result of DSS alone: `rejected` exactly when DSS fails.

The tool reads ADR-0013 for inputs as a rule per file. A file is rejected if DSS would fail on it when it uses it, even when this validation does not use it. For example, a CRL that covers no certificate of the run is still rejected when DSS cannot read its entries.

DSS loads the inputs before the validation but parses part of them only during it. There it drops some inputs it cannot parse, and fails with an error on others. The tool therefore makes, before the validation, the calls that DSS makes on each input when it uses it. It rejects the input when one of them fails, with the message of DSS or Bouncy Castle. The calls involve the input alone, or the input and the supplied certificates, never the validation, so a failure belongs to the input. The rule for each kind of input:

| Input | Rejected when |
| --- | --- |
| Certificate (`--trust-anchor`, `--certificate`) | DSS cannot load it, or cannot decode its public key, its extensions or the values of its subject name |
| CRL (`--crl`) | DSS cannot load it; or an element declares a length beyond the remaining bytes by more than the size of the CRL (see below); or the CRL parser of DSS fails on it, an error that DSS itself catches before dropping the CRL; or DSS fails while making revocation tokens from it |
| OCSP response (`--ocsp`) | DSS cannot load it; or cannot decode its single responses, an error that DSS itself catches before using none of them; or does not support its signature algorithm, which DSS resolves when it verifies or reports the response; or cannot convert or decode a certificate that it holds; or fails while making revocation tokens from it |
| Signed document (`--document`) | DSS recognises no format in it, or fails to parse it; or it fails, uncaught, on one of the calls described below; or it is a JWS whose JSON is nested deeper than 100,000 levels, found before the validation or refused by DSS during it (see "Resource limits") |
| Policy (`--policy`) | DSS cannot load it as a validation policy, which DSS reports as "Unable to load the policy"; or DSS fails during the validation on the cryptographic constraints of the policy, such as an `AlgoExpirationDate` whose `Format` is not a date pattern, as described under `validate-document` |
| Timestamp token (`--timestamp`) | DSS cannot parse it, including a CMS structure without encapsulated content, on which Bouncy Castle fails; or it does not support the algorithm of the message imprint, or cannot compute it when `--data` is given; or a CMS structure that lacks members; or an ESS signing certificate reference makes DSS fail (see below); or DSS cannot decode a certificate that it holds, as for `--certificate`; or DSS cannot decode its signature value or algorithm with a certificate that it tries as the signer |

DSS makes revocation tokens, as it does during the validation, for every pair of a certificate and an issuer whose subject is the issuer name of that certificate. The certificates are the supplied ones, which include the certificate under validation, and those of the timestamp token, or those of the signed document that DSS processes (see below). DSS tries as the signer of a token the best candidate found in the token. When the token does not hold it, DSS tries the supplied certificates that match the signer identifier.

**Declared lengths in CRLs.** DSS 6.5.1 has been observed to use memory in proportion to the length that a CRL element declares, several times over, whatever the size of the file. When the bytes run out before the declared length, it treats the missing ones as zeros and continues. That is why it uses a CRL whose signature lacks its last, zero, octet. A length that the file cannot come close to filling, however, leaves DSS with a CRL whose signature does not verify, and so with no usable token, after it has used memory that the length decides. Such a CRL is therefore rejected: DSS's parsing of it depends on the heap and yields no usable token.

Before DSS reads a CRL, the tool walks it, following the encoding rules of ITU-T X.690 (02/2021), without allocating anything in proportion to a declared length:

- The identifier octets follow clause 8.1.2, including the high tag number form of clause 8.1.2.4. The length octets follow clause 8.1.3: the short form (8.1.3.4), the long form (8.1.3.5) and the indefinite form (8.1.3.6).
- Starting from the first octet, the walk visits every position where a reader that goes through the encoding in order can meet identifier octets. Those are the contents of a constructed element (clause 8.1.2.5) or of an element of indefinite length, and the position after the contents of an element of definite length. It keeps one bit per input octet, so it takes memory and time in proportion to the input.
- An element is rejected when its definite length exceeds the bytes that remain after its length octets by more than the size of the CRL. The slack keeps the short reads that DSS accepts. With it, no declared length is more than twice the size of the CRL, and every element of `crl/ca-ecdsa` given a length just under 64 MiB in turn ends with exit code 0 in a JVM with a heap of 128 MiB.
- The length of the outermost SEQUENCE is not checked. DSS has been observed to use a CRL whose outer length is wrong or indefinite.
- Indefinite lengths are left to DSS. A CRL signed again with an indefinite length in its crlExtensions is used by DSS. One with an indefinite length on a revoked certificate entry makes DSS fail while it makes revocation tokens, and is rejected for that.
- Incomplete identifier or length octets, the reserved initial octet 0xFF of clause 8.1.3.5 c), tag numbers and the contents of primitive elements are left to DSS.

A probe tried every single-byte change, truncation and insertion of a zero byte in both CRLs of the corpus. At each byte outside the signed part it tried every value, and inside it 12 values. That is 34,318 variants of `crl/ca-ecdsa` and 106,925 of `crl/root-ca`. The walk rejected 1,351 and 2,388 of them. DSS alone made a usable revocation token from 4 of the rejected ones, all variants of `crl/root-ca`. They change the identifier octet of its signatureValue BIT STRING from 0x03 to 0x23, 0x63, 0xA3 or 0xE3, which sets the constructed bit. The walk then reads the bytes of the signature as encodings, while DSS still reads the signature value. DER requires a BIT STRING to be primitive (X.690, clause 10.2), so these CRLs are not valid DER; they are known and recorded for a follow-up. A change inside the signed part makes the signature fail, so the probe cannot find a false rejection there: that needs CRLs signed again after the change, such as the CRLs with indefinite lengths above.

**Signed documents.** DSS parses a signed document in stages: it recognises the format, builds the signatures and the timestamps of the document, then adds each signature to the validation and reports it. The tool makes, before the validation, the calls of these stages that DSS does not catch, on the validator that then runs the validation, so that the calls are DSS's own:

- it builds the signatures, with their counter-signatures, and the timestamps of the document;
- for each signature, it reads the certificate, CRL and OCSP sources, resolves the signing certificate, which checks the signature value, and reads the timestamps and evidence records;
- it identifies every certificate reference of a signature, as DSS does in its reports; DSS fails on a reference that holds no value identifying a certificate, such as a digest, an issuer or a key identifier;
- it requires the CRL and OCSP sources of each signature: DSS leaves a source unset after an error that it only logs, then fails on it when it reports the signature;
- before DSS parses a JWS, it checks the nesting depth of its JSON, as described under "Resource limits";
- it decodes, as for `--certificate`, the certificates that DSS processes and reports: the signing certificate of each signature, or its valid candidates, the signing certificate of each timestamp, and, transitively, the certificates of the document and the supplied ones whose subject is the issuer name of one of these. DSS does not process a certificate of the document or of a timestamp token outside these chains, and does not fail on it;
- for each timestamp, it resolves the algorithm of the message imprint and, when DSS computes the imprint, the digest implementation that it computes it with: always for a timestamp of a signature, and for a timestamp given as the document only with `--detached`. It then checks the signing certificate references and the signature value of the token as for `--timestamp`.

The calls follow how DSS 6.5.1 has been observed to fail on mutated documents. They are not exhaustive: a document on which DSS fails at a later stage still ends the run with exit code 1. DSS also compares the pages of a PDF that has revisions after a signature, rendering up to 10 pages, so its memory use there follows the page sizes that the document declares; see "Resource limits". Revocation data embedded in a signature, as at baseline LT, is not walked as `--crl` is. Mutations of the PDF structure seldom reach the stages above, so the mutation test exercises PAdES less than CAdES and JAdES.

**Signing certificate references.** DSS 6.5.1 reads the ESSCertIDs of the signingCertificate attributes, then the ESSCertIDv2s of the signingCertificateV2 attributes, in their order. Tokens changed and signed again showed when it fails:

- an ESSCertIDv2 whose hash algorithm DSS cannot compute, such as SHAKE-128, fails wherever it stands, unless DSS has stopped reading that list at an earlier ESSCertIDv2 with an algorithm it does not know: DSS reads no further in a list after such an entry;
- an ESSCertID with an empty hash and no issuer and serial number fails wherever it stands;
- an ESSCertID with an empty hash but an issuer and serial number fails when it comes before a reference whose hash matches a certificate of the token or a supplied one, and is harmless after one.

The tool rejects the token in exactly these cases.

OCSP responses need no such walk: DSS reads them with Bouncy Castle from a byte array, and Bouncy Castle refuses a length beyond the bytes it has.

A file that DSS can use is never rejected:

- a CRL or OCSP response whose signature does not verify, or that covers none of the certificates, is kept when DSS can read it, and the validation reports what follows from it;
- a CRL whose outer length octets are wrong is kept, because the CRL parser of DSS ignores them;
- an OCSP response with an unsuccessful status but with response bytes is kept, because DSS reads the response bytes whatever the status;
- bytes after the first structure of a CRL or OCSP response are ignored, as DSS ignores them;
- a certificate in a token that DSS cannot convert at all is skipped, as DSS skips it.

The catches are limited to the exceptions that DSS and Bouncy Castle throw for malformed input. Two calls are the exception: the CRL parser of DSS and the decoding of the single responses of an OCSP response. DSS itself catches every exception at those calls and then drops the file, so the tool catches every exception there too. An environment failure at those calls, such as a missing security provider, would therefore also become `rejected` rather than a failure of the tool. Any other error, during the checks or the validation, remains a failure of the tool, with exit code 1.

### Fuzz coverage

The test `MutationTest` is the fuzz coverage of the Java tool. It runs each validation mode on inputs of the corpus with deterministic mutations, 2000 per mode, each mode from its own fixed seed. The inputs of `validate-timestamp` are:

- the four timestamp tokens and their content;
- the CRLs of `pki/ca-ecdsa` and `pki/root-ca`;
- an OCSP response for `pki/tsa` signed by `pki/ocsp-responder`, built by the tests;
- the certificate of `pki/tsa`, supplied with `--certificate` for the valid token without its certificates, so that DSS takes it as the signer;
- the trust anchor `pki/root-ca`.

The inputs of `validate-document`, with the chain and CRLs of `pki/signer-p256`, are:

- the test documents described under `validate-document`: the CAdES baseline B signature, enveloping and detached, the CAdES baseline T signature, the PAdES signature and the two JAdES signatures;
- the detached content, with the detached CAdES signature;
- the default policy of DSS, given with `--policy`, with the enveloping CAdES signature.

The inputs of `validate-certificate`, which validates `pki/signer-p256` with the chain of `pki/ca-ecdsa`, are:

- the certificate under validation, `pki/signer-p256`, in DER;
- the CRLs of `pki/ca-ecdsa` and `pki/root-ca`;
- the OCSP response `ocsp/signer-p256`, signed by `pki/ocsp-responder`, which holds the certificate of the responder. It is mutated in two runs: beside the CRL of `pki/ca-ecdsa`, which DSS loads only when the mutated response no longer covers `pki/signer-p256`, and without that CRL, where the response is the only revocation data for `pki/signer-p256`;
- two policy files given with `--policy`: the aligned certificate policy, written as a DSS policy file by the test, and the same policy with a date `Format` in `AlgoExpirationDate` that DSS cannot use. They are not DER, so their mutations do not include changes to DER length octets.

The mutations are bit flips, byte replacements, truncations, insertions and changes to DER length octets. The test runs each through its mode in process and requires exit code 0 with the result `validated` or `rejected`: no exception, no failure of the tool and no network attempt.

It also checks every rejection against DSS alone, without any code of the tool, so that the tool rejects only what DSS cannot use:

- a rejected document, detached content or policy must make DSS fail, since every validation of the document uses all three, and a validated one must give the indication and sub-indication of its first signature that DSS alone gives, since the checks of the tool run on the objects that DSS then validates;
- a rejected token must make DSS fail, at the stage where the tool rejected it;
- a rejected policy file must make DSS alone fail, when it loads the file or validates `pki/signer-p256` with it;
- a rejected certificate under validation must make DSS fail, since every validation of that certificate uses it;
- any other rejected certificate, CRL or OCSP response is put where the corpus uses it, and DSS validates the token or the certificate with it. If that validation completes, the file must not be among the certificates that DSS used, or among the revocation data whose signing certificate DSS found, whether or not the signature verifies.

As controls, DSS alone must validate the corpus as PASSED, and every test document as TOTAL_PASSED, and must use the corpus files that the cross-checks look for. The test takes a few minutes in `mvn -B verify` and needs no dependency of its own.

### summary.json

`summary.json` is a JSON object (RFC 8259) in UTF-8, written with its members in the order below, indented by two spaces and ending with a line feed. Two runs with the same inputs give the same bytes.

| Member | Content |
| --- | --- |
| `format-version` | `3`, the version of this schema. Version 2 added `policy`; version 3 added `oracle` and the result `resource-limit` |
| `oracle` | The identity of the oracle, which decides its results: `tool-version`, `dss-version`, `pdf-backend`, the DSS module that reads PDF documents (`"dss-pades-pdfbox"`), and `pdf-backend-version`, the version of Apache PDFBox that it uses, as PDFBox reports it |
| `mode` | The mode, such as `"validate-certificate"`, `"validate-timestamp"` or `"validate-document"` |
| `validation-time` | The validation time, in UTC, such as `"2030-01-15T10:00:00Z"` |
| `policy` | The validation policy of the run: `"aligned-1"`, the aligned policy in version 1; `"default"`, the default policy of DSS; or, for a policy file, an object with `file`, the file as named on the command line, and `sha256`, the SHA-256 digest of its content in lowercase hexadecimal |
| `result` | `"validated"` when DSS ran the validation, `"rejected"` when it could not parse or use an input, a policy file included ([ADR-0023](../../docs/design/adr/0023-validation-policy-of-the-dss-oracle.md)), `"resource-limit"` when the run exceeded a resource limit |

When the result is `validated`:

| Member | Content |
| --- | --- |
| `indication` | The indication of the validated token or certificate as DSS names it, such as `"PASSED"`, `"FAILED"`, `"INDETERMINATE"` or `"TOTAL_PASSED"`. DSS writes indications with underscores where ETSI EN 319 102-1 V1.4.1 uses hyphens. For a certificate, it is the conclusion of the X.509 certificate validation block (XCV) of the certificate in the detailed report, which covers the whole chain (see below). For a document, it is the indication of its signature when it has exactly one, and `null` otherwise: one signature must not stand for others. `details` gives every signature |
| `sub-indication` | The sub-indication as DSS names it, such as `"HASH_FAILURE"`, or `null` |
| `details` | An object with the details of the mode |

The details of `validate-timestamp` are:

| Member | Content |
| --- | --- |
| `token-id` | The identifier of the token in the DSS reports |
| `production-time` | The `genTime` of the token, in UTC |
| `produced-by` | The name that DSS gives the signer of the token, usually the common name of its certificate |
| `message-imprint` | An object: `digest-algorithm`, the DSS name of the algorithm of the message imprint; `data-found`, whether data or a digest was supplied; `data-intact`, whether the message imprint matches it |
| `errors` | The errors of the validation in the simple report, as a list of objects with the message `key` of DSS and its English `message` |
| `warnings` | The warnings, in the same form |

The details of `validate-certificate` are:

| Member | Content |
| --- | --- |
| `certificate-id` | The identifier of the certificate in the DSS reports |
| `common-name` | The common name of its subject, or `null` |
| `simple-report` | An object: `indication` and `sub-indication`, the result that the simple certificate report gives the certificate (see below) |
| `revocation` | The revocation data that DSS used for the certificate, described below, or `null` when it used none: for a trust anchor, or when no supplied revocation data is acceptable |
| `errors` | The errors of the X.509 validation in the simple certificate report, as a list of objects with the message `key` of DSS and its English `message` |
| `warnings` | The warnings, in the same form |

The details of `validate-document` are:

| Member | Content |
| --- | --- |
| `signatures` | One object per signature of the simple report, in its order, described below; empty when the document has no signature |

Each signature is an object:

| Member | Content |
| --- | --- |
| `signature-id` | The identifier of the signature in the DSS reports |
| `format` | The form of the format that DSS detected: `"CAdES"`, `"PAdES"` or `"JAdES"`, also for a signature of that form that follows no ETSI profile (the levels `CMS_NOT_ETSI`, `PDF_NOT_ETSI` and `JSON_NOT_ETSI` of DSS); `"PKCS7"` for the PKCS7 levels of DSS; `null` only when DSS detects no format (`UNKNOWN`) |
| `level` | The level that DSS detected, as its reports write it, such as `"CAdES-BASELINE-B"` or `"CAdES-BASELINE-T"` |
| `indication` | The indication of the signature, such as `"TOTAL_PASSED"` |
| `sub-indication` | Its sub-indication, or `null` |
| `signing-time` | The signing time that the signature claims, in UTC, or `null` |
| `best-signature-time` | The best signature time that DSS determined, in UTC: the earliest time at which it has proof that the signature existed, such as the time of a valid signature timestamp, and otherwise the validation time |
| `errors` | The errors of the validation of the signature in the simple report, as a list of objects with the message `key` of DSS and its English `message` |
| `warnings` | The warnings, in the same form |

`revocation` is the latest acceptable revocation data that the certificate revocation data selector of DSS chose for the certificate, in the detailed report. It is an object:

| Member | Content |
| --- | --- |
| `status` | The status that it gives the certificate, as DSS names it: `"GOOD"`, `"REVOKED"` or `"UNKNOWN"` |
| `revocation-time` | The revocation time, in UTC, or `null` |
| `reason` | The reason for revocation as DSS names it, such as `"KEY_COMPROMISE"`, or `null` |
| `this-update` | The `thisUpdate` of the CRL or of the single response, in UTC |
| `source` | An object: `type`, `"CRL"` or `"OCSP"`; `input`, the option that named the file, `"--crl"` or `"--ocsp"`; `file`, the file as named on the command line; `revocation-id`, the identifier of the revocation data in the DSS reports. When two files hold the same revocation data, the first is named |

DSS 6.5.1 gives the certificate, in the simple certificate report, the conclusion of the checks of the certificate itself only, not those of the certificates above it. A certificate issued by a CA certificate without the `cA` flag, for example, is PASSED there, while its XCV block concludes INDETERMINATE with CERTIFICATE_CHAIN_GENERAL_FAILURE. `indication` and `sub-indication` therefore give the conclusion of the X.509 certificate validation block (XCV) of the certificate, which is the result of clause 5.2.6 for the chain, and `simple-report` keeps the other for comparison.

When the result is `resource-limit`:

| Member | Content |
| --- | --- |
| `limit` | The limit exceeded: `"heap"`, `"stack"` or `"time"` |
| `limits` | An object: `heap-bytes`, the maximum heap of the JVM; `stack-bytes`, the stack of the worker; `timeout-seconds`, the time limit; `garbage-collectors`, the names of the garbage collectors of the JVM, joined with commas |
| `message` | The error, or the time limit exceeded |

When the result is `rejected`:

| Member | Content |
| --- | --- |
| `input` | The option that named the file, such as `"--timestamp"` |
| `file` | The file, as named on the command line |
| `message` | The message of the DSS parser, joined with the messages of its causes |

Later validation modes add their own `details` and keep the other members.

## Maven dependencies

Runtime dependencies of the tool, as reported by `license-maven-plugin` for DSS 6.5.1. Test-only dependencies (JUnit) are not included. "GNU Lesser General Public License" is the plugin's wording for DSS, which is licensed under LGPL-2.1.

| Artefact | Version | Licence |
| --- | --- | --- |
| `com.github.erosb:json-sKema` | 0.32.0 | MIT |
| `com.sanctionco.jmail:jmail` | 2.1.0 | MIT License |
| `com.sun.activation:jakarta.activation` | 2.0.1 | EDL 1.0 |
| `com.sun.istack:istack-commons-runtime` | 4.0.1 | Eclipse Distribution License - v 1.0 |
| `commons-codec:commons-codec` | 1.18.0 | Apache-2.0 |
| `commons-io:commons-io` | 2.22.0 | Apache-2.0 |
| `commons-logging:commons-logging` | 1.4.0 | Apache-2.0 |
| `eu.europa.ec.joinup.sd-dss:dss-alert` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-cades` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-cms` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-cms-object` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-crl-parser` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-crl-parser-stream` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-detailed-report-jaxb` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-diagnostic-jaxb` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-document` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-enumerations` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-i18n` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-jades` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-jaxb-common` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-jaxb-parsers` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-json-common` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-model` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-pades` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-pades-pdfbox` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-policy-jaxb` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-simple-certificate-report-jaxb` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-simple-report-jaxb` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-spi` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-utils` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-utils-apache-commons` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-validation` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-xml-common` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:specs-jades` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:specs-jws` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:specs-trusted-list-v211` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:specs-validation-report` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:specs-xades` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:specs-xmldsig` | 6.5.1 | GNU Lesser General Public License |
| `jakarta.xml.bind:jakarta.xml.bind-api` | 3.0.1 | Eclipse Distribution License - v 1.0 |
| `org.apache.commons:commons-collections4` | 4.6.0 | Apache-2.0 |
| `org.apache.commons:commons-lang3` | 3.21.0 | Apache-2.0 |
| `org.apache.pdfbox:fontbox` | 3.0.8 | Apache-2.0 |
| `org.apache.pdfbox:pdfbox` | 3.0.8 | Apache-2.0 |
| `org.apache.pdfbox:pdfbox-io` | 3.0.8 | Apache-2.0 |
| `org.bitbucket.b_c:jose4j` | 0.9.7 | The Apache Software License, Version 2.0 |
| `org.bouncycastle:bcpkix-jdk18on` | 1.86 | Bouncy Castle Licence |
| `org.bouncycastle:bcprov-jdk18on` | 1.86 | Bouncy Castle Licence |
| `org.bouncycastle:bcutil-jdk18on` | 1.86 | Bouncy Castle Licence |
| `org.glassfish.jaxb:jaxb-core` | 3.0.2 | Eclipse Distribution License - v 1.0 |
| `org.glassfish.jaxb:jaxb-runtime` | 3.0.2 | Eclipse Distribution License - v 1.0 |
| `org.glassfish.jaxb:txw2` | 3.0.2 | Eclipse Distribution License - v 1.0 |
| `org.jetbrains:annotations` | 13.0 | The Apache Software License, Version 2.0 |
| `org.jetbrains.kotlin:kotlin-stdlib` | 2.4.20 | Apache-2.0 |
| `org.slf4j:slf4j-api` | 2.0.20 | MIT |
| `org.yaml:snakeyaml` | 2.6 | Apache License, Version 2.0 |

On every change to `pom.xml`, regenerate the list with the command below and compare it with this table. Then update the table, and state in the pull request that the licences were checked.

```
mvn org.codehaus.mojo:license-maven-plugin:2.7.1:add-third-party -Dlicense.excludedScopes=test
```

The list is written to `target/generated-sources/license/THIRD-PARTY.txt`.
