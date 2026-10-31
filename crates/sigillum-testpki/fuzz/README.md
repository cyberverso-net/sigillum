# Fuzz targets of sigillum-testpki

The target `manifest` feeds arbitrary text to the manifest parser. A manifest that parses is written back with `Manifest::to_toml` and must read back unchanged, as the generators rely on. It needs the nightly toolchain and `cargo-fuzz`:

```
cargo +nightly fuzz run manifest corpus/manifest seeds/manifest -- -dict=manifest.dict -max_total_time=600
```

`seeds/manifest` holds manifests of the current format to start from, one with a `dss-divergence` and an `attack-class`, and `manifest.dict` the field names and values of the format.

The target `tsa_input` feeds arbitrary bytes to the input handling of the `tsa` subcommand: the module `timestamp::input` and `Tsa::from_pem`. The whole input goes to `check_der`, which checks that every DER length fits its parent and the input before any owned decoding. Valid UTF-8 also goes to the parsers of the digest algorithm, the digest and the time. The first byte then chooses what the remaining bytes stand for. When it is even, they are the key file, read with the committed certificate of `pki/tsa`. When it is odd, they are the certificate file, read with the committed test key of `pki/tsa`, so that certificate parsing and the check that the key matches the certificate are reached:

```
cargo +nightly fuzz run tsa_input corpus/tsa_input seeds/tsa_input -- -dict=tsa_input.dict -max_total_time=600
```

`seeds/tsa_input` holds valid option values, certificate files in PEM, DER and with a byte order mark, and key files in PEM and DER, each after its selector byte. The key seeds, whose names end in `.test-key`, are copies of the published test keys under `testdata/pki/keys/`, with no value outside the test suite, and `key-rsa-unbalanced.test-key`, an RSA key with the primes 3 and 2^607 - 1 that `Tsa::new` must refuse before signing. `tsa_input.dict` holds the algorithm names and identifiers, time separators and PEM syntax.

The target `openssl_output` feeds arbitrary text to the readers of `verify --openssl`: `parse_version`, which reads the output of `openssl version`, `crl_times`, which reads the times that `openssl crl -lastupdate -nextupdate` prints, and `covered_certificate`, which reads the notes of a manifest entry. The first line of the text then names a certificate, and `ocsp_status` reads the rest as the output of `openssl ocsp` for it:

```
cargo +nightly fuzz run openssl_output corpus/openssl_output seeds/openssl_output -- -dict=openssl_output.dict -max_total_time=600
```

`seeds/openssl_output` holds the output of `openssl version` of OpenSSL 3.5.9, which names the library, and of OpenSSL 1.1.1w, which does not, the times of a CRL, outputs of `openssl ocsp` for a response with a warning on its times and for a revoked certificate, each after the line that names the certificate, notes that name a covered certificate, a CAdES signature of the corpus, `signed/cades-detached-b-b-p256`, and a 21-byte ContentInfo of type SignedData whose content declares about 256 MiB, for the peek at the content type of a signed document. `openssl_output.dict` holds the words that the readers look for.

The target `dss_output` feeds arbitrary text to the readers of `verify --dss`: `parse_version`, which reads the version line of `tools/dss-oracle --version`, and `read_summary`, which reads the `summary.json` of a validation, once for each validation mode, at the validation time and DSS version of the corpus:

```
cargo +nightly fuzz run dss_output corpus/dss_output seeds/dss_output -- -dict=dss_output.dict -max_total_time=600
```

`seeds/dss_output` holds the version line of the tool and summaries that it wrote for the corpus: a certificate validated with CRLs, a timestamp token whose imprint does not match its data, a JAdES signature, and an OCSP response that DSS rejects, with the paths of the files made relative to the repository. It also holds a summary of a run that exceeded the time limit, written by hand in the form that the README of the tool describes. `dss_output.dict` holds the members and values of `summary.json`.

The target `mutations` feeds arbitrary bytes to the readers of `generate mutations`: `modify_signing_time` and `modify_encapsulated_content`, which look for the signing-time attribute and for the encapsulated content of a CMS signature, and `tamper_protected_header` and `duplicate_protected_header_parameter`, which read a JWS in the compact serialisation and the `iat` of its protected header. The JWS readers refuse an input over 1 MiB, a protected header over 64 KiB, a header with an escape sequence or with a name given twice, and read `iat` only among the members of the outer object. It also feeds them to the PAdES mutations, `add_page_content`, `remove_overlay`, `replace_field_value`, `switch_page_tree` and `wrap_byte_range`, which read the cross-reference tables of a PDF of at most 4 MiB and its `ByteRange`. A mutation that succeeds must change one byte of a CMS signature, by its bit 0x20 for the content, or the protected header of a JWS only, and a header with `iat` given twice is refused. A PAdES mutation that appends an incremental update must keep every byte of its input and not apply again to its output, and the wrapping must change its input only in the value of the `ByteRange` and append a copy of its end:

```
cargo +nightly fuzz run mutations corpus/mutations seeds/mutations -- -dict=mutations.dict -max_total_time=600
```

`seeds/mutations` holds three signatures of the corpus that the variants derive from, `signed/cades-enveloping-b-b-p256`, `signed/jades-compact-b-b-p256` and `signed/pades-b-b-p256`, the three base documents prepared for shadow attacks, `documents/shadow-hide`, `documents/shadow-replace` and `documents/shadow-hide-and-replace`, a signing-time attribute alone with a UTCTime and with a GeneralizedTime, an encapsulated content of three octets, and a short compact JWS. `mutations.dict` holds the encodings of the attribute and of the encapsulated content, the syntax of a compact JWS, and the keywords and entries of a PDF that the PAdES mutations read.
