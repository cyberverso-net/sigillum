# Fuzz targets of sigillum-testpki

The target `manifest` feeds arbitrary text to the manifest parser. It needs the nightly toolchain and `cargo-fuzz`:

```
cargo +nightly fuzz run manifest corpus/manifest seeds/manifest -- -dict=manifest.dict -max_total_time=600
```

`seeds/manifest` holds valid manifests to start from, and `manifest.dict` the field names and values of the format.

The target `tsa_input` feeds arbitrary bytes to the input handling of the `tsa` subcommand: the module `timestamp::input` and `Tsa::from_pem`. The whole input goes to `check_der`, which checks that every DER length fits its parent and the input before any owned decoding. Valid UTF-8 also goes to the parsers of the digest algorithm, the digest and the time. The first byte then chooses what the remaining bytes stand for. When it is even, they are the key file, read with the committed certificate of `pki/tsa`. When it is odd, they are the certificate file, read with the committed test key of `pki/tsa`, so that certificate parsing and the check that the key matches the certificate are reached:

```
cargo +nightly fuzz run tsa_input corpus/tsa_input seeds/tsa_input -- -dict=tsa_input.dict -max_total_time=600
```

`seeds/tsa_input` holds valid option values, certificate files in PEM, DER and with a byte order mark, and key files in PEM and DER, each after its selector byte. The key seeds, whose names end in `.test-key`, are copies of the published test keys under `testdata/pki/keys/`, with no value outside the test suite, and `key-rsa-unbalanced.test-key`, an RSA key with the primes 3 and 2^607 - 1 that `Tsa::new` must refuse before signing. `tsa_input.dict` holds the algorithm names and identifiers, time separators and PEM syntax.
