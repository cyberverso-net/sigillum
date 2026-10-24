# Test keys

The files in this directory are private keys of the sigillum test PKI. They are test keys with no value: anyone can derive them again from their names with `sigillum-testpki generate pki`, and they protect nothing. They are never used outside the test suite.

Each file is a PKCS#8 private key (RFC 5958) in PEM form, and its name ends in `.test-key.pem`. The certificate of each key has the same name in the parent directory, `testdata/pki/`.

The seeds of the fuzz target `tsa_input`, under `crates/sigillum-testpki/fuzz/seeds/tsa_input/`, contain copies of the keys of `pki/tsa` and `pki/signer-p384`, in PEM and DER. Their names end in `.test-key`, and they are the same published test keys.
