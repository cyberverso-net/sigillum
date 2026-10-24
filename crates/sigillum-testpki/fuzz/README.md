# Fuzz targets of sigillum-testpki

The target `manifest` feeds arbitrary text to the manifest parser. It needs the nightly toolchain and `cargo-fuzz`:

```
cargo +nightly fuzz run manifest corpus/manifest seeds/manifest -- -dict=manifest.dict -max_total_time=600
```

`seeds/manifest` holds valid manifests to start from, and `manifest.dict` the field names and values of the format. The generated corpus under `corpus/` is not committed. This directory is a separate Cargo workspace with its own `Cargo.lock`; continuous integration checks that it builds. Dependabot and `cargo deny` do not cover that lock file, so its dependencies are refreshed by hand with `cargo update` in this directory.
