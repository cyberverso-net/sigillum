#!/bin/bash
# Runs in the development image and checks that each tool it holds is the
# version that versions.env names.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
failed=0

value() {
    sed -n "s/^$1=//p" "$here/versions.env"
}

# Checks that the first line of a command's output contains the expected text.
expect() {
    local wanted=$1 line
    shift
    line=$("$@" 2>&1 | head -n 1)
    if [[ "$line" == *"$wanted"* ]]; then
        echo "ok: $line"
    else
        echo "smoke: $* gives \"$line\", expected \"$wanted\"" >&2
        failed=1
    fi
}

expect "VERSION_ID=\"$(value UBUNTU_IMAGE | sed 's/^ubuntu:\([0-9.]*\)@.*/\1/')\"" grep VERSION_ID /etc/os-release
expect "build $(value TEMURIN_VERSION)" bash -c 'java -version 2>&1 | sed -n 2p'
expect "Apache Maven $(value MAVEN_VERSION)" mvn -v
expect "rustup $(value RUSTUP_VERSION)" rustup --version
expect "rustc $(value RUST_STABLE)" rustc --version
expect "rustc $(value RUST_MSRV)" rustc "+$(value RUST_MSRV)" --version
expect "$(value RUST_NIGHTLY)-" bash -c "rustup toolchain list | grep -F '$(value RUST_NIGHTLY)-'"
expect "nightly" rustc "+$(value RUST_NIGHTLY)" --version
expect "$(rustc "+$(value RUST_NIGHTLY)" --version)" rustc +nightly --version
for target in wasm32-unknown-unknown aarch64-apple-ios aarch64-linux-android; do
    expect "$target" bash -c "rustup target list --installed | grep -Fx $target"
done
expect "OpenSSL $(value OPENSSL_MANIFEST_VERSION) " "$SIGILLUM_TESTPKI_OPENSSL" version
expect "OpenSSL $(value OPENSSL_OTHER_VERSION) " "$SIGILLUM_TESTPKI_OPENSSL_OTHER" version
expect "OpenSSL $(value OPENSSL_MANIFEST_VERSION) " openssl version
expect "yq (https://github.com/mikefarah/yq/) version v$(value YQ_VERSION)" yq --version
expect "UnZip" unzip -v
expect "cargo-llvm-cov $(value CARGO_LLVM_COV_VERSION)" cargo llvm-cov --version
expect "cargo-mutants $(value CARGO_MUTANTS_VERSION)" cargo mutants --version
expect "cargo-fuzz $(value CARGO_FUZZ_VERSION)" cargo fuzz --version
expect "cargo-deny $(value CARGO_DENY_VERSION)" cargo deny --version
expect "cargo-vet $(value CARGO_VET_VERSION)" cargo vet --version
if [ "$(id -u):$(id -g)" = "$DEV_IMAGE_UID:$DEV_IMAGE_GID" ]; then
    echo "ok: runs as $DEV_IMAGE_UID:$DEV_IMAGE_GID"
else
    echo "smoke: runs as $(id -u):$(id -g), expected $DEV_IMAGE_UID:$DEV_IMAGE_GID" >&2
    failed=1
fi

exit "$failed"
