#!/bin/bash
# Tests check-versions.sh: it passes on the repository as it is, and fails
# when any version that it compares differs, in versions.env or in a
# workflow. Each case runs on a copy of the files that the check reads.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

copy() {
    rm -rf "$scratch/repo"
    mkdir -p "$scratch/repo/tools/dev-image" "$scratch/repo/testdata" "$scratch/repo/.github"
    cp "$here/check-versions.sh" "$here/versions.env" "$scratch/repo/tools/dev-image/"
    cp "$root/testdata/manifest.toml" "$scratch/repo/testdata/"
    cp "$root/Cargo.toml" "$scratch/repo/"
    cp -R "$root/.github/workflows" "$scratch/repo/.github/"
}

# Runs the check on the copy, with the network unreachable, and returns its exit code.
check() {
    local code=0
    env https_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 \
        bash "$scratch/repo/tools/dev-image/check-versions.sh" > /dev/null 2>&1 || code=$?
    return "$code"
}

failures=0
expect() {
    local wanted=$1 name=$2 code=0
    check || code=$?
    if [ "$code" -ne "$wanted" ]; then
        echo "FAIL: $name: exit code $code, expected $wanted" >&2
        failures=$((failures + 1))
    else
        echo "ok: $name"
    fi
}

# Applies a sed expression to one file of the copy, and fails the test when it changes nothing.
mutate() {
    local file=$scratch/repo/$1 before
    before=$(cat "$file")
    sed -i.bak "$2" "$file" && rm "$file.bak"
    if [ "$before" = "$(cat "$file")" ]; then
        echo "FAIL: the mutation $2 of $1 changes nothing" >&2
        failures=$((failures + 1))
    fi
}

copy
expect 0 "the repository as it is"

cases=(
    "tools/dev-image/versions.env|s/^OPENSSL_MANIFEST_VERSION=.*/OPENSSL_MANIFEST_VERSION=3.5.8/|another OpenSSL release than the manifest"
    "tools/dev-image/versions.env|s/^OPENSSL_OTHER_VERSION=.*/OPENSSL_OTHER_VERSION=4.0.2/|another second OpenSSL release"
    "tools/dev-image/versions.env|s/^\(OPENSSL_MANIFEST_SHA256=.*\).$/\10/|another digest of the manifest release"
    "tools/dev-image/versions.env|s/^\(OPENSSL_OTHER_SHA256=.*\).$/\10/|another digest of the second release"
    "tools/dev-image/versions.env|s/^TEMURIN_VERSION=.*/TEMURIN_VERSION=17.0.16+8/|another Java release"
    "tools/dev-image/versions.env|s/^CARGO_VET_VERSION=.*/CARGO_VET_VERSION=0.10.2/|another cargo vet"
    "tools/dev-image/versions.env|s/^CARGO_LLVM_COV_VERSION=.*/CARGO_LLVM_COV_VERSION=0.9.0/|another cargo llvm-cov"
    "tools/dev-image/versions.env|s/^CARGO_MUTANTS_VERSION=.*/CARGO_MUTANTS_VERSION=27.0.0/|another cargo mutants"
    "tools/dev-image/versions.env|s/^RUST_MSRV=.*/RUST_MSRV=1.87/|another minimum Rust version"
    "tools/dev-image/versions.env|s/^UBUNTU_IMAGE=ubuntu:24.04/UBUNTU_IMAGE=ubuntu:22.04/|another Ubuntu release"
    ".github/workflows/fixtures-openssl.yml|s/runs-on: ubuntu-24.04/runs-on: ubuntu-22.04/|a workflow on another Ubuntu release"
    ".github/workflows/dss-oracle.yml|s/distribution: temurin/distribution: zulu/|a workflow with another Java distribution"
    ".github/workflows/dss-oracle.yml|s/java-version: \"21\"/java-version: \"25\"/|a workflow with another Java release"
    ".github/workflows/cargo-vet.yml|s/cargo-vet@[0-9.]*/cargo-vet@0.10.4/|a workflow with another cargo vet"
    ".github/workflows/coverage.yml|s/cargo-llvm-cov@[0-9.]*/cargo-llvm-cov@0.9.2/|a workflow with another cargo llvm-cov"
    ".github/workflows/mutants.yml|s/cargo-mutants@[0-9.]*/cargo-mutants@27.0.0/|a workflow with another cargo mutants"
    "Cargo.toml|s/^rust-version = .*/rust-version = \"1.89\"/|a workspace with another minimum Rust version"
)
for case in "${cases[@]}"; do
    IFS='|' read -r file expression name <<< "$case"
    copy
    mutate "$file" "$expression"
    expect 1 "$name"
done

# Newer releases of stable Rust and Temurin are reported, never a failure.
copy
printf '[pkg.cargo]\nversion = "0.1.0"\n[pkg.rust]\nversion = "9.9.9 (0123456789 2030-01-01)"\n' > "$scratch/channel.toml"
printf '{"releases": ["jdk-21.0.99+1"]}\n' > "$scratch/releases.json"
code=0
output=$(env DEV_IMAGE_RUST_CHANNEL_URL="file://$scratch/channel.toml" \
    DEV_IMAGE_TEMURIN_RELEASES_URL="file://$scratch/releases.json" \
    bash "$scratch/repo/tools/dev-image/check-versions.sh" 2>&1) || code=$?
for wanted in "the workflows now install Rust 9.9.9" "the workflows now install Temurin 21.0.99+1"; do
    if [ "$code" -eq 0 ] && [[ "$output" == *"$wanted"* ]]; then
        echo "ok: reports \"$wanted\""
    else
        echo "FAIL: exit code $code, no report \"$wanted\" in: $output" >&2
        failures=$((failures + 1))
    fi
done

# Responses without a release are no information: no report, no failure.
printf 'not a channel\n' > "$scratch/channel.toml"
printf '{"releases": []}\n' > "$scratch/releases.json"
code=0
output=$(env DEV_IMAGE_RUST_CHANNEL_URL="file://$scratch/channel.toml" \
    DEV_IMAGE_TEMURIN_RELEASES_URL="file://$scratch/releases.json" \
    bash "$scratch/repo/tools/dev-image/check-versions.sh" 2>&1) || code=$?
if [ "$code" -eq 0 ] && [[ "$output" != *"now install"* ]]; then
    echo "ok: responses without a release"
else
    echo "FAIL: responses without a release: exit code $code: $output" >&2
    failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
    echo "$failures case(s) failed" >&2
    exit 1
fi
echo "every case passed"
