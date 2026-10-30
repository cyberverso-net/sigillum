#!/bin/bash
# Checks that the versions of the development image are those that the
# workflows pin, so that the image and continuous integration cannot drift
# apart. Exits with 1 on the first difference. The stable Rust release,
# which the workflows do not pin, is compared with the current one and
# only reported, when the network can be reached.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
workflows=$root/.github/workflows
failed=0

value() {
    sed -n "s/^$1=//p" "$here/versions.env"
}

differs() {
    echo "check-versions: $1" >&2
    failed=1
}

# OpenSSL: the release that the manifest names, the second release of the
# matrix, and the digest that fixtures-openssl.yml records for each.
manifest_version=$(sed -n 's/^openssl-version *= *"\([^"]*\)".*/\1/p' "$root/testdata/manifest.toml" | head -n 1)
[ "$(value OPENSSL_MANIFEST_VERSION)" = "$manifest_version" ] \
    || differs "OPENSSL_MANIFEST_VERSION is $(value OPENSSL_MANIFEST_VERSION), the manifest names $manifest_version"
other=$(value OPENSSL_OTHER_VERSION)
grep -Eq "^ +- check: \"${other//./\\.}\"$" "$workflows/fixtures-openssl.yml" \
    || differs "OPENSSL_OTHER_VERSION $(value OPENSSL_OTHER_VERSION) is not a release of the matrix of fixtures-openssl.yml"
for release in MANIFEST OTHER; do
    version=$(value "OPENSSL_${release}_VERSION")
    recorded=$(sed -n "s/^ *${version//./\\.}) sha256=\([0-9a-f]*\) ;;.*/\1/p" "$workflows/fixtures-openssl.yml")
    [ "$(value "OPENSSL_${release}_SHA256")" = "$recorded" ] \
        || differs "OPENSSL_${release}_SHA256 differs from the digest of OpenSSL $version in fixtures-openssl.yml"
done

# Java: every workflow installs Temurin of the same major release.
java_major=$(value TEMURIN_VERSION | cut -d. -f1)
while IFS= read -r line; do
    file=${line%%:*}
    release=$(grep -o 'java-version: *"\{0,1\}[0-9]*' <<< "$line" | grep -o '[0-9]*$')
    [ "$release" = "$java_major" ] \
        || differs "$(basename "$file") installs another Java release than Temurin $java_major"
done < <(grep -H 'java-version:' "$workflows"/*.yml)
while IFS= read -r line; do
    grep -q 'distribution: temurin' <<< "$line" \
        || differs "$(basename "${line%%:*}") installs another Java distribution than Temurin"
done < <(grep -H 'distribution:' "$workflows"/*.yml)

# Ubuntu: every runner label that names a release names the release of the image.
ubuntu_release=$(value UBUNTU_IMAGE | sed 's/^ubuntu:\([0-9.]*\)@.*/\1/')
while IFS= read -r label; do
    [ "$label" = "ubuntu-$ubuntu_release" ] || [ "$label" = "ubuntu-$ubuntu_release-arm" ] \
        || differs "a workflow runs on $label, the image is Ubuntu $ubuntu_release"
done < <(grep -ho 'ubuntu-[0-9][0-9.]*\(-arm\)\{0,1\}' "$workflows"/*.yml | sort -u)

# cargo vet: the version that cargo-vet.yml installs.
vet=$(sed -n 's/.*tool: cargo-vet@\([0-9.]*\).*/\1/p' "$workflows/cargo-vet.yml")
[ "$(value CARGO_VET_VERSION)" = "$vet" ] \
    || differs "CARGO_VET_VERSION is $(value CARGO_VET_VERSION), cargo-vet.yml installs $vet"

# cargo llvm-cov: the version that coverage.yml installs.
llvm_cov=$(sed -n 's/.*tool: cargo-llvm-cov@\([0-9.]*\).*/\1/p' "$workflows/coverage.yml")
[ "$(value CARGO_LLVM_COV_VERSION)" = "$llvm_cov" ] \
    || differs "CARGO_LLVM_COV_VERSION is $(value CARGO_LLVM_COV_VERSION), coverage.yml installs $llvm_cov"
# The nightly and the cargo fuzz that fuzz-nightly.yml installs.
for name in RUST_NIGHTLY CARGO_FUZZ_VERSION; do
    pinned=$(sed -n "s/^  $name: *\([^ #]*\).*/\1/p" "$workflows/fuzz-nightly.yml")
    [ "$(value "$name")" = "$pinned" ] \
        || differs "$name is $(value "$name"), fuzz-nightly.yml installs ${pinned:-nothing}"
done

# The minimum supported Rust version of the workspace.
msrv=$(sed -n 's/^rust-version *= *"\([^"]*\)".*/\1/p' "$root/Cargo.toml" | head -n 1)
[ "$(value RUST_MSRV)" = "$msrv" ] || differs "RUST_MSRV is $(value RUST_MSRV), Cargo.toml declares $msrv"

# Releases that the workflows install at their latest version: stable Rust
# and the latest Temurin 21. A newer one is reported, never a failure, when
# the network can be reached. The addresses can be changed for the tests.
rust_channel=${DEV_IMAGE_RUST_CHANNEL_URL:-https://static.rust-lang.org/dist/channel-rust-stable.toml}
temurin_releases=${DEV_IMAGE_TEMURIN_RELEASES_URL:-https://api.adoptium.net/v3/info/release_names?release_type=ga&version=%5B$java_major%2C$((java_major + 1))%29&page_size=1&sort_order=DESC&vendor=eclipse&image_type=jdk}

report() {
    echo "check-versions: $1" >&2
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "::warning file=tools/dev-image/versions.env::$1"
    fi
}

if manifest=$(curl -sSfL --max-time 10 "$rust_channel" 2> /dev/null); then
    stable=$(sed -n '/^\[pkg.rust\]/{n;s/^version = "\([0-9.]*\) .*/\1/p;}' <<< "$manifest" | head -n 1 || true)
    if [ -n "$stable" ] && [ "$stable" != "$(value RUST_STABLE)" ]; then
        report "RUST_STABLE is $(value RUST_STABLE), the workflows now install Rust $stable"
    fi
fi
if releases=$(curl -sSfL --max-time 10 "$temurin_releases" 2> /dev/null); then
    # A response without a release is no information, not a difference.
    latest=$(grep -o '"jdk-[0-9][^"]*"' <<< "$releases" | head -n 1 | tr -d '"' || true)
    latest=${latest#jdk-}
    if [ -n "$latest" ] && [ "$latest" != "$(value TEMURIN_VERSION)" ]; then
        report "TEMURIN_VERSION is $(value TEMURIN_VERSION), the workflows now install Temurin $latest"
    fi
fi

if [ "$failed" -eq 0 ]; then
    echo "check-versions: the image pins the versions of the workflows"
fi
exit "$failed"
