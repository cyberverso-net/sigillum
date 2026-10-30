#!/usr/bin/env bash
# Lists every cargo-fuzz target of the repository, for the matrix of
# fuzz-nightly.yml: one JSON array, on one line, of objects with the crate,
# the directory of its fuzz project and the target, by crate, and by target
# in the order of cargo metadata. A fuzz project is a directory
# crates/<crate>/fuzz; its targets are the binaries of its manifest, as
# cargo metadata reads them. Fails when a fuzz directory is not a cargo-fuzz
# project or has no target, or when no target is found at all.
# Usage: fuzz-targets.sh [<root of the repository>]. Requires cargo and jq.
set -euo pipefail

root=$(cd "${1:-.}" && pwd -P)

shopt -s nullglob
manifests=("$root"/crates/*/fuzz/Cargo.toml)
if [ "${#manifests[@]}" -eq 0 ]; then
  echo "fuzz-targets: no fuzz project under $root/crates/*/fuzz" >&2
  exit 1
fi

all='[]'
for manifest in "${manifests[@]}"; do
  directory=${manifest#"$root"/}
  directory=${directory%/Cargo.toml}
  crate=${directory#crates/}
  crate=${crate%/fuzz}
  if ! metadata=$(cargo metadata --no-deps --offline --format-version 1 --manifest-path "$manifest"); then
    echo "fuzz-targets: cannot read $directory/Cargo.toml" >&2
    exit 1
  fi
  package=$(jq -c --arg manifest "$manifest" \
    '[.packages[] | select(.manifest_path == $manifest)] | first // empty' <<< "$metadata")
  if [ -z "$package" ] || [ "$(jq '.metadata."cargo-fuzz" == true' <<< "$package")" != true ]; then
    echo "fuzz-targets: $directory is not a cargo-fuzz project" >&2
    exit 1
  fi
  targets=$(jq -c --arg crate "$crate" --arg directory "$directory" \
    '[.targets[] | select(.kind == ["bin"]) | {crate: $crate, directory: $directory, target: .name}]' \
    <<< "$package")
  if [ "$targets" = '[]' ]; then
    echo "fuzz-targets: $directory has no fuzz target" >&2
    exit 1
  fi
  all=$(jq -c --argjson more "$targets" '. + $more' <<< "$all")
done

echo "$all"
