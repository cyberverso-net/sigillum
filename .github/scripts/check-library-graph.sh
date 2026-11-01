#!/usr/bin/env bash
# Checks that no library crate depends on crypto-bigint 0.5 or der 0.7.
#
# ADR-0025 builds the library crates on the der 0.8 generation, where
# crypto-bigint 0.7 replaces crypto-bigint 0.5. deny.toml still accepts
# RUSTSEC-2026-0387, on crypto-bigint 0.5, for sigillum-testpki, which stays
# on the der 0.7 generation. Ignores in deny.toml apply to the whole
# workspace, so this check keeps the advisory out of the library instead.
#
# The library crates are the workspace members that can be published, that
# is without `publish = false`. Names given as arguments are checked instead.
# The graph of each crate has its normal and build dependencies, with all
# its features and for every target. Dependencies used only by its tests,
# examples and benchmarks are not part of it, because they are never built
# into the library.
#
# Run it from the root of the workspace. Requires cargo and jq.
set -euo pipefail

if ! command -v jq >/dev/null; then
  echo "This check needs jq (https://jqlang.org)."
  exit 2
fi

# Name and version prefix of each package that the library must not use.
forbidden='^(crypto-bigint v0\.5\.|der v0\.7\.)'

if [ "$#" -gt 0 ]; then
  crates=$(printf '%s\n' "$@")
else
  crates=$(cargo metadata --no-deps --format-version 1 |
    jq -r '.packages[] | select(.publish != []) | .name' | sort)
fi
if [ -z "$crates" ]; then
  echo "No library crate found."
  exit 1
fi

status=0
while read -r crate; do
  # A failure of cargo stops the check here, through set -e.
  tree=$(cargo tree --locked --package "$crate" --all-features --target all \
    --edges normal,build --prefix none --format '{p}')
  found=$(printf '%s\n' "$tree" | awk '{ print $1 " " $2 }' |
    { grep -E "$forbidden" || true; } | sort -u)
  while read -r package; do
    [ -n "$package" ] || continue
    echo "$crate depends on $package:"
    name=${package% v*}
    version=${package#* v}
    cargo tree --locked --package "$crate" --all-features --target all \
      --edges normal,build --invert "$name@$version" | sed 's/^/  /'
    status=1
  done <<< "$found"
done <<< "$crates"

count=$(printf '%s\n' "$crates" | wc -l | tr -d ' ')
noun=crates
[ "$count" -eq 1 ] && noun=crate
if [ "$status" -eq 0 ]; then
  echo "No library crate depends on crypto-bigint 0.5 or der 0.7 ($count $noun checked: $(printf '%s\n' "$crates" | paste -sd ',' - | sed 's/,/, /g'))."
else
  echo "The library crates must stay on the der 0.8 generation (ADR-0025). $count $noun checked."
fi
exit "$status"
