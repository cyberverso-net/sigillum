#!/usr/bin/env bash
# Tests check-library-graph.sh on small workspaces built for each case. The
# crates they depend on are local stand-ins with the names and versions of
# the real crates, so the tests need no network. Requires cargo and jq.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
export CARGO_NET_OFFLINE=true CARGO_TARGET_DIR="$scratch/target"

# stand_in <name> <version> [<dependency line>...]: a crate outside the
# workspaces, at $scratch/deps/<name>-<version>.
stand_in() {
  local name=$1 version=$2 dir=$scratch/deps/$1-$2
  shift 2
  mkdir -p "$dir/src"
  : > "$dir/src/lib.rs"
  {
    printf '[package]\nname = "%s"\nversion = "%s"\nedition = "2021"\n\n[dependencies]\n' "$name" "$version"
    printf '%s\n' "$@"
  } > "$dir/Cargo.toml"
}

stand_in crypto-bigint 0.5.5
stand_in crypto-bigint 0.7.10
stand_in der 0.7.10
stand_in der 0.8.3
stand_in elliptic-curve 0.13.8 "crypto-bigint = { path = \"../crypto-bigint-0.5.5\" }"
stand_in elliptic-curve 0.14.3 "crypto-bigint = { path = \"../crypto-bigint-0.7.10\" }"

dep() { printf '%s = { path = "%s/deps/%s-%s" }' "$1" "$scratch" "$1" "$2"; }

# workspace: a library crate `lib` and a tooling crate `tool`, with
# publish = false, each with the manifest sections given.
# workspace <sections of lib> <sections of tool>
workspace() {
  rm -rf "$scratch/ws"
  mkdir -p "$scratch/ws/lib/src" "$scratch/ws/tool/src"
  : > "$scratch/ws/lib/src/lib.rs"
  : > "$scratch/ws/tool/src/lib.rs"
  printf '[workspace]\nresolver = "2"\nmembers = ["lib", "tool"]\n' > "$scratch/ws/Cargo.toml"
  printf '[package]\nname = "lib"\nversion = "0.0.0"\nedition = "2021"\n\n%s\n' "$1" > "$scratch/ws/lib/Cargo.toml"
  printf '[package]\nname = "tool"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n%s\n' "$2" > "$scratch/ws/tool/Cargo.toml"
  (cd "$scratch/ws" && cargo generate-lockfile --quiet)
}

failures=0
# expect <exit code> <name> [<text the output must contain>...]
expect() {
  local wanted=$1 name=$2 code=0 text
  shift 2
  (cd "$scratch/ws" && bash "$here/check-library-graph.sh") > "$scratch/output" 2>&1 || code=$?
  if [ "$code" -ne "$wanted" ]; then
    echo "FAIL: $name: exit code $code, expected $wanted" >&2
    sed 's/^/  /' "$scratch/output" >&2
    failures=$((failures + 1))
    return
  fi
  for text in "$@"; do
    if ! grep -qF -- "$text" "$scratch/output"; then
      echo "FAIL: $name: the output does not contain: $text" >&2
      sed 's/^/  /' "$scratch/output" >&2
      failures=$((failures + 1))
      return
    fi
  done
  echo "ok: $name"
}

workspace "[dependencies]
$(dep elliptic-curve 0.14.3)
$(dep der 0.8.3)" "[dependencies]
$(dep elliptic-curve 0.13.8)
$(dep der 0.7.10)"
expect 0 "the der 0.8 generation in the library, der 0.7 in a tooling crate" \
  "No library crate depends on crypto-bigint 0.5 or der 0.7 (1 crate checked: lib)."

workspace "[dependencies]
$(dep crypto-bigint 0.5.5)" ""
expect 1 "crypto-bigint 0.5 as a direct dependency" \
  "lib depends on crypto-bigint v0.5.5" "1 crate checked."

workspace "[dependencies]
$(dep elliptic-curve 0.13.8)" ""
expect 1 "crypto-bigint 0.5 through elliptic-curve 0.13" \
  "lib depends on crypto-bigint v0.5.5"

workspace "[dependencies]
$(dep der 0.7.10)" ""
expect 1 "der 0.7 in the library" "lib depends on der v0.7.10"

workspace "[features]
legacy = [\"dep:elliptic-curve\"]

[dependencies]
elliptic-curve = { path = \"$scratch/deps/elliptic-curve-0.13.8\", optional = true }" ""
expect 1 "crypto-bigint 0.5 behind an optional feature" \
  "lib depends on crypto-bigint v0.5.5"

workspace "[target.'cfg(target_os = \"android\")'.dependencies]
$(dep elliptic-curve 0.13.8)" ""
expect 1 "crypto-bigint 0.5 on another target only" \
  "lib depends on crypto-bigint v0.5.5"

workspace "[build-dependencies]
$(dep crypto-bigint 0.5.5)" ""
expect 1 "crypto-bigint 0.5 as a build dependency" \
  "lib depends on crypto-bigint v0.5.5"

workspace "[dev-dependencies]
$(dep elliptic-curve 0.13.8)
$(dep der 0.7.10)" ""
expect 0 "the der 0.7 generation in the tests of a library crate only"

workspace "[dependencies]
tool = { path = \"../tool\" }" "[dependencies]
$(dep elliptic-curve 0.13.8)"
expect 1 "crypto-bigint 0.5 through a workspace crate" \
  "lib depends on crypto-bigint v0.5.5"

workspace "" "[dependencies]
$(dep elliptic-curve 0.13.8)"
(cd "$scratch/ws" && sed -i.bak '/^publish = false$/d' tool/Cargo.toml && rm tool/Cargo.toml.bak)
expect 1 "a second library crate" "tool depends on crypto-bigint v0.5.5" \
  "2 crates checked"

workspace "" ""
printf '[dependencies]\n%s\n' "$(dep elliptic-curve 0.13.8)" >> "$scratch/ws/lib/Cargo.toml"
expect 101 "a lock file that does not match the manifests" "--locked"

if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed." >&2
  exit 1
fi
echo "All cases passed."
