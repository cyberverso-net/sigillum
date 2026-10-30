#!/usr/bin/env bash
# Tests fuzz-targets.sh: on the repository as it is, it lists every [[bin]]
# of every fuzz project under crates/*/fuzz; on scratch trees, it lists the
# targets of each project in order, and fails when a fuzz directory is not a
# cargo-fuzz project, when its manifest cannot be read, or when there is no
# target at all, so that the nightly matrix is never silently empty.
# Requires cargo and jq.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

failures=0
pass() { echo "ok: $1"; }
fail() {
  echo "FAIL: $1" >&2
  sed 's/^/  /' "$scratch/output" >&2
  failures=$((failures + 1))
}

# Runs the script on a tree, keeps its standard output and returns its exit code.
run() {
  local code=0
  bash "$here/fuzz-targets.sh" "$1" > "$scratch/output" 2> "$scratch/errors" || code=$?
  cat "$scratch/errors" >> "$scratch/output"
  return "$code"
}

# project <tree> <crate> [<target>...]: a cargo-fuzz project with these targets.
project() {
  local dir=$1/crates/$2/fuzz target
  mkdir -p "$dir/fuzz_targets"
  {
    printf '[package]\nname = "%s-fuzz"\nversion = "0.0.0"\npublish = false\nedition = "2021"\n\n' "$2"
    printf '[package.metadata]\ncargo-fuzz = true\n\n'
    shift 2
    for target in "$@"; do
      printf '[[bin]]\nname = "%s"\npath = "fuzz_targets/%s.rs"\ntest = false\n\n' "$target" "$target"
      echo 'fn main() {}' > "$dir/fuzz_targets/$target.rs"
    done
    printf '[workspace]\nmembers = ["."]\n'
  } > "$dir/Cargo.toml"
}

# The repository as it is: the targets are the [[bin]] names of the manifests.
expected=$(
  cd "$root"
  for manifest in crates/*/fuzz/Cargo.toml; do
    crate=${manifest#crates/}
    crate=${crate%%/*}
    awk -v crate="$crate" '
      /^\[\[bin\]\]/ { bin = 1; next }
      /^\[/ { bin = 0 }
      bin && /^name *=/ { gsub(/^name *= *"|".*$/, ""); print crate "/" $0 }
    ' "$manifest"
  done | sort
)
code=0
run "$root" || code=$?
listed=$(jq -r '.[] | .crate + "/" + .target' "$scratch/output" 2> /dev/null | sort || true)
if [ "$code" -eq 0 ] && [ -n "$expected" ] && [ "$listed" = "$expected" ]; then
  pass "the repository as it is ($(wc -l <<< "$listed" | tr -d ' ') targets)"
else
  fail "the repository as it is: exit code $code, expected the targets: $(tr "\n" " " <<< "$expected")"
fi

# Two projects: every target, with its crate and directory, in order.
tree=$scratch/two
project "$tree" beta zeta
project "$tree" alpha one two
code=0
run "$tree" || code=$?
wanted='[{"crate":"alpha","directory":"crates/alpha/fuzz","target":"one"},{"crate":"alpha","directory":"crates/alpha/fuzz","target":"two"},{"crate":"beta","directory":"crates/beta/fuzz","target":"zeta"}]'
if [ "$code" -eq 0 ] && [ "$(cat "$scratch/output")" = "$wanted" ]; then
  pass "two projects"
else
  fail "two projects: exit code $code, expected $wanted"
fi

# expect_failure <name> <tree>: the script exits with 1.
expect_failure() {
  local code=0
  run "$2" || code=$?
  if [ "$code" -eq 1 ]; then pass "$1"; else fail "$1: exit code $code, expected 1"; fi
}

tree=$scratch/none
mkdir -p "$tree/crates/alpha/src"
expect_failure "no fuzz project" "$tree"

tree=$scratch/not-cargo-fuzz
project "$tree" alpha one
project "$tree" beta two
sed -i.bak '/^cargo-fuzz = true$/d' "$tree/crates/beta/fuzz/Cargo.toml" && rm "$tree/crates/beta/fuzz/Cargo.toml.bak"
expect_failure "a fuzz directory that is not a cargo-fuzz project" "$tree"

tree=$scratch/no-target
project "$tree" alpha one
project "$tree" beta
expect_failure "a fuzz project without a target" "$tree"

tree=$scratch/broken
project "$tree" alpha one
echo 'not toml [' >> "$tree/crates/alpha/fuzz/Cargo.toml"
expect_failure "a manifest that cannot be read" "$tree"

if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed" >&2
  exit 1
fi
echo "every case passed"
