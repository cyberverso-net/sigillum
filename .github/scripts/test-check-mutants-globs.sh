#!/usr/bin/env bash
# Tests check-mutants-globs.sh: it fails when a glob of examine_globs
# matches no source file, and when a source file of the tool crates is
# neither selected by the globs nor named on the list of files that are
# not critical. Each case runs in a small tree written here, and cargo
# mutants is replaced by a stub.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
tree=$scratch/tree

# The stub. `cargo mutants --no-config --file <glob> --list-files` prints
# the lines of $STUB_FILES whose first field is <glob>; `cargo mutants
# --list-files` prints the lines of $STUB_LISTED, the files that the
# configuration selects.
mkdir -p "$scratch/bin"
cat > "$scratch/bin/cargo" << 'STUB'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = mutants ] || exit 64
shift
glob= no_config=0 list=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-config) no_config=1 ;;
    --file) glob=$2; shift ;;
    --list-files) list=1 ;;
    *) exit 64 ;;
  esac
  shift
done
[ "$list" = 1 ] || exit 64
[ ! -f "$STUB_FAIL" ] || exit 1
if [ -n "$glob" ]; then
  [ "$no_config" = 1 ] || exit 64
  awk -v g="$glob" '$1 == g { print $2 }' "$STUB_FILES"
else
  [ "$no_config" = 0 ] || exit 64
  cat "$STUB_LISTED"
fi
STUB
chmod +x "$scratch/bin/cargo"

# The tree: two tool crates with a few source files each.
reset() {
  rm -rf "$tree"
  mkdir -p "$tree/.cargo" "$tree/crates/sigillum-testpki/src/pki" "$tree/crates/sigillum-oracle/src/compare"
  for f in lib.rs main.rs signed.rs pki/keys.rs pki/tests.rs; do
    : > "$tree/crates/sigillum-testpki/src/$f"
  done
  for f in lib.rs compare.rs compare/tests.rs; do
    : > "$tree/crates/sigillum-oracle/src/$f"
  done
  cat > "$tree/.cargo/mutants.toml" << 'TOML'
# A comment with "crates/commented/*.rs" in it.
#
# Not critical, for the reasons in quality-gates.md:
# not critical: crates/sigillum-testpki/src/lib.rs
# not critical: crates/sigillum-testpki/src/main.rs
# not critical: crates/sigillum-oracle/src/lib.rs
examine_globs = [
    # The first crate.
    "crates/sigillum-testpki/src/**/*.rs",
    "crates/sigillum-oracle/src/compare.rs", # a trailing comment
]
exclude_globs = ["crates/excluded/*.rs"]
TOML
  printf '%s\n' \
    "crates/sigillum-testpki/src/**/*.rs crates/sigillum-testpki/src/signed.rs" \
    "crates/sigillum-testpki/src/**/*.rs crates/sigillum-testpki/src/pki/keys.rs" \
    "crates/sigillum-oracle/src/compare.rs crates/sigillum-oracle/src/compare.rs" > "$scratch/files"
  printf '%s\n' crates/sigillum-testpki/src/signed.rs crates/sigillum-testpki/src/pki/keys.rs \
    crates/sigillum-oracle/src/compare.rs > "$scratch/listed"
  rm -f "$scratch/fail"
}

failures=0
# expect <wanted exit code> <name> [<text the output must contain>...]
expect() {
  local wanted=$1 name=$2 code=0 text
  shift 2
  (cd "$tree" && env PATH="$scratch/bin:$PATH" STUB_FILES="$scratch/files" STUB_LISTED="$scratch/listed" \
    STUB_FAIL="$scratch/fail" bash "$here/check-mutants-globs.sh") > "$scratch/output" 2>&1 || code=$?
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

reset
expect 0 "every glob matches and every file is accounted for" "2 globs" "3 files that are not critical"

reset
sed -i.bak '/oracle\/src\/compare.rs crates/d' "$scratch/files" && rm "$scratch/files.bak"
expect 1 "a glob that matches nothing" "crates/sigillum-oracle/src/compare.rs matches no source file"

reset
sed -i.bak '/testpki\/src\/\*\*/d' "$scratch/files" && rm "$scratch/files.bak"
expect 1 "the first glob matches nothing" "crates/sigillum-testpki/src/**/*.rs matches no source file"

reset
: > "$scratch/fail"
expect 1 "cargo mutants fails" "cargo mutants failed"

reset
printf 'examine_globs = []\n' > "$tree/.cargo/mutants.toml"
expect 1 "an empty list" "no glob"
printf 'exclude_globs = ["x.rs"]\n' > "$tree/.cargo/mutants.toml"
expect 1 "no list" "no glob"

# A new file of a tool crate must be selected or named as not critical.
reset
: > "$tree/crates/sigillum-oracle/src/report.rs"
expect 1 "a new file left out" "crates/sigillum-oracle/src/report.rs is neither selected by examine_globs nor named as not critical"
mkdir -p "$tree/crates/sigillum-oracle/src/report"
: > "$tree/crates/sigillum-oracle/src/report/tests.rs"
printf '# not critical: crates/sigillum-oracle/src/report.rs\n' >> "$tree/.cargo/mutants.toml"
expect 0 "a new file named as not critical, and its test module" "4 files that are not critical"

reset
sed -i.bak '/not critical: crates\/sigillum-testpki\/src\/main.rs/d' "$tree/.cargo/mutants.toml"
rm "$tree/.cargo/mutants.toml.bak"
expect 1 "a file no longer named" "crates/sigillum-testpki/src/main.rs is neither selected"

# The list must not name files that are gone or that are selected.
reset
printf '# not critical: crates/sigillum-testpki/src/gone.rs\n' >> "$tree/.cargo/mutants.toml"
expect 1 "a file named that does not exist" "crates/sigillum-testpki/src/gone.rs is named as not critical but does not exist"
reset
printf '# not critical: crates/sigillum-testpki/src/signed.rs\n' >> "$tree/.cargo/mutants.toml"
expect 1 "a file named and selected" "crates/sigillum-testpki/src/signed.rs is named as not critical but examine_globs selects it"

if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed" >&2
  exit 1
fi
echo "every case passed"
