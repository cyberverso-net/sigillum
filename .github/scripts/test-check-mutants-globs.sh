#!/usr/bin/env bash
# Tests check-mutants-globs.sh: it reads every glob of examine_globs and
# fails when one of them matches no source file. cargo mutants is replaced
# by a stub that lists, for a glob, the files that a list of the test
# gives for it.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# The stub: `cargo mutants --no-config --file <glob> --list-files` prints
# the lines of $scratch/files whose first field is <glob>.
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
[ "$no_config" = 1 ] && [ "$list" = 1 ] && [ -n "$glob" ] || exit 64
[ ! -f "$STUB_FAIL" ] || exit 1
awk -v g="$glob" '$1 == g { print $2 }' "$STUB_FILES"
STUB
chmod +x "$scratch/bin/cargo"

failures=0
# expect <wanted exit code> <name> [<text the output must contain>...]
expect() {
  local wanted=$1 name=$2 code=0 text
  shift 2
  env PATH="$scratch/bin:$PATH" STUB_FILES="$scratch/files" STUB_FAIL="$scratch/fail" \
    bash "$here/check-mutants-globs.sh" "$scratch/mutants.toml" > "$scratch/output" 2>&1 || code=$?
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

cat > "$scratch/mutants.toml" << 'TOML'
# A comment with "crates/commented/*.rs" in it.
examine_globs = [
    # The first crate.
    "crates/a/src/**/*.rs",
    "crates/b/src/lib.rs", # a trailing comment
]
exclude_globs = ["crates/excluded/*.rs"]
TOML
printf 'crates/a/src/**/*.rs crates/a/src/lib.rs\ncrates/a/src/**/*.rs crates/a/src/x.rs\ncrates/b/src/lib.rs crates/b/src/lib.rs\n' > "$scratch/files"
expect 0 "every glob matches" "2 globs"

printf 'crates/a/src/**/*.rs crates/a/src/lib.rs\n' > "$scratch/files"
expect 1 "a glob that matches nothing" "crates/b/src/lib.rs matches no source file"

printf 'crates/b/src/lib.rs crates/b/src/lib.rs\n' > "$scratch/files"
expect 1 "the first glob matches nothing" "crates/a/src/**/*.rs matches no source file"

: > "$scratch/fail"
printf 'crates/a/src/**/*.rs crates/a/src/lib.rs\ncrates/b/src/lib.rs crates/b/src/lib.rs\n' > "$scratch/files"
expect 1 "cargo mutants fails" "cargo mutants failed"
rm "$scratch/fail"

printf 'examine_globs = []\n' > "$scratch/mutants.toml"
expect 1 "an empty list" "no glob"
printf 'exclude_globs = ["x.rs"]\n' > "$scratch/mutants.toml"
expect 1 "no list" "no glob"

if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed" >&2
  exit 1
fi
echo "every case passed"
