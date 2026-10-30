#!/usr/bin/env bash
# Checks the list of critical modules in .cargo/mutants.toml:
#
# - every glob of examine_globs matches at least one source file that
#   cargo mutants would mutate, so that a renamed or removed module cannot
#   silently leave the list. Each glob is given alone to
#   `cargo mutants --list-files`, with the configuration file ignored;
# - every .rs file under the src directories of the tool crates
#   sigillum-testpki and sigillum-oracle is either selected by the globs,
#   a test module named tests.rs, or named on a line
#   `# not critical: <path>` of the configuration file, so that a new
#   file cannot be left out silently. A named file must exist and must
#   not be selected. docs/development/quality-gates.md gives the reason
#   for each.
#
# Run from the root of the workspace. Exits with 1 on any of these.
set -euo pipefail

config=.cargo/mutants.toml
tool_dirs=(crates/sigillum-testpki/src crates/sigillum-oracle/src)

# The quoted strings between `examine_globs = [` and the closing `]`, one
# per line, without comments.
globs=()
while IFS= read -r glob; do
  globs+=("$glob")
done < <(sed -n '/^examine_globs *= *\[/,/^\]/p' "$config" \
  | sed 's/#.*$//' \
  | grep -o '"[^"]*"' \
  | tr -d '"' || true)

if [ "${#globs[@]}" -eq 0 ]; then
  echo "check-mutants-globs: no glob in examine_globs of $config" >&2
  exit 1
fi

failed=0
for glob in "${globs[@]}"; do
  if ! files=$(cargo mutants --no-config --file "$glob" --list-files); then
    echo "check-mutants-globs: cargo mutants failed for $glob" >&2
    exit 1
  fi
  if [ -z "$files" ]; then
    echo "check-mutants-globs: $glob matches no source file" >&2
    failed=1
  fi
done

if ! selected=$(cargo mutants --list-files); then
  echo "check-mutants-globs: cargo mutants failed to list the selected files" >&2
  exit 1
fi
excluded=$(sed -n 's/^# *not critical: *\([^ ]*\).*$/\1/p' "$config")

for path in $excluded; do
  if [ ! -f "$path" ]; then
    echo "check-mutants-globs: $path is named as not critical but does not exist" >&2
    failed=1
  elif grep -qxF -- "$path" <<< "$selected"; then
    echo "check-mutants-globs: $path is named as not critical but examine_globs selects it" >&2
    failed=1
  fi
done

while IFS= read -r path; do
  [ "$(basename "$path")" != tests.rs ] || continue
  if ! grep -qxF -- "$path" <<< "$selected" && ! grep -qxF -- "$path" <<< "$excluded"; then
    echo "check-mutants-globs: $path is neither selected by examine_globs nor named as not critical in $config" >&2
    failed=1
  fi
done < <(find "${tool_dirs[@]}" -name '*.rs' -type f | sort)

if [ "$failed" -eq 0 ]; then
  echo "check-mutants-globs: each of the ${#globs[@]} globs matches a source file, and every source file of the tool crates is selected or one of the $(grep -c . <<< "$excluded") files that are not critical"
fi
exit "$failed"
