#!/usr/bin/env bash
# Checks that every glob of examine_globs in .cargo/mutants.toml matches
# at least one source file that cargo mutants would mutate, so that a
# renamed or removed module cannot silently leave the critical modules.
# Each glob is given alone to `cargo mutants --list-files`, with the
# configuration file ignored, which lists the files it selects.
#
# Usage: check-mutants-globs.sh [<config file>], by default
# .cargo/mutants.toml. Run from the root of the workspace. Exits with 1
# when a glob matches nothing, the list is empty or cargo mutants fails.
set -euo pipefail

config=${1:-.cargo/mutants.toml}

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
if [ "$failed" -eq 0 ]; then
  echo "check-mutants-globs: each of the ${#globs[@]} globs matches a source file"
fi
exit "$failed"
