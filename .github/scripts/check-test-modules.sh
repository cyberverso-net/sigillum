#!/usr/bin/env bash
# Checks that the Rust files that the coverage report measures hold no
# test-only code. cargo llvm-cov leaves test files out of the report by
# their names, not by #[cfg(test)], so a test written inline in a source
# file would count as covered code. Unit tests therefore live in their own
# file: an item under #[cfg(test)], or under #[cfg(all(...))] with test, in
# a measured file must be a module declaration without a body, such as
#
#   #[cfg(test)]
#   mod tests;
#
# with the tests in src/<module>/tests.rs. Run it in the repository; it
# checks the Rust files that Git tracks, except those that cargo llvm-cov
# leaves out by default: files under tests, examples and benches
# directories, and files named tests.rs or ending in _tests.rs or -tests.rs.
#
# Exits with 1 and names each item when it finds test-only code.
set -euo pipefail

found=0
while IFS= read -r -d '' file; do
  if [[ "$file" =~ (^|/)(tests|examples|benches)/ ]] \
    || [[ "$file" =~ (^|/)(tests\.rs|[0-9a-zA-Z_-]+[_-]tests\.rs)$ ]]; then
    continue
  fi
  awk -v file="$file" '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
    # The item after a test attribute: a module declaration passes, any
    # other item is reported. Empty lines, comments and other attributes
    # are skipped.
    function item(t) {
      if (t == "" || t ~ /^\/\//) return
      if (t ~ /^#\[/) return
      if (t !~ /^(pub(\([^)]*\))? )?mod [A-Za-z_][A-Za-z0-9_]*;$/) {
        printf "%s:%d: test-only code in a measured file; move it to a tests.rs file and declare it with mod <name>;\n", file, pending
        bad = 1
      }
      pending = 0
    }
    {
      t = trim($0)
      if (pending) { item(t); next }
      if (t ~ /^#\[cfg\((test|all\(([^)]*[ ,(])?test[ ,)].*)\)\]/) {
        pending = NR
        rest = t
        sub(/^#\[cfg\(test\)\]/, "", rest)
        # For all(...), the attribute ends at its last ")]".
        if (t ~ /^#\[cfg\(all\(/) { rest = t; while (index(rest, ")]")) rest = substr(rest, index(rest, ")]") + 2) }
        item(trim(rest))
      }
    }
    END {
      if (pending) {
        printf "%s:%d: a test attribute without an item\n", file, pending
        bad = 1
      }
      exit bad
    }
  ' "$file" || found=1
done < <(git ls-files -z -- '*.rs')

if [ "$found" -ne 0 ]; then
  exit 1
fi
echo "check-test-modules: no test-only code in the measured files"
