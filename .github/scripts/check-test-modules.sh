#!/usr/bin/env bash
# Checks that the Rust files that the coverage report measures hold no
# test-only code. cargo llvm-cov leaves test files out of the report by
# their names, not by #[cfg(test)], so test code anywhere else would count
# as covered code. Unit tests therefore live in src/<module>/tests.rs,
# which the report leaves out, declared in the measured file as
#
#   #[cfg(test)]
#   mod tests;
#
# A cfg attribute whose condition contains the word test, in any form,
# must apply to exactly that declaration: the module named tests, with no
# visibility and no other attribute, such as #[path], before or after the
# condition. An inner #![cfg(...)] with test is refused.
#
# Run it in the repository. It checks the Rust files that Git tracks,
# except those that cargo llvm-cov leaves out by default: files under
# tests, examples and benches directories, and files named tests.rs or
# ending in _tests.rs or -tests.rs. Exits with 1 and names each finding.
set -euo pipefail

found=0
while IFS= read -r -d '' file; do
  if [[ "$file" =~ (^|/)(tests|examples|benches)/ ]] \
    || [[ "$file" =~ (^|/)(tests\.rs|[0-9a-zA-Z_-]+[_-]tests\.rs)$ ]]; then
    continue
  fi
  awk -v file="$file" '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }
    function report(line, message) {
      printf "%s:%d: %s\n", file, line, message
      bad = 1
    }
    # The length of the attribute at the start of s, or 0 if it does not
    # end on this text. Brackets are counted; strings are not parsed.
    function attribute_length(s,    i, c, depth) {
      depth = 0
      for (i = 1; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (c == "[") depth++
        else if (c == "]") { depth--; if (depth == 0) return i }
      }
      return 0
    }
    # Whether an attribute is cfg with the word test in its condition.
    function is_test_condition(a,    words) {
      if (a !~ /^#!?\[[ \t]*cfg[ \t]*\(/) return 0
      words = a
      gsub(/[^A-Za-z0-9_]+/, " ", words)
      return (" " words " ") ~ / test /
    }
    function attribute(a, line) {
      if (is_test_condition(a)) {
        if (a ~ /^#!/) report(line, "a whole file for tests; move it to a tests.rs file")
        else if (condition) report(line, "a second test condition on one item")
        else condition = line
      } else if (a !~ /^#!/) {
        others++
      }
    }
    # The item after the attributes, or the end of the file.
    function item(t) {
      if (condition && (t != "mod tests;" || others > 0)) {
        report(condition, "test-only code in a measured file; only \"#[cfg(test)] mod tests;\", with the tests in a tests.rs file, is allowed")
      }
      condition = 0
      others = 0
    }
    {
      t = trim($0)
      if (pending != "") {
        t = pending " " t
        if (!(n = attribute_length(t))) { pending = t; next }
        pending = ""
        attribute(substr(t, 1, n), pending_line)
        t = trim(substr(t, n + 1))
      }
      while (t != "") {
        if (t ~ /^\/\//) break
        if (t ~ /^#!?\[/) {
          if (!(n = attribute_length(t))) { pending = t; pending_line = NR; break }
          attribute(substr(t, 1, n), NR)
          t = trim(substr(t, n + 1))
          continue
        }
        item(t)
        break
      }
    }
    END {
      if (pending != "") report(pending_line, "an attribute that does not end")
      if (condition) item("")
      exit bad
    }
  ' "$file" || found=1
done < <(git ls-files -z -- '*.rs')

if [ "$found" -ne 0 ]; then
  exit 1
fi
echo "check-test-modules: no test-only code in the measured files"
