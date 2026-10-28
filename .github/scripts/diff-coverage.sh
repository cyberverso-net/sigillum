#!/usr/bin/env bash
# Reports line coverage from an lcov file, in Markdown for a job summary:
# the total, and the coverage of the lines added or changed between the
# merge base of <base> and HEAD. Run it in the repository.
#
#   diff-coverage.sh <lcov file> <base commit>
#
# A line counts when the report has data for it, and is covered when any
# record gives it a count above zero. Changed lines without data, such as
# comments, do not count. Records of files outside the repository are
# ignored. Changed Rust files that have no record are listed, since their
# lines are not measured: they are excluded from the report, as tests are,
# or not built in the configuration that was measured. Percentages are
# truncated to two decimals, never rounded up.
#
# Exits with 2 when an input is missing or cannot be read, and with 0
# otherwise, whatever the coverage.
set -euo pipefail

fail() {
  echo "diff-coverage: $1" >&2
  exit 2
}

[ "$#" -eq 2 ] || fail "usage: diff-coverage.sh <lcov file> <base commit>"
report=$1
[ -f "$report" ] && [ -r "$report" ] || fail "$report cannot be read"
root=$(git rev-parse --show-toplevel) || fail "not in a Git repository"
root=$(cd "$root" && pwd -P)
git rev-parse --quiet --verify "$2^{commit}" > /dev/null || fail "$2 is not a commit"
base=$(git merge-base "$2" HEAD) || fail "$2 and HEAD have no merge base"

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# The lines of the report: <path> TAB <line> TAB <1 if covered, else 0>,
# one per line of a file, with paths relative to the repository.
COVERAGE_ROOT=$root/ awk '
  BEGIN { root = ENVIRON["COVERAGE_ROOT"] }
  function malformed() {
    printf "diff-coverage: malformed record at line %d of the report: %s\n", NR, $0 > "/dev/stderr"
    bad = 1
    exit 2
  }
  /^SF:/ {
    path = substr($0, 4)
    if (index(path, root) == 1) path = substr(path, length(root) + 1)
    else if (substr(path, 1, 1) == "/") path = ""
    records++
    next
  }
  /^end_of_record$/ { path = ""; next }
  /^DA:/ {
    if (path == "") next
    n = split(substr($0, 4), field, ",")
    if (n < 2 || field[1] !~ /^[0-9]+$/ || field[2] !~ /^-?[0-9]+$/) malformed()
    key = path "\t" (field[1] + 0)
    if (!(key in hit)) hit[key] = 0
    # The count is compared as text, so that no count overflows.
    if (field[2] !~ /^-/ && field[2] !~ /^0+$/) hit[key] = 1
  }
  END {
    if (bad) exit 2
    if (records == 0) {
      print "diff-coverage: the report has no coverage record" > "/dev/stderr"
      exit 2
    }
    for (key in hit) print key "\t" hit[key]
  }
' "$report" > "$scratch/lines" || exit 2

# The changed lines: "L" TAB <path> TAB <line> for each line added or
# changed, and "F" TAB <path> for each file added or changed. The options
# set every part of the output that Git settings could change.
git -c core.quotePath=false diff --no-ext-diff --no-textconv --no-color \
  --unified=0 --find-renames --diff-filter=d --src-prefix=a/ --dst-prefix=b/ \
  "$base" HEAD > "$scratch/diff" || fail "git diff failed"
awk '
  # In the body of a hunk, every line is content, whatever it looks like.
  old > 0 || new > 0 {
    c = substr($0, 1, 1)
    if (c == "-") old--
    else if (c == "+") { new--; print "L\t" path "\t" line++ }
    next
  }
  /^diff --git / { path = ""; next }
  /^\+\+\+ / {
    name = substr($0, 5)
    if (name == "/dev/null") { path = ""; next }
    if (substr(name, 1, 1) == "\"") {
      printf "diff-coverage: Git quoted the file name %s, which cannot be matched with the report\n", name > "/dev/stderr"
      exit 2
    }
    # Git ends a name that contains a space with a tab.
    sub(/\t$/, "", name)
    path = substr(name, 3)
    print "F\t" path
    next
  }
  /^@@ / {
    # @@ -<start>[,<count>] +<start>[,<count>] @@
    split($2, o, ",")
    split($3, h, ",")
    old = (2 in o) ? o[2] + 0 : 1
    new = (2 in h) ? h[2] + 0 : 1
    line = substr(h[1], 2) + 0
  }
' "$scratch/diff" > "$scratch/changed" || exit 2

base_name=$(git rev-parse --short "$base")
awk -F '\t' -v base="$base_name" '
  function percent(covered, total) {
    if (total == 0) return "n/a"
    p = int(covered * 10000 / total)
    return sprintf("%d.%02d%%", int(p / 100), p % 100)
  }
  # Consecutive numbers of a sorted list, as ranges.
  function ranges(list,    n, item, out, i, first, last) {
    n = split(list, item, " ")
    out = ""
    for (i = 1; i <= n; i++) {
      first = item[i]
      last = first
      while (i < n && item[i + 1] == last + 1) { i++; last = item[i] }
      out = out (out == "" ? "" : ", ") (first == last ? first : first "-" last)
    }
    return out
  }
  FILENAME == ARGV[1] {
    known[$1] = 1
    covered[$1 "\t" $2] = $3
    total++
    hits += $3
    next
  }
  $1 == "F" { changed_file[$2] = 1; next }
  $1 == "L" {
    key = $2 "\t" $3
    if (!(key in covered)) next
    file_lines[$2]++
    changed++
    if (covered[key]) { file_hits[$2]++; changed_hits++ }
    else missed[$2] = missed[$2] " " $3
  }
  END {
    print "### Line coverage"
    print ""
    print "| | Lines covered | Lines | Coverage |"
    print "| --- | ---: | ---: | ---: |"
    printf "| Total | %d | %d | %s |\n", hits, total, percent(hits, total)
    printf "| Changed lines | %d | %d | %s |\n", changed_hits, changed, percent(changed_hits, changed)
    print ""
    printf "Changed lines are those added or changed since %s, the merge base, that the report measures.\n", base
    count = 0
    for (f in file_lines) name[++count] = f
    # Insertion sort, for the same order with every awk.
    for (i = 2; i <= count; i++) {
      v = name[i]
      for (j = i - 1; j > 0 && name[j] > v; j--) name[j + 1] = name[j]
      name[j + 1] = v
    }
    if (count > 0) {
      print ""
      print "| File | Changed lines covered | Changed lines | Coverage | Lines not covered |"
      print "| --- | ---: | ---: | ---: | --- |"
      for (i = 1; i <= count; i++) {
        f = name[i]
        printf "| `%s` | %d | %d | %s | %s |\n", f, file_hits[f], file_lines[f], percent(file_hits[f], file_lines[f]), ranges(missed[f])
      }
    }
    unmeasured = ""
    for (f in changed_file) {
      if (f ~ /\.rs$/ && !(f in known)) list[++m] = f
    }
    for (i = 2; i <= m; i++) {
      v = list[i]
      for (j = i - 1; j > 0 && list[j] > v; j--) list[j + 1] = list[j]
      list[j + 1] = v
    }
    for (i = 1; i <= m; i++) unmeasured = unmeasured (i > 1 ? ", " : "") "`" list[i] "`"
    if (m > 0) {
      print ""
      printf "Changed Rust files with no line in the report: %s.\n", unmeasured
    }
  }
' "$scratch/lines" <(LC_ALL=C sort -t "$(printf '\t')" -k1,1 -k2,2 -k3,3n "$scratch/changed")
