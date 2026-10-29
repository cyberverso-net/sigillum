#!/usr/bin/env bash
# Tests diff-coverage.sh on small Git repositories built for each case, with
# lcov reports written by hand: the counts of the total and of the changed
# lines, the lines that are not covered, and the inputs that it refuses.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script=$here/diff-coverage.sh
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

failures=0

# Starts a new repository in $repo, with one commit that adds the files
# given as <path>=<number of lines>, and records it as the base.
repo=
new_repo() {
  local spec path lines
  repo=$scratch/repo
  rm -rf "$repo"
  mkdir -p "$repo"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.name Test
  git -C "$repo" config user.email test@example.invalid
  git -C "$repo" config commit.gpgsign false
  for spec in "$@"; do
    path=${spec%=*}
    lines=${spec##*=}
    mkdir -p "$repo/$(dirname "$path")"
    seq 1 "$lines" | sed 's/^/line /' > "$repo/$path"
  done
  git -C "$repo" add -A
  git -C "$repo" commit -q -m base
  base=$(git -C "$repo" rev-parse HEAD)
}

commit() {
  git -C "$repo" add -A
  git -C "$repo" commit -q -m change
}

# Replaces line <n> of <path> with new text.
change_line() {
  sed -i.bak "$2s/.*/changed $2/" "$repo/$1" && rm "$repo/$1.bak"
}

# Writes the lcov report: one argument per record, <path>:<line>=<count>,...
# A path that starts with / is written as it is; any other is placed under
# the repository.
lcov() {
  local record path data entry
  : > "$scratch/lcov.info"
  for record in "$@"; do
    path=${record%%:*}
    data=${record#*:}
    case "$path" in
      /*) ;;
      *) path=$(cd "$repo" && pwd -P)/$path ;;
    esac
    {
      echo "TN:"
      echo "SF:$path"
      echo "FN:1,f"
      IFS=',' read -ra entries <<< "$data"
      for entry in "${entries[@]}"; do
        echo "DA:${entry%=*},${entry#*=}"
      done
      echo "end_of_record"
    } >> "$scratch/lcov.info"
  done
}

# expect <exit code> <name> [<text the output must contain>...]
# Text that starts with ! must not appear in the output.
expect() {
  local wanted=$1 name=$2 code=0 text
  shift 2
  (cd "$repo" && bash "$script" "$scratch/lcov.info" "${base_arg:-$base}") > "$scratch/output" 2>&1 || code=$?
  if [ "$code" -ne "$wanted" ]; then
    echo "FAIL: $name: exit code $code, expected $wanted" >&2
    sed 's/^/  /' "$scratch/output" >&2
    failures=$((failures + 1))
    return
  fi
  for text in "$@"; do
    if [ "${text:0:1}" = "!" ]; then
      if grep -qF -- "${text:1}" "$scratch/output"; then
        echo "FAIL: $name: the output contains: ${text:1}" >&2
        sed 's/^/  /' "$scratch/output" >&2
        failures=$((failures + 1))
        return
      fi
    elif ! grep -qF -- "$text" "$scratch/output"; then
      echo "FAIL: $name: the output does not contain: $text" >&2
      sed 's/^/  /' "$scratch/output" >&2
      failures=$((failures + 1))
      return
    fi
  done
  echo "ok: $name"
}

# Two changed lines out of three instrumented ones are covered; a changed
# line without coverage data, such as a comment, does not count.
new_repo src/a.rs=10
change_line src/a.rs 2
change_line src/a.rs 3
change_line src/a.rs 4
change_line src/a.rs 9
commit
lcov "src/a.rs:1=1,2=5,3=0,4=1,5=0"
expect 0 "changed lines, covered and not" \
  "| Total | 3 | 5 | 60.00% |" \
  "| Changed lines | 2 | 3 | 66.66% |" \
  "| \`src/a.rs\` | 2 | 3 | 66.66% | 3 |"

# A file that appears in several records is covered where any record covers it.
lcov "src/a.rs:1=1,2=0,3=0,4=1,5=0" "src/a.rs:2=1,3=0,5=0"
expect 0 "records of the same file merged" \
  "| Total | 3 | 5 | 60.00% |" \
  "| Changed lines | 2 | 3 | 66.66% |"

# A checksum after the count is allowed, and counts above the range of a
# 32-bit integer are covered.
printf 'SF:%s/src/a.rs\nDA:2,4294967296,abc\nDA:3,0,def\nDA:4,1\nend_of_record\n' "$(cd "$repo" && pwd -P)" > "$scratch/lcov.info"
expect 0 "checksums and large counts" "| Changed lines | 2 | 3 | 66.66% |"

# Consecutive lines that are not covered are shown as ranges.
new_repo src/a.rs=20
for n in 2 3 4 5 8 10 11; do change_line src/a.rs "$n"; done
commit
lcov "src/a.rs:2=0,3=0,4=0,5=1,8=0,10=0,11=0"
expect 0 "ranges of lines not covered" "| \`src/a.rs\` | 1 | 7 | 14.28% | 2-4, 8, 10-11 |"

# The percentage is truncated, never rounded up to a threshold.
new_repo src/a.rs=1
seq 1 20000 >> "$repo/src/a.rs"
commit
data=$(seq 2 20001 | awk '{ printf "%s%s=%d", sep, $1, ($1 == 20001 ? 0 : 1); sep = "," }')
lcov "src/a.rs:$data"
expect 0 "a percentage truncated" "| Changed lines | 19999 | 20000 | 99.99% |" "!100.00%"

# Lines removed and files deleted are not changed lines; added and renamed
# files count under their new path; a file outside the repository and a
# file that did not change count only in the total.
new_repo src/a.rs=5 src/b.rs=5 src/c.rs=5 src/old.rs=8
sed -i.bak '2d' "$repo/src/a.rs" && rm "$repo/src/a.rs.bak"
git -C "$repo" rm -q src/b.rs
git -C "$repo" mv src/old.rs src/new.rs
change_line src/new.rs 7
seq 1 3 > "$repo/src/added.rs"
commit
lcov "src/a.rs:1=1,2=1" "src/c.rs:1=0" "src/new.rs:6=1,7=0" "src/added.rs:1=1,2=1,3=0" "/elsewhere/lib.rs:1=0"
expect 0 "deletions, additions and renames" \
  "| Total | 5 | 8 | 62.50% |" \
  "| Changed lines | 2 | 4 | 50.00% |" \
  "| \`src/added.rs\` | 2 | 3 | 66.66% | 3 |" \
  "| \`src/new.rs\` | 0 | 1 | 0.00% | 7 |" \
  "!src/a.rs\` |" "!src/b.rs" "!src/old.rs" "!elsewhere"

# A changed Rust file that has no record in the report is listed; other
# changed files are not.
new_repo src/a.rs=3 src/gated.rs=3 README.md=3
change_line src/a.rs 1
change_line src/gated.rs 1
change_line README.md 1
commit
lcov "src/a.rs:1=1"
expect 0 "changed Rust files missing from the report" \
  "Changed Rust files with no line in the report: \`src/gated.rs\`." "!README.md"

# Test files, which cargo llvm-cov leaves out of the report by default, are
# not listed as missing.
new_repo src/a.rs=3 src/m/tests.rs=3 src/m_tests.rs=3 tests/it.rs=3 benches/b.rs=3 examples/e.rs=3 fuzz/fuzz_targets/t.rs=3 src/contests.rs=3
for f in src/a.rs src/m/tests.rs src/m_tests.rs tests/it.rs benches/b.rs examples/e.rs fuzz/fuzz_targets/t.rs src/contests.rs; do
  change_line "$f" 1
done
commit
lcov "src/a.rs:1=1"
expect 0 "test files not listed as missing" \
  "Changed Rust files with no line in the report: \`fuzz/fuzz_targets/t.rs\`, \`src/contests.rs\`." \
  "!m/tests.rs" "!m_tests.rs" "!tests/it.rs" "!benches/" "!examples/"

# Without a changed instrumented line, the changed coverage is not a number.
new_repo src/a.rs=3 README.md=3
change_line README.md 1
commit
lcov "src/a.rs:1=1,2=0"
expect 0 "no changed instrumented line" "| Changed lines | 0 | 0 | n/a |" "!Changed Rust files"

# Changes made on the base branch after the merge base do not count.
new_repo src/a.rs=5
git -C "$repo" checkout -q -b topic
change_line src/a.rs 2
commit
topic=$(git -C "$repo" rev-parse HEAD)
git -C "$repo" checkout -q main
change_line src/a.rs 4
commit
base_arg=$(git -C "$repo" rev-parse HEAD)
git -C "$repo" checkout -q "$topic"
lcov "src/a.rs:2=1,4=0"
expect 0 "a base that moved on" "| Changed lines | 1 | 1 | 100.00% |"
base_arg=

# Added lines whose text looks like a file or hunk header are content.
new_repo src/a.rs=5
printf '%s\n' "++ b/src/z.rs" "@@ -1 +1,9 @@" "-- a/src/a.rs" >> "$repo/src/a.rs"
commit
lcov "src/a.rs:6=1,7=1,8=0"
expect 0 "lines that look like headers" "| \`src/a.rs\` | 2 | 3 | 66.66% | 8 |" "!src/z.rs"

# File names with spaces, and Git settings that change the diff output.
new_repo "src/with space.rs=4"
change_line "src/with space.rs" 2
commit
git -C "$repo" config diff.noprefix true
git -C "$repo" config diff.mnemonicPrefix true
git -C "$repo" config color.ui always
git -C "$repo" config diff.context 5
lcov "src/with space.rs:1=1,2=0"
expect 0 "a name with a space and unusual Git settings" "| \`src/with space.rs\` | 0 | 1 | 0.00% | 2 |"

# Git can join nearby hunks with the lines between them as context, even
# with --unified=0, when diff.interHunkContext is set.
new_repo src/a.rs=10
change_line src/a.rs 2
change_line src/a.rs 5
commit
git -C "$repo" config diff.interHunkContext 10
lcov "src/a.rs:2=1,3=1,4=1,5=0"
expect 0 "hunks joined by diff.interHunkContext" "| Changed lines | 1 | 2 | 50.00% |" "| \`src/a.rs\` | 1 | 2 | 50.00% | 5 |"

# Renames are found even when diff.renames is off, so a renamed file counts
# only its changed lines.
new_repo src/old.rs=8
git -C "$repo" mv src/old.rs src/new.rs
change_line src/new.rs 7
commit
git -C "$repo" config diff.renames false
lcov "src/new.rs:1=1,2=1,3=1,4=1,5=1,6=1,7=0,8=1"
expect 0 "renames found with diff.renames off" "| \`src/new.rs\` | 0 | 1 | 0.00% | 7 |"

# Refused inputs.
new_repo src/a.rs=3
change_line src/a.rs 1
commit
lcov "src/a.rs:1=1"
base_arg=0000000000000000000000000000000000000000
expect 2 "a base that is not a commit" "is not a commit"
base_arg=
: > "$scratch/lcov.info"
expect 2 "a report without a record" "has no coverage record"
rm "$scratch/lcov.info"
expect 2 "a missing report" "cannot be read"
printf 'SF:%s/src/a.rs\nDA:x,1\nend_of_record\n' "$(cd "$repo" && pwd -P)" > "$scratch/lcov.info"
expect 2 "a malformed line record" "malformed"
code=0
(cd "$repo" && bash "$script" "$scratch/lcov.info") > "$scratch/output" 2>&1 || code=$?
if [ "$code" -eq 2 ] && grep -qF "usage" "$scratch/output"; then
  echo "ok: a missing argument"
else
  echo "FAIL: a missing argument: exit code $code" >&2
  failures=$((failures + 1))
fi

# A file name that Git quotes cannot be matched with the report.
if touch "$scratch/probe$(printf '\t')name" 2> /dev/null; then
  new_repo src/a.rs=3
  printf 'x\n' > "$repo/src/tab$(printf '\t')name.rs"
  commit
  lcov "src/a.rs:1=1"
  expect 2 "a Rust file name that Git quotes" "quoted"

  # Other quoted names are not in the report, and are skipped.
  new_repo src/a.rs=3
  change_line src/a.rs 1
  printf 'x\n' > "$repo/doc$(printf '\t')name.md"
  commit
  lcov "src/a.rs:1=1"
  expect 0 "another file name that Git quotes" "| \`src/a.rs\` | 1 | 1 | 100.00% |  |" "!doc"
fi

# The base of the comparison for each event, from coverage-base.sh.
base_script=$here/coverage-base.sh
# expect_base <exit code> <name> <wanted base, or empty> <variable=value>...
expect_base() {
  local wanted_code=$1 name=$2 wanted=$3 code=0 got
  shift 3
  got=$(cd "$repo" && env -u EVENT -u GROUP_BASE -u BEFORE "$@" bash "$base_script" 2> "$scratch/output") || code=$?
  if [ "$code" -ne "$wanted_code" ]; then
    echo "FAIL: $name: exit code $code, expected $wanted_code" >&2
    sed 's/^/  /' "$scratch/output" >&2
    failures=$((failures + 1))
  elif [ "$code" -eq 0 ] && [ "$got" != "$wanted" ]; then
    echo "FAIL: $name: base $got, expected $wanted" >&2
    failures=$((failures + 1))
  else
    echo "ok: $name"
  fi
}
new_repo src/a.rs=3
first=$base
git -C "$repo" checkout -q -b topic
change_line src/a.rs 1
commit
topic=$(git -C "$repo" rev-parse HEAD)
git -C "$repo" checkout -q main
change_line src/a.rs 3
commit
main_tip=$(git -C "$repo" rev-parse HEAD)
git -C "$repo" merge -q --no-ff --no-edit topic
head=$(git -C "$repo" rev-parse HEAD)
expect_base 0 "a pull request: the first parent of the merge commit" "$main_tip" EVENT=pull_request
expect_base 0 "a merge group: its base" "$first" EVENT=merge_group "GROUP_BASE=$first"
expect_base 2 "a merge group without a base" "" EVENT=merge_group
expect_base 0 "a push: the commit before it" "$topic" EVENT=push "BEFORE=$topic"
expect_base 0 "a push of a new branch: no base" "$head" EVENT=push BEFORE=0000000000000000000000000000000000000000
expect_base 0 "a push whose previous commit is unknown: no base" "$head" EVENT=push BEFORE=1234567890123456789012345678901234567890
expect_base 0 "another event: no base" "$head" EVENT=workflow_dispatch
git -C "$repo" checkout -q "$topic"
expect_base 2 "a pull request whose head is not a merge commit" "" EVENT=pull_request

# Test-only code in measured files, from check-test-modules.sh. Each case
# writes one file in a new repository and runs the check there.
modules_script=$here/check-test-modules.sh
# expect_modules <exit code> <name> <path> <contents> [<text the output must contain>]
expect_modules() {
  local wanted=$1 name=$2 path=$3 contents=$4 text=${5:-} code=0
  new_repo README.md=1
  mkdir -p "$repo/$(dirname "$path")"
  printf '%s\n' "$contents" > "$repo/$path"
  commit
  (cd "$repo" && bash "$modules_script") > "$scratch/output" 2>&1 || code=$?
  if [ "$code" -ne "$wanted" ]; then
    echo "FAIL: $name: exit code $code, expected $wanted" >&2
    sed 's/^/  /' "$scratch/output" >&2
    failures=$((failures + 1))
  elif [ -n "$text" ] && ! grep -qF -- "$text" "$scratch/output"; then
    echo "FAIL: $name: the output does not contain: $text" >&2
    sed 's/^/  /' "$scratch/output" >&2
    failures=$((failures + 1))
  else
    echo "ok: $name"
  fi
}
nl=$'\n'
expect_modules 0 "a test module in its own file" src/a.rs "fn f() {}${nl}#[cfg(test)]${nl}mod tests;"
expect_modules 0 "a test module on one line" src/a.rs "#[cfg(test)] mod tests;"
expect_modules 0 "a test module under a condition with test and another" src/a.rs "#[cfg(all(not(windows), test))]${nl}mod tests;"
expect_modules 0 "a commented attribute" src/a.rs "// #[cfg(test)]${nl}fn f() {}"
expect_modules 0 "a feature whose name contains test" src/a.rs "#[cfg(feature = \"testing\")]${nl}fn f() {}${nl}#[cfg(test_x)]${nl}fn g() {}"
expect_modules 0 "an attribute that is not cfg" src/a.rs "#[cfg_attr(test, allow(dead_code))]${nl}fn f() {}"
expect_modules 0 "an inline module in a tests.rs file" src/a/tests.rs "#[cfg(test)]${nl}mod more {}"
expect_modules 0 "an inline module in a _tests.rs file" src/a_tests.rs "#[cfg(test)]${nl}mod more {}"
expect_modules 0 "an inline module under a tests directory" tests/it.rs "#[cfg(test)]${nl}mod more {}"
expect_modules 1 "an inline test module" src/a.rs "fn f() {}${nl}${nl}#[cfg(test)]${nl}mod tests {${nl}}" "src/a.rs:3"
expect_modules 1 "an inline test module on one line" src/a.rs "#[cfg(test)] mod tests { }" "src/a.rs:1"
expect_modules 1 "a test-only function" src/a.rs "#[cfg(test)]${nl}fn helper() {}" "src/a.rs:1"
expect_modules 1 "a test module with another name" src/a.rs "#[cfg(test)]${nl}mod test_helpers;" "src/a.rs:1"
expect_modules 1 "a public test module" src/a.rs "#[cfg(test)]${nl}pub(crate) mod tests;" "src/a.rs:1"
expect_modules 1 "a test module with a path after the condition" src/a.rs "#[cfg(test)]${nl}#[path = \"t.rs\"]${nl}mod tests;" "src/a.rs:1"
expect_modules 1 "a test module with a path before the condition" src/a.rs "#[path = \"t.rs\"]${nl}#[cfg(test)]${nl}mod tests;" "src/a.rs:2"
expect_modules 1 "a test module with a path on the same line" src/a.rs "#[cfg(test)] #[path = \"t.rs\"] mod tests;" "src/a.rs:1"
expect_modules 1 "an inline module for tests with a feature" src/a.rs "#[cfg(all(test, feature = \"x\"))]${nl}mod t {}" "src/a.rs:1"
expect_modules 1 "an inline module after a nested condition" src/a.rs "#[cfg(all(not(windows), test))]${nl}mod t {}" "src/a.rs:1"
expect_modules 1 "a condition over several lines" src/a.rs "#[cfg(all(${nl}    unix,${nl}    test,${nl}))]${nl}fn f() {}" "src/a.rs:1"
expect_modules 1 "code for builds without tests" src/a.rs "#[cfg(not(test))]${nl}fn f() {}" "src/a.rs:1"
expect_modules 1 "a whole file for tests" src/helpers.rs "#![cfg(test)]${nl}fn f() {}" "src/helpers.rs:1"
expect_modules 1 "an inline test module with another attribute" src/a.rs "    #[cfg(test)]${nl}    #[allow(dead_code)]${nl}    mod tests {}" "src/a.rs:1"
expect_modules 1 "a condition at the end of the file" src/a.rs "fn f() {}${nl}#[cfg(test)]" "src/a.rs:2"

# The repository as it is.
code=0
(cd "$here/../.." && bash "$modules_script") > "$scratch/output" 2>&1 || code=$?
if [ "$code" -eq 0 ]; then
  echo "ok: the repository as it is"
else
  echo "FAIL: the repository as it is: exit code $code" >&2
  sed 's/^/  /' "$scratch/output" >&2
  failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed" >&2
  exit 1
fi
echo "every case passed"
