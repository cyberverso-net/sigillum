#!/usr/bin/env bash
# Tests mutants-summary.sh: the score of one or more shards, the result
# against the threshold, the lists of missed mutants and timeouts, and the
# failures of cargo mutants itself. Each case runs on shard directories
# written here: the mutants.out of cargo-mutants 27.1.0, with the file
# exit-status that mutants.yml adds. Requires jq.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# shard <name> <exit status> <caught> <missed> <timeout> <unviable> [<baseline summary>]
# Writes the shard directory $scratch/<name> with these counts. The missed
# and timed out mutants are listed in missed.txt and timeout.txt, one per
# line, named after the shard.
shard() {
  local dir=$scratch/$1 status=$2 caught=$3 missed=$4 timeout=$5 unviable=$6 baseline=${7:-Success} i
  rm -rf "$dir"
  mkdir -p "$dir"
  echo "$status" > "$dir/exit-status"
  cat > "$dir/outcomes.json" << EOF
{
  "outcomes": [
    {"scenario": "Baseline", "summary": "$baseline", "log_path": "log/baseline.log", "diff_path": null, "phase_results": []}
  ],
  "total_mutants": $((caught + missed + timeout + unviable)),
  "missed": $missed,
  "caught": $caught,
  "timeout": $timeout,
  "unviable": $unviable,
  "success": 0,
  "start_time": "2026-10-28T10:00:00Z",
  "end_time": "2026-10-28T10:05:00Z",
  "cargo_mutants_version": "27.1.0"
}
EOF
  : > "$dir/missed.txt"
  : > "$dir/timeout.txt"
  for ((i = 1; i <= missed; i++)); do
    echo "crates/sigillum-cms/src/$1.rs:$i:5: replace parse -> bool with true" >> "$dir/missed.txt"
  done
  for ((i = 1; i <= timeout; i++)); do
    echo "crates/sigillum-cms/src/$1.rs:$((100 + i)):9: replace < with <= in decode" >> "$dir/timeout.txt"
  done
}

failures=0
# expect <wanted exit code> <name> <threshold> <shards> [<text the output must contain>...]
# <shards> is a space-separated list of shard names. A text that starts
# with ! must not be in the output.
expect() {
  local wanted=$1 name=$2 threshold=$3 shards=$4 code=0 text dirs=() s
  shift 4
  for s in $shards; do
    dirs+=("$scratch/$s")
  done
  bash "$here/mutants-summary.sh" "$threshold" ${dirs[@]+"${dirs[@]}"} > "$scratch/output" 2>&1 || code=$?
  if [ "$code" -ne "$wanted" ]; then
    echo "FAIL: $name: exit code $code, expected $wanted" >&2
    sed 's/^/  /' "$scratch/output" >&2
    failures=$((failures + 1))
    return
  fi
  for text in "$@"; do
    if [[ "$text" == !* ]]; then
      if grep -qF -- "${text#!}" "$scratch/output"; then
        echo "FAIL: $name: the output contains: ${text#!}" >&2
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

shard a 0 10 0 0 2
expect 0 "every mutant caught" 80 a "| Caught | 10 |" "| Unviable | 2 |" "| Score | 100.0% |" \
  "The score meets the threshold of 80%." "No mutant was missed." "!replace parse"

shard a 2 8 2 0 0
expect 0 "a score equal to the threshold" 80 a "| Missed | 2 |" "| Score | 80.0% |" \
  "The score meets the threshold of 80%." "crates/sigillum-cms/src/a.rs:2:5: replace parse -> bool with true"

shard a 2 7 3 0 5
expect 1 "a score below the threshold" 80 a "| Score | 70.0% |" \
  "The score is below the threshold of 80%." "crates/sigillum-cms/src/a.rs:3:5: replace parse -> bool with true"

# Unviable mutants are left out of the score, timeouts count as not caught.
shard a 3 8 0 2 9
expect 0 "timeouts count as not caught" 80 a "| Timeouts | 2 |" "| Score | 80.0% |" \
  "crates/sigillum-cms/src/a.rs:102:9: replace < with <= in decode"
shard a 3 7 0 3 0
expect 1 "timeouts below the threshold" 80 a "| Score | 70.0% |" "The score is below the threshold of 80%."

shard a 2 2 1 0 0
expect 1 "a score rounded down" 67 a "| Score | 66.6% |" "The score is below the threshold of 67%."
expect 0 "a score just above the threshold" 66 a "| Score | 66.6% |" "The score meets the threshold of 66%."

shard a 0 0 0 0 4
expect 0 "only unviable mutants" 80 a "No viable mutant" "!| Score |"

# The shards are added up, and their lists joined.
shard a 2 9 1 0 1
shard b 3 9 0 1 2
shard c 0 10 0 0 0
expect 0 "three shards" 80 "a b c" "| Caught | 28 |" "| Missed | 1 |" "| Timeouts | 1 |" \
  "| Unviable | 3 |" "| Score | 93.3% |" "crates/sigillum-cms/src/a.rs:1:5:" "crates/sigillum-cms/src/b.rs:101:9:"
shard b 2 1 9 0 0
expect 1 "shards below the threshold together" 80 "a b c" "| Score | 66.6% |"

# With --in-diff, cargo mutants exits with 0 and writes no outcomes when
# nothing in the diff can be mutated. A shard can also be empty.
shard a 0 0 0 0 0
rm "$scratch/a/outcomes.json" "$scratch/a/missed.txt" "$scratch/a/timeout.txt"
expect 0 "no mutant to test" 80 a "No mutant of the critical modules was tested." "!| Score |"
shard b 0 5 0 0 0
expect 0 "an empty shard" 80 "a b" "| Caught | 5 |" "| Score | 100.0% |"

shard a 4 5 0 0 0 Failure
expect 1 "a baseline that fails" 80 a "The tests fail without any mutation" "!| Score |"
shard a 0 5 0 0 0 Failure
expect 1 "a failing baseline in outcomes.json" 80 a "The tests fail without any mutation"
shard b 0 5 0 0 0
expect 1 "a failing baseline in one shard" 80 "b a" "The tests fail without any mutation" "!| Score |"

shard a 5 5 0 0 0
expect 1 "a diff that does not match the tree" 80 a "exit code 5"
shard a 1 5 0 0 0
expect 1 "a usage error" 80 a "exit code 1"
shard a 70 5 0 0 0
expect 1 "an internal error" 80 a "exit code 70"

shard a 2 5 1 0 0
rm "$scratch/a/outcomes.json"
expect 1 "no outcomes after a run with missed mutants" 80 a "no outcomes.json"
shard a 0 5 0 0 0
rm "$scratch/a/exit-status"
expect 1 "a shard without its exit status" 80 a "no exit status"
rm -rf "$scratch/a"
expect 1 "a shard that is missing" 80 "a b" "no exit status"
shard a x 5 0 0 0
expect 1 "an exit status that is not a number" 80 a "exit status"

shard a 0 5 0 0 0
expect 2 "a threshold that is not a percentage" eighty a "threshold"
expect 2 "a threshold above 100" 101 a "threshold"
expect 2 "no shard" 80 "" "usage"

shard a 2 0 600 0 0
expect 1 "a long list is cut" 80 a "| Missed | 600 |" "crates/sigillum-cms/src/a.rs:500:5:" \
  "!crates/sigillum-cms/src/a.rs:501:5:" "100 more in missed.txt of the artefacts"

if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed" >&2
  exit 1
fi
echo "every case passed"
