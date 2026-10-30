#!/usr/bin/env bash
# Tests mutants-summary.sh: the score of one or more shards, the result
# against the threshold, the lists of missed mutants and timeouts, the
# failures of cargo mutants itself, and shards that are missing or did not
# complete. Each case runs on shard directories written here: the
# mutants.out of cargo-mutants 27.1.0, with the files shard and
# exit-status that mutants.yml adds. Requires jq.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
shards=$scratch/shards

reset() {
  rm -rf "$shards"
  mkdir -p "$shards"
}

# shard <index> <count> <exit status> <caught> <missed> <timeout> <unviable> [<baseline summary>]
# Writes the directory of shard <index>/<count> with these counts. The
# missed and timed out mutants are listed in missed.txt and timeout.txt,
# one per line, named after the shard.
shard() {
  local index=$1 count=$2 status=$3 caught=$4 missed=$5 timeout=$6 unviable=$7 baseline=${8:-Success}
  local dir=$shards/mutants-out-shard-$index i
  rm -rf "$dir"
  mkdir -p "$dir"
  echo "$index/$count" > "$dir/shard"
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
    echo "crates/sigillum-cms/src/s$index.rs:$i:5: replace parse -> bool with true" >> "$dir/missed.txt"
  done
  for ((i = 1; i <= timeout; i++)); do
    echo "crates/sigillum-cms/src/s$index.rs:$((100 + i)):9: replace < with <= in decode" >> "$dir/timeout.txt"
  done
}

failures=0
# expect <wanted exit code> <name> <threshold> [<text the output must contain>...]
# A text that starts with ! must not be in the output.
expect() {
  local wanted=$1 name=$2 threshold=$3 code=0 text
  shift 3
  bash "$here/mutants-summary.sh" "$threshold" "$shards" > "$scratch/output" 2>&1 || code=$?
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

reset
shard 0 1 0 10 0 0 2
expect 0 "every mutant caught" 80 "| Caught | 10 |" "| Unviable | 2 |" "| Score | 100.0% |" \
  "The score meets the threshold of 80%." "No mutant was missed." "!replace parse" "!did not complete"

shard 0 1 2 8 2 0 0
expect 0 "a score equal to the threshold" 80 "| Missed | 2 |" "| Score | 80.0% |" \
  "The score meets the threshold of 80%." "crates/sigillum-cms/src/s0.rs:2:5: replace parse -> bool with true"

shard 0 1 2 7 3 0 5
expect 1 "a score below the threshold" 80 "| Score | 70.0% |" \
  "The score is below the threshold of 80%." "crates/sigillum-cms/src/s0.rs:3:5: replace parse -> bool with true"

# Unviable mutants are left out of the score, timeouts count as not caught.
shard 0 1 3 8 0 2 9
expect 0 "timeouts count as not caught" 80 "| Timeouts | 2 |" "| Score | 80.0% |" \
  "crates/sigillum-cms/src/s0.rs:102:9: replace < with <= in decode"
shard 0 1 3 7 0 3 0
expect 1 "timeouts below the threshold" 80 "| Score | 70.0% |" "The score is below the threshold of 80%."

shard 0 1 2 2 1 0 0
expect 1 "a score rounded down" 67 "| Score | 66.6% |" "The score is below the threshold of 67%."
expect 0 "a score just above the threshold" 66 "| Score | 66.6% |" "The score meets the threshold of 66%."

shard 0 1 0 0 0 0 4
expect 0 "only unviable mutants" 80 "No viable mutant" "!| Score |"

# The shards are added up, and their lists joined.
reset
shard 0 3 2 9 1 0 1
shard 1 3 3 9 0 1 2
shard 2 3 0 10 0 0 0
expect 0 "three shards" 80 "| Caught | 28 |" "| Missed | 1 |" "| Timeouts | 1 |" \
  "| Unviable | 3 |" "| Score | 93.3% |" "crates/sigillum-cms/src/s0.rs:1:5:" "crates/sigillum-cms/src/s1.rs:101:9:"
shard 1 3 2 1 9 0 0
expect 1 "shards below the threshold together" 80 "| Score | 66.6% |"

# With --in-diff, cargo mutants exits with 0 and writes no outcomes when
# nothing in the diff can be mutated. A shard can also be empty.
reset
shard 0 2 0 0 0 0 0
shard 1 2 0 0 0 0 0
rm "$shards"/mutants-out-shard-*/outcomes.json
expect 0 "no mutant to test" 80 "No mutant of the critical modules was tested." "!| Score |"
shard 1 2 0 5 0 0 0
expect 0 "an empty shard" 80 "| Caught | 5 |" "| Score | 100.0% |"

# A shard that did not complete is reported, the others are counted, and
# the run fails.
reset
shard 0 3 0 5 0 0 0
shard 2 3 0 4 0 0 0
expect 1 "a missing shard" 80 "| Caught | 9 |" "| Score | 100.0% |" "Shard 1 of 3 reported no result." \
  "1 of 3 shards did not complete"
shard 1 3 0 5 0 0 0
rm "$shards/mutants-out-shard-1/exit-status"
expect 1 "a shard without its exit status" 80 "| Caught | 9 |" "Shard 1 of 3 has no exit status"
shard 1 3 4 5 0 0 0 Failure
expect 1 "a baseline that fails" 80 "| Caught | 9 |" "Shard 1 of 3: the tests fail without any mutation"
shard 1 3 0 5 0 0 0 Failure
expect 1 "a failing baseline in outcomes.json" 80 "Shard 1 of 3: the tests fail without any mutation"
shard 1 3 5 5 0 0 0
expect 1 "a diff that does not match the tree" 80 "| Caught | 9 |" "exit code 5"
shard 1 3 1 5 0 0 0
expect 1 "a usage error" 80 "exit code 1"
shard 1 3 70 5 0 0 0
expect 1 "an internal error" 80 "exit code 70"
shard 1 3 2 5 1 0 0
rm "$shards/mutants-out-shard-1/outcomes.json"
expect 1 "no outcomes after a run with missed mutants" 80 "no outcomes.json"
shard 1 3 x 5 0 0 0
expect 1 "an exit status that is not a number" 80 "exit status"
shard 1 3 0 5 0 0 0
expect 0 "the three shards again" 80 "| Caught | 14 |" "!did not complete"

# The shards must agree on their count and have one directory each.
shard 1 2 0 5 0 0 0
expect 1 "shards that disagree on their count" 80 "do not agree"
shard 1 3 0 5 0 0 0
mkdir -p "$shards/copy"
cp "$shards/mutants-out-shard-1/"* "$shards/copy/"
expect 1 "a shard reported twice" 80 "Shard 1 of 3 reported twice"
rm -rf "$shards/copy"
echo "one of three" > "$shards/mutants-out-shard-1/shard"
expect 1 "a shard that is not named" 80 "not a shard"

reset
expect 1 "no shard" 80 "No shard reported a result."
rmdir "$shards"
expect 1 "no directory of shards" 80 "No shard reported a result."
reset

shard 0 1 0 5 0 0 0
expect 2 "a threshold that is not a percentage" eighty "threshold"
expect 2 "a threshold above 100" 101 "threshold"
code=0
bash "$here/mutants-summary.sh" 80 > /dev/null 2>&1 || code=$?
if [ "$code" -eq 2 ]; then echo "ok: no directory given"; else
  echo "FAIL: no directory given: exit code $code, expected 2" >&2
  failures=$((failures + 1))
fi

shard 0 1 2 0 600 0 0
expect 1 "a long list is cut" 80 "| Missed | 600 |" "crates/sigillum-cms/src/s0.rs:500:5:" \
  "!crates/sigillum-cms/src/s0.rs:501:5:" "100 more in missed.txt of the artefacts"

if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed" >&2
  exit 1
fi
echo "every case passed"
