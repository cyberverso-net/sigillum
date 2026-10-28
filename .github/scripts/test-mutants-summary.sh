#!/usr/bin/env bash
# Tests mutants-summary.sh: the score, the result against the threshold,
# the lists of missed mutants and timeouts, and the failures of cargo
# mutants itself. Each case runs on a mutants.out directory written here,
# in the format that cargo-mutants 27.1.0 writes. Requires jq.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# outcomes <caught> <missed> <timeout> <unviable> [<baseline summary>]
# Writes mutants.out with these counts. The missed and timed out mutants
# are listed in missed.txt and timeout.txt, one per line.
outcomes() {
  local caught=$1 missed=$2 timeout=$3 unviable=$4 baseline=${5:-Success} i
  rm -rf "$scratch/mutants.out"
  mkdir -p "$scratch/mutants.out"
  cat > "$scratch/mutants.out/outcomes.json" << EOF
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
  : > "$scratch/mutants.out/missed.txt"
  : > "$scratch/mutants.out/timeout.txt"
  for ((i = 1; i <= missed; i++)); do
    echo "crates/sigillum-cms/src/lib.rs:$i:5: replace parse -> bool with true" >> "$scratch/mutants.out/missed.txt"
  done
  for ((i = 1; i <= timeout; i++)); do
    echo "crates/sigillum-cms/src/lib.rs:$((100 + i)):9: replace < with <= in decode" >> "$scratch/mutants.out/timeout.txt"
  done
}

failures=0
# expect <wanted exit code> <name> <cargo mutants exit code> <threshold> [<text the output must contain>...]
# A text that starts with ! must not be in the output.
expect() {
  local wanted=$1 name=$2 status=$3 threshold=$4 code=0 text
  shift 4
  bash "$here/mutants-summary.sh" "$status" "$scratch/mutants.out" "$threshold" > "$scratch/output" 2>&1 || code=$?
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

outcomes 10 0 0 2
expect 0 "every mutant caught" 0 80 "| Caught | 10 |" "| Unviable | 2 |" "| Score | 100.0% |" \
  "The score meets the threshold of 80%." "No mutant was missed." "!replace parse"

outcomes 8 2 0 0
expect 0 "a score equal to the threshold" 2 80 "| Missed | 2 |" "| Score | 80.0% |" \
  "The score meets the threshold of 80%." "crates/sigillum-cms/src/lib.rs:2:5: replace parse -> bool with true"

outcomes 7 3 0 5
expect 1 "a score below the threshold" 2 80 "| Score | 70.0% |" \
  "The score is below the threshold of 80%." "crates/sigillum-cms/src/lib.rs:3:5: replace parse -> bool with true"

# Unviable mutants are left out of the score, timeouts count as not caught.
outcomes 8 0 2 9
expect 0 "timeouts count as not caught" 3 80 "| Timeouts | 2 |" "| Score | 80.0% |" \
  "crates/sigillum-cms/src/lib.rs:102:9: replace < with <= in decode"
outcomes 7 0 3 0
expect 1 "timeouts below the threshold" 3 80 "| Score | 70.0% |" "The score is below the threshold of 80%."

outcomes 2 1 0 0
expect 1 "a score rounded down" 2 67 "| Score | 66.6% |" "The score is below the threshold of 67%."
expect 0 "a score just above the threshold" 2 66 "| Score | 66.6% |" "The score meets the threshold of 66%."

outcomes 0 0 0 4
expect 0 "only unviable mutants" 0 80 "No viable mutant" "!| Score |"

rm -rf "$scratch/mutants.out"
expect 0 "no mutant in the diff" 0 80 "No mutant of the critical modules overlaps the diff."

outcomes 5 0 0 0 Failure
expect 1 "a baseline that fails" 4 80 "The tests fail without any mutation" "!| Score |"
expect 1 "a failing baseline in outcomes.json" 0 80 "The tests fail without any mutation"

outcomes 5 0 0 0
expect 1 "a diff that does not match the tree" 5 80 "exit code 5"
expect 1 "a diff that cannot be read" 6 80 "exit code 6"
expect 1 "a usage error" 1 80 "exit code 1"
expect 1 "an internal error" 70 80 "exit code 70"

rm -rf "$scratch/mutants.out"
expect 1 "no outcomes after a run with missed mutants" 2 80 "no outcomes.json"

outcomes 5 0 0 0
expect 2 "a threshold that is not a percentage" 0 eighty "threshold"
expect 2 "a threshold above 100" 0 101 "threshold"
expect 2 "an exit code that is not a number" x 80 "exit code"

outcomes 0 600 0 0
expect 1 "a long list is cut" 2 80 "| Missed | 600 |" "crates/sigillum-cms/src/lib.rs:500:5:" \
  "!crates/sigillum-cms/src/lib.rs:501:5:" "100 more in missed.txt of the artefact"

if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed" >&2
  exit 1
fi
echo "every case passed"
