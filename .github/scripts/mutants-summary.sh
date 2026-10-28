#!/usr/bin/env bash
# Reports a run of cargo mutants as Markdown on standard output, for the
# job summary: the counts of each outcome, the mutation score, the result
# against the threshold, and the missed and timed out mutants.
#
# Usage: mutants-summary.sh <exit code of cargo mutants> <mutants.out> <threshold>
#
# The score is the share of caught mutants among those that the tests
# ran against: caught / (caught + missed + timeouts). A timeout counts as
# not caught. Unviable mutants, which do not build, are left out. The score
# is shown rounded down to one decimal place.
#
# Exits with 0 when the score meets the threshold, or when no mutant was
# tested; 1 when the score is below the threshold, when the tests fail
# without any mutation, or when cargo mutants failed; 2 on a usage error.
# Requires jq.
set -euo pipefail

# The number of mutants listed in each list; the artefact has them all.
max_listed=500

if [ "$#" -ne 3 ]; then
  echo "usage: mutants-summary.sh <exit code of cargo mutants> <mutants.out> <threshold>" >&2
  exit 2
fi
status=$1 out=$2 threshold=$3
if ! [[ "$status" =~ ^[0-9]+$ ]]; then
  echo "mutants-summary: the exit code of cargo mutants is not a number: $status" >&2
  exit 2
fi
if ! [[ "$threshold" =~ ^[0-9]+$ ]] || [ "$threshold" -gt 100 ]; then
  echo "mutants-summary: the threshold is not a percentage from 0 to 100: $threshold" >&2
  exit 2
fi

echo "## Mutation testing"
echo

baseline_failed() {
  echo "The tests fail without any mutation, so no mutant was tested. The log of the baseline is in \`log/\` of the artefact."
  exit 1
}

# Exit codes of cargo-mutants 27.1.0 (src/exit_code.rs): 0 every mutant
# caught or nothing to test, 2 missed mutants, 3 timeouts, 4 baseline
# failed. Every other code is a failure of the run itself.
case "$status" in
  0 | 2 | 3) ;;
  4) baseline_failed ;;
  *)
    echo "cargo mutants failed with exit code $status. Its output is in the log of the job."
    exit 1
    ;;
esac

outcomes=$out/outcomes.json
if [ ! -f "$outcomes" ]; then
  if [ "$status" -eq 0 ]; then
    # With --in-diff, cargo mutants exits with 0 and writes no outcomes
    # when the diff changes no mutable code of the examined files.
    echo "No mutant of the critical modules overlaps the diff."
    exit 0
  fi
  echo "cargo mutants exited with $status but wrote no outcomes.json in $out."
  exit 1
fi

if jq -e '[.outcomes[] | select(.scenario == "Baseline" and .summary != "Success")] | length > 0' "$outcomes" > /dev/null; then
  baseline_failed
fi

caught=$(jq -r '.caught' "$outcomes")
missed=$(jq -r '.missed' "$outcomes")
timeout=$(jq -r '.timeout' "$outcomes")
unviable=$(jq -r '.unviable' "$outcomes")
tested=$((caught + missed + timeout))

echo "| Outcome | Mutants |"
echo "| --- | ---: |"
echo "| Caught | $caught |"
echo "| Missed | $missed |"
echo "| Timeouts | $timeout |"
echo "| Unviable | $unviable |"

if [ "$tested" -eq 0 ]; then
  echo
  echo "No viable mutant: every mutant of the diff fails to build, so there is no score."
  exit 0
fi

permille=$((caught * 1000 / tested))
echo "| Score | $((permille / 10)).$((permille % 10))% |"
echo

if [ $((caught * 100)) -ge $((threshold * tested)) ]; then
  echo "The score meets the threshold of $threshold%."
  result=0
else
  echo "The score is below the threshold of $threshold%."
  result=1
fi

# list <title> <file>: the mutants of one list, in a code block.
list() {
  local title=$1 file=$2 count
  count=$(grep -c . "$file" 2> /dev/null || true)
  [ "${count:-0}" -gt 0 ] || return 0
  echo
  echo "### $title"
  echo
  echo '````text'
  head -n "$max_listed" "$file"
  echo '````'
  if [ "$count" -gt "$max_listed" ]; then
    echo
    echo "$((count - max_listed)) more in $(basename "$file") of the artefact."
  fi
}

if [ "$missed" -eq 0 ] && [ "$timeout" -eq 0 ]; then
  echo
  echo "No mutant was missed."
fi
list "Missed mutants" "$out/missed.txt"
list "Timeouts" "$out/timeout.txt"
exit "$result"
