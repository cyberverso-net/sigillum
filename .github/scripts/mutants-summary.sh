#!/usr/bin/env bash
# Reports a run of cargo mutants, in one or more shards, as Markdown on
# standard output, for the job summary: the counts of each outcome, the
# mutation score, the result against the threshold, and the missed and
# timed out mutants.
#
# Usage: mutants-summary.sh <threshold> <shard>...
#
# Each shard is a mutants.out directory of cargo-mutants 27.1.0 that also
# holds the file exit-status, with the exit code of cargo mutants in that
# shard. The counts of the shards are added up.
#
# The score is the share of caught mutants among those that the tests
# ran against: caught / (caught + missed + timeouts). A timeout counts as
# not caught. Unviable mutants, which do not build, are left out. The score
# is shown rounded down to one decimal place.
#
# Exits with 0 when the score meets the threshold, or when no mutant was
# tested; 1 when the score is below the threshold, when the tests fail
# without any mutation, or when cargo mutants failed or left no result;
# 2 on a usage error. Requires jq.
set -euo pipefail

# The number of mutants listed in each list; the artefacts have them all.
max_listed=500

usage() {
  echo "usage: mutants-summary.sh <threshold> <shard>..." >&2
  exit 2
}

[ "$#" -ge 2 ] || usage
threshold=$1
shift
if ! [[ "$threshold" =~ ^[0-9]+$ ]] || [ "$threshold" -gt 100 ]; then
  echo "mutants-summary: the threshold is not a percentage from 0 to 100: $threshold" >&2
  exit 2
fi

echo "## Mutation testing"
echo

baseline_failed() {
  echo "The tests fail without any mutation in $1, so its mutants were not tested. The log of the baseline is in \`log/\` of its artefact."
  exit 1
}

# Checks every shard before anything is counted. Exit codes of
# cargo-mutants 27.1.0 (src/exit_code.rs): 0 every mutant caught or
# nothing to test, 2 missed mutants, 3 timeouts, 4 baseline failed.
# Every other code is a failure of the run itself.
with_outcomes=()
for shard in "$@"; do
  if [ ! -f "$shard/exit-status" ]; then
    echo "The shard $shard left no exit status: cargo mutants did not complete in it."
    exit 1
  fi
  status=$(cat "$shard/exit-status")
  if ! [[ "$status" =~ ^[0-9]+$ ]]; then
    echo "The exit status of the shard $shard is not a number: $status"
    exit 1
  fi
  case "$status" in
    0 | 2 | 3) ;;
    4) baseline_failed "$shard" ;;
    *)
      echo "cargo mutants failed with exit code $status in the shard $shard. Its output is in the log of the job."
      exit 1
      ;;
  esac
  if [ ! -f "$shard/outcomes.json" ]; then
    # With nothing to test, as when --in-diff matches no mutant or a
    # shard is empty, cargo mutants exits with 0 and writes no outcomes.
    if [ "$status" -ne 0 ]; then
      echo "cargo mutants exited with $status but wrote no outcomes.json in the shard $shard."
      exit 1
    fi
    continue
  fi
  if jq -e '[.outcomes[] | select(.scenario == "Baseline" and .summary != "Success")] | length > 0' \
    "$shard/outcomes.json" > /dev/null; then
    baseline_failed "$shard"
  fi
  with_outcomes+=("$shard")
done

if [ "${#with_outcomes[@]}" -eq 0 ]; then
  echo "No mutant of the critical modules was tested."
  exit 0
fi

# total <field>: the sum of one count over the shards.
total() {
  local shard sum=0 n
  for shard in "${with_outcomes[@]}"; do
    n=$(jq -r ".$1" "$shard/outcomes.json")
    sum=$((sum + n))
  done
  echo "$sum"
}

caught=$(total caught)
missed=$(total missed)
timeout=$(total timeout)
unviable=$(total unviable)
tested=$((caught + missed + timeout))

echo "| Outcome | Mutants |"
echo "| --- | ---: |"
echo "| Caught | $caught |"
echo "| Missed | $missed |"
echo "| Timeouts | $timeout |"
echo "| Unviable | $unviable |"

if [ "$tested" -eq 0 ]; then
  echo
  echo "No viable mutant: every mutant fails to build, so there is no score."
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

# list <title> <file name>: the mutants of one list over the shards, in a code block.
list() {
  local title=$1 name=$2 shard all count
  all=$(for shard in "${with_outcomes[@]}"; do
    if [ -f "$shard/$name" ]; then cat "$shard/$name"; fi
  done | grep . || true)
  [ -n "$all" ] || return 0
  count=$(grep -c . <<< "$all")
  echo
  echo "### $title"
  echo
  echo '````text'
  head -n "$max_listed" <<< "$all"
  echo '````'
  if [ "$count" -gt "$max_listed" ]; then
    echo
    echo "$((count - max_listed)) more in $name of the artefacts."
  fi
}

if [ "$missed" -eq 0 ] && [ "$timeout" -eq 0 ]; then
  echo
  echo "No mutant was missed."
fi
list "Missed mutants" missed.txt
list "Timeouts" timeout.txt
exit "$result"
