#!/usr/bin/env bash
# Reports a run of cargo mutants in shards as Markdown on standard output,
# for the job summary: the counts of each outcome, the mutation score, the
# result against the threshold, the missed and timed out mutants, and the
# problems: shards that did not complete, and mutants of another outcome.
#
# Usage: mutants-summary.sh <threshold> <directory of shards>
#
# Each subdirectory of <directory of shards> is the mutants.out directory
# of cargo-mutants 27.1.0 of one shard, with two files that mutants.yml
# adds: shard, which holds <index>/<count>, and exit-status, which holds
# the exit code of cargo mutants. The count of shards comes from these
# files, so a shard that left no directory is still noticed.
#
# The score is the share of caught mutants among those that the tests
# ran against: caught / (caught + missed + timeouts). A timeout counts as
# not caught. Unviable mutants, which do not build, are left out. The score
# is shown rounded down to one decimal place, over the shards that
# completed.
#
# Exits with 0 when every shard completed and the score meets the
# threshold, or no mutant was tested; 1 when the score is below the
# threshold, a shard is missing, failed or ran on a failing baseline, or
# a mutant had another outcome than the four counted;
# 2 on a usage error. Requires jq.
set -euo pipefail

# The number of mutants listed in each list; the artefacts have them all.
max_listed=500

if [ "$#" -ne 2 ]; then
  echo "usage: mutants-summary.sh <threshold> <directory of shards>" >&2
  exit 2
fi
threshold=$1 root=$2
if ! [[ "$threshold" =~ ^[0-9]+$ ]] || [ "$threshold" -gt 100 ]; then
  echo "mutants-summary: the threshold is not a percentage from 0 to 100: $threshold" >&2
  exit 2
fi

echo "## Mutation testing"
echo

problems=()
problem() {
  problems+=("$1")
}

# The shards found, by index, and the count they agree on.
count=
seen=" "
completed=0
with_outcomes=()
dirs=()
if [ -d "$root" ]; then
  for dir in "$root"/*/; do
    [ -d "$dir" ] && dirs+=("${dir%/}")
  done
fi
for dir in ${dirs[@]+"${dirs[@]}"}; do
  name=$(cat "$dir/shard" 2> /dev/null || true)
  if ! [[ "$name" =~ ^([0-9]+)/([0-9]+)$ ]]; then
    problem "$(basename "$dir") is not a shard: its file shard does not hold <index>/<count>."
    continue
  fi
  index=${BASH_REMATCH[1]} total=${BASH_REMATCH[2]}
  if [ -z "$count" ]; then
    count=$total
  elif [ "$total" != "$count" ]; then
    problem "The shards do not agree on their count: $count and $total."
    continue
  fi
  label="Shard $index of $total"
  if [[ "$seen" == *" $index "* ]]; then
    problem "$label reported twice."
    continue
  fi
  seen="$seen$index "
  if [ ! -f "$dir/exit-status" ]; then
    problem "$label has no exit status: cargo mutants did not complete in it."
    continue
  fi
  status=$(cat "$dir/exit-status")
  if ! [[ "$status" =~ ^[0-9]+$ ]]; then
    problem "$label: its exit status is not a number: $status."
    continue
  fi
  # Exit codes of cargo-mutants 27.1.0 (src/exit_code.rs): 0 every mutant
  # caught or nothing to test, 2 missed mutants, 3 timeouts, 4 baseline
  # failed. Every other code is a failure of the run itself.
  case "$status" in
    0 | 2 | 3) ;;
    4)
      problem "$label: the tests fail without any mutation, so its mutants were not tested. The log of the baseline is in \`log/\` of its artefact."
      continue
      ;;
    *)
      problem "$label: cargo mutants failed with exit code $status. Its output is in the log of the job."
      continue
      ;;
  esac
  if [ ! -f "$dir/outcomes.json" ]; then
    # With nothing to test, as when --in-diff matches no mutant or a
    # shard is empty, cargo mutants exits with 0 and writes no outcomes.
    if [ "$status" -ne 0 ]; then
      problem "$label: cargo mutants exited with $status but wrote no outcomes.json."
    else
      completed=$((completed + 1))
    fi
    continue
  fi
  if jq -e '[.outcomes[] | select(.scenario == "Baseline" and .summary != "Success")] | length > 0' \
    "$dir/outcomes.json" > /dev/null; then
    problem "$label: the tests fail without any mutation, so its mutants were not tested. The log of the baseline is in \`log/\` of its artefact."
    continue
  fi
  # A mutant whose outcome is neither of the four counted ones, success
  # or failure in cargo-mutants 27.1.0 (src/outcome.rs), is not in the
  # score: it is reported, and the shard is still counted.
  other=$(jq -r '.total_mutants - (.caught + .missed + .timeout + .unviable)' "$dir/outcomes.json")
  if [ "$other" != 0 ]; then
    problem "$label: $other mutants had an outcome other than caught, missed, timeout or unviable; see outcomes.json in its artefact."
  fi
  completed=$((completed + 1))
  with_outcomes+=("$dir")
done

if [ -z "$count" ]; then
  echo "No shard reported a result."
  for p in ${problems[@]+"${problems[@]}"}; do
    echo "- $p"
  done
  exit 1
fi
for ((k = 0; k < count; k++)); do
  if [[ "$seen" != *" $k "* ]]; then
    problem "Shard $k of $count reported no result."
  fi
done

# report_problems: the shards that did not complete, if any.
report_problems() {
  local p
  [ "${#problems[@]}" -gt 0 ] || return 0
  echo
  echo "### Problems"
  echo
  echo "The run fails for the reasons below. The counts above cover only the shards that completed."
  echo
  for p in "${problems[@]}"; do
    echo "- $p"
  done
}

result=0
if [ "${#problems[@]}" -gt 0 ]; then
  result=1
fi

if [ "${#with_outcomes[@]}" -eq 0 ]; then
  if [ "$result" -eq 0 ]; then
    echo "No mutant of the critical modules was tested."
  else
    echo "No completed shard tested a mutant."
    report_problems
  fi
  exit "$result"
fi

# total <field>: the sum of one count over the shards.
total() {
  local dir sum=0 n
  for dir in "${with_outcomes[@]}"; do
    n=$(jq -r ".$1" "$dir/outcomes.json")
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
  report_problems
  exit "$result"
fi

permille=$((caught * 1000 / tested))
echo "| Score | $((permille / 10)).$((permille % 10))% |"
echo

if [ $((caught * 100)) -ge $((threshold * tested)) ]; then
  echo "The score meets the threshold of $threshold%."
else
  echo "The score is below the threshold of $threshold%."
  result=1
fi
if [ "$completed" -lt "$count" ]; then
  echo
  echo "$((count - completed)) of $count shards did not complete; see the problems below."
fi

# list <title> <file name>: the mutants of one list over the shards, in a code block.
list() {
  local title=$1 name=$2 dir all lines
  all=$(for dir in "${with_outcomes[@]}"; do
    if [ -f "$dir/$name" ]; then cat "$dir/$name"; fi
  done | grep . || true)
  [ -n "$all" ] || return 0
  lines=$(grep -c . <<< "$all")
  echo
  echo "### $title"
  echo
  echo '````text'
  head -n "$max_listed" <<< "$all"
  echo '````'
  if [ "$lines" -gt "$max_listed" ]; then
    echo
    echo "$((lines - max_listed)) more in $name of the artefacts."
  fi
}

if [ "$missed" -eq 0 ] && [ "$timeout" -eq 0 ]; then
  echo
  echo "No mutant was missed."
fi
list "Missed mutants" missed.txt
list "Timeouts" timeout.txt
report_problems
exit "$result"
