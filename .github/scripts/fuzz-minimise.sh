#!/usr/bin/env bash
# Minimises the corpus of a fuzz target with `cargo fuzz cmin`, for
# fuzz-nightly.yml. Run it from the fuzz project; the corpus is
# corpus/<target>. RUST_NIGHTLY names the toolchain and FUZZ_TIMEOUT the
# time limit of one input, in seconds.
#
# The minimisation fails, and the script exits with 1, when cargo fuzz
# exits with another code than 0; when it prints "Failed to minimize
# corpus", with which cargo fuzz 0.13.2 reports a failed merge while still
# exiting with 0; when a new crash, leak, timeout or out-of-memory input is
# written to artifacts/<target>/, which happens when an input of the corpus
# makes the merge crash, since libFuzzer then continues without it; when
# the output reports such a finding without an input being written; and
# when an inner merge process failed without any report, as when the kernel
# kills it for its memory. libFuzzer's outer merge then starts another
# inner process, printing "MERGE-OUTER: attempt <n>" with n of 2 or more,
# and that process prints "MERGE-INNER: '<file>' caused a failure at the
# previous merge step" before it skips the file (FuzzerMerge.cpp of the
# libFuzzer of libfuzzer-sys 0.4.13). The check is also positive: a merge
# of a corpus that is not empty fails unless the outer merge printed
# "MERGE-OUTER: successful in <n> attempt(s)", which it prints only when an
# inner process exits with 0; with one input, a killed inner process is
# the only attempt and leaves no other trace. The inputs that an inner
# process did not finish are read from the merge control file, which
# libFuzzer keeps when it is named, and from the output, and copied to
# artifacts/<target>/merge-failure-<file>. A failed minimisation leaves the
# corpus as it was before; fuzz-nightly.yml then does not save it.
# Usage: fuzz-minimise.sh <target>.
set -euo pipefail

target=$1
: "${RUST_NIGHTLY:?}" "${FUZZ_TIMEOUT:?}"
corpus=corpus/$target
artifacts=artifacts/$target
scratch=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/cmin.XXXXXX")
# On every exit but a successful one, from any step, the corpus is put
# back as it was before the minimisation.
restore=0
finish() {
  if [ "$restore" -eq 1 ] && [ -d "$scratch/corpus" ]; then
    rm -rf "$corpus"
    mv "$scratch/corpus" "$corpus"
    echo "The corpus is left as it was before the minimisation, with $before inputs."
  fi
  rm -rf "$scratch"
}
trap finish EXIT
log=$scratch/log
# Kept by libFuzzer when it is named, so that the inputs that an inner
# process started and never finished can be read from it.
control=$scratch/merge-control

list_artifacts() {
  if [ -d "$artifacts" ]; then find "$artifacts" -type f | sort; fi
}

before=$(find "$corpus" -type f | wc -l | tr -d ' ')
artifacts_before=$(list_artifacts)
cp -R "$corpus" "$scratch/corpus"
restore=1

code=0
cargo "+$RUST_NIGHTLY" fuzz cmin --fuzz-dir . "$target" "$corpus" -- \
  "-timeout=$FUZZ_TIMEOUT" "-merge_control_file=$control" 2>&1 \
  | tee "$log" || {
  # With pipefail, a failure of tee alone also ends here, as a failure.
  statuses=("${PIPESTATUS[@]}")
  code=${statuses[0]}
  if [ "$code" -eq 0 ]; then code=1; fi
}

failed=0
if [ "$code" -ne 0 ]; then
  echo "::error::cargo fuzz cmin exited with $code"
  failed=1
fi
if grep -q 'Failed to minimize corpus' "$log"; then
  echo "::error::cargo fuzz cmin reported: Failed to minimize corpus"
  failed=1
fi
new=$(comm -13 <(echo "$artifacts_before") <(list_artifacts) | sed '/^$/d')
if [ -n "$new" ]; then
  while IFS= read -r input; do
    echo "::error::The minimisation found an input that fails: $input"
  done <<< "$new"
  failed=1
fi
if grep -Eq 'ERROR: (libFuzzer|AddressSanitizer|LeakSanitizer|MemorySanitizer|UndefinedBehaviorSanitizer)' "$log"; then
  echo "::error::The output of the minimisation reported a finding"
  failed=1
fi
if grep -Eq 'MERGE-OUTER: attempt ([2-9]|[1-9][0-9]+)$|caused a failure at the previous merge step' "$log"; then
  echo "::error::During the minimisation, an inner merge process failed"
  failed=1
fi
# The positive check: the outer merge prints this line only when an inner
# process exits with 0. When every attempt fails, as when the only inner
# process of a one-input corpus is killed, it still merges what the control
# file holds and exits with 0, printing its summary of new files.
if [ "$before" -gt 0 ] && ! grep -Eq '^MERGE-OUTER: successful in [0-9]+ attempt\(s\)$' "$log"; then
  echo "::error::The merge did not complete: no inner merge process succeeded"
  failed=1
fi

# The inputs that an inner process started and did not finish: in the
# control file, a STARTED line without its FT line, and those that the
# next inner process names. Each is kept with the artefacts, from the copy
# of the corpus, since a process that is killed writes none.
failed_inputs() {
  if [ -s "$control" ]; then
    awk 'NR == 1 { files = $1; next }
         NR == 2 { next }
         NR <= files + 2 { name[NR - 3] = $0; next }
         $1 == "STARTED" { started[$2] = 1 }
         $1 == "FT" { delete started[$2] }
         END { for (id in started) print name[id] }' "$control"
  fi
  sed -n "s/^MERGE-INNER: '\(.*\)' caused a failure at the previous merge step$/\1/p" "$log"
}

if [ "$failed" -ne 0 ]; then
  # A failure of the listing must not hide the failure of the merge.
  failed_inputs | sort -u | while IFS= read -r input; do
    [ -n "$input" ] || continue
    echo "::error::An inner merge process did not finish $input"
    name=$(basename "$input")
    if [ -f "$scratch/corpus/$name" ]; then
      mkdir -p "$artifacts"
      cp "$scratch/corpus/$name" "$artifacts/merge-failure-$name"
    fi
  done || echo "::error::The inputs that the merge did not finish could not all be listed or kept"
  exit 1
fi
restore=0
echo "The corpus went from $before to $(find "$corpus" -type f | wc -l | tr -d ' ') inputs."
