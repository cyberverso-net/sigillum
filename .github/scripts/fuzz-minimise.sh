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
# libFuzzer of libfuzzer-sys 0.4.13). A failed minimisation leaves the
# corpus as it was before; fuzz-nightly.yml then does not save it.
# Usage: fuzz-minimise.sh <target>.
set -euo pipefail

target=$1
: "${RUST_NIGHTLY:?}" "${FUZZ_TIMEOUT:?}"
corpus=corpus/$target
artifacts=artifacts/$target
scratch=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/cmin.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
log=$scratch/log

list_artifacts() {
  if [ -d "$artifacts" ]; then find "$artifacts" -type f | sort; fi
}

before=$(find "$corpus" -type f | wc -l | tr -d ' ')
artifacts_before=$(list_artifacts)
cp -R "$corpus" "$scratch/corpus"

code=0
cargo "+$RUST_NIGHTLY" fuzz cmin --fuzz-dir . "$target" "$corpus" -- "-timeout=$FUZZ_TIMEOUT" 2>&1 \
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
  grep -F 'caused a failure at the previous merge step' "$log" | sed 's/^/::error::/' || true
  echo "::error::During the minimisation, an inner merge process failed"
  failed=1
fi
if [ "$failed" -ne 0 ]; then
  rm -rf "$corpus"
  mv "$scratch/corpus" "$corpus"
  echo "The corpus is left as it was before the minimisation, with $before inputs."
  exit 1
fi
echo "The corpus went from $before to $(find "$corpus" -type f | wc -l | tr -d ' ') inputs."
