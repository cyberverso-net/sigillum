#!/usr/bin/env bash
# Tests fuzz-minimise.sh with a stand-in for cargo, which records its
# arguments and acts as `cargo fuzz cmin` would in each case: it minimises
# the corpus, fails, prints the message with which cargo fuzz reports a
# failed minimisation while exiting with 0, writes a crash or timeout input
# to the artefacts of the target, reports a crash only in its output, or
# loses an inner merge process without any report, as when it is killed.
# Every case but the first must fail the script and leave the corpus as it
# was before the minimisation, with the input that fails. The script is run as the
# workflow runs it, so that it must be executable.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

mkdir -p "$scratch/bin"
cat > "$scratch/bin/cargo" <<'EOF'
#!/usr/bin/env bash
echo "$*" > "$FAKE_ARGUMENTS"
corpus=corpus/target_a
case "$FAKE_CMIN" in
  minimise)
    rm -f "$corpus/b" "$corpus/c"
    echo "MERGE-OUTER: attempt 1"
    echo "MERGE-OUTER: successful in 1 attempt(s)"
    echo "MERGE-OUTER: 1 new files with 3 new features added" ;;
  killed-worker)
    # An inner process killed by a signal writes no input and no report;
    # the outer merge starts another one, which skips the input.
    rm -f "$corpus/b"
    echo "MERGE-OUTER: attempt 1"
    echo "MERGE-OUTER: attempt 2"
    echo "MERGE-INNER: '$corpus/b' caused a failure at the previous merge step"
    echo "MERGE-OUTER: successful in 2 attempt(s)" ;;
  exit-code)
    echo "error: could not compile" >&2
    exit 101 ;;
  failed-message)
    echo "Failed to minimize corpus: exit status: 1" ;;
  crash-artefact)
    # libFuzzer leaves out the input that fails, and cargo fuzz replaces the corpus.
    rm -f "$corpus/b"
    mkdir -p artifacts/target_a
    printf 'x' > artifacts/target_a/crash-0123456789abcdef
    echo "MERGE-OUTER: attempt 2" ;;
  timeout-artefact)
    mkdir -p artifacts/target_a
    printf 'y' > artifacts/target_a/timeout-0123456789abcdef
    echo "MERGE-OUTER: attempt 2" ;;
  crash-in-output)
    echo "==1234== ERROR: libFuzzer: deadly signal" >&2
    echo "MERGE-OUTER: attempt 2" ;;
esac
EOF
chmod +x "$scratch/bin/cargo"

failures=0
# expect <exit code> <case> [<text the output must contain>]
expect() {
  local wanted=$1 name=$2 text=${3:-} code=0
  rm -rf "$scratch/project"
  mkdir -p "$scratch/project/corpus/target_a"
  printf a > "$scratch/project/corpus/target_a/a"
  printf b > "$scratch/project/corpus/target_a/b"
  printf c > "$scratch/project/corpus/target_a/c"
  (cd "$scratch/project" && env PATH="$scratch/bin:$PATH" FAKE_CMIN="$name" \
    FAKE_ARGUMENTS="$scratch/arguments" RUST_NIGHTLY=nightly-2000-01-01 FUZZ_TIMEOUT=60 \
    RUNNER_TEMP="$scratch" "$here/fuzz-minimise.sh" target_a) > "$scratch/output" 2>&1 || code=$?
  if [ "$code" -ne "$wanted" ]; then
    echo "FAIL: $name: exit code $code, expected $wanted" >&2
    sed 's/^/  /' "$scratch/output" >&2
    failures=$((failures + 1))
  elif [ -n "$text" ] && ! grep -qF -- "$text" "$scratch/output"; then
    echo "FAIL: $name: the output does not contain: $text" >&2
    sed 's/^/  /' "$scratch/output" >&2
    failures=$((failures + 1))
  elif [ "$wanted" -ne 0 ] && [ "$(cd "$scratch/project/corpus/target_a" && find . -type f | sort | tr '\n' ' ')" != "./a ./b ./c " ]; then
    echo "FAIL: $name: the corpus was not restored" >&2
    failures=$((failures + 1))
  else
    echo "ok: $name"
  fi
}

expect 0 minimise "The corpus went from 3 to 1 inputs."
wanted="+nightly-2000-01-01 fuzz cmin --fuzz-dir . target_a corpus/target_a -- -timeout=60"
if [ "$(cat "$scratch/arguments")" = "$wanted" ]; then
  echo "ok: the arguments of cargo fuzz cmin"
else
  echo "FAIL: cargo was called with: $(cat "$scratch/arguments"), expected: $wanted" >&2
  failures=$((failures + 1))
fi
expect 1 exit-code "exited with 101"
expect 1 failed-message "Failed to minimize corpus"
expect 1 crash-artefact "artifacts/target_a/crash-0123456789abcdef"
expect 1 timeout-artefact "artifacts/target_a/timeout-0123456789abcdef"
expect 1 crash-in-output "reported a finding"
expect 1 killed-worker "an inner merge process failed"

if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed" >&2
  exit 1
fi
echo "every case passed"
