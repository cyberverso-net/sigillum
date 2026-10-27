#!/usr/bin/env bash
# Tests check-dependabot-lists.sh: it passes on the repository as it is, and
# fails on each kind of mismatch that it checks. Each case runs on a copy of
# dependabot.yml and of the Maven build files. Requires yq 4.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

copy() {
  rm -rf "$scratch/repo"
  mkdir -p "$scratch/repo/.github/scripts"
  cp "$here/check-dependabot-lists.sh" "$scratch/repo/.github/scripts/"
  cp "$root/.github/dependabot.yml" "$scratch/repo/.github/"
  (cd "$root" && find . -name pom.xml -not -path '*/target/*' -not -path './.git/*') |
    while read -r pom; do
      mkdir -p "$scratch/repo/$(dirname "$pom")"
      cp "$root/$pom" "$scratch/repo/$pom"
    done
}

# Runs the check on the copy, keeps its output and returns its exit code.
check() {
  local code=0
  (cd "$scratch/repo" && bash .github/scripts/check-dependabot-lists.sh) > "$scratch/output" 2>&1 || code=$?
  return "$code"
}

failures=0
# expect <exit code> <name> [<text the output must contain>...]
expect() {
  local wanted=$1 name=$2 code=0 text
  shift 2
  check || code=$?
  if [ "$code" -ne "$wanted" ]; then
    echo "FAIL: $name: exit code $code, expected $wanted" >&2
    sed 's/^/  /' "$scratch/output" >&2
    failures=$((failures + 1))
    return
  fi
  for text in "$@"; do
    if ! grep -qF -- "$text" "$scratch/output"; then
      echo "FAIL: $name: the output does not contain: $text" >&2
      sed 's/^/  /' "$scratch/output" >&2
      failures=$((failures + 1))
      return
    fi
  done
  echo "ok: $name"
}

# Applies a yq expression to the copy of dependabot.yml, and fails the test when it changes nothing.
mutate() {
  # yq rewrites the quoting of some values, so the contents are compared as JSON.
  local file=$scratch/repo/.github/dependabot.yml before
  before=$(yq -o=json '.' "$file")
  yq -i "$1" "$file"
  if [ "$before" = "$(yq -o=json '.' "$file")" ]; then
    echo "FAIL: the mutation $1 changes nothing" >&2
    failures=$((failures + 1))
  fi
}

cargo='.updates[] | select(."package-ecosystem" == "cargo")'
maven='.updates[] | select(."package-ecosystem" == "maven")'

copy
expect 0 "the repository as it is"

copy
mutate "($cargo | .ignore[] | select(.\"dependency-name\" == \"der\") | .\"dependency-name\") = \"not-a-crate\""
expect 1 "an ignore rule outside the RustCrypto group" \
  "only in the group: der" "only in the ignore rules: not-a-crate"

copy
mutate "($cargo | .groups.\"rustcrypto-dalek\".patterns) += [\"der\"]"
expect 1 "a crate listed twice in the RustCrypto group" "Listed twice in the group: der"

copy
mutate "del(.updates[] | select(.\"package-ecosystem\" == \"maven\"))"
expect 1 "no Maven entry" "Expected exactly one maven entry"

copy
mutate "del($maven | .groups.dss)"
expect 1 "no dss group" "No dss group"

copy
mutate "($maven | .groups.dss.patterns) = [\"eu.europa.ec.joinup.sd-dss:dss-validation\"]"
expect 1 "a dss group without every DSS artefact" "eu.europa.ec.joinup.sd-dss:*"

copy
mutate "del($maven | .groups.\"maven-routine\".\"exclude-patterns\")"
expect 1 "DSS artefacts not excluded from the routine group" \
  "not excluded from the maven-routine group: eu.europa.ec.joinup.sd-dss:*"

copy
mkdir -p "$scratch/repo/tools/measurements/dss"
cp "$scratch/repo/tools/dss-oracle/pom.xml" "$scratch/repo/tools/measurements/dss/pom.xml"
expect 1 "a Maven build that the Maven entry does not list" \
  "pom.xml not listed in the Maven entry: /tools/measurements/dss"

copy
mkdir -p "$scratch/repo/tools/measurements/dss"
cp "$scratch/repo/tools/dss-oracle/pom.xml" "$scratch/repo/tools/measurements/dss/pom.xml"
mutate "($maven | .directories) += [\"/tools/measurements/dss\"]"
expect 0 "a second Maven build listed in the Maven entry"

copy
mutate "($maven | .directories) += [\"/tools/measurements/dss\"]"
expect 1 "a listed directory without pom.xml" \
  "listed in the Maven entry without pom.xml: /tools/measurements/dss"

if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed." >&2
  exit 1
fi
echo "All cases passed."
