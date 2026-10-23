#!/usr/bin/env bash
# Checks that the Cargo group and the ignore rules in a Dependabot
# configuration name the same crates (ADR-0011). Every ignore rule of the
# Cargo entry must therefore belong to the group. Requires yq 4.
set -euo pipefail

file="${1:-.github/dependabot.yml}"

if ! command -v yq >/dev/null || ! yq --version | grep -q ' v4\.'; then
  echo "This check needs yq version 4 (https://github.com/mikefarah/yq)."
  exit 2
fi

entries=$(yq '[.updates[] | select(."package-ecosystem" == "cargo")] | length' "$file")
if [ "$entries" != "1" ]; then
  echo "Expected exactly one cargo entry in $file, found $entries."
  exit 1
fi

cargo='.updates[] | select(."package-ecosystem" == "cargo")'
group=$(yq "$cargo | .groups.\"rustcrypto-dalek\".patterns[]" "$file" | sort)
ignored=$(yq "$cargo | .ignore[].\"dependency-name\"" "$file" | sort)

if [ -z "$group" ]; then
  echo "No rustcrypto-dalek group found in $file."
  exit 1
fi

status=0
for list in group ignored; do
  duplicates=$(printf '%s\n' "${!list}" | uniq -d)
  if [ -n "$duplicates" ]; then
    printf 'Listed twice in the %s: %s\n' "${list/ignored/ignore rules}" "$(echo "$duplicates" | paste -sd ' ' -)"
    status=1
  fi
done

group_set=$(printf '%s\n' "$group" | sort -u)
ignored_set=$(printf '%s\n' "$ignored" | sort -u)
if [ "$group_set" != "$ignored_set" ]; then
  echo "The rustcrypto-dalek group and the ignore rules in $file differ:"
  comm -23 <(echo "$group_set") <(echo "$ignored_set") | sed '/^$/d; s/^/  only in the group: /'
  comm -13 <(echo "$group_set") <(echo "$ignored_set") | sed '/^$/d; s/^/  only in the ignore rules: /'
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "The group and the ignore rules name the same $(printf '%s\n' "$group" | wc -l | tr -d ' ') crates."
fi
exit "$status"
