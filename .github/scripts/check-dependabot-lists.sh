#!/usr/bin/env bash
# Checks a Dependabot configuration:
# - the ignore rules of the Cargo entry name the crates of the Cargo group
#   and the crates updated on their own, each once (ADR-0011, ADR-0025);
# - no crate updated on its own is in the Cargo group;
# - the Maven entry lists every directory that holds a pom.xml, under the
#   current directory, and no other, so that every Maven build is watched;
# - its dss group takes every DSS artefact, and the maven-routine group
#   excludes each pattern of the dss group, so that a DSS update never
#   arrives as a routine update.
# Run it from the root of the repository. Requires yq 4.
set -euo pipefail

file="${1:-.github/dependabot.yml}"

# ADR-0025, rule 2: cms and rsa are pinned to release candidates and leave
# the rustcrypto-dalek group, so that each new release arrives in its own
# pull request. They keep their ignore rules. Change this list together
# with the group and the ignore rules of dependabot.yml.
individual='cms
rsa'

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

individual_set=$(printf '%s\n' "$individual" | sort -u)
grouped_individual=$(comm -12 <(printf '%s\n' "$group" | sort -u) <(echo "$individual_set") | sed '/^$/d')
if [ -n "$grouped_individual" ]; then
  while read -r crate; do
    echo "Updated on its own, but listed in the rustcrypto-dalek group: $crate"
  done <<< "$grouped_individual"
  status=1
fi

expected_set=$(printf '%s\n' "$group" "$individual" | sort -u)
ignored_set=$(printf '%s\n' "$ignored" | sort -u)
if [ "$expected_set" != "$ignored_set" ]; then
  echo "The rustcrypto-dalek group with the crates updated on their own, and the ignore rules in $file, differ:"
  comm -23 <(echo "$expected_set") <(echo "$ignored_set") | sed '/^$/d; s/^/  only in the group or updated on its own: /'
  comm -13 <(echo "$expected_set") <(echo "$ignored_set") | sed '/^$/d; s/^/  only in the ignore rules: /'
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "The ignore rules name the $(printf '%s\n' "$group" | wc -l | tr -d ' ') crates of the group and the $(echo "$individual_set" | wc -l | tr -d ' ') crates updated on their own."
fi

entries=$(yq '[.updates[] | select(."package-ecosystem" == "maven")] | length' "$file")
if [ "$entries" != "1" ]; then
  echo "Expected exactly one maven entry in $file, found $entries."
  exit 1
fi

maven='.updates[] | select(."package-ecosystem" == "maven")'
dss_all='eu.europa.ec.joinup.sd-dss:*'
maven_status=0

dss=$(yq "$maven | .groups.dss.patterns // [] | .[]" "$file" | sort -u)
if [ -z "$dss" ]; then
  echo "No dss group found in the maven entry of $file."
  maven_status=1
elif ! grep -qxF -- "$dss_all" <<< "$dss"; then
  echo "The dss group of $file must have the pattern $dss_all."
  maven_status=1
fi

routine_excluded=$(yq "$maven | .groups.\"maven-routine\".\"exclude-patterns\" // [] | .[]" "$file" | sort -u)
if [ -n "$dss" ]; then
  missing=$(comm -23 <(echo "$dss") <(echo "$routine_excluded") | sed '/^$/d')
  if [ -n "$missing" ]; then
    while read -r pattern; do
      echo "Pattern of the dss group not excluded from the maven-routine group: $pattern"
    done <<< "$missing"
    maven_status=1
  fi
fi

listed=$(yq "$maven | [.directory] + (.directories // []) | .[] | select(. != null)" "$file" | sed 's#^\([^/]\)#/\1#; s#\(.\)/$#\1#' | sort -u)
found=$(find . -name pom.xml -not -path '*/target/*' -not -path './.git/*' |
  sed 's#^\./##; s#/\{0,1\}pom\.xml$##; s#^#/#' | sort -u)
comm -13 <(echo "$listed") <(echo "$found") | sed '/^$/d; s/^/pom.xml not listed in the Maven entry: /'
comm -23 <(echo "$listed") <(echo "$found") | sed '/^$/d; s/^/Directory listed in the Maven entry without pom.xml: /'
if [ "$listed" != "$found" ]; then
  maven_status=1
fi

if [ "$maven_status" -eq 0 ]; then
  echo "The Maven entry lists every directory with a pom.xml ($(printf '%s\n' "$found" | wc -l | tr -d ' ') in all), and the routine group excludes the dss group."
else
  status=1
fi
exit "$status"
