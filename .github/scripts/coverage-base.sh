#!/usr/bin/env bash
# Prints the commit that diff-coverage.sh compares HEAD with, for the event
# of the run. Run it in the checkout of the workflow. It reads:
#
#   EVENT       the event name: pull_request, merge_group, push or another
#   GROUP_BASE  for merge_group, the base commit of the merge group
#   BEFORE      for push, the tip of the branch before the push
#
# For a pull request, the checkout is the merge commit of the pull request
# into its base, and the base is its first parent. When there is no base
# to compare with, a push of a new branch or of a commit that is not in
# the history, or another event, it prints HEAD, so that no line counts as
# changed.
#
# Exits with 2 when the base of a pull request or a merge group cannot be
# found.
set -euo pipefail

fail() {
  echo "coverage-base: $1" >&2
  exit 2
}

commit() {
  git rev-parse --quiet --verify "$1^{commit}"
}

case "${EVENT:-}" in
  pull_request)
    git rev-parse --quiet --verify 'HEAD^2' > /dev/null \
      || fail "HEAD is not the merge commit of a pull request"
    commit 'HEAD^1' || fail "the first parent of HEAD cannot be read"
    ;;
  merge_group)
    [ -n "${GROUP_BASE:-}" ] || fail "GROUP_BASE names no commit"
    commit "$GROUP_BASE" || fail "$GROUP_BASE is not a commit of the checkout"
    ;;
  push)
    if [ -n "${BEFORE:-}" ] && commit "$BEFORE"; then
      :
    else
      commit HEAD
    fi
    ;;
  *)
    commit HEAD
    ;;
esac
