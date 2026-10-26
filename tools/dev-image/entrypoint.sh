#!/bin/bash
# Runs a command in the development image as the user of the host, given
# by DEV_IMAGE_UID and DEV_IMAGE_GID, so that the files it writes in the
# mounted worktree belong to that user. The cache volumes are given to the
# user first.
set -euo pipefail

uid=${DEV_IMAGE_UID:?DEV_IMAGE_UID is not set}
gid=${DEV_IMAGE_GID:?DEV_IMAGE_GID is not set}

for dir in /cache/home /work/target /work/tools/dss-oracle/target /work/crates/sigillum-testpki/fuzz/target; do
    if [ -d "$dir" ] && [ "$(stat -c %u "$dir")" != "$uid" ]; then
        chown -R "$uid:$gid" "$dir"
    fi
done

exec setpriv --reuid="$uid" --regid="$gid" --clear-groups -- "$@"
