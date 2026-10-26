#!/bin/bash
# Runs a command in the development image, with the worktree mounted at
# /work. The image is built first when it does not exist yet.
#
#   tools/dev-image/run.sh [--offline] [--platform linux/amd64|linux/arm64] [--] <command> [<argument>...]
#
# --offline runs the command without network, as the workflows run the
# checks that must work offline. Fetch what it needs first, for example
# with `tools/dev-image/run.sh cargo fetch --locked`.
#
# --platform selects the architecture, by default that of the host. The
# workflows run on linux/amd64; on another host, that platform is emulated.
set -euo pipefail

offline=false
platform=
while [ $# -gt 0 ]; do
    case "$1" in
        --offline) offline=true; shift ;;
        --platform) platform=${2:?--platform needs a value}; shift 2 ;;
        --) shift; break ;;
        -*) echo "run.sh: unknown option $1" >&2; exit 2 ;;
        *) break ;;
    esac
done
if [ $# -eq 0 ]; then
    echo "usage: tools/dev-image/run.sh [--offline] [--platform <platform>] [--] <command> [<argument>...]" >&2
    exit 2
fi

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(git -C "$here" rev-parse --show-toplevel)
if [ -z "$platform" ]; then
    case "$(uname -m)" in
        x86_64 | amd64) platform=linux/amd64 ;;
        arm64 | aarch64) platform=linux/arm64 ;;
        *) echo "run.sh: unsupported architecture $(uname -m)" >&2; exit 2 ;;
    esac
fi
arch=${platform#linux/}

digest() {
    if command -v sha256sum > /dev/null; then sha256sum; else shasum -a 256; fi | cut -c1-16
}

# The tag changes with every input of the image, so a changed version is never run from an old image.
inputs=$(cat "$here/Dockerfile" "$here/entrypoint.sh" "$here/versions.env" "$root/tools/dss-oracle/pom.xml" | digest)
image="sigillum-dev:$inputs-$arch"

if ! docker image inspect "$image" > /dev/null 2>&1; then
    build_args=()
    while IFS= read -r line; do
        case "$line" in '' | '#'*) continue ;; esac
        build_args+=(--build-arg "$line")
    done < "$here/versions.env"
    docker build --platform "$platform" "${build_args[@]}" \
        --build-context oracle="$root/tools/dss-oracle" \
        --tag "$image" "$here"
fi

# Build outputs stay in volumes, apart from those of the host, one set per worktree and architecture.
# The home volume belongs to one image, which fills it with its Maven
# dependencies when Docker creates it. The mount points are created here
# first, so that Docker does not create them in the worktree as root.
volumes=$(printf '%s' "$root" | digest)-$arch
mkdir -p "$root/target" "$root/tools/dss-oracle/target" "$root/crates/sigillum-testpki/fuzz/target"
options=(
    --rm --init --platform "$platform"
    --env "DEV_IMAGE_UID=$(id -u)" --env "DEV_IMAGE_GID=$(id -g)"
    --volume "$root:/work"
    --volume "sigillum-dev-home-$inputs-$arch:/cache/home"
    --volume "sigillum-dev-target-$volumes:/work/target"
    --volume "sigillum-dev-oracle-$volumes:/work/tools/dss-oracle/target"
    --volume "sigillum-dev-fuzz-$volumes:/work/crates/sigillum-testpki/fuzz/target"
)
if [ "$offline" = true ]; then
    options+=(--network none --env CARGO_NET_OFFLINE=true)
fi
if [ -t 0 ] && [ -t 1 ]; then
    options+=(--interactive --tty)
fi

exec docker run "${options[@]}" "$image" "$@"
