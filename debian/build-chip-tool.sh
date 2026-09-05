#!/usr/bin/env bash
#
# Fetches connectedhomeip at one tag and builds chip-tool from it.
#
# Everything the build touches lives under the work directory: the checkout,
# Pigweed's environment, the CIPD cache and a HOME of its own. Nothing lands in
# the real home of whoever runs this, and a build in a chroot sees the same
# layout as a build on a desk.
#
# Usage: build-chip-tool.sh <tag> <workdir>

set -euo pipefail

tag=$1
work=$2
src=$work/src
out=$work/out/chip-tool
jobs=$(nproc)

mkdir -p "$work"
started=$(date +%s)

# The checkout. Shallow, one tag, and only the submodules the Linux platform
# needs: the full set is every vendor SDK the project supports and runs to
# many gigabytes nobody here will compile.
#
# Kept between builds when it is already at the tag asked for. A tag is a fixed
# point, so a checkout at it is as good as a fresh one and costs no download.
if [ -d "$src/.git" ]; then
    have=$(git -C "$src" describe --tags --exact-match 2>/dev/null || true)
    if [ "$have" != "$tag" ]; then
        echo "checkout at '$have', not '$tag' - starting over" >&2
        rm -rf "$src"
    fi
fi
if [ ! -d "$src/.git" ]; then
    git clone --depth 1 --branch "$tag" \
        https://github.com/project-chip/connectedhomeip.git "$src"
fi

# HOME first: the submodule script and Pigweed both write user-level state, and
# git's safe.directory check reads the global config.
export HOME=$work/home
export PW_ENVIRONMENT_ROOT=$work/pw-env
export CIPD_CACHE_DIR=$work/cipd-cache
mkdir -p "$HOME" "$PW_ENVIRONMENT_ROOT" "$CIPD_CACHE_DIR"

cd "$src"
python3 scripts/checkout_submodules.py --shallow --platform linux --jobs "$jobs"

# Pigweed's bootstrap: gn, ninja, a Python of its own and zap arrive over CIPD.
# Whether CIPD has every one of them for this architecture is the first thing
# this build proves or disproves, which is why the log is kept verbose.
#
# bootstrap.sh is written for an interactive shell and trips over `set -u`.
set +u
# shellcheck disable=SC1091
source scripts/bootstrap.sh
set -u

# One target, upstream's own script, release flags. gn_build_example.sh
# sources activate.sh itself, so the environment above is what it finds.
scripts/examples/gn_build_example.sh examples/chip-tool "$out" \
    is_debug=false

finished=$(date +%s)
binary=$out/chip-tool
test -x "$binary"

# What was built, in numbers a person can compare against the last time. Ends
# up under /usr/share/doc in the package.
{
    echo "tag=$tag"
    echo "commit=$(git rev-parse HEAD)"
    echo "arch=$(dpkg-architecture -qDEB_HOST_ARCH 2>/dev/null || uname -m)"
    echo "jobs=$jobs"
    echo "build_seconds=$((finished - started))"
    echo "binary_bytes_unstripped=$(stat -c %s "$binary")"
    echo "checkout_bytes=$(du -sb "$src" | cut -f1)"
} > "$work/build-info.txt"
cat "$work/build-info.txt"
