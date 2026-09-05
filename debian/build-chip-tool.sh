#!/usr/bin/env bash
#
# Fetches connectedhomeip at one tag and builds the phi Matter sidecar and
# chip-tool from it, in one gn root: adapter/ in this repository, which reaches
# the checkout through two symlinks laid here.
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
out=$work/out
repo=$(cd "$(dirname "$0")/.." && pwd)
root=$repo/adapter
# Parallelism. nproc is right on a build host; on a machine that also runs the
# stack, PHI_CHIP_JOBS caps it - a CHIP translation unit takes the better part
# of a gigabyte to compile.
jobs=${PHI_CHIP_JOBS:-$(nproc)}

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

# --force re-checks out every working tree: a clone interrupted between
# registering a submodule and populating it leaves the commit recorded and the
# directory empty, and a plain update sees nothing to do.
cd "$src"
python3 scripts/checkout_submodules.py --shallow --force --platform linux --jobs "$jobs"
checked_out=$(date +%s)

# Pigweed's bootstrap: gn, ninja, a Python of its own and zap arrive over CIPD.
# Whether CIPD has every one of them for this architecture is the first thing
# this build proves or disproves, which is why the log is kept verbose.
#
# `-p build` limits the pip step to what the code generators need. The
# default is every platform's requirements at once, and the Zephyr and ESP-IDF
# sets pin conflicting versions - that combination does not resolve.
#
# bootstrap.sh is written for an interactive shell and trips over `set -u`.
set +u
# shellcheck disable=SC1091
source scripts/bootstrap.sh -p build
set -u
bootstrapped=$(date +%s)

# The sidecar's gn root sees the checkout as third_party/connectedhomeip and
# borrows the examples' build_overrides, the way chip-tool itself does.
mkdir -p "$root/third_party"
ln -sfn ../../debian/upstream/src "$root/third_party/connectedhomeip"
ln -sfn third_party/connectedhomeip/examples/build_overrides "$root/build_overrides"

# Release flags. This is what upstream's gn_build_example.sh does, spelled out
# because that script hands ninja no job count and this one has to.
gn gen --check --fail-on-unused-args --root="$root" "$out" \
    --args="is_debug=false"
ninja -C "$out" -j "$jobs"

finished=$(date +%s)
binary=$out/chip-tool
test -x "$binary"
test -x "$out/phi_adapter_matter_ipc"

# What was built, in numbers a person can compare against the last time. Ends
# up under /usr/share/doc in the package. The phases are timed separately
# because the checkout and the CIPD cache survive between builds: a rebuild
# spends seconds where the first build spent twenty minutes downloading.
{
    echo "tag=$tag"
    echo "commit=$(git rev-parse HEAD)"
    echo "arch=$(dpkg-architecture -qDEB_HOST_ARCH 2>/dev/null || uname -m)"
    echo "jobs=$jobs"
    echo "checkout_seconds=$((checked_out - started))"
    echo "bootstrap_seconds=$((bootstrapped - checked_out))"
    echo "compile_seconds=$((finished - bootstrapped))"
    echo "build_seconds=$((finished - started))"
    echo "binary_bytes_unstripped=$(stat -c %s "$binary")"
    echo "sidecar_bytes_unstripped=$(stat -c %s "$out/phi_adapter_matter_ipc")"
    echo "checkout_bytes=$(du -sb "$src" | cut -f1)"
} > "$work/build-info.txt"
cat "$work/build-info.txt"
