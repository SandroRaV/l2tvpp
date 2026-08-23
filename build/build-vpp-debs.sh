#!/bin/bash
# Build the VyOS VPP .debs (stable/2510 + vyos-vpp-patches) WITH the l2tp2
# plugin inside, using VyOS's own build container so the result matches the
# image. Run on a Linux host with docker, from the lns-vpp repo root:
#
#   /path/to/lns-vpp/build/build-vpp-debs.sh [vyos-build-branch]
#
# Output: /path/to/lns-vpp/build/out/*.deb  (vpp, vpp-plugin-core, ...)
# Takes 30-60 min the first time (full VPP build).
set -euo pipefail

BRANCH="${1:-current}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO/build/out"
WORK="$REPO/build/work"
mkdir -p "$OUT" "$WORK"

if [ ! -d "$WORK/vyos-build" ]; then
  git clone -b "$BRANCH" --single-branch https://github.com/vyos/vyos-build "$WORK/vyos-build"
fi
# Our package.toml replaces the stock one (diff against package.toml.vyos-orig
# to see the single addition).
cp "$REPO/build/package.toml" "$WORK/vyos-build/scripts/package-build/vpp/package.toml"

docker pull "vyos/vyos-build:$BRANCH"
docker run --rm -it \
  -v "$WORK/vyos-build:/vyos" \
  -v "$REPO:/lns-vpp:ro" \
  -w /vyos/scripts/package-build/vpp \
  --privileged \
  "vyos/vyos-build:$BRANCH" \
  bash -c './build.py'

cp "$WORK"/vyos-build/scripts/package-build/vpp/*.deb "$OUT/"
ls -la "$OUT"
echo "Next: build/build-iso.sh to roll these into a VyOS ISO, or dpkg -i on a running box for a quick test."
