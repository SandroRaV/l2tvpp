#!/bin/bash
# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
# Build the VyOS VPP .debs (stable/2510 + vyos-vpp-patches) WITH the l2tvpp
# plugin inside, using VyOS's own build container so the result matches the
# image. Run on a Linux host with docker, from the l2tvpp repo root:
#
#   /path/to/l2tvpp/build/build-vpp-debs.sh [vyos-build-branch]
#
# Output: /path/to/l2tvpp/build/out/*.deb  (vpp, vpp-plugin-core, ...)
# Takes 30-60 min the first time (full VPP build).
set -euo pipefail
TTY=$([ -t 0 ] && echo -it || echo -i)

BRANCH="${1:-rolling}"
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
docker run --rm $TTY \
  -v "$WORK/vyos-build:/vyos" \
  -v "$REPO:/l2tvpp:ro" \
  -w /vyos/scripts/package-build/vpp \
  --privileged \
  "vyos/vyos-build:$BRANCH" \
  bash -c './build.py'

cp "$WORK"/vyos-build/scripts/package-build/vpp/*.deb "$OUT/"
ls -la "$OUT"
echo "Next: build/build-iso.sh to roll these into a VyOS ISO, or dpkg -i on a running box for a quick test."
