#!/bin/bash
# Copyright (c) 2026 Sandro (ravana.me)
# SPDX-License-Identifier: Apache-2.0
# Build a VyOS ISO that includes the .debs from build/out (our VPP build with
# l2tp2). vyos-build picks up any .deb placed in its packages/ directory.
#
#   /path/to/lns-vpp/build/build-iso.sh [vyos-build-branch]
set -euo pipefail

BRANCH="${1:-current}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$REPO/build/work"
[ -d "$WORK/vyos-build" ] || { echo "run build-vpp-debs.sh first"; exit 1; }
ls "$REPO"/build/out/*.deb >/dev/null 2>&1 || { echo "no debs in build/out"; exit 1; }

mkdir -p "$WORK/vyos-build/packages"
cp "$REPO"/build/out/*.deb "$WORK/vyos-build/packages/"

docker run --rm -it -v "$WORK/vyos-build:/vyos" -w /vyos --privileged \
  "vyos/vyos-build:$BRANCH" \
  bash -c 'sudo make clean && sudo ./build-vyos-image generic --architecture amd64 --build-by lns-vpp --build-type release --version "$(date +%Y%m%d)-l2tp2"'

ls -la "$WORK"/vyos-build/build/*.iso
