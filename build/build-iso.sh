#!/bin/bash
# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
# Build a VyOS ISO that includes the .debs from build/out (our VPP build with
# l2tvpp). vyos-build picks up any .deb placed in its packages/ directory.
#
#   /path/to/l2tvpp/build/build-iso.sh [vyos-build-branch]
set -euo pipefail
TTY=$([ -t 0 ] && echo -it || echo -i)

BRANCH="${1:-rolling}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$REPO/build/work"
[ -d "$WORK/vyos-build" ] || { echo "run build-vpp-debs.sh first"; exit 1; }
ls "$REPO"/build/out/*.deb >/dev/null 2>&1 || { echo "no debs in build/out"; exit 1; }

mkdir -p "$WORK/vyos-build/packages"
cp "$REPO"/build/out/*.deb "$WORK/vyos-build/packages/"

# bake the l2tvpp VPP-plugin-enable hook into the image build
install -m 0755 "$REPO"/build/vyos-hooks/*.chroot \
  "$WORK/vyos-build/data/live-build-config/hooks/live/"

# bake the sync daemon + its systemd unit into the image rootfs
INC="$WORK/vyos-build/data/live-build-config/includes.chroot"
install -d "$INC/usr/libexec/l2tvpp" "$INC/lib/systemd/system"
install -m 0755 "$REPO"/syncd/l2tvppd.py "$INC/usr/libexec/l2tvpp/l2tvppd.py"
install -m 0644 "$REPO"/build/vyos-image/l2tvppd.service "$INC/lib/systemd/system/l2tvppd.service"

docker run --rm $TTY -v "$WORK/vyos-build:/vyos" -w /vyos --privileged \
  "vyos/vyos-build:$BRANCH" \
  bash -c 'sudo make clean && sudo ./build-vyos-image generic --architecture amd64 --build-by l2tvpp --build-type release --version "$(date +%Y%m%d)-l2tvpp"'

ls -la "$WORK"/vyos-build/build/*.iso
