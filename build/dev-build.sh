#!/bin/bash
# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
#
# Fast development loop: plain upstream VPP tree at the branch VyOS uses
# (stable/2510), plugin symlinked in, debug build, make test. No docker, no
# VyOS patches; use build-vpp-debs.sh for the box-identical build.
#
#   /path/to/l2tvpp/build/dev-build.sh            # clone + deps + build + test
#   /path/to/l2tvpp/build/dev-build.sh test       # rebuild + test only
#
# Debian 12/13 host, ~20 min first run, needs sudo for install-dep.
# Output goes to the shell AND build/ci-logs/dev-build-<timestamp>.log.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
VPP="${VPP_DIR:-$REPO/build/work/vpp}"
BRANCH="${VPP_BRANCH:-stable/2510}"

if [ ! -d "$VPP" ]; then
  git clone -b "$BRANCH" --single-branch https://github.com/FDio/vpp "$VPP"
  (cd "$VPP" && make UNATTENDED=yes install-dep install-ext-deps)
fi
ln -sfn "$REPO/plugin/l2tvpp" "$VPP/src/plugins/l2tvpp"
mkdir -p "$REPO/plugin/l2tvpp/test"
ln -sfn "$REPO/test/test_l2tvpp.py" "$REPO/plugin/l2tvpp/test/test_l2tvpp.py"

# Everything below is also written to build/ci-logs/dev-build-<timestamp>.log
LOGDIR="$REPO/build/ci-logs"; mkdir -p "$LOGDIR"
LOG="$LOGDIR/dev-build-$(date +%Y%m%d-%H%M%S).log"
echo "log: $LOG"
cd "$VPP"
{
  make build
  make test TEST=test_l2tvpp V=1
} 2>&1 | tee "$LOG"
