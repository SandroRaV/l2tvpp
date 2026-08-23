#!/bin/bash
# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
#
# Clean plugin build + make test in a throwaway container from the base
# image. Run as often as you like; nothing persists between runs except the
# log copied to build/ci-logs/.
#
#   /path/to/l2tvpp/build/ci-test.sh              # build + test
#   /path/to/l2tvpp/build/ci-test.sh shell        # drop into the container instead
#
# First time: build the base image (30-60 min):
#   docker build -f /path/to/l2tvpp/build/Dockerfile.base -t l2tvpp-base:2510 /path/to/l2tvpp/build/
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${L2TVPP_BASE_IMAGE:-l2tvpp-base:2510}"
LOGDIR="$REPO/build/ci-logs"
mkdir -p "$LOGDIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
GITREV="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo nogit)"

# make test starts real VPP processes: needs /dev/shm space and, on some
# kernels, extra capabilities. --privileged is the pragmatic choice for a CI box.
DOCKER_RUN=(docker run --rm --privileged --shm-size=2g
            -v "$REPO:/src:ro"
            -e VPP_TEST_FAILED_DIR=/tmp/vpp-failed
            "$IMAGE")

if [ "${1:-}" = "shell" ]; then
  "${DOCKER_RUN[@]:0:${#DOCKER_RUN[@]}-1}" -it "$IMAGE" bash
  exit
fi

"${DOCKER_RUN[@]}" bash -c '
  set -euo pipefail
  cd /vpp
  rm -rf src/plugins/l2tvpp
  cp -r /src/plugin/l2tvpp src/plugins/l2tvpp
  mkdir -p src/plugins/l2tvpp/test
  cp /src/test/test_l2tvpp.py src/plugins/l2tvpp/test/
  echo "== build (incremental, plugin only)"
  make build
  echo "== checkstyle"
  make checkstyle-all 2>/dev/null || extras/scripts/checkstyle.sh || true
  echo "== test"
  make test TEST=test_l2tvpp V=1
' 2>&1 | tee "$LOGDIR/$STAMP-$GITREV.log"

echo "log: $LOGDIR/$STAMP-$GITREV.log"
