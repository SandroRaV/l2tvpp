#!/bin/bash
# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
# Build a VyOS ISO that includes the .debs from build/out (our VPP build with
# l2tvpp). vyos-build picks up any .deb placed in its packages/ directory.
#
#   /path/to/l2tvpp/build/build-iso.sh [vyos-build-branch]
#
# Result: build/iso/<image>/ with the ISO, <image>-release-notes.md (+ .html
# for the browser), <image>-release.json and <image>.sha256 (written by
# build/release-notes.py), uploaded as one folder to the download host, which
# also gets one line appended to its vyos-images.md index (and
# vyos-images.html re-rendered from it). The vpp-vlan-fast repo's build does
# the same for the two-plugin image with the same script.
# Optional inputs for the notes: RELEASE_NOTES_FILE (free text for the Notes
# section, first line = index line), L2TVPP_REV (source revision when the
# checkout was copied without .git), PUBLISH_URL (public base URL for the
# install line; or line 2 of build/publish.local).
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

# finished images are kept in build/iso/<image>/ below (ISO + release notes),
# because the `make clean` of the next build wipes vyos-build/build/ including
# the previous image; keep the three newest folders (~700M each) plus this
# build so the build host does not fill up.
ISODIR="$REPO/build/iso"
mkdir -p "$ISODIR"
# (ls exits 2 when nothing matches; with pipefail that would abort the script)
{ ls -dt "$ISODIR"/vyos-*/ 2>/dev/null || true; } | tail -n +4 | xargs -r rm -rf
sudo rm -f "$WORK"/vyos-build/build/*.iso

# publish destination and public URL (site-specific, not in the repo): the
# environment wins, else build/publish.local (gitignored), line 1 =
# user@host:/dir, line 2 = https://public-base-url
LOCALPUB="$REPO/build/publish.local"
DEST="${PUBLISH_DEST:-}"
URL="${PUBLISH_URL:-}"
[ -z "$DEST" ] && [ -f "$LOCALPUB" ] && DEST=$(sed -n 1p "$LOCALPUB")
[ -z "$URL" ] && [ -f "$LOCALPUB" ] && URL=$(sed -n 2p "$LOCALPUB")

docker run --rm $TTY -v "$WORK/vyos-build:/vyos" -w /vyos --privileged \
  "vyos/vyos-build:$BRANCH" \
  bash -c 'sudo make clean && sudo ./build-vyos-image generic --architecture amd64 --build-by l2tvpp --build-type release --version "$(date +%Y%m%d-%H%M)-l2tvpp"'

ls -la "$WORK"/vyos-build/build/*.iso
ISO_SRC=$(ls -t "$WORK"/vyos-build/build/vyos-*-l2tvpp-generic-amd64.iso | head -1)
IMAGE=$(basename "$ISO_SRC" -generic-amd64.iso)
DIR="$ISODIR/$IMAGE"
mkdir -p "$DIR"
cp "$ISO_SRC" "$DIR/" && echo "kept a copy in $DIR"

# release notes: diff against the newest earlier image folder that has a *-release.json
PREV=""
for d in $(ls -dt "$ISODIR"/vyos-*/ 2>/dev/null); do
  d="${d%/}"
  [ "$d" = "$DIR" ] && continue
  ls "$d"/*-release.json >/dev/null 2>&1 && PREV="$d" && break
done
python3 "$REPO/build/release-notes.py" --iso "$DIR/$(basename "$ISO_SRC")" \
  --l2tvpp "$REPO" --work "$WORK" \
  ${PREV:+--previous "$PREV"} ${RELEASE_NOTES_FILE:+--notes "$RELEASE_NOTES_FILE"} \
  ${L2TVPP_REV:+--l2tvpp-rev "$L2TVPP_REV"} ${URL:+--url "$URL"} \
  || echo "WARNING: release notes failed - write $DIR/$IMAGE-release-notes.md by hand"

# publish the whole folder (ISO + notes + checksum) to the download host and
# append the image's line to the index there. An upload failure must not fail
# the build - copy by hand then.
if [ -n "$DEST" ]; then
  if scp -r -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$DIR" "$DEST/"; then
    echo "published: $IMAGE/ to $DEST"
    if [ -f "$DIR/$IMAGE-index-line.md" ]; then
      if ssh -o BatchMode=yes "${DEST%%:*}" "cat >> '${DEST#*:}/vyos-images.md' && cat '${DEST#*:}/vyos-images.md'" \
           < "$DIR/$IMAGE-index-line.md" > "$DIR/.vyos-images.md"; then
        echo "index: appended to ${DEST#*:}/vyos-images.md"
        # browser version of the index, rendered from the appended file
        python3 "$REPO/build/release-notes.py" --render "$DIR/.vyos-images.md" "$DIR/.vyos-images.html" --title "DGW VyOS images" >/dev/null \
          && scp -q -o BatchMode=yes "$DIR/.vyos-images.html" "$DEST/vyos-images.html" \
          && echo "index: vyos-images.html re-rendered" \
          || echo "WARNING: could not re-render vyos-images.html on ${DEST%%:*}"
        rm -f "$DIR/.vyos-images.md" "$DIR/.vyos-images.html"
      else
        echo "WARNING: could not append to the index vyos-images.md on ${DEST%%:*}"
      fi
    fi
  else
    echo "WARNING: upload of $IMAGE/ to $DEST failed - copy $DIR by hand"
  fi
else
  echo "not published: set PUBLISH_DEST=user@host:/dir or write it to $LOCALPUB"
fi
