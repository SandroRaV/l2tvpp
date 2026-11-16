#!/bin/bash
# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
#
# Upload the image folders that wait in build/iso/ to the download host and
# add them to the index there. Called by build-iso.sh at the end of a build
# and by the CI job publish-images, so an image built while there was no
# download host (or while it was unreachable) goes up later without a
# rebuild.
#
#   /path/to/l2tvpp/build/publish.sh             # every folder not published yet
#
# Destination and public URL are site-specific and not in the repo: the
# environment wins (PUBLISH_DEST=user@host:/dir, PUBLISH_URL=https://...),
# else build/publish.local (gitignored), line 1 = destination, line 2 = URL.
# Without a destination nothing happens and the exit code is 0.
#
# Only rsync is used, in both directions, so the upload account on the
# download host can be limited to its directory (rrsync). A folder that went
# up gets a .published marker and is skipped from then on. The public URL is
# filled into the release notes at upload time: a build without PUBLISH_URL
# writes them with the placeholder <download-url>.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
ISODIR="${ISODIR:-$REPO/build/iso}"
LOCALPUB="$REPO/build/publish.local"
DEST="${PUBLISH_DEST:-}"
URL="${PUBLISH_URL:-}"
[ -z "$DEST" ] && [ -f "$LOCALPUB" ] && DEST=$(sed -n 1p "$LOCALPUB")
[ -z "$URL" ] && [ -f "$LOCALPUB" ] && URL=$(sed -n 2p "$LOCALPUB")

waiting=()
for d in $(ls -dtr "$ISODIR"/vyos-*/ 2>/dev/null); do
  d="${d%/}"
  [ -f "$d/.published" ] && continue
  # a folder without an ISO is not an image (e.g. only the release.json of
  # the previous image, kept for the change list)
  ls "$d"/*.iso >/dev/null 2>&1 || continue
  waiting+=("$d")
done

if [ ${#waiting[@]} -eq 0 ]; then
  echo "nothing to publish in $ISODIR"
  exit 0
fi
if [ -z "$DEST" ]; then
  echo "not published: set PUBLISH_DEST=user@host:/dir or write it to $LOCALPUB"
  printf 'waiting: %s\n' "${waiting[@]}"
  exit 0
fi

RSH="ssh -o BatchMode=yes -o ConnectTimeout=20 -o StrictHostKeyChecking=accept-new"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
rc=0
for DIR in "${waiting[@]}"; do
  IMAGE=$(basename "$DIR")
  if [ -n "$URL" ]; then
    # the notes of a build without PUBLISH_URL carry a placeholder (in the
    # HTML version with escaped brackets)
    sed -i -e "s|<download-url>/|${URL%/}/|g" -e "s|&lt;download-url&gt;/|${URL%/}/|g" \
      "$DIR"/*-release-notes.md "$DIR"/*-release-notes.html 2>/dev/null || true
  fi
  if ! rsync -a -e "$RSH" --exclude '.published' "$DIR" "$DEST/"; then
    echo "WARNING: upload of $IMAGE/ to $DEST failed - it stays in $DIR and is tried again by the next run"
    rc=1
    continue
  fi
  echo "published: $IMAGE/ to $DEST"
  # the index: fetch it (a new download host has none yet), add this
  # image's line once, send it back with its browser version
  if [ -f "$DIR/$IMAGE-index-line.md" ]; then
    rsync -q -e "$RSH" "$DEST/vyos-images.md" "$TMP/vyos-images.md" 2>/dev/null || : > "$TMP/vyos-images.md"
    if ! grep -qF "[$IMAGE]($IMAGE/)" "$TMP/vyos-images.md"; then
      cat "$DIR/$IMAGE-index-line.md" >> "$TMP/vyos-images.md"
    fi
    python3 "$REPO/build/release-notes.py" --render "$TMP/vyos-images.md" "$TMP/vyos-images.html" \
      --title "DGW VyOS images" >/dev/null || echo "WARNING: could not render vyos-images.html"
    if rsync -q -e "$RSH" "$TMP"/vyos-images.* "$DEST/"; then
      echo "index: $IMAGE in vyos-images.md and vyos-images.html"
    else
      echo "WARNING: could not update the index on ${DEST%%:*}"
      rc=1
    fi
  fi
  echo "$DEST $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$DIR/.published"
done
exit $rc
