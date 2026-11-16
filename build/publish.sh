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
# The upload needs scp and `cat` over ssh on the download host, nothing
# else (the DGW mirror has no rsync). A folder that went up gets a
# .published marker and is skipped from then on. The public URL is filled
# into the release notes at upload time: a build without PUBLISH_URL writes
# them with the placeholder <download-url>.
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

SSHOPT=(-o BatchMode=yes -o ConnectTimeout=20 -o StrictHostKeyChecking=accept-new)
case "$DEST" in
  *:*) HOST="${DEST%%:*}"; RDIR="${DEST#*:}" ;;
  *)   HOST=""; RDIR="$DEST" ;;         # a local directory (tests)
esac
# copy files or a folder into the destination directory
put() {
  if [ -n "$HOST" ]; then scp -q -r "${SSHOPT[@]}" "$@" "$DEST/"; else cp -r "$@" "$RDIR/"; fi
}
# print the index of the download host; nothing if it has none yet
get_index() {
  if [ -n "$HOST" ]; then
    ssh "${SSHOPT[@]}" "$HOST" "cat '$RDIR/vyos-images.md' 2>/dev/null || true"
  else
    cat "$RDIR/vyos-images.md" 2>/dev/null || true
  fi
}
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
  if ! put "$DIR"; then
    echo "WARNING: upload of $IMAGE/ to $DEST failed - it stays in $DIR and is tried again by the next run"
    rc=1
    continue
  fi
  echo "published: $IMAGE/ to $DEST"
  # the index: fetch it (a new download host has none yet), add this
  # image's line once, send it back with its browser version
  if [ -f "$DIR/$IMAGE-index-line.md" ]; then
    if ! get_index > "$TMP/vyos-images.md"; then
      echo "WARNING: could not read the index on ${DEST%%:*} - $IMAGE is uploaded but not in the index, next run tries again"
      rc=1
      continue
    fi
    if ! grep -qF "[$IMAGE]($IMAGE/)" "$TMP/vyos-images.md"; then
      cat "$DIR/$IMAGE-index-line.md" >> "$TMP/vyos-images.md"
    fi
    python3 "$REPO/build/release-notes.py" --render "$TMP/vyos-images.md" "$TMP/vyos-images.html" \
      --title "DGW VyOS images" >/dev/null || echo "WARNING: could not render vyos-images.html"
    if put "$TMP"/vyos-images.*; then
      echo "index: $IMAGE in vyos-images.md and vyos-images.html"
    else
      echo "WARNING: could not update the index on ${DEST%%:*} - next run tries again"
      rc=1
      continue
    fi
  fi
  echo "$DEST $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$DIR/.published"
done
exit $rc
