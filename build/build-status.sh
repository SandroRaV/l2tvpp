#!/bin/bash
# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
# Show where the current l2tvpp deb+ISO build is in its timeline. Parses the
# newest /home/sandro/l2tvpp-build-*.log on the build box (the log the build
# chain writes), so it works while a build runs and after it finished.
#
#   /Users/sandro/Nextclouds/cl0ud/04_AI/01_claude/l2tvpp/build/build-status.sh      # one shot
#   /Users/sandro/Nextclouds/cl0ud/04_AI/01_claude/l2tvpp/build/build-status.sh -w   # refresh every 30 s
#
# The build machine is site-specific and not part of the repo: set
# BUILD_BOX=user@host in the environment, or put the user@host line in
# build/build-box.local (gitignored) next to this script.
set -euo pipefail
LOCALCFG="$(cd "$(dirname "$0")" && pwd)/build-box.local"
BOX="${BUILD_BOX:-}"
[ -z "$BOX" ] && [ -f "$LOCALCFG" ] && BOX=$(head -1 "$LOCALCFG")
[ -n "$BOX" ] || { echo "set BUILD_BOX=user@host or write it to $LOCALCFG" >&2; exit 1; }

show() {
ssh -o BatchMode=yes -o ConnectTimeout=8 "$BOX" 'bash -s' <<'REMOTE'
LOG=$(ls -t "$HOME"/l2tvpp-build-*.log 2>/dev/null | head -1)
[ -n "$LOG" ] || { echo "no /home/sandro/l2tvpp-build-*.log on the box - no build has been started"; exit 1; }

NOW=$(date +%s)
MTIME=$(stat -c %Y "$LOG")
AGE=$((NOW - MTIME))

STARTLINE=$(head -1 "$LOG")
STARTSTR=$(sed -E 's/^build (re)?started //' <<<"$STARTLINE")
STARTE=$(date -d "$STARTSTR" +%s 2>/dev/null || echo "")
if [ -n "$STARTE" ]; then
  EL=$((NOW - STARTE))
  ELAPSED=$(printf '%dh %02dm' $((EL/3600)) $((EL%3600/60)))
else
  ELAPSED="?"
fi

have() { grep -q -m1 -e "$1" "$LOG"; }
last() { tac "$LOG" | grep -m1 -e "$1" || true; }

# highest phase reached (1..6), from the markers each build step writes
P=0
have "Cloning into"                    && P=1
have "build_cmd applying patch"        && P=2
NINJA=$(last '^\[[0-9]\+/[0-9]\+\]')
[ -n "$NINJA" ]                        && P=3
DEBS=$(grep -c "dpkg-deb: building package" "$LOG" || true)
[ "$DEBS" -gt 0 ]                      && P=4
have "Next: build/build-iso.sh"        && P=5
PUBLISHED=$(last '^published: ')
UPFAIL=$(last 'WARNING: upload')
{ [ -n "$PUBLISHED" ] || [ -n "$UPFAIL" ]; } && P=6
FINISHED=$(last '^build finished rc=')

echo "l2tvpp build status - $LOG"
echo "started : $STARTSTR  (elapsed $ELAPSED)"
echo "activity: last log write ${AGE}s ago"
CONT=$(docker ps --filter ancestor=vyos/vyos-build:rolling --format '{{.Status}}' 2>/dev/null | head -1)
[ -n "$CONT" ] && echo "container: vyos/vyos-build:rolling up ($CONT)"
echo

# print one timeline row: box [done|>...|    ], number, name, detail
row() { # rownum name detail
  local n=$1 name=$2 detail=${3:-}
  local box="    "
  if   [ "$n" -lt "$P" ]; then box="done"
  elif [ "$n" -eq "$P" ] && [ -z "$FINISHED" ]; then box=" >> "
  elif [ "$n" -eq "$P" ]; then box="done"
  fi
  printf '[%s] %d. %s%s\n' "$box" "$n" "$name" "${detail:+  ($detail)}"
}

# the live percent is only meaningful while compiling is the active phase;
# afterwards the last ninja line in the log is a trailing [0/1] re-run
NINJADET=""
if [ -n "$NINJA" ] && [ "$P" -eq 3 ]; then
  NM=$(grep -oE '^\[[0-9]+/[0-9]+\]' <<<"$NINJA" | tr -d '[]')
  CUR=${NM%/*}; TOT=${NM#*/}
  [ "$TOT" -gt 0 ] 2>/dev/null && NINJADET="${CUR}/${TOT} targets, $((CUR*100/TOT))%"
fi
LB=$(last '^P: ')

row 1 "VPP source clone (stable/2510)"
row 2 "VyOS patches + l2tvpp plugin"
row 3 "VPP compile" "$NINJADET"
row 4 "deb packaging" "${DEBS:+$DEBS debs}"
row 5 "ISO build (live-build)" "${LB:+last: ${LB:0:60}}"
if [ -n "$PUBLISHED" ]; then
  row 6 "upload to docker02.ravana.me" "OK"
  echo; echo "$PUBLISHED"
elif [ -n "$UPFAIL" ]; then
  row 6 "upload to docker02.ravana.me" "FAILED"
  echo; echo "$UPFAIL"
else
  row 6 "upload to docker02.ravana.me"
fi

echo
if [ -n "$FINISHED" ]; then
  echo "$FINISHED"
else
  echo "current: $(tail -1 "$LOG" | cut -c1-110)"
fi
REMOTE
}

if [ "${1:-}" = "-w" ]; then
  while true; do clear; show || true; sleep 30; done
else
  show
fi
