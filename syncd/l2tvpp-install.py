#!/usr/bin/env python3
# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
"""
l2tvpp-install: M1 helper that mirrors the kernel's L2TP/PPP sessions into the
VPP l2tvpp plugin, by hand, through vppctl. This is the "install the session
from the CLI after it comes up in the kernel" step of docs/design.md M1, made
repeatable for 500 sessions. The M2 sync daemon grows out of this file.

Sources of truth on the LNS (VyOS, accel-ppp, kernel pppol2tp):
  /proc/net/pppol2tp      one SESSION block per kernel L2TP/PPP session with
                          peer ip/port, local/peer tunnel id, local/peer
                          session id and (kernel >= 4.17) the pppN interface
  ip -4 addr show pppN    the subscriber's address (the "peer" of the ppp link)

What it programs in VPP (vppctl):
  l2tvpp tunnel  local <lns-ip> peer <lac-ip> local-port <p> peer-port <p> local-tid <t> peer-tid <pt>
  l2tvpp session tunnel <idx> local-sid <s> peer-sid <ps>          -> l2tvppN
  set interface state l2tvppN up
  ip route add <subscriber>/32 via l2tvppN

Usage:
  l2tvpp-install.py list                       show what the kernel has
  l2tvpp-install.py apply  [--dry-run]         install everything not yet in VPP
  l2tvpp-install.py remove [--dry-run]         tear down everything this tool installed
  common options: --local-ip 10.66.0.1 --local-port 1701 --vppctl /usr/bin/vppctl
                  --state /run/l2tvpp-install.json

ACFC/PFC are NOT read from accel-ppp (not exposed); sessions are installed
with both off, so encap always writes FF 03 00 21, which every LAC accepts.
If the LAC sends compressed framing, decap still handles it (node.c).
"""
import argparse
import json
import os
import re
import subprocess
import sys

SESSION_RE = re.compile(
    r"^\s*SESSION\s+'(?P<name>[^']*)',?\s+(?P<peer_ip>[0-9A-Fa-f]{8})/(?P<peer_port>\d+)\s+"
    r"(?P<tid>[0-9A-Fa-f]{4})/(?P<sid>[0-9A-Fa-f]{4})\s+->\s+"
    r"(?P<ptid>[0-9A-Fa-f]{4})/(?P<psid>[0-9A-Fa-f]{4})")
IFACE_RE = re.compile(r"^\s*interface\s+(?P<ifname>\S+)")
PEER_RE = re.compile(r"inet\s+\S+\s+peer\s+(?P<peer>[0-9.]+)/32")


def hex_ip(h):
    v = int(h, 16)
    return "%d.%d.%d.%d" % (v >> 24 & 255, v >> 16 & 255, v >> 8 & 255, v & 255)


def kernel_sessions():
    """Parse /proc/net/pppol2tp into a list of dicts."""
    try:
        text = open("/proc/net/pppol2tp").read()
    except FileNotFoundError:
        sys.exit("/proc/net/pppol2tp missing: l2tp_ppp not loaded or no pppol2tp sessions")
    sessions, cur = [], None
    for line in text.splitlines():
        m = SESSION_RE.match(line)
        if m:
            cur = {
                "name": m.group("name"),
                "peer_ip": hex_ip(m.group("peer_ip")),
                "peer_port": int(m.group("peer_port")),
                "local_tid": int(m.group("tid"), 16),
                "local_sid": int(m.group("sid"), 16),
                "peer_tid": int(m.group("ptid"), 16),
                "peer_sid": int(m.group("psid"), 16),
                "ifname": None,
                "subscriber": None,
            }
            sessions.append(cur)
            continue
        m = IFACE_RE.match(line)
        if m and cur is not None:
            cur["ifname"] = m.group("ifname")
    for s in sessions:
        if s["ifname"]:
            out = subprocess.run(["ip", "-4", "addr", "show", "dev", s["ifname"]],
                                 capture_output=True, text=True).stdout
            m = PEER_RE.search(out)
            if m:
                s["subscriber"] = m.group("peer")
    return sessions


def vppctl(args, cmd, dry):
    if dry:
        print("vppctl " + cmd)
        return ""
    r = subprocess.run([args.vppctl] + cmd.split(), capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    if r.returncode != 0 or "returned" in out or "unknown input" in out:
        sys.exit("vppctl %s failed: %s" % (cmd, out))
    return out


def load_state(path):
    try:
        return json.load(open(path))
    except (FileNotFoundError, ValueError):
        return {"tunnels": {}, "sessions": {}}


def save_state(path, st):
    tmp = path + ".tmp"
    json.dump(st, open(tmp, "w"), indent=2)
    os.replace(tmp, path)


def tunnel_key(s):
    return "%s:%d:%d" % (s["peer_ip"], s["peer_port"], s["local_tid"])


def session_key(s):
    return "%s/%d" % (tunnel_key(s), s["local_sid"])


def cmd_list(args):
    ss = kernel_sessions()
    print("%-18s %-6s %-6s %-6s %-6s %-6s %-8s %s" %
          ("peer", "port", "ltid", "ptid", "lsid", "psid", "ifname", "subscriber"))
    for s in ss:
        print("%-18s %-6d %-6d %-6d %-6d %-6d %-8s %s" %
              (s["peer_ip"], s["peer_port"], s["local_tid"], s["peer_tid"],
               s["local_sid"], s["peer_sid"], s["ifname"] or "?", s["subscriber"] or "?"))
    print("%d sessions, %d tunnels" % (len(ss), len({tunnel_key(s) for s in ss})))
    missing = [s for s in ss if not s["ifname"] or not s["subscriber"]]
    if missing:
        print("WARNING: %d sessions without ifname/subscriber mapping - this kernel's "
              "/proc/net/pppol2tp lacks the 'interface pppN' line; see docs/rig-test.md step 6"
              % len(missing))


def cmd_apply(args):
    st = load_state(args.state)
    ss = kernel_sessions()
    n_t = n_s = 0
    for s in ss:
        if not s["subscriber"]:
            print("skip %s: no subscriber address (session not up, or no ifname mapping)" % s["name"])
            continue
        tk = tunnel_key(s)
        if tk not in st["tunnels"]:
            out = vppctl(args, "l2tvpp tunnel local %s peer %s local-port %d peer-port %d "
                         "local-tid %d peer-tid %d" % (args.local_ip, s["peer_ip"], args.local_port,
                                                       s["peer_port"], s["local_tid"], s["peer_tid"]),
                         args.dry_run)
            m = re.search(r"tunnel\s+(\d+)", out)
            st["tunnels"][tk] = int(m.group(1)) if m else -1
            n_t += 1
        sk = session_key(s)
        if sk in st["sessions"]:
            continue
        tidx = st["tunnels"][tk]
        out = vppctl(args, "l2tvpp session tunnel %d local-sid %d peer-sid %d"
                     % (tidx, s["local_sid"], s["peer_sid"]), args.dry_run)
        m = re.search(r"(l2tvpp\d+)", out)
        ifname = m.group(1) if m else "l2tvpp?"
        vppctl(args, "set interface state %s up" % ifname, args.dry_run)
        vppctl(args, "ip route add %s/32 via %s" % (s["subscriber"], ifname), args.dry_run)
        st["sessions"][sk] = {"vpp_if": ifname, "tunnel": tidx, "local_sid": s["local_sid"],
                              "subscriber": s["subscriber"], "ppp": s["ifname"]}
        n_s += 1
        if not args.dry_run:
            save_state(args.state, st)
    if not args.dry_run:
        save_state(args.state, st)
    print("installed %d tunnels, %d sessions (%d total in state)" % (n_t, n_s, len(st["sessions"])))


def cmd_remove(args):
    st = load_state(args.state)
    for sk, s in list(st["sessions"].items()):
        vppctl(args, "ip route del %s/32 via %s" % (s["subscriber"], s["vpp_if"]), args.dry_run)
        vppctl(args, "l2tvpp session del tunnel %d local-sid %d" % (s["tunnel"], s["local_sid"]),
               args.dry_run)
        if not args.dry_run:
            del st["sessions"][sk]
    for tk, tidx in list(st["tunnels"].items()):
        peer_ip, peer_port, ltid = tk.split(":")
        vppctl(args, "l2tvpp tunnel del local %s peer %s local-port %d peer-port %s local-tid %s"
               % (args.local_ip, peer_ip, args.local_port, peer_port, ltid), args.dry_run)
        if not args.dry_run:
            del st["tunnels"][tk]
    if not args.dry_run:
        save_state(args.state, st)
    print("removed")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cmd", choices=["list", "apply", "remove"])
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--local-ip", default="10.66.0.1", help="LNS tunnel endpoint (accel-ppp outside-address)")
    p.add_argument("--local-port", type=int, default=1701, help="LNS UDP port (1701 unless ephemeral ports)")
    p.add_argument("--vppctl", default="/usr/bin/vppctl")
    p.add_argument("--state", default="/run/l2tvpp-install.json")
    args = p.parse_args()
    {"list": cmd_list, "apply": cmd_apply, "remove": cmd_remove}[args.cmd](args)


if __name__ == "__main__":
    main()
