#!/usr/bin/env python3
# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
"""
l2tvppd: the M2 sync daemon. It keeps the VPP l2tvpp data plane in step with
the sessions accel-ppp brings up in the kernel, using the VPP binary API
(vpp_papi) rather than shelling vppctl, so it scales to hundreds of sessions.

Design: docs/design.md step 4.

Model
-----
Kernel is the source of truth. accel-ppp terminates L2TP/PPP and creates a
netdev per session (pppN, or l2tpN on VyOS); /proc/net/pppol2tp lists each
with local/peer tunnel id and session id and the netdev name. Both tunnel
endpoints come from `ip l2tp show tunnel` (the addr field in
/proc/net/pppol2tp is NOT trustworthy: on the VyOS accel-ppp LNS it holds
the local address, not the peer). The subscriber's addresses and routed
prefixes come from one `ip -o addr show` and one `ip -o -4/-6 route show`
per pass for all interfaces (kernel_routes).

For every kernel session the daemon ensures, in VPP:
  l2tvpp_tunnel_add_del   (one per distinct peer-ip/peer-port/local-tid)
  l2tvpp_session_add_del  (-> an l2tvpp interface)
  l2tvpp_route_add_del    (subscriber /32 and any /128 + delegated prefix,
                           via the session interface; the plugin installs it
                           with its own FIB source so it beats linux-cp's
                           mirror of the kernel session route - a plain
                           ip_route_add_del would lose to lcp-rt and
                           downstream traffic would keep punting)
and removes, in reverse, whatever VPP has that the kernel no longer does.

Event sources (pick with --mode)
  reconcile : one full kernel<->VPP reconcile pass, then exit. Idempotent;
              safe to run from cron or by hand. This is also what runs on
              daemon start and on SIGHUP.
  daemon    : reconcile on start, then again on SIGHUP and every
              --interval seconds as a safety net. Wire accel-ppp's
              ip-up/ip-down (or ipv6-up/down) to `kill -HUP` the daemon, or
              to call `l2tvppd reconcile`, so a new session is mirrored
              within milliseconds instead of at the next tick.

ACFC/PFC are not exposed by accel-ppp, so sessions are installed with both
off (encap writes FF 03 00 21, which every LAC accepts; decap still handles
compressed framing). See node.c / design.md step 4.

vpp_papi ships with VPP (python3 vpp-api). On VyOS it is under the VPP
install; point PYTHONPATH at it or run inside the VPP venv.
"""
import argparse
import logging
import os
import re
import signal
import subprocess
import sys
import time

log = logging.getLogger("l2tvppd")

# ---------------------------------------------------------------------------
# kernel side: parse /proc/net/pppol2tp + ip addr, no VPP needed (unit-tested)
# ---------------------------------------------------------------------------

SESSION_RE = re.compile(
    r"^\s*SESSION\s+'(?P<name>[^']*)',?\s+(?P<peer_ip>[0-9A-Fa-f]{8})/(?P<peer_port>\d+)\s+"
    r"(?P<tid>[0-9A-Fa-f]{4})/(?P<sid>[0-9A-Fa-f]{4})\s+->\s+"
    r"(?P<ptid>[0-9A-Fa-f]{4})/(?P<psid>[0-9A-Fa-f]{4})")
IFACE_RE = re.compile(r"^\s*interface\s+(?P<ifname>\S+)")


def _hex_ip(h):
    v = int(h, 16)
    return "%d.%d.%d.%d" % (v >> 24 & 255, v >> 16 & 255, v >> 8 & 255, v & 255)


def parse_pppol2tp(text):
    """Parse /proc/net/pppol2tp text into a list of session dicts. Pure, so a
    test can feed it a captured file. Peer ip is decoded from the kernel's
    big-endian hex word."""
    sessions, cur = [], None
    for line in text.splitlines():
        m = SESSION_RE.match(line)
        if m:
            cur = {
                "name": m.group("name"),
                "peer_ip": _hex_ip(m.group("peer_ip")),
                "peer_port": int(m.group("peer_port")),
                "local_tid": int(m.group("tid"), 16),
                "local_sid": int(m.group("sid"), 16),
                "peer_tid": int(m.group("ptid"), 16),
                "peer_sid": int(m.group("psid"), 16),
                "ifname": None,
                "routes": None,     # subscriber prefixes; filled by reconcile
            }
            sessions.append(cur)
            continue
        m = IFACE_RE.match(line)
        if m and cur is not None:
            cur["ifname"] = m.group("ifname")
    return sessions


ADDR4_RE = re.compile(
    r"^\d+:\s+(\S+)\s+inet\s+\S+\s+peer\s+([0-9.]+)/32", re.M)
ADDR6_RE = re.compile(
    r"^\d+:\s+(\S+)\s+inet6\s+[0-9A-Fa-f:]+\s+peer\s+([0-9A-Fa-f:]+)/128", re.M)
ROUTE_DEV_RE = re.compile(r"\sdev\s+(\S+)")


def parse_ppp_routes(addr_text, route_text):
    """Subscriber prefixes per interface, {ifname: [prefix, ...]}: the peer
    /32 (IPv4), any global peer /128 (IPv6), and prefixes routed at the
    interface (delegated prefixes, framed routes). addr_text is `ip -o addr
    show`, route_text the concatenated `ip -o -4 route show` and `ip -o -6
    route show`, all WITHOUT a dev filter: one dump covers every session.
    Pure, so it is tested."""
    routes = {}
    for m in ADDR4_RE.finditer(addr_text):
        routes.setdefault(m.group(1), set()).add(m.group(2) + "/32")
    for m in ADDR6_RE.finditer(addr_text):
        if not m.group(2).lower().startswith("fe80"):   # skip link-local
            routes.setdefault(m.group(1), set()).add(m.group(2) + "/128")
    # Delegated prefixes (PD) show up as routes with dev pppN, not addresses.
    for line in route_text.splitlines():
        fields = line.split()
        m = ROUTE_DEV_RE.search(line)
        if not fields or not m:
            continue
        pfx = fields[0]
        if "/" in pfx and not pfx.startswith(("fe80", "169.254")):
            routes.setdefault(m.group(1), set()).add(pfx)
    return {ifname: sorted(pfxs) for ifname, pfxs in routes.items()}


def kernel_routes(run=subprocess.run):
    """Subscriber prefixes of every interface in three `ip` calls, whatever
    the session count (a per-interface query costs two process spawns per
    session, which turns a mass reconnect into minutes of install latency).
    The IPv6 table has to be asked for explicitly: a plain `ip route show`
    lists IPv4 only, so delegated prefixes would never be seen."""
    def out(*args):
        return run(["ip", "-o"] + list(args),
                   capture_output=True, text=True).stdout
    return parse_ppp_routes(
        out("addr", "show"),
        out("-4", "route", "show") + out("-6", "route", "show"))


TUNNEL_RE = re.compile(r"^Tunnel\s+(?P<tid>\d+),")
FROM_TO_RE = re.compile(r"^\s*From\s+(?P<local>\S+)\s+to\s+(?P<peer>\S+)")
PORTS_RE = re.compile(r"UDP source / dest ports:\s*(?P<sport>\d+)/(?P<dport>\d+)")


def parse_l2tp_tunnels(text):
    """Parse `ip l2tp show tunnel` into {local_tid: {local_ip, peer_ip,
    local_port, peer_port}}. This is the authoritative source for BOTH tunnel
    endpoints: the addr field in /proc/net/pppol2tp holds the LOCAL address
    on the VyOS accel-ppp LNS (rig, 2026-08-24), so the peer parsed there is
    only a fallback. Pure, so it is tested."""
    tunnels, cur = {}, None
    for line in text.splitlines():
        m = TUNNEL_RE.match(line)
        if m:
            cur = {"local_ip": None, "peer_ip": None,
                   "local_port": 1701, "peer_port": 1701}
            tunnels[int(m.group("tid"))] = cur
            continue
        if cur is None:
            continue
        m = FROM_TO_RE.match(line)
        if m:
            cur["local_ip"] = m.group("local")
            cur["peer_ip"] = m.group("peer")
            continue
        m = PORTS_RE.search(line)
        if m:
            cur["local_port"] = int(m.group("sport"))
            cur["peer_port"] = int(m.group("dport"))
    return tunnels


def kernel_tunnels(run=subprocess.run):
    out = run(["ip", "l2tp", "show", "tunnel"],
              capture_output=True, text=True).stdout
    return parse_l2tp_tunnels(out)


def kernel_sessions(run=subprocess.run):
    """Enumerate kernel L2TP/PPP sessions cheaply: two reads
    (/proc/net/pppol2tp + `ip l2tp show tunnel`) regardless of session count.
    Subscriber routes are NOT fetched here - reconcile pulls them for all
    interfaces at once (kernel_routes) when a session needs them."""
    try:
        text = open("/proc/net/pppol2tp").read()
    except FileNotFoundError:
        # l2tp_ppp not loaded yet (no L2TP sessions have come up): that is a
        # normal steady state, not an error - just report no sessions so the
        # daemon keeps running and mirrors them once they appear.
        return []
    return merge_tunnel_endpoints(parse_pppol2tp(text),
                                  kernel_tunnels(run=run))


def merge_tunnel_endpoints(sessions, tunnels):
    """Fill per-session tunnel endpoints from `ip l2tp show tunnel` (auto,
    no config). Both ends: the /proc-derived peer_ip stays only as a
    fallback, because on the VyOS accel-ppp LNS that field is really the
    local address and using it as peer made the plugin encap to itself.
    Pure, so it is tested."""
    for s in sessions:
        t = tunnels.get(s["local_tid"])
        if not t:
            continue
        if t["local_ip"]:
            s["local_ip"] = t["local_ip"]
            s["local_port"] = t["local_port"]
        if t["peer_ip"]:
            s["peer_ip"] = t["peer_ip"]
            s["peer_port"] = t["peer_port"]
    return sessions


def tunnel_key(s):
    return (s["peer_ip"], s["peer_port"], s["local_tid"])


def session_key(s):
    return (s["local_tid"], s["local_sid"])


# ---------------------------------------------------------------------------
# VPP side: reconcile kernel sessions into the l2tvpp plugin via vpp_papi
# ---------------------------------------------------------------------------

class Syncd:
    """Holds the VPP API client and mirrors kernel sessions into l2tvpp. The
    client only needs the l2tvpp_* and ip_route_add_del calls; a make-test
    can pass VPP's own test-framework client instead of a real one."""

    def __init__(self, vpp, local_ip=None, local_port=1701, state_path=None):
        self.vpp = vpp
        # fallback local endpoint; per-session values from `ip l2tp show
        # tunnel` (s["local_ip"]) take precedence, so this is usually unused
        self.local_ip = local_ip
        self.local_port = local_port
        # session_key(str) -> installed record {sw_if_index, tunnel_index,
        # local_sid, peer_sid, tunnel_key, routes[]}. This is what the daemon
        # installed, so it knows exactly what to remove; it is the source for
        # route teardown (the FIB is not re-dumped). Persisted so a daemon
        # restart does not lose track of prior installs.
        self.state_path = state_path
        self.installed = self._load_state()
        # check our record against what VPP really holds on the next pass:
        # set at start (the state file may predate a VPP restart) and after
        # a failed pass or a reconnect
        self.verify_state = True

    def _load_state(self):
        if not self.state_path:
            return {}
        try:
            import json
            with open(self.state_path) as f:
                return json.load(f)
        except (FileNotFoundError, ValueError):
            return {}

    def _save_state(self):
        if not self.state_path:
            return
        import json
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.installed, f, indent=2)
        os.replace(tmp, self.state_path)

    # -- current VPP state -------------------------------------------------
    def vpp_tunnels(self):
        """(peer_ip, peer_port, local_tid) -> tunnel_index"""
        out = {}
        for t in self.vpp.l2tvpp_tunnel_dump(tunnel_index=0xFFFFFFFF):
            out[(str(t.peer_ip), t.peer_port, t.local_tid)] = t.tunnel_index
        return out

    # -- mutations ---------------------------------------------------------
    def ensure_tunnel(self, s, cache):
        tk = tunnel_key(s)
        if tk in cache:
            return cache[tk]
        local_ip = s.get("local_ip") or self.local_ip
        if not local_ip:
            raise RuntimeError(
                "no local IP for tunnel %s: `ip l2tp show tunnel` gave none "
                "and no --local-ip fallback set" % (tk,))
        local_port = s.get("local_port") or self.local_port
        r = self._check(self.vpp.l2tvpp_tunnel_add_del(
            is_add=True, local_ip=local_ip, peer_ip=s["peer_ip"],
            local_port=local_port, peer_port=s["peer_port"],
            local_tid=s["local_tid"], peer_tid=s["peer_tid"]), "tunnel add")
        cache[tk] = r.tunnel_index
        log.info("tunnel + %s -> %d", tk, r.tunnel_index)
        return r.tunnel_index

    @staticmethod
    def _check(r, what):
        """vpp_papi returns a failed call as a reply with a negative retval
        instead of raising; without this a refused session add was recorded
        as installed with sw_if_index ~0."""
        rv = getattr(r, "retval", 0)
        if rv:
            raise RuntimeError("%s failed: VPP retval %d" % (what, rv))
        return r

    def vpp_sessions(self):
        """(tunnel_index, local_sid) -> session details"""
        return {(d.tunnel_index, d.local_sid): d for d in
                self.vpp.l2tvpp_session_dump(sw_if_index=0xFFFFFFFF)}

    def drop_stale_records(self, live):
        """Forget installed records VPP no longer has (VPP restarted while
        the state file survived): they are re-installed by the same pass.
        Without this the daemon believed everything was in place and an
        empty VPP stayed empty."""
        for key in list(self.installed):
            rec = self.installed[key]
            d = live.get((rec["tunnel_index"], rec["local_sid"]))
            if d is None or d.sw_if_index != rec["sw_if_index"]:
                del self.installed[key]
                log.warning("session %s (sw_if_index %d) is not in VPP any "
                            "more; re-installing", key, rec["sw_if_index"])

    def add_session(self, s, tunnels_cache, run=subprocess.run, live=None):
        # reconcile supplies the routes; this is only for a direct caller
        if s.get("routes") is None:
            s["routes"] = (kernel_routes(run).get(s["ifname"], [])
                           if s["ifname"] else [])
        tidx = self.ensure_tunnel(s, tunnels_cache)
        d = (live or {}).get((tidx, s["local_sid"]))
        if d is not None and d.peer_sid != s["peer_sid"]:
            # same local id, different peer id: not the session we want
            self._check(self.vpp.l2tvpp_session_add_del(
                is_add=False, tunnel_index=tidx, local_sid=s["local_sid"],
                peer_sid=d.peer_sid), "session del")
            d = None
        if d is not None:
            # VPP already has it but our record does not (state file lost):
            # adopt it instead of failing on "already exists" every pass.
            # Route adds are idempotent in the plugin.
            swif = d.sw_if_index
            log.info("session tid %d sid %d already in VPP, adopting "
                     "sw_if_index %d", s["local_tid"], s["local_sid"], swif)
        else:
            swif = self._check(self.vpp.l2tvpp_session_add_del(
                is_add=True, tunnel_index=tidx,
                local_sid=s["local_sid"], peer_sid=s["peer_sid"],
                acfc=False, pfc=False), "session add").sw_if_index
        # record before the routes go in, so a failed route add leaves a
        # session we know about (and whose routes the next pass completes)
        rec = {"sw_if_index": swif, "tunnel_index": tidx,
               "local_sid": s["local_sid"], "peer_sid": s["peer_sid"],
               "tunnel_key": list(tunnel_key(s)), "routes": []}
        self.installed["%d/%d" % session_key(s)] = rec
        for pfx in s["routes"]:
            self._route(pfx, swif, is_add=1)
            rec["routes"].append(pfx)
        log.info("session + tid %d sid %d -> sw_if_index %d (%d routes)",
                 s["local_tid"], s["local_sid"], swif, len(s["routes"]))
        return swif

    def sync_routes(self, s):
        """Bring an already-installed session's routes in line with the
        kernel's current list (handles a subscriber gaining/losing a PD)."""
        rec = self.installed["%d/%d" % session_key(s)]
        have, want = set(rec["routes"]), set(s["routes"])
        # sorted: deterministic order; the record follows each call, so a
        # failure half way leaves it describing what VPP really has
        for pfx in sorted(want - have):
            self._route(pfx, rec["sw_if_index"], is_add=1)
            rec["routes"] = sorted(set(rec["routes"]) | {pfx})
        for pfx in sorted(have - want):
            self._route(pfx, rec["sw_if_index"], is_add=0)
            rec["routes"] = sorted(set(rec["routes"]) - {pfx})
        if have != want:
            log.info("session tid %d sid %d routes %d -> %d",
                     s["local_tid"], s["local_sid"], len(have), len(want))

    def del_session(self, key):
        rec = self.installed[key]
        for pfx in rec["routes"]:
            self._route(pfx, rec["sw_if_index"], is_add=0)
        self._check(self.vpp.l2tvpp_session_add_del(
            is_add=False, tunnel_index=rec["tunnel_index"],
            local_sid=rec["local_sid"], peer_sid=rec["peer_sid"]),
            "session del")
        del self.installed[key]
        log.info("session - %s (sw_if_index %d)", key, rec["sw_if_index"])

    def prune_tunnels(self):
        """Drop tunnels with no sessions left (add_del refuses in-use ones)."""
        live = {s.tunnel_index for s in
                self.vpp.l2tvpp_session_dump(sw_if_index=0xFFFFFFFF)}
        for tk, tidx in self.vpp_tunnels().items():
            if tidx in live:
                continue
            self.vpp.l2tvpp_tunnel_add_del(
                is_add=False, local_ip=self.local_ip, peer_ip=tk[0],
                local_port=self.local_port, peer_port=tk[1],
                local_tid=tk[2], peer_tid=0)
            log.info("tunnel - %s", tk)

    def _route(self, prefix, sw_if_index, is_add):
        # the plugin installs it with its own FIB source, which outranks
        # linux-cp's lcp-rt mirror of the kernel session route; an
        # ip_route_add_del route (API source) loses to that mirror and
        # downstream traffic keeps punting to the kernel
        self._check(self.vpp.l2tvpp_route_add_del(
            is_add=bool(is_add), prefix=prefix, sw_if_index=sw_if_index),
            "route %s %s" % ("add" if is_add else "del", prefix))

    # -- the reconcile pass ------------------------------------------------
    def reconcile(self, ksessions, sync_existing_routes=True, run=subprocess.run):
        """Make VPP match the given kernel session list, using our own record
        of what we installed. Returns (added, removed).

        sync_existing_routes re-checks routes of already-installed sessions
        (to catch a subscriber gaining/losing a delegated prefix, or an
        address that was not assigned yet when the session was installed).
        The routes of all interfaces come from one kernel_routes() call per
        pass, so this is cheap whatever the session count.

        One session VPP refuses does not stop the pass: it is logged, the
        others are still handled, and the next pass retries it. Errors of
        the API transport itself (VPP gone) do abort the pass."""
        want = {"%d/%d" % session_key(s): s for s in ksessions if s["ifname"]}
        tunnels_cache = self.vpp_tunnels()
        live = None
        if self.verify_state:
            live = self.vpp_sessions()
            self.drop_stale_records(live)
        self.verify_state = True        # until this pass ends cleanly
        kroutes = []                    # fetched once, on first need

        def fill_routes(s):
            if s.get("routes") is None:
                if not kroutes:
                    kroutes.append(kernel_routes(run))
                s["routes"] = kroutes[0].get(s["ifname"], [])

        added = removed = failed = 0
        for key, s in want.items():
            try:
                if key not in self.installed:
                    fill_routes(s)
                    if live is None:
                        live = self.vpp_sessions()
                    self.add_session(s, tunnels_cache, run=run, live=live)
                    added += 1
                elif sync_existing_routes:
                    fill_routes(s)
                    self.sync_routes(s)
            except RuntimeError as e:
                failed += 1
                log.error("session %s: %s", key, e)
        for key in list(self.installed):
            if key not in want:
                try:
                    self.del_session(key)
                    removed += 1
                except RuntimeError as e:
                    failed += 1
                    log.error("session %s: %s", key, e)
        if removed:
            self.prune_tunnels()
        self._save_state()
        self.verify_state = failed > 0
        log.info("reconcile: %d kernel sessions, +%d -%d in VPP%s",
                 len(want), added, removed,
                 ", %d failed" % failed if failed else "")
        return added, removed


# ---------------------------------------------------------------------------
# main / daemon
# ---------------------------------------------------------------------------

def connect_vpp():
    try:
        from vpp_papi import VPPApiClient
    except ImportError:
        sys.exit("vpp_papi not found: install python3-vpp-api or set PYTHONPATH "
                 "to the VPP api python dir (see module docstring)")
    vpp = VPPApiClient()
    vpp.connect("l2tvppd")
    return vpp


def run_once(local_ip, local_port, state_path):
    vpp = connect_vpp()
    try:
        # real vpp_papi exposes API calls under vpp.api.<name>; the test
        # framework's provider exposes them at the top level, so Syncd always
        # gets an object whose l2tvpp_* / ip_route_add_del are top-level
        return Syncd(vpp.api, local_ip, local_port, state_path).reconcile(
            kernel_sessions())
    finally:
        vpp.disconnect()


def connect_vpp_retry(interval):
    """Wait for VPP to be up rather than crash-looping under systemd: the
    daemon may start before VPP is configured/ready."""
    while True:
        try:
            return connect_vpp()
        except SystemExit:
            raise
        except Exception as e:
            log.info("VPP API not ready (%s); retrying in %ds", e, interval)
            time.sleep(interval)


def run_daemon(local_ip, local_port, interval, state_path):
    vpp = connect_vpp_retry(interval)
    sync = Syncd(vpp.api, local_ip, local_port, state_path)   # see run_once
    wake = {"now": False}
    signal.signal(signal.SIGHUP, lambda *_: wake.__setitem__("now", True))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    log.info("l2tvppd up: reconcile every %ds (SIGHUP to poke), local-ip "
             "auto per tunnel%s", interval,
             "" if local_ip is None else " (fallback %s)" % local_ip)
    try:
        # reconcile UNCONDITIONALLY each iteration - this is the interval
        # safety net; SIGHUP only cuts the sleep short. (Gating the pass on
        # the wake flag meant the daemon reconciled once at start and then
        # never again without a SIGHUP - found on the rig 2026-08-25 when a
        # whole benchmark ran the kernel path with the daemon "active".)
        while True:
            wake["now"] = False
            try:
                sync.reconcile(kernel_sessions())
            except Exception:               # never let one bad pass kill the loop
                log.exception("reconcile failed; will retry")
                # a pass that dies on the API transport usually means VPP
                # restarted: this client is then dead for good and VPP is
                # empty, so get a fresh connection and re-check our record
                try:
                    vpp.api.control_ping()
                except Exception:
                    log.warning("VPP API connection lost; reconnecting")
                    try:
                        vpp.disconnect()
                    except Exception:
                        pass
                    vpp = connect_vpp_retry(interval)
                    sync.vpp = vpp.api
                    sync.verify_state = True
            for _ in range(interval):
                if wake["now"]:
                    break
                time.sleep(1)
    finally:
        vpp.disconnect()


def main():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("mode", choices=["reconcile", "daemon"])
    p.add_argument("--local-ip", default=None,
                   help="fallback LNS tunnel endpoint; normally auto-derived "
                        "per tunnel from `ip l2tp show tunnel`, so leave unset")
    p.add_argument("--local-port", type=int, default=1701)
    p.add_argument("--interval", type=int, default=30,
                   help="daemon safety-net reconcile interval (s)")
    p.add_argument("--state", default="/run/l2tvppd.json",
                   help="path to the installed-session state file")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s l2tvppd %(levelname)s %(message)s")
    if args.mode == "reconcile":
        run_once(args.local_ip, args.local_port, args.state)
    else:
        run_daemon(args.local_ip, args.local_port, args.interval, args.state)


if __name__ == "__main__":
    main()
