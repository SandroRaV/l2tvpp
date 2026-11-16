#!/usr/bin/env python3
# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
"""
RADIUS accounting from the VPP data plane, for l2tvppd.

Why
---
accel-ppp fills Acct-Input/Output-Octets and -Packets from the statistics of
the kernel session netdev (RTM_GETLINK). Once l2tvpp forwards a session that
netdev carries no data traffic, so every interim and stop record would report
(almost) zero. accel-ppp has no hook to take the counters from somewhere
else, so the numbers are corrected on the way to the RADIUS server.

How
---
accel-ppp sends its RADIUS traffic to this relay on the LNS itself; the relay
forwards it to the real server(s). Access-Requests and every reply pass
unchanged. In an Accounting-Request (interim or stop) of a session that VPP
forwards, the counters of the VPP session interface are ADDED to what
accel-ppp reported (the kernel netdev still counts what went through the
kernel: the first packets before the session was mirrored, IPv6 neighbour
discovery, DHCPv6), the Request Authenticator is recomputed, and the
Response Authenticator of the reply is recomputed for accel-ppp. That needs
the shared secret; with a wrong secret the relay forwards unchanged and says
so in the log.

Which VPP session an accounting record belongs to
-------------------------------------------------
The request carries Acct-Session-Id and NAS-Port-Id (the netdev name), no
tunnel or session id. A netdev name is reused by the next session, often
within the same second (a CPE that reconnects), so the name alone cannot be
trusted. The kernel interface index can: it is never reused. The first time
the relay sees an Acct-Session-Id (in the start record, or in an interim
record after a restart) it reads the interface index the netdev of that name
has at that moment and binds the id to it; the daemon reports each mirrored
session with the interface index of its netdev. A session that has gone
keeps its final counters for a while (FINAL_KEEP), so the stop record, which
accel-ppp may send before or after the daemon removed the session from VPP,
still gets them. An id first seen in a stop record is left alone.

No VPP and no accel-ppp is needed to test this file: syncd/test_acct.py.
"""
import hashlib
import hmac
import logging
import select
import socket
import struct
import threading
import time

log = logging.getLogger("l2tvppd.acct")

ACCESS_REQUEST = 1
ACCOUNTING_REQUEST = 4
ACCOUNTING_RESPONSE = 5

ATTR_NAS_PORT_ID = 87
ATTR_ACCT_STATUS_TYPE = 40
ATTR_ACCT_INPUT_OCTETS = 42
ATTR_ACCT_OUTPUT_OCTETS = 43
ATTR_ACCT_SESSION_ID = 44
ATTR_ACCT_INPUT_PACKETS = 47
ATTR_ACCT_OUTPUT_PACKETS = 48
ATTR_ACCT_INPUT_GIGAWORDS = 52
ATTR_ACCT_OUTPUT_GIGAWORDS = 53
ATTR_MESSAGE_AUTHENTICATOR = 80

STATUS_START, STATUS_STOP, STATUS_INTERIM = 1, 2, 3

# bytes the plugin prepends per downstream packet (outer IPv4 20 + UDP 8 +
# L2TP 6 + PPP 4): the VPP TX counter of a session interface counts the
# encapsulated packet, RADIUS wants what the subscriber received
ENCAP_OVERHEAD = 38

FINAL_KEEP = 900        # s a removed session's final counters are kept
FLOW_IDLE = 120         # s an unused client flow keeps its upstream socket
PENDING_KEEP = 30       # s a forwarded request waits for its reply
FAILOVER_AFTER = 3      # unanswered requests in a row before the next server


# ---------------------------------------------------------------------------
# packet helpers (pure)
# ---------------------------------------------------------------------------

def parse_packet(data):
    """(code, ident, authenticator, [(type, value), ...]) or None if the
    datagram is not a well-formed RADIUS packet."""
    if len(data) < 20:
        return None
    code, ident, length = struct.unpack("!BBH", data[:4])
    if length < 20 or length > len(data):
        return None
    attrs, pos = [], 20
    while pos < length:
        if pos + 2 > length:
            return None
        t, l = data[pos], data[pos + 1]
        if l < 2 or pos + l > length:
            return None
        attrs.append((t, data[pos + 2:pos + l]))
        pos += l
    return code, ident, data[4:20], attrs


def build_packet(code, ident, authenticator, attrs):
    body = b"".join(bytes([t, len(v) + 2]) + v for t, v in attrs)
    return struct.pack("!BBH", code, ident, 20 + len(body)) + authenticator + body


def _attr(attrs, t):
    for at, v in attrs:
        if at == t:
            return v
    return None


def _u32(v):
    return struct.unpack("!I", v)[0] if v is not None and len(v) == 4 else 0


def request_authenticator(code, ident, attrs, secret):
    """Accounting-Request authenticator (RFC 2866 step 3): MD5 over the
    packet with a zero authenticator, then the secret."""
    return hashlib.md5(build_packet(code, ident, b"\0" * 16, attrs)
                       + secret).digest()


def response_authenticator(code, ident, attrs, req_auth, secret):
    """Reply authenticator (RFC 2865 step 3): MD5 over the reply with the
    REQUEST authenticator in the authenticator field, then the secret."""
    return hashlib.md5(build_packet(code, ident, req_auth, attrs)
                       + secret).digest()


def _sign_message_authenticator(code, ident, auth_field, attrs, secret):
    """Refill a Message-Authenticator attribute, if the packet has one:
    HMAC-MD5 over the packet with that attribute zeroed and auth_field in
    the authenticator field (zeros for an Accounting-Request, the request
    authenticator for a reply)."""
    if _attr(attrs, ATTR_MESSAGE_AUTHENTICATOR) is None:
        return attrs
    zeroed = [(t, b"\0" * 16 if t == ATTR_MESSAGE_AUTHENTICATOR else v)
              for t, v in attrs]
    mac = hmac.new(secret, build_packet(code, ident, auth_field, zeroed),
                   hashlib.md5).digest()
    return [(t, mac if t == ATTR_MESSAGE_AUTHENTICATOR else v)
            for t, v in zeroed]


def add_counters(attrs, in_octets, out_octets, in_packets, out_packets):
    """Add the given amounts to the accounting counters of an attribute
    list and return the new list. Octets are 64 bit across the Octets and
    Gigawords attributes; a Gigawords attribute that is needed but missing
    is appended. Packets are 32 bit and wrap, as accel-ppp's own do."""
    cur_in = (_u32(_attr(attrs, ATTR_ACCT_INPUT_GIGAWORDS)) << 32) \
        | _u32(_attr(attrs, ATTR_ACCT_INPUT_OCTETS))
    cur_out = (_u32(_attr(attrs, ATTR_ACCT_OUTPUT_GIGAWORDS)) << 32) \
        | _u32(_attr(attrs, ATTR_ACCT_OUTPUT_OCTETS))
    new_in = (cur_in + in_octets) & 0xFFFFFFFFFFFFFFFF
    new_out = (cur_out + out_octets) & 0xFFFFFFFFFFFFFFFF
    want = {
        ATTR_ACCT_INPUT_OCTETS: new_in & 0xFFFFFFFF,
        ATTR_ACCT_OUTPUT_OCTETS: new_out & 0xFFFFFFFF,
        ATTR_ACCT_INPUT_GIGAWORDS: new_in >> 32,
        ATTR_ACCT_OUTPUT_GIGAWORDS: new_out >> 32,
        ATTR_ACCT_INPUT_PACKETS:
            (_u32(_attr(attrs, ATTR_ACCT_INPUT_PACKETS)) + in_packets)
            & 0xFFFFFFFF,
        ATTR_ACCT_OUTPUT_PACKETS:
            (_u32(_attr(attrs, ATTR_ACCT_OUTPUT_PACKETS)) + out_packets)
            & 0xFFFFFFFF,
    }
    out, seen = [], set()
    for t, v in attrs:
        if t in want:
            out.append((t, struct.pack("!I", want[t])))
            seen.add(t)
        else:
            out.append((t, v))
    # a Message-Authenticator stays last if it was last; new attributes go
    # before it
    tail = []
    if out and out[-1][0] == ATTR_MESSAGE_AUTHENTICATOR:
        tail = [out.pop()]
    for t in (ATTR_ACCT_INPUT_OCTETS, ATTR_ACCT_OUTPUT_OCTETS,
              ATTR_ACCT_INPUT_PACKETS, ATTR_ACCT_OUTPUT_PACKETS):
        if t not in seen:
            out.append((t, struct.pack("!I", want[t])))
    for t in (ATTR_ACCT_INPUT_GIGAWORDS, ATTR_ACCT_OUTPUT_GIGAWORDS):
        if t not in seen and want[t]:
            out.append((t, struct.pack("!I", want[t])))
    return out + tail


# ---------------------------------------------------------------------------
# which VPP session an Acct-Session-Id belongs to, and its counters
# ---------------------------------------------------------------------------

def sysfs_ifindex(ifname):
    """Interface index of the netdev that has this name right now, None if
    there is none."""
    if "/" in ifname or ifname in (".", ".."):
        return None
    try:
        with open("/sys/class/net/%s/ifindex" % ifname) as f:
            return int(f.read())
    except (OSError, ValueError):
        return None


class AcctSessions:
    """Bookkeeping between the daemon (which mirrors sessions into VPP) and
    the relay (which sees accounting records). Thread-safe: the daemon
    thread calls installed()/removed(), the relay thread calls counters().

    live_counters(sw_if_index) -> (rx_packets, rx_bytes, tx_packets,
    tx_bytes) of a VPP session interface, or None if it is gone.
    ifindex_of(ifname) -> kernel interface index of that netdev now."""

    def __init__(self, live_counters, ifindex_of=sysfs_ifindex,
                 now=time.monotonic):
        self.live_counters = live_counters
        self.ifindex_of = ifindex_of
        self.now = now
        self.lock = threading.Lock()
        self.live = {}       # ifindex -> {key, sw_if_index}
        self.final = {}      # ifindex -> {until, counters}
        self.bound = {}      # Acct-Session-Id -> (ifindex, first seen)

    # -- daemon side -------------------------------------------------------
    def installed(self, key, ifname, sw_if_index, ifindex=None):
        """A session is in VPP. ifindex: the kernel interface index of its
        netdev; without it the session cannot be told apart from an earlier
        one with the same netdev name and gets no VPP counters."""
        if ifindex is None:
            return
        with self.lock:
            for idx in [i for i, s in self.live.items()
                        if s["key"] == key and i != ifindex]:
                del self.live[idx]
            self.live[ifindex] = {"key": key, "sw_if_index": sw_if_index}

    def removed(self, key, counters):
        """counters: the session's last VPP counters, read by the daemon
        right before it deleted the session (None if it could not)."""
        with self.lock:
            for idx in [i for i, s in self.live.items() if s["key"] == key]:
                del self.live[idx]
                self.final[idx] = {"until": self.now(), "counters": counters}
            self._expire()

    def _expire(self):
        t = self.now()
        for idx in [i for i, f in self.final.items()
                    if t - f["until"] > FINAL_KEEP]:
            del self.final[idx]
        # an id whose session is neither in VPP nor remembered: gone for
        # good, or (kernel-forwarded) never mirrored
        for asid in [a for a, (idx, seen) in self.bound.items()
                     if idx not in self.live and idx not in self.final
                     and t - seen > FINAL_KEEP]:
            del self.bound[asid]

    # -- relay side --------------------------------------------------------
    def counters(self, asid, ifname, status):
        """(in_octets, out_octets, in_packets, out_packets) to add to an
        accounting record, or None to leave it alone."""
        with self.lock:
            b = self.bound.get(asid)
            if b is None:
                # first sighting of this id. In a start or interim record
                # the netdev named there is the session's own; in a stop
                # record it may already be gone or belong to a new session
                if status == STATUS_STOP:
                    return None
                idx = self.ifindex_of(ifname)
                if idx is None:
                    return None
                b = self.bound[asid] = (idx, self.now())
            idx = b[0]
            cur = self.live.get(idx)
            if cur is None:
                f = self.final.get(idx)
                return self._convert(f["counters"]) if f else None
            sw_if_index = cur["sw_if_index"]
        # outside the lock: a VPP call
        c = self.live_counters(sw_if_index)
        if c is None:
            # deleted between the two steps: its final counters are there now
            with self.lock:
                f = self.final.get(idx)
            return self._convert(f["counters"]) if f else None
        return self._convert(c)

    @staticmethod
    def _convert(c):
        if c is None:
            return None
        rx_packets, rx_bytes, tx_packets, tx_bytes = c
        return (rx_bytes, max(0, tx_bytes - tx_packets * ENCAP_OVERHEAD),
                rx_packets, tx_packets)


# ---------------------------------------------------------------------------
# the relay
# ---------------------------------------------------------------------------

def rewrite_request(data, secret, counters_for):
    """Return (datagram to forward, original authenticator or None). The
    second value is set when the request was rewritten, i.e. when the reply
    needs its authenticator recomputed. counters_for(asid, ifname, status)
    is AcctSessions.counters. Anything that is not an interim/stop
    Accounting-Request of a VPP session comes back unchanged."""
    pkt = parse_packet(data)
    if pkt is None:
        return data, None
    code, ident, auth, attrs = pkt
    if code != ACCOUNTING_REQUEST:
        return data, None
    status = _u32(_attr(attrs, ATTR_ACCT_STATUS_TYPE))
    asid = _attr(attrs, ATTR_ACCT_SESSION_ID)
    ifname = _attr(attrs, ATTR_NAS_PORT_ID)
    if asid is None or ifname is None \
            or status not in (STATUS_START, STATUS_STOP, STATUS_INTERIM):
        return data, None
    # the start record is only looked at: it is the first sighting of the id
    c = counters_for(asid.decode("latin-1"), ifname.decode("latin-1"), status)
    if status == STATUS_START or c is None:
        return data, None
    if request_authenticator(code, ident, attrs, secret) != auth:
        log.warning("accounting request with an authenticator that does not "
                    "match the configured secret: forwarded unchanged (VPP "
                    "counters NOT added); fix the secret")
        return data, None
    attrs = add_counters(attrs, *c)
    attrs = _sign_message_authenticator(code, ident, b"\0" * 16, attrs, secret)
    new_auth = request_authenticator(code, ident, attrs, secret)
    return build_packet(code, ident, new_auth, attrs), auth


def rewrite_reply(data, secret, orig_auth):
    """Recompute the reply authenticator for the request accel-ppp sent
    (orig_auth), after the server answered the rewritten one."""
    pkt = parse_packet(data)
    if pkt is None:
        return data
    code, ident, _, attrs = pkt
    attrs = _sign_message_authenticator(code, ident, orig_auth, attrs, secret)
    return build_packet(
        code, ident,
        response_authenticator(code, ident, attrs, orig_auth, secret), attrs)


class RadiusRelay(threading.Thread):
    """UDP relay between accel-ppp and the RADIUS servers. One upstream
    socket per client address, so RADIUS identifiers never clash and a reply
    finds its way back without touching the packet.

    listen:  address accel-ppp sends to (its `server=` line), usually
             127.0.0.1
    ports:   {"auth": port, "acct": port} to listen on
    servers: [(host, auth_port, acct_port), ...] tried in order; the relay
             moves to the next one after FAILOVER_AFTER unanswered requests
    source:  local address for the upstream sockets (the NAS address the
             server knows), or None
    device:  interface/VRF device to bind the upstream sockets to, or None
    """

    def __init__(self, listen, ports, servers, secret, counters_for,
                 source=None, device=None):
        super().__init__(name="l2tvppd-radius", daemon=True)
        self.servers = servers
        self.secret = secret
        self.counters_for = counters_for
        self.source = source
        self.device = device
        self.cur = 0            # index of the server in use
        self.unanswered = 0
        self.listeners = {}     # socket -> "auth" | "acct"
        for kind, port in ports.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((listen, port))
            self.listeners[s] = kind
        self.flows = {}         # (listener, client addr) -> flow
        self.by_upstream = {}   # upstream socket -> flow
        self.stop_flag = False
        self.stats = {"relayed": 0, "rewritten": 0, "replies": 0}

    def ports(self):
        """{"auth": port, "acct": port} really bound (for port 0 in tests)"""
        return {k: s.getsockname()[1] for s, k in self.listeners.items()}

    def _upstream_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self.device:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                         self.device.encode() + b"\0")
        if self.source:
            s.bind((self.source, 0))
        return s

    def _flow(self, listener, client):
        f = self.flows.get((listener, client))
        if f is None:
            f = {"listener": listener, "client": client,
                 "sock": self._upstream_socket(), "pending": {},
                 "used": time.monotonic()}
            self.flows[(listener, client)] = f
            self.by_upstream[f["sock"]] = f
        f["used"] = time.monotonic()
        return f

    def _from_client(self, listener):
        data, client = listener.recvfrom(4096)
        kind = self.listeners[listener]
        orig_auth = None
        if kind == "acct":
            try:
                data, orig_auth = rewrite_request(data, self.secret,
                                                  self.counters_for)
            except Exception:           # never lose a record over a bug here
                log.exception("accounting rewrite failed; forwarding as is")
        f = self._flow(listener, client)
        if len(data) >= 2:
            f["pending"][data[1]] = (orig_auth, time.monotonic())
        host, auth_port, acct_port = self.servers[self.cur]
        f["sock"].sendto(data, (host, acct_port if kind == "acct" else auth_port))
        self.stats["relayed"] += 1
        if orig_auth is not None:
            self.stats["rewritten"] += 1

    def _from_server(self, sock):
        data, _ = sock.recvfrom(4096)
        f = self.by_upstream.get(sock)
        if f is None or len(data) < 2:
            return
        orig_auth, _ = f["pending"].pop(data[1], (None, 0))
        if orig_auth is not None:
            data = rewrite_reply(data, self.secret, orig_auth)
        self.unanswered = 0
        f["listener"].sendto(data, f["client"])
        self.stats["replies"] += 1

    def _housekeeping(self):
        t = time.monotonic()
        for f in list(self.flows.values()):
            for ident in [i for i, (_, ts) in f["pending"].items()
                          if t - ts > PENDING_KEEP]:
                del f["pending"][ident]
                self.unanswered += 1
            if t - f["used"] > FLOW_IDLE and not f["pending"]:
                del self.flows[(f["listener"], f["client"])]
                del self.by_upstream[f["sock"]]
                f["sock"].close()
        if self.unanswered >= FAILOVER_AFTER and len(self.servers) > 1:
            self.cur = (self.cur + 1) % len(self.servers)
            self.unanswered = 0
            log.warning("RADIUS server not answering; now using %s",
                        self.servers[self.cur][0])

    def run(self):
        last = time.monotonic()
        while not self.stop_flag:
            socks = list(self.listeners) + list(self.by_upstream)
            try:
                ready, _, _ = select.select(socks, [], [], 1.0)
            except (OSError, ValueError):
                continue
            for s in ready:
                try:
                    if s in self.listeners:
                        self._from_client(s)
                    else:
                        self._from_server(s)
                except OSError as e:
                    log.warning("relay socket error: %s", e)
            if time.monotonic() - last >= 1.0:
                last = time.monotonic()
                self._housekeeping()

    def stop(self):
        self.stop_flag = True


def parse_server(text):
    """HOST[:AUTHPORT[:ACCTPORT]] -> (host, auth_port, acct_port)"""
    parts = text.split(":")
    host = parts[0]
    auth = int(parts[1]) if len(parts) > 1 and parts[1] else 1812
    acct = int(parts[2]) if len(parts) > 2 and parts[2] else 1813
    return host, auth, acct
