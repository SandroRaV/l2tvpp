# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the accounting relay (l2tvpp_acct.py). No VPP, no
accel-ppp, no RADIUS server needed:

    python3 syncd/test_acct.py
"""
import hashlib
import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import l2tvpp_acct as A  # noqa: E402

SECRET = b"radsecret"


def acct_request(status, asid=b"a1b2c3", ifname=b"l2tp0", ident=7,
                 in_octets=None, out_octets=None, in_pkts=None, out_pkts=None,
                 in_giga=None, out_giga=None, secret=SECRET, extra=()):
    attrs = [(1, b"usera@lab"),
             (A.ATTR_ACCT_STATUS_TYPE, struct.pack("!I", status)),
             (A.ATTR_ACCT_SESSION_ID, asid),
             (A.ATTR_NAS_PORT_ID, ifname)]
    for t, v in ((A.ATTR_ACCT_INPUT_OCTETS, in_octets),
                 (A.ATTR_ACCT_OUTPUT_OCTETS, out_octets),
                 (A.ATTR_ACCT_INPUT_PACKETS, in_pkts),
                 (A.ATTR_ACCT_OUTPUT_PACKETS, out_pkts),
                 (A.ATTR_ACCT_INPUT_GIGAWORDS, in_giga),
                 (A.ATTR_ACCT_OUTPUT_GIGAWORDS, out_giga)):
        if v is not None:
            attrs.append((t, struct.pack("!I", v)))
    attrs += list(extra)
    auth = A.request_authenticator(A.ACCOUNTING_REQUEST, ident, attrs, secret)
    return A.build_packet(A.ACCOUNTING_REQUEST, ident, auth, attrs)


def u32(attrs, t):
    return struct.unpack("!I", dict(attrs)[t])[0]


class TestPackets(unittest.TestCase):
    def test_parse_build_roundtrip(self):
        p = acct_request(A.STATUS_INTERIM, in_octets=5, out_octets=6)
        code, ident, auth, attrs = A.parse_packet(p)
        self.assertEqual((code, ident), (A.ACCOUNTING_REQUEST, 7))
        self.assertEqual(A.build_packet(code, ident, auth, attrs), p)

    def test_malformed_is_rejected(self):
        self.assertIsNone(A.parse_packet(b"\x04\x01\x00"))
        p = bytearray(acct_request(A.STATUS_INTERIM))
        p[21] = 1                       # attribute length below 2
        self.assertIsNone(A.parse_packet(bytes(p)))
        p = bytearray(acct_request(A.STATUS_INTERIM))
        p[21] = 250                     # attribute runs past the packet
        self.assertIsNone(A.parse_packet(bytes(p)))

    def test_add_counters_carries_into_gigawords(self):
        _, _, _, attrs = A.parse_packet(acct_request(
            A.STATUS_INTERIM, in_octets=0xFFFFFF00, out_octets=10,
            in_pkts=1, out_pkts=2, in_giga=1, out_giga=0))
        out = A.add_counters(attrs, 0x200, 5 * 2 ** 32 + 7, 100, 200)
        self.assertEqual(u32(out, A.ATTR_ACCT_INPUT_OCTETS), 0x100)
        self.assertEqual(u32(out, A.ATTR_ACCT_INPUT_GIGAWORDS), 2)
        self.assertEqual(u32(out, A.ATTR_ACCT_OUTPUT_OCTETS), 17)
        self.assertEqual(u32(out, A.ATTR_ACCT_OUTPUT_GIGAWORDS), 5)
        self.assertEqual(u32(out, A.ATTR_ACCT_INPUT_PACKETS), 101)
        self.assertEqual(u32(out, A.ATTR_ACCT_OUTPUT_PACKETS), 202)

    def test_add_counters_appends_missing_gigawords(self):
        _, _, _, attrs = A.parse_packet(acct_request(
            A.STATUS_INTERIM, in_octets=1, out_octets=1))
        out = A.add_counters(attrs, 3 * 2 ** 32, 5, 0, 0)
        self.assertEqual(u32(out, A.ATTR_ACCT_INPUT_GIGAWORDS), 3)
        # not needed, not added
        self.assertNotIn(A.ATTR_ACCT_OUTPUT_GIGAWORDS, dict(out))


class TestRewrite(unittest.TestCase):
    def counters(self, value):
        return lambda asid, ifname, status: value

    def test_interim_gets_vpp_counters_and_a_valid_authenticator(self):
        req = acct_request(A.STATUS_INTERIM, in_octets=100, out_octets=200,
                           in_pkts=1, out_pkts=2)
        new, orig = A.rewrite_request(req, SECRET,
                                      self.counters((1000, 2000, 10, 20)))
        self.assertEqual(orig, req[4:20])
        code, ident, auth, attrs = A.parse_packet(new)
        self.assertEqual(u32(attrs, A.ATTR_ACCT_INPUT_OCTETS), 1100)
        self.assertEqual(u32(attrs, A.ATTR_ACCT_OUTPUT_OCTETS), 2200)
        self.assertEqual(u32(attrs, A.ATTR_ACCT_INPUT_PACKETS), 11)
        self.assertEqual(u32(attrs, A.ATTR_ACCT_OUTPUT_PACKETS), 22)
        # what a RADIUS server checks
        self.assertEqual(
            hashlib.md5(new[:4] + b"\0" * 16 + new[20:] + SECRET).digest(),
            auth)

    def test_start_and_unknown_sessions_pass_unchanged(self):
        req = acct_request(A.STATUS_START)
        self.assertEqual(A.rewrite_request(
            req, SECRET, self.counters((1, 1, 1, 1))), (req, None))
        req = acct_request(A.STATUS_INTERIM, in_octets=1)
        self.assertEqual(A.rewrite_request(
            req, SECRET, self.counters(None)), (req, None))

    def test_wrong_secret_forwards_unchanged(self):
        req = acct_request(A.STATUS_STOP, in_octets=1, secret=b"other")
        with self.assertLogs("l2tvppd.acct", "WARNING"):
            self.assertEqual(A.rewrite_request(
                req, SECRET, self.counters((1, 1, 1, 1))), (req, None))

    def test_access_request_and_garbage_pass_unchanged(self):
        acc = A.build_packet(A.ACCESS_REQUEST, 1, b"R" * 16, [(1, b"u")])
        self.assertEqual(A.rewrite_request(acc, SECRET, None), (acc, None))
        self.assertEqual(A.rewrite_request(b"xx", SECRET, None), (b"xx", None))

    def test_reply_authenticator_matches_the_original_request(self):
        req = acct_request(A.STATUS_STOP, in_octets=1, out_octets=1)
        new, orig = A.rewrite_request(req, SECRET,
                                      self.counters((5, 5, 5, 5)))
        # the server answers the rewritten request
        srv = A.build_packet(
            A.ACCOUNTING_RESPONSE, 7,
            A.response_authenticator(A.ACCOUNTING_RESPONSE, 7, [],
                                     new[4:20], SECRET), [])
        back = A.rewrite_reply(srv, SECRET, orig)
        # what accel-ppp checks: against the authenticator IT sent
        self.assertEqual(
            hashlib.md5(back[:4] + req[4:20] + back[20:] + SECRET).digest(),
            back[4:20])

    def test_message_authenticator_is_resigned(self):
        import hmac
        req = acct_request(
            A.STATUS_INTERIM, in_octets=1,
            extra=[(A.ATTR_MESSAGE_AUTHENTICATOR, b"\0" * 16)])
        new, _ = A.rewrite_request(req, SECRET, self.counters((5, 5, 5, 5)))
        code, ident, auth, attrs = A.parse_packet(new)
        zeroed = [(t, b"\0" * 16 if t == A.ATTR_MESSAGE_AUTHENTICATOR else v)
                  for t, v in attrs]
        self.assertEqual(
            dict(attrs)[A.ATTR_MESSAGE_AUTHENTICATOR],
            hmac.new(SECRET, A.build_packet(code, ident, b"\0" * 16, zeroed),
                     hashlib.md5).digest())
        self.assertEqual(attrs[-1][0], A.ATTR_MESSAGE_AUTHENTICATOR)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class TestSessions(unittest.TestCase):
    """which VPP session an Acct-Session-Id belongs to"""

    def setUp(self):
        self.clock = Clock()
        self.vpp = {}                   # sw_if_index -> counters
        self.netdev = {}                # ifname -> ifindex, the kernel now
        self.s = A.AcctSessions(self.vpp.get, ifindex_of=self.netdev.get,
                                now=self.clock)

    def test_counters_are_converted(self):
        self.netdev["l2tp0"] = 40
        self.s.installed("1/1", "l2tp0", 10, 40)
        # rx 5 packets / 500 bytes, tx 4 packets / 1000 bytes on the wire
        self.vpp[10] = (5, 500, 4, 1000)
        self.assertEqual(self.s.counters("A", "l2tp0", A.STATUS_START),
                         (500, 1000 - 4 * A.ENCAP_OVERHEAD, 5, 4))

    def test_start_before_the_session_is_mirrored(self):
        self.netdev["l2tp0"] = 40
        self.assertIsNone(self.s.counters("A", "l2tp0", A.STATUS_START))
        self.clock.t += 3
        self.s.installed("1/1", "l2tp0", 10, 40)
        self.vpp[10] = (1, 100, 0, 0)
        self.clock.t += 300
        self.assertEqual(self.s.counters("A", "l2tp0", A.STATUS_INTERIM),
                         (100, 0, 1, 0))

    def test_stop_after_removal_gets_the_final_counters(self):
        self.netdev["l2tp0"] = 40
        self.s.installed("1/1", "l2tp0", 10, 40)
        self.s.counters("A", "l2tp0", A.STATUS_START)
        self.clock.t += 600
        del self.netdev["l2tp0"]
        self.s.removed("1/1", (9, 900, 8, 800 + 8 * A.ENCAP_OVERHEAD))
        self.assertEqual(self.s.counters("A", "l2tp0", A.STATUS_STOP),
                         (900, 800, 9, 8))

    def test_immediate_reconnect_on_the_same_netdev_name(self):
        """a CPE reconnects at once and gets the same netdev name and the
        same VPP interface index; the daemon has not yet noticed that the
        old session is gone when the new start record arrives, and the
        relay never saw a record of the old session"""
        self.netdev["l2tp0"] = 40
        self.s.installed("1/1", "l2tp0", 10, 40)
        self.vpp[10] = (9, 900, 0, 0)
        self.clock.t += 600
        # old session ends, new one comes up as l2tp0 with a new ifindex
        self.netdev["l2tp0"] = 48
        self.assertIsNone(self.s.counters("B", "l2tp0", A.STATUS_START))
        # the daemon catches up
        self.s.removed("1/1", (9, 900, 0, 0))
        self.s.installed("1/2", "l2tp0", 10, 48)
        self.vpp[10] = (1, 50, 0, 0)
        self.assertEqual(self.s.counters("B", "l2tp0", A.STATUS_INTERIM),
                         (50, 0, 1, 0))
        # the stop of the old session, id never seen before: left alone
        self.assertIsNone(self.s.counters("A", "l2tp0", A.STATUS_STOP))

    def test_reused_netdev_name_with_both_ids_known(self):
        self.netdev["l2tp0"] = 40
        self.s.installed("1/1", "l2tp0", 10, 40)
        self.s.counters("A", "l2tp0", A.STATUS_START)
        self.clock.t += 600
        self.s.removed("1/1", (9, 900, 0, 0))
        self.netdev["l2tp0"] = 48
        self.s.installed("1/2", "l2tp0", 10, 48)
        self.vpp[10] = (1, 50, 0, 0)
        self.s.counters("B", "l2tp0", A.STATUS_START)
        # the old stop arrives after the new session is already forwarding
        self.assertEqual(self.s.counters("A", "l2tp0", A.STATUS_STOP),
                         (900, 0, 9, 0))
        self.assertEqual(self.s.counters("B", "l2tp0", A.STATUS_INTERIM),
                         (50, 0, 1, 0))

    def test_relay_restart(self):
        """no start seen: an interim binds to the netdev of that name (the
        session is alive, the netdev is its own), a stop is left alone"""
        self.netdev["l2tp0"] = 40
        self.s.installed("1/1", "l2tp0", 10, 40)
        self.vpp[10] = (1, 100, 0, 0)
        self.clock.t += 500
        self.assertIsNone(self.s.counters("OLD", "l2tp0", A.STATUS_STOP))
        self.assertEqual(self.s.counters("A", "l2tp0", A.STATUS_INTERIM),
                         (100, 0, 1, 0))

    def test_kernel_forwarded_session_is_left_alone(self):
        self.netdev["ppp7"] = 60
        self.assertIsNone(self.s.counters("A", "ppp7", A.STATUS_START))
        self.assertIsNone(self.s.counters("A", "ppp7", A.STATUS_INTERIM))
        self.assertIsNone(self.s.counters("B", "gone0", A.STATUS_START))

    def test_session_without_an_interface_index_gets_nothing(self):
        self.netdev["l2tp0"] = 40
        self.s.installed("1/1", "l2tp0", 10)        # index unknown
        self.vpp[10] = (1, 100, 0, 0)
        self.assertIsNone(self.s.counters("A", "l2tp0", A.STATUS_START))

    def test_final_counters_expire(self):
        self.netdev["l2tp0"] = 40
        self.s.installed("1/1", "l2tp0", 10, 40)
        self.s.counters("A", "l2tp0", A.STATUS_START)
        self.s.removed("1/1", (1, 1, 1, 100))
        self.clock.t += A.FINAL_KEEP + 1
        self.s.installed("1/9", "l2tp9", 19, 49)
        self.s.removed("1/9", None)                 # triggers the cleanup
        self.assertEqual(list(self.s.final), [49])
        self.assertNotIn("A", self.s.bound)

    def test_sysfs_ifindex(self):
        self.assertIsNone(A.sysfs_ifindex("no-such-netdev0"))
        self.assertIsNone(A.sysfs_ifindex("../../etc/passwd"))


class FakeServer(threading.Thread):
    """answers every Accounting-Request like a RADIUS server would, if its
    authenticator is right, and keeps what it received"""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.got = []
        self.alive = True
        self.silent = False

    def run(self):
        while self.alive:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            self.got.append(data)
            code, ident, auth, attrs = A.parse_packet(data)
            if self.silent:
                continue
            if code == A.ACCOUNTING_REQUEST:
                if A.request_authenticator(code, ident, attrs, SECRET) != auth:
                    continue            # a real server drops it
                rcode = A.ACCOUNTING_RESPONSE
            else:
                rcode = 2               # Access-Accept
            self.sock.sendto(A.build_packet(
                rcode, ident,
                A.response_authenticator(rcode, ident, [], auth, SECRET), []),
                addr)


class TestRelay(unittest.TestCase):
    def setUp(self):
        self.srv = FakeServer()
        self.srv.start()
        self.counters = {"value": (1000, 2000, 10, 20)}
        self.relay = A.RadiusRelay(
            "127.0.0.1", {"auth": 0, "acct": 0},
            [("127.0.0.1", self.srv.port, self.srv.port)], SECRET,
            lambda asid, ifname, status: self.counters["value"])
        self.relay.start()
        self.cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.cli.settimeout(3)

    def tearDown(self):
        self.relay.stop()
        self.srv.alive = False
        self.cli.close()

    def ask(self, kind, data):
        self.cli.sendto(data, ("127.0.0.1", self.relay.ports()[kind]))
        return self.cli.recvfrom(4096)[0]

    def test_accounting_round_trip(self):
        req = acct_request(A.STATUS_INTERIM, in_octets=1, out_octets=2,
                           in_pkts=3, out_pkts=4)
        back = self.ask("acct", req)
        # the server saw the VPP counters added ...
        _, _, _, attrs = A.parse_packet(self.srv.got[-1])
        self.assertEqual(u32(attrs, A.ATTR_ACCT_INPUT_OCTETS), 1001)
        self.assertEqual(u32(attrs, A.ATTR_ACCT_OUTPUT_OCTETS), 2002)
        # ... and the reply verifies against the request accel-ppp sent
        self.assertEqual(back[0], A.ACCOUNTING_RESPONSE)
        self.assertEqual(
            hashlib.md5(back[:4] + req[4:20] + back[20:] + SECRET).digest(),
            back[4:20])
        self.assertEqual(self.relay.stats["rewritten"], 1)

    def test_unknown_session_and_auth_pass_through(self):
        self.counters["value"] = None
        req = acct_request(A.STATUS_INTERIM, in_octets=1)
        back = self.ask("acct", req)
        self.assertEqual(self.srv.got[-1], req)
        self.assertEqual(
            hashlib.md5(back[:4] + req[4:20] + back[20:] + SECRET).digest(),
            back[4:20])
        acc = A.build_packet(A.ACCESS_REQUEST, 9, b"R" * 16, [(1, b"u")])
        back = self.ask("auth", acc)
        self.assertEqual(self.srv.got[-1], acc)
        self.assertEqual(back[0], 2)
        self.assertEqual(self.relay.stats["rewritten"], 0)

    def test_failover_to_the_next_server(self):
        second = FakeServer()
        second.start()
        try:
            self.relay.servers.append(("127.0.0.1", second.port, second.port))
            self.srv.silent = True
            old = A.PENDING_KEEP
            A.PENDING_KEEP = 0.2
            try:
                for i in range(A.FAILOVER_AFTER):
                    self.cli.sendto(
                        acct_request(A.STATUS_INTERIM, ident=i, in_octets=1),
                        ("127.0.0.1", self.relay.ports()["acct"]))
                deadline = 50
                while self.relay.cur == 0 and deadline:
                    threading.Event().wait(0.1)
                    deadline -= 1
            finally:
                A.PENDING_KEEP = old
            self.assertEqual(self.relay.cur, 1)
            back = self.ask("acct", acct_request(A.STATUS_INTERIM, ident=99,
                                                 in_octets=1))
            self.assertEqual(back[0], A.ACCOUNTING_RESPONSE)
            self.assertEqual(len(second.got), 1)
        finally:
            second.alive = False


if __name__ == "__main__":
    unittest.main()
