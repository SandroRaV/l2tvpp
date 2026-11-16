# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
"""
VPP make-test for l2tvppd's reconcile against the live l2tvpp plugin. This
exercises the real integration point - the daemon programming VPP over the
binary API - without needing accel-ppp: a mock kernel-session list is fed to
Syncd.reconcile() and the resulting VPP state (session dump + FIB + a
forwarded packet) is checked.

    make test TEST=test_l2tvpp_syncd
"""
import os
import sys
import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, ICMP
from scapy.packet import Raw
from scapy.layers.l2tp import L2TP
from scapy.layers.ppp import PPP, HDLC

# find the syncd dir whether the test is symlinked into vpp/test/ (dev loop:
# ../syncd is the repo's) or copied there by CI (../syncd sits beside test/)
_here = os.path.dirname(os.path.realpath(__file__))
for _cand in (os.path.join(_here, "..", "syncd"),
              os.path.join(os.path.dirname(__file__), "..", "syncd")):
    if os.path.exists(os.path.join(_cand, "l2tvppd.py")):
        sys.path.insert(0, _cand)
        break
import l2tvppd  # noqa: E402

L2TP_PORT = 1701


def ksession(peer_ip, ltid, lsid, ptid, psid, ifname, routes, table=0,
             mtu=None, ifindex=None):
    # table, mtu and ifindex are what kernel_links() reads off the session
    # netdev
    return {"name": "", "peer_ip": peer_ip, "peer_port": L2TP_PORT,
            "local_tid": ltid, "local_sid": lsid, "peer_tid": ptid,
            "peer_sid": psid, "ifname": ifname, "routes": routes,
            "table": table, "mtu": mtu, "ifindex": ifindex}


class TestL2tvppSyncd(VppTestCase):
    """l2tvppd reconcile drives the l2tvpp binary API correctly"""

    VRF = 77

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(3))
        # pg2: an uplink inside a VRF
        cls.vapi.ip_table_add_del(is_add=True, table={"table_id": cls.VRF})
        cls.pg2.set_table_ip4(cls.VRF)
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
        cls.vapi.ip_neighbor_add_del(
            cls.pg0.sw_if_index, cls.pg0.remote_mac, cls.pg0.remote_ip4,
            is_add=1, flags=1)
        cls.sync = l2tvppd.Syncd(cls.vapi, cls.pg0.local_ip4, L2TP_PORT)

    def l2tp_data(self, lsid, src, dst):
        return (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                / IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4)
                / UDP(sport=L2TP_PORT, dport=L2TP_PORT)
                / L2TP(hdr="", tunnel_id=100, session_id=lsid)
                / HDLC() / PPP(proto=0x0021)
                / IP(src=src, dst=dst) / UDP(sport=1234, dport=5678))

    def tearDown(self):
        # leave VPP clean between tests: reconcile to an empty kernel
        self.sync.reconcile([])
        super().tearDown()

    def test_reconcile_adds_then_removes(self):
        """two sessions in one tunnel appear, then are removed"""
        sub_a, sub_b = "10.200.0.5/32", "10.200.0.6/32"
        ks = [
            ksession(self.pg0.remote_ip4, 100, 1000, 200, 2000, "ppp0", [sub_a]),
            ksession(self.pg0.remote_ip4, 100, 1001, 200, 2001, "ppp1", [sub_b]),
        ]
        added, removed = self.sync.reconcile(ks)
        self.assertEqual((added, removed), (2, 0))

        sessions = self.vapi.l2tvpp_session_dump(sw_if_index=0xFFFFFFFF)
        self.assertEqual(len(sessions), 2)
        # one tunnel shared by both
        self.assertEqual(len({s.tunnel_index for s in sessions}), 1)

        # idempotent: a second pass changes nothing
        self.assertEqual(self.sync.reconcile(ks), (0, 0))

        # drop one session; reconcile removes exactly it
        added, removed = self.sync.reconcile([ks[0]])
        self.assertEqual((added, removed), (0, 1))
        self.assertEqual(len(self.vapi.l2tvpp_session_dump(sw_if_index=0xFFFFFFFF)), 1)

    def test_reconciled_session_forwards(self):
        """a session installed purely via reconcile actually encaps traffic"""
        sub = "10.200.0.9"
        ks = [ksession(self.pg0.remote_ip4, 100, 1000, 200, 2000, "ppp0",
                       [sub + "/32"])]
        self.sync.reconcile(ks)

        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
             / IP(src=self.pg1.remote_ip4, dst=sub) / UDP(sport=5678, dport=1234))
        self.pg_enable_capture(self.pg_interfaces)
        self.pg1.add_stream([p] * 5)
        self.pg_start()
        rx = self.pg0.get_capture(5)
        for r in rx:
            self.assertEqual(r[UDP].dport, L2TP_PORT)
            self.assertEqual(r[L2TP].tunnel_id, 200)
            self.assertEqual(r[L2TP].session_id, 2000)
            self.assertEqual(r[PPP][IP].dst, sub)

    def test_source_validation_is_on_by_default(self):
        """a reconciled session can only send from what is routed at it;
        the same holds for a later session that reuses its interface index
        (the urpf plugin keeps per-index state across an interface delete)"""
        sub = "10.200.0.20"
        for lsid in (1000, 1001):
            ks = [ksession(self.pg0.remote_ip4, 100, lsid, 200, lsid + 1000,
                           "ppp0", [sub + "/32"])]
            self.sync.reconcile(ks)
            self.send_and_expect(
                self.pg0, [self.l2tp_data(lsid, sub, self.pg1.remote_ip4)] * 5,
                self.pg1)
            self.send_and_assert_no_replies(
                self.pg0,
                [self.l2tp_data(lsid, "10.200.0.99", self.pg1.remote_ip4)] * 5)
            self.sync.reconcile([])

    def test_session_enters_and_leaves_a_vrf(self):
        """the netdev is enslaved to a VRF: the daemon binds the session
        and its routes to that table, and the session forwards there in
        both directions with source validation on; a later pass without
        the VRF moves everything back"""
        sub = "10.200.0.21"

        def fib(table):
            out = self.vapi.cli("show ip fib table %d %s/32" % (table, sub))
            return ("%s/32" % sub) in out and "l2tvpp" in out

        def ks(table):
            return [ksession(self.pg0.remote_ip4, 100, 1000, 200, 2000,
                             "ppp0", [sub + "/32"], table=table)]

        self.sync.reconcile(ks(77))
        self.assertTrue(fib(77))
        self.assertFalse(fib(0))
        # subscriber <-> the uplink in its VRF
        self.send_and_expect(
            self.pg0, [self.l2tp_data(1000, sub, self.pg2.remote_ip4)] * 5,
            self.pg2)
        v = (Ether(src=self.pg2.remote_mac, dst=self.pg2.local_mac)
             / IP(src=self.pg2.remote_ip4, dst=sub) / UDP(sport=5678, dport=1234))
        self.send_and_expect(self.pg2, [v] * 5, self.pg0)
        # a spoofed source is still dropped inside the VRF
        self.send_and_assert_no_replies(
            self.pg0,
            [self.l2tp_data(1000, "10.200.0.99", self.pg2.remote_ip4)] * 5)
        # not reachable from the default table
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
             / IP(src=self.pg1.remote_ip4, dst=sub) / UDP(sport=5678, dport=1234))
        self.send_and_assert_no_replies(self.pg1, [p] * 5)
        self.assertEqual(self.sync.reconcile(ks(0)), (0, 0))
        self.assertTrue(fib(0))
        self.assertFalse(fib(77))
        self.send_and_expect(self.pg1, [p] * 5, self.pg0)
        self.send_and_expect(
            self.pg0, [self.l2tp_data(1000, sub, self.pg1.remote_ip4)] * 5,
            self.pg1)
        self.sync.reconcile([])
        self.assertFalse(fib(0))

    def test_missing_vrf_table_is_created(self):
        """a VRF whose table VPP does not have yet (VyOS creates it only
        for VRFs with VPP interfaces of their own)"""
        sub = "10.200.0.24"
        self.sync.reconcile([ksession(
            self.pg0.remote_ip4, 100, 1000, 200, 2000, "ppp0", [sub + "/32"],
            table=88)])
        out = self.vapi.cli("show ip fib table 88 %s/32" % sub)
        self.assertIn("l2tvpp", out)

    def test_mtu_from_the_netdev(self):
        sub = "10.200.0.22"
        ks = [ksession(self.pg0.remote_ip4, 100, 1000, 200, 2000, "ppp0",
                       [sub + "/32"], mtu=1300)]
        self.sync.reconcile(ks)
        big = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
               / IP(src=self.pg1.remote_ip4, dst=sub, flags="DF")
               / UDP(sport=5678, dport=1234) / Raw(b"x" * 1350))
        rx = self.send_and_expect(self.pg1, [big], self.pg1)
        self.assertEqual(rx[0][ICMP].nexthopmtu, 1300)
        # the netdev MTU changes (LCP renegotiated): the next pass follows
        ks[0]["mtu"] = 1400
        self.sync.reconcile(ks)
        self.send_and_expect(self.pg1, [big], self.pg0)

    def test_final_counters_reach_the_accounting_relay(self):
        """the daemon hands a session's last counters to the relay when it
        removes the session from VPP (the stop record needs them)"""
        import l2tvpp_acct
        sub = "10.200.0.23"
        acct = l2tvpp_acct.AcctSessions(self.sync.session_counters,
                                        ifindex_of={"ppp0": 40}.get)
        self.sync.acct = acct
        try:
            ks = [ksession(self.pg0.remote_ip4, 100, 1000, 200, 2000, "ppp0",
                           [sub + "/32"], ifindex=40)]
            self.sync.reconcile(ks)
            # the start record: first sighting of the Acct-Session-Id
            acct.counters("ASID1", "ppp0", l2tvpp_acct.STATUS_START)
            up = [self.l2tp_data(1000, sub, self.pg1.remote_ip4)] * 6
            inner = len(up[0][PPP][IP])
            self.send_and_expect(self.pg0, up, self.pg1)
            down = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
                    / IP(src=self.pg1.remote_ip4, dst=sub)
                    / UDP(sport=5678, dport=1234) / Raw(b"x" * 172))
            self.send_and_expect(self.pg1, [down] * 4, self.pg0)
            want = (6 * inner, 4 * 200, 6, 4)
            # interim: read live from VPP
            self.assertEqual(acct.counters(
                "ASID1", "ppp0", l2tvpp_acct.STATUS_INTERIM), want)
            # stop, after the daemon removed the session
            self.sync.reconcile([])
            self.assertEqual(acct.counters(
                "ASID1", "ppp0", l2tvpp_acct.STATUS_STOP), want)
        finally:
            self.sync.acct = None

    def test_reconcile_churn(self):
        """repeated full add/remove cycles stay correct (safety-net loop)"""
        ks = [ksession(self.pg0.remote_ip4, 100, 1000, 200, 2000, "ppp0",
                       ["10.200.0.5/32"])]
        for _ in range(3):
            self.assertEqual(self.sync.reconcile(ks), (1, 0))
            self.assertEqual(len(self.vapi.l2tvpp_session_dump(sw_if_index=0xFFFFFFFF)), 1)
            self.assertEqual(self.sync.reconcile([]), (0, 1))
            self.assertEqual(len(self.vapi.l2tvpp_session_dump(sw_if_index=0xFFFFFFFF)), 0)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
