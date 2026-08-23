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
from scapy.layers.inet import IP, UDP
from scapy.layers.l2tp import L2TP
from scapy.layers.ppp import PPP

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


def ksession(peer_ip, ltid, lsid, ptid, psid, ifname, routes):
    return {"name": "", "peer_ip": peer_ip, "peer_port": L2TP_PORT,
            "local_tid": ltid, "local_sid": lsid, "peer_tid": ptid,
            "peer_sid": psid, "ifname": ifname, "routes": routes}


class TestL2tvppSyncd(VppTestCase):
    """l2tvppd reconcile drives the l2tvpp binary API correctly"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
        cls.vapi.ip_neighbor_add_del(
            cls.pg0.sw_if_index, cls.pg0.remote_mac, cls.pg0.remote_ip4,
            is_add=1, flags=1)
        cls.sync = l2tvppd.Syncd(cls.vapi, cls.pg0.local_ip4, L2TP_PORT)

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
