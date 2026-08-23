# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
"""
VPP make-test suite for the l2tvpp plugin (scapy, no NIC needed).

    make test TEST=test_l2tvpp V=1

Topology: pg0 is the access side (the LAC lives at pg0.remote), pg1 is the
core/uplink. One L2TPv2 tunnel + session is set up once for the class; the
subscriber 10.200.0.5/32 routes out the session interface.
"""
import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.l2tp import L2TP
from scapy.layers.ppp import PPP, HDLC
from vpp_ip_route import VppIpRoute, VppRoutePath
from vpp_neighbor import VppNeighbor

L2TP_PORT = 1701
LOCAL_TID, PEER_TID = 100, 200
LOCAL_SID, PEER_SID = 1000, 2000
SUB_IP = "10.200.0.5"


class TestL2tvpp(VppTestCase):
    """L2TPv2 LNS data plane"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
        cls.lac = cls.pg0        # access side, LAC lives here
        cls.core = cls.pg1       # uplink
        # static neighbor for the LAC: its MAC is known, keeps the encap
        # midchain stacked on a complete adjacency
        # static neighbor for the LAC via raw vapi (not a VppNeighbor object)
        # so the per-test registry cleanup does not remove it between methods
        cls.vapi.ip_neighbor_add_del(
            cls.pg0.sw_if_index, cls.pg0.remote_mac, cls.pg0.remote_ip4,
            is_add=1, flags=1)

        # one tunnel + session + subscriber route for the whole class. The
        # route is added with a raw ip_route_add_del (not a VppIpRoute object)
        # so the per-test registry cleanup does not tear it down between
        # methods. Session churn is covered by TestL2tvppAddDel.
        cls.tunnel = cls.vapi.l2tvpp_tunnel_add_del(
            is_add=True, local_ip=cls.lac.local_ip4, peer_ip=cls.lac.remote_ip4,
            local_port=L2TP_PORT, peer_port=L2TP_PORT,
            local_tid=LOCAL_TID, peer_tid=PEER_TID).tunnel_index
        cls.session = cls.vapi.l2tvpp_session_add_del(
            is_add=True, tunnel_index=cls.tunnel,
            local_sid=LOCAL_SID, peer_sid=PEER_SID,
            acfc=False, pfc=False).sw_if_index
        cls.sub_path = VppRoutePath("0.0.0.0", cls.session).encode()
        cls.sub_prefix = {"address": {"un": {"ip4": SUB_IP}, "af": 0},
                          "len": 32}
        cls.vapi.ip_route_add_del(
            is_add=1, is_multipath=0,
            route={"table_id": 0, "prefix": cls.sub_prefix,
                   "n_paths": 1, "paths": [cls.sub_path]})

    @classmethod
    def tearDownClass(cls):
        try:
            cls.vapi.ip_route_add_del(
                is_add=0, is_multipath=0,
                route={"table_id": 0, "prefix": cls.sub_prefix,
                       "n_paths": 1, "paths": [cls.sub_path]})
            cls.vapi.ip_neighbor_add_del(
                cls.pg0.sw_if_index, cls.pg0.remote_mac, cls.pg0.remote_ip4,
                is_add=0, flags=1)
            cls.vapi.l2tvpp_session_add_del(
                is_add=False, tunnel_index=cls.tunnel,
                local_sid=LOCAL_SID, peer_sid=PEER_SID)
            cls.vapi.l2tvpp_tunnel_add_del(
                is_add=False, local_ip=cls.lac.local_ip4,
                peer_ip=cls.lac.remote_ip4, local_port=L2TP_PORT,
                peer_port=L2TP_PORT, local_tid=LOCAL_TID, peer_tid=PEER_TID)
        finally:
            super().tearDownClass()

    def l2tp_data(self, inner):
        """LAC -> LNS: an L2TPv2 data packet carrying PPP/IPv4"""
        return (
            Ether(src=self.lac.remote_mac, dst=self.lac.local_mac)
            / IP(src=self.lac.remote_ip4, dst=self.lac.local_ip4)
            / UDP(sport=L2TP_PORT, dport=L2TP_PORT)
            / L2TP(hdr="", tunnel_id=LOCAL_TID, session_id=LOCAL_SID)
            / HDLC()
            / PPP(proto=0x0021)
            / inner)

    def test_upstream_decap(self):
        """LAC -> LNS: IPv4 in PPP in L2TP is decapsulated and routed"""
        inner = IP(src=SUB_IP, dst=self.core.remote_ip4) / UDP(sport=1234, dport=5678)
        self.pg_enable_capture(self.pg_interfaces)
        self.lac.add_stream([self.l2tp_data(inner)] * 10)
        self.pg_start()
        rx = self.core.get_capture(10)
        for p in rx:
            self.assertEqual(p[IP].src, SUB_IP)
            self.assertEqual(p[IP].dst, self.core.remote_ip4)
            self.assertFalse(p.haslayer(L2TP))

    def test_downstream_encap(self):
        """core -> subscriber: routed via session interface, L2TP/PPP encap"""
        p = (Ether(src=self.core.remote_mac, dst=self.core.local_mac)
             / IP(src=self.core.remote_ip4, dst=SUB_IP)
             / UDP(sport=5678, dport=1234))
        self.pg_enable_capture(self.pg_interfaces)
        self.core.add_stream([p] * 10)
        self.pg_start()
        rx = self.lac.get_capture(10)
        for r in rx:
            self.assertEqual(r[IP].dst, self.lac.remote_ip4)
            self.assertEqual(r[UDP].dport, L2TP_PORT)
            self.assertEqual(r[L2TP].tunnel_id, PEER_TID)
            self.assertEqual(r[L2TP].session_id, PEER_SID)
            self.assertEqual(r[PPP].proto, 0x0021)
            self.assertEqual(r[PPP][IP].dst, SUB_IP)

    def test_control_is_punted(self):
        """L2TP control message (T bit) must not be consumed by the plugin"""
        ctrl = (Ether(src=self.lac.remote_mac, dst=self.lac.local_mac)
                / IP(src=self.lac.remote_ip4, dst=self.lac.local_ip4)
                / UDP(sport=L2TP_PORT, dport=L2TP_PORT)
                / L2TP(hdr="control+length+sequence",
                       tunnel_id=LOCAL_TID, session_id=0, ns=1, nr=1))
        self.pg_enable_capture(self.pg_interfaces)
        self.lac.add_stream([ctrl])
        self.pg_start()
        self.core.assert_nothing_captured()
        self.assertIn("control message, punted", self.vapi.cli("show errors"))

    def test_unknown_session_is_punted(self):
        """unknown session id: not decapsulated"""
        inner = IP(src=SUB_IP, dst=self.core.remote_ip4) / UDP()
        pkt = self.l2tp_data(inner)
        pkt[L2TP].session_id = 9999
        self.pg_enable_capture(self.pg_interfaces)
        self.lac.add_stream([pkt])
        self.pg_start()
        self.core.assert_nothing_captured()

    def test_lcp_is_punted(self):
        """PPP LCP (0xc021) inside a known session goes to the control plane"""
        pkt = self.l2tp_data(IP())
        pkt[PPP].proto = 0xC021
        self.pg_enable_capture(self.pg_interfaces)
        self.lac.add_stream([pkt])
        self.pg_start()
        self.core.assert_nothing_captured()


class TestL2tvppAddDel(VppTestCase):
    """l2tvpp session churn: repeated add/del must not corrupt forwarding"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_pg_interfaces(range(2))
        for i in cls.pg_interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
        cls.nbr = VppNeighbor(cls, cls.pg0.sw_if_index, cls.pg0.remote_mac,
                              cls.pg0.remote_ip4, is_static=True)
        cls.nbr.add_vpp_config()

    def test_add_del_add(self):
        """create, tear down, and recreate a session; encap must still work"""
        for iteration in range(3):
            ti = self.vapi.l2tvpp_tunnel_add_del(
                is_add=True, local_ip=self.pg0.local_ip4,
                peer_ip=self.pg0.remote_ip4, local_port=L2TP_PORT,
                peer_port=L2TP_PORT, local_tid=LOCAL_TID,
                peer_tid=PEER_TID).tunnel_index
            swif = self.vapi.l2tvpp_session_add_del(
                is_add=True, tunnel_index=ti, local_sid=LOCAL_SID,
                peer_sid=PEER_SID, acfc=False, pfc=False).sw_if_index
            route = VppIpRoute(self, SUB_IP, 32,
                               [VppRoutePath("0.0.0.0", swif)])
            route.add_vpp_config()

            p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
                 / IP(src=self.pg1.remote_ip4, dst=SUB_IP)
                 / UDP(sport=5678, dport=1234))
            self.pg_enable_capture(self.pg_interfaces)
            self.pg1.add_stream([p] * 5)
            self.pg_start()
            rx = self.pg0.get_capture(5)
            for r in rx:
                self.assertEqual(r[L2TP].session_id, PEER_SID,
                                 f"iteration {iteration}")

            route.remove_vpp_config()
            self.vapi.l2tvpp_session_add_del(
                is_add=False, tunnel_index=ti, local_sid=LOCAL_SID,
                peer_sid=PEER_SID)
            self.vapi.l2tvpp_tunnel_add_del(
                is_add=False, local_ip=self.pg0.local_ip4,
                peer_ip=self.pg0.remote_ip4, local_port=L2TP_PORT,
                peer_port=L2TP_PORT, local_tid=LOCAL_TID, peer_tid=PEER_TID)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
