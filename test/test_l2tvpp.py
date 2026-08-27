# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
"""
VPP make-test suite for the l2tvpp plugin (scapy, no NIC needed).

    make test TEST=test_l2tvpp V=1

Topology: pg0 is the access side (the LAC lives at pg0.remote), pg1 is the
core/uplink. One L2TPv2 tunnel + session is set up once for the class; the
subscriber 10.200.0.5/32 routes out the session interface.
"""
import struct
import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.l2tp import L2TP
from scapy.layers.ppp import PPP, HDLC
from scapy.packet import Raw
from vpp_ip import VppIpPuntRedirect
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

        # one tunnel + session + subscriber route for the whole class, all
        # added with raw vapi calls (no Vpp* objects) so the per-test
        # registry cleanup does not tear them down between methods. Session
        # churn is covered by TestL2tvppAddDel.
        cls.tunnel = cls.vapi.l2tvpp_tunnel_add_del(
            is_add=True, local_ip=cls.lac.local_ip4, peer_ip=cls.lac.remote_ip4,
            local_port=L2TP_PORT, peer_port=L2TP_PORT,
            local_tid=LOCAL_TID, peer_tid=PEER_TID).tunnel_index
        cls.session = cls.vapi.l2tvpp_session_add_del(
            is_add=True, tunnel_index=cls.tunnel,
            local_sid=LOCAL_SID, peer_sid=PEER_SID,
            acfc=False, pfc=False).sw_if_index
        cls.vapi.l2tvpp_route_add_del(
            is_add=True, prefix=SUB_IP + "/32", sw_if_index=cls.session)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.vapi.l2tvpp_route_add_del(
                is_add=False, prefix=SUB_IP + "/32", sw_if_index=cls.session)
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

    def test_sequenced_data_decaps(self):
        """data with the S bit (Ns/Nr present) is decapsulated, not punted:
        Cisco LACs (ASR1001-X) sequence their data packets, and punting
        them sent all upstream traffic through the kernel (Viavi bench
        2026-08-25)"""
        inner = IP(src=SUB_IP, dst=self.core.remote_ip4) / UDP(sport=1, dport=2)
        pkt = (Ether(src=self.lac.remote_mac, dst=self.lac.local_mac)
               / IP(src=self.lac.remote_ip4, dst=self.lac.local_ip4)
               / UDP(sport=L2TP_PORT, dport=L2TP_PORT)
               / L2TP(hdr="length+sequence", tunnel_id=LOCAL_TID,
                      session_id=LOCAL_SID, ns=7, nr=3)
               / HDLC() / PPP(proto=0x0021) / inner)
        self.pg_enable_capture(self.pg_interfaces)
        self.lac.add_stream([pkt] * 10)
        self.pg_start()
        rx = self.core.get_capture(10)
        for p in rx:
            self.assertEqual(p[IP].src, SUB_IP)
            self.assertFalse(p.haslayer(L2TP))
        self.assertIn("sequenced, decapsulated", self.vapi.cli("show errors"))

    def test_offset_data_decaps(self):
        """data with the O bit (offset size 0, the other Cisco quirk -
        found on the ASR1001-X after the S fix, Viavi bench 2026-08-27)
        is decapsulated, not punted"""
        inner = IP(src=SUB_IP, dst=self.core.remote_ip4) / UDP(sport=1, dport=2)
        # flags O|ver2, tid, sid, offset size 0 - raw-crafted, scapy's L2TP
        # layer does not model the offset field
        hdr = struct.pack('!HHHH', 0x0202, LOCAL_TID, LOCAL_SID, 0)
        pkt = (Ether(src=self.lac.remote_mac, dst=self.lac.local_mac)
               / IP(src=self.lac.remote_ip4, dst=self.lac.local_ip4)
               / UDP(sport=L2TP_PORT, dport=L2TP_PORT)
               / Raw(hdr + b'\xff\x03\x00\x21' + bytes(inner)))
        self.pg_enable_capture(self.pg_interfaces)
        self.lac.add_stream([pkt] * 10)
        self.pg_start()
        rx = self.core.get_capture(10)
        for p in rx:
            self.assertEqual(p[IP].src, SUB_IP)
        self.assertIn("offset, decapsulated", self.vapi.cli("show errors"))

    def test_all_data_flag_combinations(self):
        """every legal L2TPv2 DATA header flag combination must decap:
        all 16 of L/S/O/P, and for O both an empty and a 4-byte offset
        pad - LACs differ in which they set (BNG Blaster: none; Cisco
        ASR1001-X: O; other IOS builds: S)"""
        inner = IP(src=SUB_IP, dst=self.core.remote_ip4) / UDP(sport=1, dport=2)
        pkts = []
        for l_bit in (0, 1):
            for s_bit in (0, 1):
                for o_bit in (0, 1):
                    for p_bit in (0, 1):
                        for pad in ((0, 4) if o_bit else (0,)):
                            flags = (0x0002 | (0x4000 if l_bit else 0)
                                     | (0x0800 if s_bit else 0)
                                     | (0x0200 if o_bit else 0)
                                     | (0x0100 if p_bit else 0))
                            # order per RFC 2661: flags [len] tid sid
                            # [Ns Nr] [offset size + pad] payload
                            rest = struct.pack('!HH', LOCAL_TID, LOCAL_SID)
                            if s_bit:
                                rest += struct.pack('!HH', 0, 0)
                            if o_bit:
                                rest += struct.pack('!H', pad) + b'\x00' * pad
                            rest += b'\xff\x03\x00\x21' + bytes(inner)
                            hdr = struct.pack('!H', flags)
                            if l_bit:
                                hdr += struct.pack('!H', 2 + 2 + len(rest))
                            pkts.append(
                                Ether(src=self.lac.remote_mac,
                                      dst=self.lac.local_mac)
                                / IP(src=self.lac.remote_ip4,
                                     dst=self.lac.local_ip4)
                                / UDP(sport=L2TP_PORT, dport=L2TP_PORT)
                                / Raw(hdr + rest))
        self.pg_enable_capture(self.pg_interfaces)
        self.lac.add_stream(pkts)
        self.pg_start()
        rx = self.core.get_capture(len(pkts))
        for p in rx:
            self.assertEqual(p[IP].src, SUB_IP)
            self.assertFalse(p.haslayer(L2TP))

    def test_offset_garbage_size_dropped(self):
        """an offset size pointing past the buffer must drop, not decap
        or crash (the S/O advances are attacker-controlled)"""
        hdr = struct.pack('!HHHH', 0x0202, LOCAL_TID, LOCAL_SID, 0xFFFF)
        pkt = (Ether(src=self.lac.remote_mac, dst=self.lac.local_mac)
               / IP(src=self.lac.remote_ip4, dst=self.lac.local_ip4)
               / UDP(sport=L2TP_PORT, dport=L2TP_PORT)
               / Raw(hdr + b'\x00' * 32))
        self.pg_enable_capture(self.pg_interfaces)
        self.lac.add_stream([pkt])
        self.pg_start()
        self.core.assert_nothing_captured()
        self.assertIn("truncated, dropped", self.vapi.cli("show errors"))

    def test_lcp_is_punted(self):
        """PPP LCP (0xc021) inside a known session goes to the control plane"""
        pkt = self.l2tp_data(IP())
        pkt[PPP].proto = 0xC021
        self.pg_enable_capture(self.pg_interfaces)
        self.lac.add_stream([pkt])
        self.pg_start()
        self.core.assert_nothing_captured()

    def l2tvpp_input_error(self, reason):
        """summed l2tvpp-input error counter across threads, 0 if absent"""
        total = 0
        for line in self.vapi.cli("show errors").splitlines():
            if "l2tvpp-input" in line and reason in line:
                total += int(line.split()[0])
        return total

    def test_counters_climb_when_forwarding(self):
        """punt/decap counters must not depend on error-drop seeing the
        buffer: on the LNS, linux-cp redirects punted packets out a tap
        instead of dropping them"""
        VppIpPuntRedirect(self, self.lac.sw_if_index, self.core.sw_if_index,
                          self.core.remote_ip4).add_vpp_config()
        ctrl_before = self.l2tvpp_input_error("control message, punted")
        decap_before = self.l2tvpp_input_error("decapsulated")
        ctrl = (Ether(src=self.lac.remote_mac, dst=self.lac.local_mac)
                / IP(src=self.lac.remote_ip4, dst=self.lac.local_ip4)
                / UDP(sport=L2TP_PORT, dport=L2TP_PORT)
                / L2TP(hdr="control+length+sequence",
                       tunnel_id=LOCAL_TID, session_id=0, ns=1, nr=1))
        inner = IP(src=SUB_IP, dst=self.core.remote_ip4) / UDP()
        self.pg_enable_capture(self.pg_interfaces)
        self.lac.add_stream([ctrl] + [self.l2tp_data(inner)] * 10)
        self.pg_start()
        # 10 decapped + 1 redirected control, all towards pg1
        self.core.get_capture(11)
        self.assertEqual(
            self.l2tvpp_input_error("control message, punted"),
            ctrl_before + 1)
        self.assertEqual(
            self.l2tvpp_input_error("decapsulated"), decap_before + 10)

    def test_route_add_del_is_clean(self):
        """a route add must create exactly one path - passing entry flags
        to fib_table_entry_path_add2 makes the FIB materialize the new
        source as a special drop path-list that then merges with the real
        path (phantom drop bucket) - and a del must remove the source
        entirely, or the high-priority source blackholes the prefix
        instead of falling back to the kernel path"""
        dump = self.vapi.cli("show ip fib %s/32" % SUB_IP)
        self.assertNotIn("exclusive", dump)
        self.assertIn("buckets:1", dump)

        self.vapi.l2tvpp_route_add_del(
            is_add=False, prefix=SUB_IP + "/32", sw_if_index=self.session)
        dump = self.vapi.cli("show ip fib %s/32" % SUB_IP)
        self.assertNotIn(SUB_IP + "/32", dump)

        self.vapi.l2tvpp_route_add_del(
            is_add=True, prefix=SUB_IP + "/32", sw_if_index=self.session)
        dump = self.vapi.cli("show ip fib %s/32" % SUB_IP)
        self.assertNotIn("exclusive", dump)
        self.assertIn("buckets:1", dump)
        p = (Ether(src=self.core.remote_mac, dst=self.core.local_mac)
             / IP(src=self.core.remote_ip4, dst=SUB_IP)
             / UDP(sport=5678, dport=1234))
        self.pg_enable_capture(self.pg_interfaces)
        self.core.add_stream([p] * 5)
        self.pg_start()
        rx = self.lac.get_capture(5)
        for r in rx:
            self.assertEqual(r[L2TP].session_id, PEER_SID)

    def test_route_source_beats_api_route(self):
        """the plugin's route source must outrank a competing API route for
        the same /32; on the LNS the competitor is linux-cp's lcp-rt mirror
        of the kernel session route (which also outranks API)"""
        # raw vapi, not VppIpRoute: the registry's removal check would see
        # the prefix still in the FIB (the class's l2tvpp-source route) and
        # flag the teardown as failed
        def detour(is_add):
            path = {"sw_if_index": self.core.sw_if_index, "table_id": 0,
                    "rpf_id": 0, "weight": 1, "preference": 0,
                    "next_hop_id": 0xFFFFFFFF, "proto": 0, "type": 0,
                    "flags": 0,
                    "nh": {"address": {"ip4": self.core.remote_ip4}},
                    "n_labels": 0, "label_stack": [{}] * 16}
            self.vapi.ip_route_add_del(
                is_add=is_add, is_multipath=0,
                route={"table_id": 0, "prefix": SUB_IP + "/32",
                       "n_paths": 1, "paths": [path]})

        detour(1)
        try:
            p = (Ether(src=self.core.remote_mac, dst=self.core.local_mac)
                 / IP(src=self.core.remote_ip4, dst=SUB_IP)
                 / UDP(sport=5678, dport=1234))
            self.pg_enable_capture(self.pg_interfaces)
            self.core.add_stream([p] * 10)
            self.pg_start()
            # the l2tvpp route wins: traffic is encapped towards the LAC,
            # not sent out the detour
            rx = self.lac.get_capture(10)
            for r in rx:
                self.assertEqual(r[L2TP].session_id, PEER_SID)
        finally:
            detour(0)


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


class TestL2tvppHandoff(VppTestCase):
    """l2tvpp worker handoff: with 2 workers handoff is on by default (no
    l2tvpp_set_handoff call here), and sessions still decap/encap correctly
    (the handoff node picks a worker by session and enqueues to
    l2tvpp-input there)."""

    vpp_worker_count = 2

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
        # two sessions in one tunnel, so the two workers each get one
        cls.tunnel = cls.vapi.l2tvpp_tunnel_add_del(
            is_add=True, local_ip=cls.pg0.local_ip4, peer_ip=cls.pg0.remote_ip4,
            local_port=L2TP_PORT, peer_port=L2TP_PORT,
            local_tid=LOCAL_TID, peer_tid=PEER_TID).tunnel_index
        cls.subs = {}
        for lsid, psid, sub in ((1000, 2000, "10.200.0.5"),
                                (1001, 2001, "10.200.0.6")):
            swif = cls.vapi.l2tvpp_session_add_del(
                is_add=True, tunnel_index=cls.tunnel, local_sid=lsid,
                peer_sid=psid, acfc=False, pfc=False).sw_if_index
            cls.vapi.l2tvpp_route_add_del(
                is_add=True, prefix=sub + "/32", sw_if_index=swif)
            cls.subs[lsid] = (psid, sub)
        # no l2tvpp_set_handoff here: 2 workers must mean handoff on by default

    def l2tp_data(self, lsid, inner):
        from scapy.layers.ppp import HDLC
        return (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                / IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4)
                / UDP(sport=L2TP_PORT, dport=L2TP_PORT)
                / L2TP(hdr="", tunnel_id=LOCAL_TID, session_id=lsid)
                / HDLC() / PPP(proto=0x0021) / inner)

    def test_handoff_decap_both_sessions(self):
        """upstream data for both sessions decaps and forwards under handoff"""
        pkts = []
        for lsid, (_psid, sub) in self.subs.items():
            inner = IP(src=sub, dst=self.pg1.remote_ip4) / UDP(sport=1, dport=2)
            pkts += [self.l2tp_data(lsid, inner)] * 8
        self.pg_enable_capture(self.pg_interfaces)
        self.pg0.add_stream(pkts)
        self.pg_start()
        rx = self.pg1.get_capture(16)
        seen = set()
        for p in rx:
            self.assertFalse(p.haslayer(L2TP))
            seen.add(p[IP].src)
        self.assertEqual(seen, {s for _p, s in self.subs.values()})
        # the handoff node must actually have run
        self.assertIn("l2tvpp-handoff", self.vapi.cli("show runtime"))

    def test_handoff_decap_sequenced(self):
        """S-bit data is handed off by session like plain data (tid/sid sit
        before Ns/Nr, and one session always maps to one worker)"""
        from scapy.layers.ppp import HDLC
        pkts = []
        for lsid, (_psid, sub) in self.subs.items():
            inner = IP(src=sub, dst=self.pg1.remote_ip4) / UDP(sport=3, dport=4)
            pkts += [(Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
                      / IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4)
                      / UDP(sport=L2TP_PORT, dport=L2TP_PORT)
                      / L2TP(hdr="length+sequence", tunnel_id=LOCAL_TID,
                             session_id=lsid)
                      / HDLC() / PPP(proto=0x0021) / inner)] * 8
        self.pg_enable_capture(self.pg_interfaces)
        self.pg0.add_stream(pkts)
        self.pg_start()
        rx = self.pg1.get_capture(16)
        seen = set()
        for p in rx:
            self.assertFalse(p.haslayer(L2TP))
            seen.add(p[IP].src)
        self.assertEqual(seen, {s for _p, s in self.subs.values()})
        self.assertIn("sequenced, decapsulated", self.vapi.cli("show errors"))

    def test_handoff_encap(self):
        """downstream encap still works with handoff enabled"""
        _psid, sub = self.subs[1000]
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
             / IP(src=self.pg1.remote_ip4, dst=sub) / UDP(sport=5678, dport=1234))
        self.pg_enable_capture(self.pg_interfaces)
        self.pg1.add_stream([p] * 6)
        self.pg_start()
        rx = self.pg0.get_capture(6)
        for r in rx:
            self.assertEqual(r[L2TP].session_id, 2000)
            self.assertEqual(r[PPP][IP].dst, sub)
