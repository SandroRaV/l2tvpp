"""
VPP make-test suite for the l2tp2 plugin (runs under vpp/test with scapy,
no NIC needed). Copied to src/plugins/l2tp2/test/ by build/package.toml.

Run from a VPP source tree:
    make test TEST=test_l2tp2 V=1

M1 scope: the tests below are the acceptance criteria for the static data
path. They are written first and fail until the plugin exists.
"""
import unittest

from framework import VppTestCase
from asfframework import VppTestRunner
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.l2tp import L2TP
from scapy.layers.ppp import PPP, HDLC

L2TP_PORT = 1701


class TestL2tp2(VppTestCase):
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

    def setUp(self):
        super().setUp()
        # tunnel: LAC pg0.remote -> LNS pg0.local, tid 100 (ours) / 200 (LAC's)
        self.tunnel = self.vapi.l2tp2_tunnel_add_del(
            is_add=True,
            local_ip=self.lac.local_ip4,
            peer_ip=self.lac.remote_ip4,
            local_port=L2TP_PORT,
            peer_port=L2TP_PORT,
            local_tid=100,
            peer_tid=200,
        ).tunnel_index
        self.session = self.vapi.l2tp2_session_add_del(
            is_add=True,
            tunnel_index=self.tunnel,
            local_sid=1000,
            peer_sid=2000,
            acfc=False,
            pfc=False,
        ).sw_if_index
        self.sub_ip = "10.200.0.5"
        self.vapi.sw_interface_set_flags(self.session, flags=1)
        # route to the subscriber via the session interface
        self.vapi.cli(f"ip route add {self.sub_ip}/32 via {self.session_name()}")

    def session_name(self):
        return self.vapi.cli("show interface").split()  # placeholder, M1 fixes naming

    def l2tp_data(self, inner):
        return (
            Ether(src=self.lac.remote_mac, dst=self.lac.local_mac)
            / IP(src=self.lac.remote_ip4, dst=self.lac.local_ip4)
            / UDP(sport=L2TP_PORT, dport=L2TP_PORT)
            / L2TP(hdr="", tunnel_id=100, session_id=1000)
            / HDLC()
            / PPP(proto=0x0021)
            / inner
        )

    def test_upstream_decap(self):
        """LAC -> LNS: IPv4 in PPP in L2TP is decapsulated and routed"""
        inner = IP(src=self.sub_ip, dst=self.core.remote_ip4) / UDP(sport=1234, dport=5678)
        self.lac.add_stream([self.l2tp_data(inner)] * 10)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.core.get_capture(10)
        for p in rx:
            self.assertEqual(p[IP].src, self.sub_ip)
            self.assertEqual(p[IP].dst, self.core.remote_ip4)
            self.assertFalse(p.haslayer(L2TP))

    def test_downstream_encap(self):
        """core -> subscriber: routed via session interface, L2TP/PPP encap"""
        p = (
            Ether(src=self.core.remote_mac, dst=self.core.local_mac)
            / IP(src=self.core.remote_ip4, dst=self.sub_ip)
            / UDP(sport=5678, dport=1234)
        )
        self.core.add_stream([p] * 10)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        rx = self.lac.get_capture(10)
        for r in rx:
            self.assertEqual(r[IP].dst, self.lac.remote_ip4)
            self.assertEqual(r[UDP].dport, L2TP_PORT)
            self.assertEqual(r[L2TP].tunnel_id, 200)
            self.assertEqual(r[L2TP].session_id, 2000)
            self.assertEqual(r[PPP].proto, 0x0021)
            self.assertEqual(r[PPP][IP].dst, self.sub_ip)

    def test_control_is_punted(self):
        """L2TP control message (T bit) must not be consumed by the plugin"""
        ctrl = (
            Ether(src=self.lac.remote_mac, dst=self.lac.local_mac)
            / IP(src=self.lac.remote_ip4, dst=self.lac.local_ip4)
            / UDP(sport=L2TP_PORT, dport=L2TP_PORT)
            / L2TP(hdr="control+length+sequence", tunnel_id=100, session_id=0, ns=1, nr=1)
        )
        self.lac.add_stream([ctrl])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.core.assert_nothing_captured()
        # M1: assert the punt counter in `show errors` / punt path instead
        self.assertIn("punt", self.vapi.cli("show errors").lower())

    def test_unknown_session_is_punted(self):
        """unknown session id: not decapsulated"""
        inner = IP(src=self.sub_ip, dst=self.core.remote_ip4) / UDP()
        pkt = self.l2tp_data(inner)
        pkt[L2TP].session_id = 9999
        self.lac.add_stream([pkt])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.core.assert_nothing_captured()

    def test_lcp_is_punted(self):
        """PPP LCP (0xc021) inside a known session goes to the control plane"""
        pkt = self.l2tp_data(IP())
        pkt[PPP].proto = 0xC021
        self.lac.add_stream([pkt])
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.core.assert_nothing_captured()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
