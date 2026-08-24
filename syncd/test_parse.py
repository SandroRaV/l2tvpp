# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
"""Pure-python unit tests for l2tvppd's kernel-side parsing. No VPP needed:

    python3 -m pytest syncd/test_parse.py      # or: python3 syncd/test_parse.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import l2tvppd  # noqa: E402

# A captured /proc/net/pppol2tp with two sessions in one tunnel and one in a
# second tunnel. Format per the kernel pppol2tp seq_file: the SESSION line
# carries peer-ip(hex)/peer-port  local-tid/local-sid -> peer-tid/peer-sid.
SAMPLE = """\
PPPoL2TP driver info, 2.0.0
TUNNEL 3 peer 5, 1 sessions
  SESSION '', C0000202/1701 0064/03e8 -> 00c8/07d0
   state 4, uptime 12, difs 0 0, reorderto 0
   interface ppp0
  SESSION '', C0000202/1701 0064/03e9 -> 00c8/07d1
   state 4, uptime 10
   interface ppp1
TUNNEL 4 peer 6, 1 sessions
  SESSION '', C0000203/1701 0065/0400 -> 00c9/0800
   state 4, uptime 8
   interface ppp2
"""


class TestParse(unittest.TestCase):
    def test_counts_and_fields(self):
        ss = l2tvppd.parse_pppol2tp(SAMPLE)
        self.assertEqual(len(ss), 3)
        s0 = ss[0]
        self.assertEqual(s0["peer_ip"], "192.0.2.2")     # C0000202
        self.assertEqual(s0["peer_port"], 1701)
        self.assertEqual(s0["local_tid"], 0x64)          # 100
        self.assertEqual(s0["local_sid"], 0x3e8)         # 1000
        self.assertEqual(s0["peer_tid"], 0xc8)           # 200
        self.assertEqual(s0["peer_sid"], 0x7d0)          # 2000
        self.assertEqual(s0["ifname"], "ppp0")

    def test_tunnel_grouping(self):
        ss = l2tvppd.parse_pppol2tp(SAMPLE)
        tks = {l2tvppd.tunnel_key(s) for s in ss}
        self.assertEqual(len(tks), 2)                    # two distinct tunnels
        # sessions 0 and 1 share a tunnel, session 2 is its own
        self.assertEqual(l2tvppd.tunnel_key(ss[0]), l2tvppd.tunnel_key(ss[1]))
        self.assertNotEqual(l2tvppd.tunnel_key(ss[0]), l2tvppd.tunnel_key(ss[2]))

    def test_session_key_unique(self):
        ss = l2tvppd.parse_pppol2tp(SAMPLE)
        keys = [l2tvppd.session_key(s) for s in ss]
        self.assertEqual(len(keys), len(set(keys)))

    def test_ppp_routes_ipv4_ipv6_pd(self):
        addr = ("1: ppp0    inet 100.64.0.1 peer 100.64.5.7/32 scope global ppp0\\"
                "       valid_lft forever\n"
                "2: ppp0    inet6 fe80::1 peer fe80::2/128 scope link\n"
                "3: ppp0    inet6 2001:db8:a:: peer 2001:db8:a:b::1/128 scope global\n")
        route = "2001:db8:beef::/56 dev ppp0 proto static metric 1024 pref medium\n"

        def fake_run(cmd, capture_output=True, text=True):
            class R:
                pass
            r = R()
            r.stdout = addr if "addr" in cmd else route
            return r

        routes = l2tvppd._ppp_routes("ppp0", run=fake_run)
        self.assertIn("100.64.5.7/32", routes)
        self.assertIn("2001:db8:a:b::1/128", routes)
        self.assertIn("2001:db8:beef::/56", routes)      # delegated prefix
        self.assertNotIn("fe80::2/128", routes)          # link-local excluded



    def test_parse_l2tp_tunnels(self):
        text = ("Tunnel 100, encap UDP\n"
                "  From 192.0.2.1 to 192.0.2.2\n"
                "  Peer tunnel 200\n"
                "  UDP source / dest ports: 1701/1701\n"
                "  UDP checksum: disabled\n"
                "Tunnel 101, encap UDP\n"
                "  From 192.0.2.5 to 192.0.2.9\n"
                "  Peer tunnel 201\n"
                "  UDP source / dest ports: 1701/1702\n")
        tuns = l2tvppd.parse_l2tp_tunnels(text)
        self.assertEqual(tuns[100]["local_ip"], "192.0.2.1")
        self.assertEqual(tuns[100]["peer_ip"], "192.0.2.2")
        self.assertEqual(tuns[100]["local_port"], 1701)
        self.assertEqual(tuns[101]["local_ip"], "192.0.2.5")
        self.assertEqual(tuns[101]["peer_port"], 1702)


if __name__ == "__main__":
    unittest.main()
