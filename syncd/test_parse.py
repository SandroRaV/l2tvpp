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

    ADDR = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
            "7: ppp0    inet 100.64.0.1 peer 100.64.5.7/32 scope global ppp0\\"
            "       valid_lft forever\n"
            "7: ppp0    inet6 fe80::1 peer fe80::2/128 scope link\n"
            "7: ppp0    inet6 2001:db8:a:: peer 2001:db8:a:b::1/128 scope global\n"
            "8: ppp1    inet 100.64.0.1 peer 100.64.5.8/32 scope global ppp1\n")
    ROUTE4 = ("default via 192.0.2.1 dev eth0\n"
              "192.0.2.0/24 dev eth0 proto kernel scope link src 192.0.2.2\n"
              "100.64.5.7 dev ppp0 proto kernel scope link src 100.64.0.1\n"
              "198.51.100.0/29 dev ppp1 proto static\n"
              "unreachable 203.0.113.0/24 proto static\n")
    ROUTE6 = ("2001:db8:beef::/56 dev ppp0 proto static metric 1024 pref medium\n"
              "fe80::/64 dev ppp0 proto kernel metric 256 pref medium\n")

    def test_ppp_routes_ipv4_ipv6_pd(self):
        routes = l2tvppd.parse_ppp_routes(self.ADDR, self.ROUTE4 + self.ROUTE6)
        self.assertEqual(routes["ppp0"], sorted([
            "100.64.5.7/32", "2001:db8:a:b::1/128",
            "2001:db8:beef::/56"]))                      # incl. delegated prefix
        # per interface: ppp1 gets its own peer and framed route, not ppp0's
        self.assertEqual(routes["ppp1"], ["100.64.5.8/32", "198.51.100.0/29"])
        self.assertNotIn("lo", routes)                   # no peer address

    def test_kernel_routes_is_three_calls_and_asks_for_ipv6(self):
        """one dump for all sessions, and the IPv6 table explicitly: a plain
        `ip route show` is IPv4 only and never showed delegated prefixes"""
        calls = []

        def fake_run(cmd, capture_output=True, text=True):
            calls.append(cmd)

            class R:
                pass
            r = R()
            r.stdout = (self.ADDR if "addr" in cmd else
                        self.ROUTE6 if "-6" in cmd else self.ROUTE4)
            return r

        routes = l2tvppd.kernel_routes(run=fake_run)
        self.assertEqual(len(calls), 3)
        self.assertFalse(any("dev" in c for c in calls))
        self.assertIn(["ip", "-o", "-6", "route", "show"], calls)
        self.assertIn("2001:db8:beef::/56", routes["ppp0"])


class FakeVpp:
    """Just enough of the l2tvpp API for Syncd, with papi-style replies:
    a refused call comes back with a negative retval, it does not raise."""

    class R:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    def __init__(self):
        self.tunnels, self.sessions, self.routes = {}, {}, set()
        self.next_tunnel, self.next_swif = 0, 10
        self.refuse_sid = None

    def l2tvpp_tunnel_dump(self, tunnel_index):
        return [self.R(tunnel_index=i, peer_ip=k[0], peer_port=k[1],
                       local_tid=k[2]) for k, i in self.tunnels.items()]

    def l2tvpp_session_dump(self, sw_if_index):
        return list(self.sessions.values())

    def l2tvpp_tunnel_add_del(self, is_add, local_ip, peer_ip, local_port,
                              peer_port, local_tid, peer_tid):
        k = (peer_ip, peer_port, local_tid)
        if is_add:
            self.tunnels[k] = self.next_tunnel
            self.next_tunnel += 1
            return self.R(retval=0, tunnel_index=self.tunnels[k])
        del self.tunnels[k]
        return self.R(retval=0, tunnel_index=0)

    def l2tvpp_session_add_del(self, is_add, tunnel_index, local_sid,
                               peer_sid, acfc=False, pfc=False):
        k = (tunnel_index, local_sid)
        if is_add:
            if k in self.sessions or local_sid == self.refuse_sid:
                return self.R(retval=-81, sw_if_index=0xFFFFFFFF)
            self.sessions[k] = self.R(tunnel_index=tunnel_index,
                                      local_sid=local_sid, peer_sid=peer_sid,
                                      sw_if_index=self.next_swif)
            self.next_swif += 1
            return self.R(retval=0, sw_if_index=self.sessions[k].sw_if_index)
        if k not in self.sessions:
            return self.R(retval=-6, sw_if_index=0xFFFFFFFF)
        swif = self.sessions.pop(k).sw_if_index
        self.routes = {r for r in self.routes if r[1] != swif}
        return self.R(retval=0, sw_if_index=swif)

    def l2tvpp_route_add_del(self, is_add, prefix, sw_if_index):
        if sw_if_index not in {s.sw_if_index for s in self.sessions.values()}:
            return self.R(retval=-2)
        (self.routes.add if is_add else self.routes.discard)(
            (prefix, sw_if_index))
        return self.R(retval=0)


def ks(lsid, ifname, routes=None, peer_sid=None):
    return {"name": "", "peer_ip": "192.0.2.2", "peer_port": 1701,
            "local_tid": 100, "local_sid": lsid, "peer_tid": 200,
            "peer_sid": peer_sid or lsid + 1000, "ifname": ifname,
            "routes": routes}


class TestReconcile(unittest.TestCase):
    """Syncd against a fake VPP: the cases a make-test cannot easily stage
    (VPP restart, lost state file, a refused call)."""

    def setUp(self):
        self.vpp = FakeVpp()
        self.sync = l2tvppd.Syncd(self.vpp, "192.0.2.1")

    def test_routes_fetched_once_per_pass(self):
        calls = []

        def fake_run(cmd, capture_output=True, text=True):
            calls.append(cmd)
            r = FakeVpp.R(stdout=TestParse.ADDR if "addr" in cmd else
                          TestParse.ROUTE6 if "-6" in cmd else TestParse.ROUTE4)
            return r

        self.assertEqual(self.sync.reconcile(
            [ks(1000, "ppp0"), ks(1001, "ppp1")], run=fake_run), (2, 0))
        self.assertEqual(len(calls), 3)          # not 2 per session
        self.assertEqual(len(self.vpp.routes), 5)

    def test_route_change_on_installed_session(self):
        self.sync.reconcile([ks(1000, "ppp0", ["10.0.0.1/32"])])
        self.sync.reconcile([ks(1000, "ppp0", ["10.0.0.1/32", "2001:db8::/56"])])
        self.assertEqual({r[0] for r in self.vpp.routes},
                         {"10.0.0.1/32", "2001:db8::/56"})
        self.sync.reconcile([ks(1000, "ppp0", ["2001:db8::/56"])])
        self.assertEqual({r[0] for r in self.vpp.routes}, {"2001:db8::/56"})

    def test_vpp_restart_reinstalls(self):
        """the record survives (state file), VPP comes back empty"""
        k = [ks(1000, "ppp0", ["10.0.0.1/32"])]
        self.assertEqual(self.sync.reconcile(k), (1, 0))
        self.vpp = FakeVpp()
        self.sync.vpp = self.vpp
        self.sync.verify_state = True            # what the reconnect sets
        self.assertEqual(self.sync.reconcile(k), (1, 0))
        self.assertEqual(len(self.vpp.sessions), 1)
        self.assertEqual(len(self.vpp.routes), 1)

    def test_lost_state_adopts_existing_session(self):
        """VPP kept its sessions, the daemon lost its record"""
        k = [ks(1000, "ppp0", ["10.0.0.1/32"])]
        self.sync.reconcile(k)
        fresh = l2tvppd.Syncd(self.vpp, "192.0.2.1")
        self.assertEqual(fresh.reconcile(k), (1, 0))
        self.assertEqual(len(self.vpp.sessions), 1)
        rec = fresh.installed["100/1000"]
        self.assertEqual(rec["sw_if_index"], 10)     # the real one, not ~0
        self.assertEqual(fresh.reconcile([]), (0, 1))
        self.assertEqual(len(self.vpp.sessions), 0)

    def test_refused_session_does_not_block_the_others(self):
        self.vpp.refuse_sid = 1000
        k = [ks(1000, "ppp0", ["10.0.0.1/32"]), ks(1001, "ppp1", ["10.0.0.2/32"])]
        self.assertEqual(self.sync.reconcile(k), (1, 0))
        self.assertNotIn("100/1000", self.sync.installed)   # not recorded
        self.assertIn("100/1001", self.sync.installed)
        self.vpp.refuse_sid = None
        self.assertEqual(self.sync.reconcile(k), (1, 0))    # retried
        self.assertEqual(len(self.vpp.sessions), 2)


class TestParseTunnels(unittest.TestCase):
    def test_merge_overrides_peer_from_tunnel_show(self):
        # accel-ppp on the VyOS LNS puts the LOCAL address in the /proc
        # addr field; the peer must come from `ip l2tp show tunnel`, or
        # the plugin encaps downstream traffic to the LNS itself
        proc = ("PPPoL2TP driver info, V2.0\n"
                "TUNNEL 'tunl 5430', Y 1\n"
                "  SESSION 'sess 5430/115' 0A420001/1701 1536/0073 -> "
                "0002/004F 3 Y\n"
                "   interface l2tp155\n")
        tun = ("Tunnel 5430, encap UDP\n"
               "  From 10.66.0.1 to 10.66.0.2\n"
               "  Peer tunnel 2\n"
               "  UDP source / dest ports: 1701/1701\n")
        ss = l2tvppd.merge_tunnel_endpoints(
            l2tvppd.parse_pppol2tp(proc), l2tvppd.parse_l2tp_tunnels(tun))
        self.assertEqual(ss[0]["local_ip"], "10.66.0.1")
        self.assertEqual(ss[0]["peer_ip"], "10.66.0.2")   # not 10.66.0.1
        self.assertEqual(ss[0]["ifname"], "l2tp155")

    def test_merge_keeps_proc_peer_without_tunnel_show(self):
        # no `ip l2tp show tunnel` data for the tid: the /proc-derived
        # peer stays as the fallback
        ss = l2tvppd.merge_tunnel_endpoints(
            l2tvppd.parse_pppol2tp(SAMPLE), {})
        self.assertEqual(ss[0]["peer_ip"], "192.0.2.2")

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
