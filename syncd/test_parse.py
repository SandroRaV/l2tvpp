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
        self.assertIn(["ip", "-o", "-6", "route", "show", "table", "all"],
                      calls)
        self.assertIn("2001:db8:beef::/56", routes["ppp0"])

    # `table all` output: the VRF's table carries the session's routes, the
    # local table the LNS's own address on the session
    ROUTE4_ALL = (
        "100.64.9.9 dev l2tp0 table 1100 proto kernel scope link src 100.64.0.1\n"
        "198.51.100.8/29 dev l2tp0 table 1100 proto static\n"
        "203.0.113.77 dev l2tp0 table 1100 proto static\n"
        "local 100.64.0.1 dev l2tp0 table 1100 proto kernel scope host src 100.64.0.1\n"
        "broadcast 192.0.2.255 dev eth0 table local proto kernel scope link\n"
        "unreachable default dev lo table 1100 metric 4278198272\n"
        "default dev l2tp0 table 1100 proto static\n")
    ROUTE6_ALL = (
        "2001:db8:cafe::/56 dev l2tp0 table 1100 proto static metric 1024\n"
        "local fe80::1 dev l2tp0 table local proto kernel metric 0\n"
        "multicast ff00::/8 dev l2tp0 table local proto kernel metric 256\n")

    def test_routes_of_a_session_in_a_vrf(self):
        routes = l2tvppd.parse_ppp_routes("", self.ROUTE4_ALL + self.ROUTE6_ALL)
        self.assertEqual(routes["l2tp0"], sorted([
            "100.64.9.9/32",            # host route, printed without /32
            "198.51.100.8/29", "203.0.113.77/32", "2001:db8:cafe::/56"]))
        # the LNS's own address, broadcast, multicast, default: never
        self.assertNotIn("eth0", routes)
        self.assertNotIn("lo", routes)

    LINKS = (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN "
        "mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 "
        "brd 00:00:00:00:00:00 promiscuity 0\n"
        "9: vrf-lns: <NOARP,MASTER,UP,LOWER_UP> mtu 65575 qdisc noqueue state UP "
        "mode DEFAULT group default qlen 1000\\    link/ether 4a:5b:00:00:00:01 "
        "brd ff:ff:ff:ff:ff:ff promiscuity 0 \\    vrf table 1100 addrgenmode none\n"
        "21: l2tp0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1460 qdisc "
        "pfifo_fast master vrf-lns state UNKNOWN mode DEFAULT group default qlen 3"
        "\\    link/ppp  promiscuity 0 \\    ppp \\    vrf_slave table 1100\n"
        "22: l2tp1: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1492 qdisc "
        "pfifo_fast state UNKNOWN mode DEFAULT group default qlen 3\\    link/ppp\n"
        "23: eth1.10@eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue "
        "master br0 state UP mode DEFAULT group default\n")

    def test_links_mtu_and_vrf_table(self):
        links = l2tvppd.parse_links(self.LINKS)
        self.assertEqual(links["l2tp0"],
                         {"mtu": 1460, "table": 1100, "ifindex": 21})
        self.assertEqual(links["l2tp1"],
                         {"mtu": 1492, "table": 0, "ifindex": 22})
        # a master that is not a VRF (a bridge) is the default table
        self.assertEqual(links["eth1.10"],
                         {"mtu": 1500, "table": 0, "ifindex": 23})


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
        # sw_if_index -> table id / MTU / uRPF mode per address family, and
        # the order of everything done to an interface
        self.table, self.mtu, self.urpf_mode = {}, {}, {}
        self.tables = {0}
        self.punt = set()
        self.refuse_table = None
        self.log = []

    def sw_interface_get_table(self, sw_if_index, is_ipv6):
        return self.R(retval=0, vrf_id=self.table.get(sw_if_index, 0))

    def sw_interface_set_table(self, sw_if_index, is_ipv6, vrf_id):
        if vrf_id not in self.tables or vrf_id == self.refuse_table:
            return self.R(retval=-3)
        self.table[sw_if_index] = vrf_id
        self.log.append(("table", sw_if_index, vrf_id, is_ipv6))
        return self.R(retval=0)

    def ip_table_dump(self):
        return [self.R(table=self.R(table_id=t, is_ip6=v6))
                for t in self.tables for v6 in (False, True)]

    def ip_table_add_del(self, is_add, table):
        self.tables.add(table["table_id"])
        return self.R(retval=0)

    def sw_interface_set_mtu(self, sw_if_index, mtu):
        self.mtu[sw_if_index] = mtu[0]
        return self.R(retval=0)

    def l2tvpp_punt_address_dump(self):
        return [self.R(address=a) for a in sorted(self.punt)]

    def l2tvpp_punt_address_add_del(self, is_add, address):
        if not is_add and address not in self.punt:
            return self.R(retval=-6)
        (self.punt.add if is_add else self.punt.discard)(address)
        self.log.append(("punt", address, is_add))
        return self.R(retval=0)

    def urpf_update_v2(self, is_input, mode, af, sw_if_index, table_id):
        # ~0: check against the table the interface is bound to
        assert table_id == 0xFFFFFFFF
        self.urpf_mode[(sw_if_index, af)] = mode
        self.log.append(("urpf", sw_if_index, af, mode))
        return self.R(retval=0)

    def l2tvpp_tunnel_dump(self, tunnel_index):
        return [self.R(tunnel_index=i, peer_ip=k[0], peer_port=k[1],
                       local_tid=k[2]) for k, i in self.tunnels.items()]

    def l2tvpp_session_dump(self, sw_if_index):
        return [s for s in self.sessions.values()
                if sw_if_index in (0xFFFFFFFF, s.sw_if_index)]

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
                                      sw_if_index=self.next_swif,
                                      rx_packets=0, rx_bytes=0,
                                      tx_packets=0, tx_bytes=0)
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
        self.log.append(("route", sw_if_index, prefix, is_add,
                         self.table.get(sw_if_index, 0)))
        return self.R(retval=0)


def ks(lsid, ifname, routes=None, peer_sid=None, **attrs):
    s = {"name": "", "peer_ip": "192.0.2.2", "peer_port": 1701,
         "local_tid": 100, "local_sid": lsid, "peer_tid": 200,
         "peer_sid": peer_sid or lsid + 1000, "ifname": ifname,
         "routes": routes}
    s.update(attrs)                     # table=, mtu=
    return s


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
                          TestParse.LINKS if "link" in cmd else
                          TestParse.ROUTE6 if "-6" in cmd else TestParse.ROUTE4)
            return r

        self.assertEqual(self.sync.reconcile(
            [ks(1000, "ppp0"), ks(1001, "ppp1")], run=fake_run), (2, 0))
        # addresses, IPv4 routes, IPv6 routes, links: not 2 per session
        self.assertEqual(len(calls), 4)
        # the links are read AFTER the routes (see fill_attrs)
        self.assertIn("link", calls[-1])
        self.assertEqual(len(self.vpp.routes), 5)

    def test_lns_address_is_registered_before_the_session(self):
        """the LNS's own address on the session netdevs: one registration
        whatever the session count, before any session, gone with the last"""
        k = [ks(1000, "l2tp0", ["100.64.9.9/32"], local4="100.64.255.1"),
             ks(1001, "l2tp1", ["100.64.9.8/32"], local4="100.64.255.1")]
        self.sync.reconcile(k)
        self.assertEqual(self.vpp.punt, {"100.64.255.1"})
        self.assertEqual(self.vpp.log[0], ("punt", "100.64.255.1", True))
        self.assertEqual(len([e for e in self.vpp.log if e[0] == "punt"]), 1)
        self.sync.reconcile(k[:1])
        self.assertEqual(self.vpp.punt, {"100.64.255.1"})
        self.sync.reconcile([])
        self.assertEqual(self.vpp.punt, set())

    def test_lns_address_left_by_an_earlier_daemon_is_cleaned_up(self):
        self.vpp.punt.add("192.0.2.77")
        self.sync.reconcile(
            [ks(1000, "l2tp0", ["100.64.9.9/32"], local4="100.64.255.1")])
        self.assertEqual(self.vpp.punt, {"100.64.255.1"})

    def test_local_address_comes_from_ip_addr(self):
        self.assertEqual(l2tvppd.parse_ppp_local4(TestParse.ADDR),
                         {"ppp0": "100.64.0.1", "ppp1": "100.64.0.1"})

    def test_session_in_a_vrf(self):
        """the netdev is enslaved to a VRF: the interface is bound to that
        table BEFORE its routes go in, and the missing table is created"""
        k = [ks(1000, "l2tp0", ["100.64.9.9/32"], table=1100, mtu=1460)]
        self.assertEqual(self.sync.reconcile(k), (1, 0))
        self.assertIn(1100, self.vpp.tables)
        self.assertEqual(self.vpp.table[10], 1100)
        self.assertEqual(self.vpp.mtu[10], 1460)
        routes = [e for e in self.vpp.log if e[0] == "route"]
        self.assertEqual(routes, [("route", 10, "100.64.9.9/32", True, 1100)])
        self.assertEqual(self.sync.installed["100/1000"]["table"], 1100)
        # a second pass changes nothing
        n = len(self.vpp.log)
        self.sync.reconcile(k)
        self.assertEqual(len(self.vpp.log), n)

    def test_session_moves_between_tables(self):
        """a CoA moves the session into a VRF and back: routes leave the
        old table before the interface is rebound, then go into the new"""
        self.sync.reconcile([ks(1000, "l2tp0", ["100.64.9.9/32"], table=0)])
        self.vpp.log.clear()
        self.sync.reconcile([ks(1000, "l2tp0", ["100.64.9.9/32"], table=1100)])
        self.assertEqual(
            [e for e in self.vpp.log if e[0] in ("route", "table")],
            [("route", 10, "100.64.9.9/32", False, 0),
             ("table", 10, 1100, False), ("table", 10, 1100, True),
             ("route", 10, "100.64.9.9/32", True, 1100)])
        self.vpp.log.clear()
        self.sync.reconcile([ks(1000, "l2tp0", ["100.64.9.9/32"], table=0)])
        self.assertEqual(self.vpp.table[10], 0)
        self.assertEqual(self.vpp.log[-1],
                         ("route", 10, "100.64.9.9/32", True, 0))

    def test_session_that_cannot_enter_its_vrf_stays_out_of_vpp(self):
        """never forward a VRF subscriber in the default table"""
        self.vpp.refuse_table = 1100
        k = [ks(1000, "l2tp0", ["100.64.9.9/32"], table=1100)]
        self.assertEqual(self.sync.reconcile(k), (0, 0))
        self.assertEqual(len(self.vpp.sessions), 0)
        self.assertEqual(len(self.vpp.routes), 0)
        self.assertNotIn("100/1000", self.sync.installed)
        self.vpp.refuse_table = None
        self.assertEqual(self.sync.reconcile(k), (1, 0))
        self.assertEqual(self.vpp.table[10 + 1], 1100)

    def test_mtu_follows_the_netdev(self):
        self.sync.reconcile([ks(1000, "l2tp0", [], mtu=1500)])
        self.assertEqual(self.vpp.mtu[10], 1500)
        self.sync.reconcile([ks(1000, "l2tp0", [], mtu=1452)])
        self.assertEqual(self.vpp.mtu[10], 1452)

    def test_urpf_strict_by_default_and_cleared_on_delete(self):
        self.sync.reconcile([ks(1000, "l2tp0", ["10.0.0.1/32"])])
        # off first (stale state of a reused interface index), then strict,
        # for IPv4 and IPv6, before the first route
        self.assertEqual(self.vpp.log[:5], [
            ("urpf", 10, 0, 0), ("urpf", 10, 0, 2),
            ("urpf", 10, 1, 0), ("urpf", 10, 1, 2),
            ("route", 10, "10.0.0.1/32", True, 0)])
        self.sync.reconcile([])
        self.assertEqual(self.vpp.urpf_mode, {(10, 0): 0, (10, 1): 0})

    def test_urpf_off(self):
        sync = l2tvppd.Syncd(self.vpp, "192.0.2.1", urpf="off")
        sync.reconcile([ks(1000, "l2tp0", ["10.0.0.1/32"])])
        self.assertEqual(self.vpp.urpf_mode, {(10, 0): 0, (10, 1): 0})

    def test_no_urpf_plugin_is_not_fatal(self):
        class NoUrpf(FakeVpp):
            urpf_update_v2 = property(lambda self: (_ for _ in ()).throw(
                AttributeError("urpf_update_v2")))
        vpp = NoUrpf()
        sync = l2tvppd.Syncd(vpp, "192.0.2.1")
        self.assertEqual(sync.reconcile(
            [ks(1000, "l2tp0", ["10.0.0.1/32"])]), (1, 0))
        self.assertTrue(sync.urpf_missing)
        self.assertEqual(len(vpp.routes), 1)

    def test_old_urpf_call_is_not_used_for_a_vrf_session(self):
        """urpf_update (v1) pins the check to the default table and would
        drop everything a session in a VRF sends"""
        class OldUrpf(FakeVpp):
            urpf_update_v2 = property(lambda self: (_ for _ in ()).throw(
                AttributeError("urpf_update_v2")))

            def urpf_update(self, is_input, mode, af, sw_if_index):
                self.urpf_mode[(sw_if_index, af)] = mode
                return self.R(retval=0)
        vpp = OldUrpf()
        sync = l2tvppd.Syncd(vpp, "192.0.2.1")
        sync.reconcile([ks(1000, "l2tp0", ["10.0.0.1/32"]),
                        ks(1001, "l2tp1", ["10.0.0.2/32"], table=1100)])
        self.assertEqual(vpp.urpf_mode[(10, 0)], 2)      # default table
        self.assertEqual(vpp.urpf_mode[(11, 0)], 0)      # VRF: off

    def test_urpf_is_reapplied_when_the_session_changes_table(self):
        self.sync.reconcile([ks(1000, "l2tp0", ["10.0.0.1/32"], table=0)])
        self.vpp.log.clear()
        self.sync.reconcile([ks(1000, "l2tp0", ["10.0.0.1/32"], table=1100)])
        kinds = [e[0] for e in self.vpp.log]
        self.assertIn("urpf", kinds)
        self.assertLess(kinds.index("table"), kinds.index("urpf"))
        self.assertLess(kinds.index("urpf"), len(kinds) - 1)   # then routes

    def test_old_state_file_gets_the_new_attributes(self):
        """a record written before VRF/MTU/uRPF existed"""
        self.sync.reconcile([ks(1000, "l2tp0", ["10.0.0.1/32"])])
        rec = self.sync.installed["100/1000"]
        for k in ("ifname", "ifindex", "table", "mtu", "urpf"):
            del rec[k]
        self.vpp.log.clear()
        self.sync.reconcile([ks(1000, "l2tp0", ["10.0.0.1/32"], mtu=1492)])
        self.assertEqual(self.vpp.mtu[10], 1492)
        self.assertEqual(self.vpp.urpf_mode[(10, 0)], 2)
        self.assertEqual(rec["ifname"], "l2tp0")

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
