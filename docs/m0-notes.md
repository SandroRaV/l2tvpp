# M0: investigation checklist

Fill in as answers are found. Each item has a decision that feeds `design.md`.

## 1. VPP pppoe plugin walkthrough
- [ ] How `pppoe_session` interfaces are created (`pppoe_add_del_session`), tx function, adjacency caching via `fib_entry_track`
- [ ] `pppoe_decap` node: how it selects next node, how unknown sessions are handled
- [ ] Counters: `vnet_interface_main.combined_sw_if_counters` use per session
Decision: confirm per-session-interface model for l2tvpp.

## 2. VyOS pppoe offload wiring
- [ ] Where the `vpp-cp` punt is configured (VyOS `vpp` python module, `vppctl show punt`), which node/tap receives punted frames
- [ ] `vyos/accel-ppp-ng` source: the code that installs pppoe sessions into VPP (API calls, event hook), and whether an L2TP equivalent can be added there instead of a separate daemon
- [ ] VPP version in the VyOS image (`vppctl show version`) and whether out-of-tree plugins load (`plugin l2tvpp_plugin.so { enable }` in startup.conf)
Decision: punt path for l2tvpp-input; daemon vs accel-ppp-ng hook.

Rig finding (2026-08-24, step 4 of the rig test): the punt path works on the
real DUT exactly as designed (`ip4-udp-lookup` -> `l2tvpp-input` -> `ip4-punt`
-> punt-redirect -> `tap4096`, 500 sessions up through accel-ppp with the
plugin loaded, 0 loss), but the punt error counters never appeared in
`show errors`. Cause: `node.c` only tagged `b->error`, which is counted by
`error-drop` - a node punted and decapsulated packets never reach once
linux-cp's punt redirect forwards them out the tap. The original make test
passed because without a punt redirect the punted packet is eventually
dropped, so the tag was counted after all. Fixed by counting punts/decaps
explicitly with `vlib_node_increment_counter` in `l2tvpp-input` (drops still
count via `b->error`), regression-tested with a punt redirect configured
(`test_counters_climb_when_forwarding`).

Rig findings (2026-08-25, step 5/6 of the rig test), both fixed:

1. The daemon installed tunnels with peer_ip = local_ip (`show l2tvpp
   tunnel` said `10.66.0.1 -> 10.66.0.1`, the encap rewrite stacked on the
   LNS's own receive DPO). Cause: the addr field in `/proc/net/pppol2tp`
   holds the LOCAL address on the VyOS accel-ppp LNS, not the peer as the
   parser assumed. Fix: `merge_tunnel_endpoints()` now takes BOTH endpoints
   from `ip l2tp show tunnel` (From/to), /proc stays a fallback only.
2. The daemon's subscriber routes (ip_route_add_del, FIB source "API",
   priority 0x80) lost to linux-cp's mirror of the kernel session route
   ("lcp-rt", 0x10, a receive path into the kernel), so downstream traffic
   kept punting even with the session installed. Fix: new
   `l2tvpp_route_add_del` API + `l2tvpp route` CLI; the plugin installs
   subscriber routes under its own FIB source at priority 0x0f
   (L2TVPP_FIB_SOURCE_PRIORITY), which outranks lcp-rt. The daemon uses it
   instead of ip_route_add_del.
3. First route-API build on the rig: every subscriber /32 got a phantom
   second load-balance bucket pointing at dpo-drop, and `l2tvpp route del`
   left the prefix blackholed (the drop outlives the real path and the
   high-priority source shadows lcp-rt). Cause: passing
   FIB_ENTRY_FLAG_ATTACHED to fib_table_entry_path_add2 - on a
   not-yet-sourced entry, non-NONE entry flags make fib_entry_src_api_add
   materialize the source as a special drop path-list first, and the real
   path then merges with it. Fix: FIB_ENTRY_FLAG_NONE (the path is already
   attached via the host-prefix fixup); regression test
   `test_route_add_del_is_clean`.
4. Benchmark day: the daemon's interval safety net never fired - run_daemon
   gated every pass on the SIGHUP wake flag, which nothing sets after the
   initial pass consumed it, so the service reconciled once at start and
   then sat idle while showing active. A whole sweep "run C/D" silently
   measured the kernel punt path (giveaway in `show errors`: millions of
   `unknown session, punted`, plus `tap*-tx no free tx slots` - the tap
   rings overflow around 300k pps, which is the kernel path's real loss
   mechanism). Fixed: reconcile unconditionally every tick, SIGHUP only
   shortens the sleep. Lesson for the rig doc: verify the data path
   mid-sweep (`show errors` decapsulated climbing, `show l2tvpp session`
   non-empty), never trust `systemctl is-active` alone.

## 3. Kernel side
- [ ] For a `pppN` created by accel-ppp over L2TP: get tunnel id, session id, peer ip/port (`ip l2tp show session`, `/proc/net/pppol2tp`, genetlink `L2TP_CMD_SESSION_GET`)
- [ ] Whether accel-ppp exposes negotiated ACFC/PFC; if not, whether `[ppp]` options can force them off
- [ ] accel-ppp `use-ephemeral-ports`: which local UDP port the tunnel actually uses (affects tunnel local_port in VPP)
Decision: event source and the data needed per session.

## 4. LAC behaviour (software LAC, vendor LNS/LAC, carrier)
- [ ] Data sequencing (S bit) on data packets: on or off
- [ ] Outer UDP checksum 0 accepted?
- [ ] Does the LAC follow a changed LNS source port (RFC 2661 requirement)?
Decision: whether sequencing support is needed before M3.

## 5. Build environment
- [ ] VPP build host (Debian 12, `make install-dep`, `make build`) with the same VPP version as the target
- [ ] Test VPP in a plain Debian host first (packet-generator, no NIC), then the VyOS build
