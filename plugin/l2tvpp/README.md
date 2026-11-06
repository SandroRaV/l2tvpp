# l2tvpp: VPP L2TPv2 LNS data plane plugin

See `../../docs/design.md` step 3. Files to be written in M1:

| File | Content | Template in VPP |
|---|---|---|
| `l2tvpp.c` | tunnel/session pools, bihash, interface classes, midchain encap rewrite + fixup, plugin init | `plugins/pppoe/pppoe.c` |
| `l2tvpp_api.c` | binary API handlers for `l2tvpp.api` | `plugins/pppoe/pppoe_api.c` |
| `l2tvpp_cli.c` | `l2tvpp tunnel/session add`, `show l2tvpp ...` | `plugins/pppoe/pppoe.c` (CLI part) |
| `node.c` | `l2tvpp-input`: udp 1701 decap + punt | `plugins/pppoe/pppoe_decap.c` |
| `handoff.c` | `l2tvpp-handoff`: spread decap across workers by a hash of (tid, sid), no lookup on the RX worker (M3) | `plugins/nat/nat44-ed/nat44_ed_handoff.c` |
| `flow_handoff.c` | `l2tvpp-flow-handoff`: spread one tunnel by inner 5-tuple right after the driver, optional decap fast path | `vnet/handoff.c` |
| `encap_fastpath.c` | `l2tvpp-encap-fastpath`: uplink -> ip4-midchain, skip ip4-lookup | - |

`l2tvpp.h` holds the one L2TPv2 header parser (`l2tvpp_parse_hdr`) all three
input-side nodes use, and the `(tid, sid)` -> worker hash.

`startup.conf` knobs:

```
l2tvpp {
  handoff-queue-nelts 256
}
```

`handoff-queue-nelts` is the depth (frames per target worker) of the handoff
frame queues; a full queue drops, counted as `congestion drop` on
`l2tvpp-handoff` / `l2tvpp-flow-handoff` in `show errors`. Default 64, rounded
up to a power of two and to at least 8 + number of threads.

Build: copy or symlink this directory to `vpp/src/plugins/l2tvpp/`, then
`make build` (or `make build-release`); the plugin loads as `l2tvpp_plugin.so`.
