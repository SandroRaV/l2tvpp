# l2tp2: VPP L2TPv2 LNS data plane plugin

See `../../docs/design.md` step 3. Files to be written in M1:

| File | Content | Template in VPP |
|---|---|---|
| `l2tp2.c` | tunnel/session pools, bihash, session interface class, adjacency tracking | `plugins/pppoe/pppoe.c` |
| `l2tp2_api.c` | binary API handlers for `l2tp2.api` | `plugins/pppoe/pppoe_api.c` |
| `l2tp2_cli.c` | `l2tp2 tunnel/session add`, `show l2tp2 ...` | `plugins/pppoe/pppoe.c` (CLI part) |
| `node.c` | `l2tp2-input` (udp 1701 decap + punt), `l2tp2-handoff` | `plugins/pppoe/pppoe_decap.c`, `plugins/nat/nat44-ed/nat44_ed_handoff.c` |
| `encap.c` | session interface tx: prepend PPP + L2TP + UDP + IP, to ip4-lookup / cached adj | `plugins/pppoe/pppoe_encap.c` |

Build: copy or symlink this directory to `vpp/src/plugins/l2tp2/`, then
`make build` (or `make build-release`); the plugin loads as `l2tp2_plugin.so`.
