# L2TPv2 LNS data plane in VPP: design

Status: draft, 2026-08-23. Target box: EPYC 7F32 / ConnectX-4 Lx
(`manuals/dgw/lns/config_manuals/epyc-7f32-h12ssl-pppoe-dut.md`), later any
VPP host with an E810.

## 1. Goal

Terminate L2TPv2/PPP subscriber sessions with the per-packet data path in
VPP, so that an LNS on commodity hardware forwards beyond 10G without the
kernel single-core limit (`vyos/vyos-l2tp-lns-tuning.md` step 1) and without
the VPP punt ceiling (~213k pps, `6wind-vsr-lns-l2tp-bngblaster.md`).

Not a goal: a new control plane. L2TP control channel, PPP LCP/auth/IPCP/
IPv6CP, RADIUS, pools and CoA stay in accel-ppp (accel-ppp-ng on VyOS).

## 2. Architecture

Same split VyOS uses for PPPoE offload (`vyos-vpp-pppoe-epyc-7f32.md`
step 9 and step 11), with L2TP/UDP/IP instead of PPPoE/Ethernet:

```
 LAC ---UDP 1701---> [VPP access port]
                          |
                    l2tp2-input (udp dst 1701)
                          |
          +---------------+----------------------+
          | session known AND PPP proto IP/IPv6  | everything else
          v                                      v
   decap, set rx sw_if_index = session if     punt to kernel via the
   -> ip4-input / ip6-input -> FIB -> uplink   LCP tap (vpp-cp punt)
                                                 |
                                              kernel l2tp_core / pppol2tp
                                              accel-ppp: control, LCP, auth,
                                              IPCP, echo, RADIUS
                                                 |
                                              l2tp2-syncd: on session up,
                                              install session in VPP;
                                              on down, remove it

 Internet ---> [VPP uplink] -> FIB: subscriber /32 or /56 -> session interface
                  -> l2tp2-encap (PPP + L2TP + UDP + IP) -> access port -> LAC
```

Packets that VPP does not own (control messages, LCP echo, IPCP, unknown
session, sequenced sessions until supported) go to the kernel unchanged, so
the existing kernel LNS keeps working underneath; VPP only takes over
sessions that the sync daemon has installed. That also gives a trivial
fallback: stop the daemon and everything runs in the kernel again.

## 3. VPP plugin `l2tp2`

Modelled on `src/plugins/pppoe/` (per-session interface, FIB adjacency,
encap/decap nodes) and `src/vnet/udp/udp.h` port registration.

### 3a. Objects

- **tunnel**: local ip, peer ip, local udp port, peer udp port, local tunnel
  id, peer tunnel id. Keyed by (peer ip, peer port, local tunnel id) on
  decap.
- **session**: tunnel, local session id, peer session id, own
  `sw_if_index` (a `l2tp2_session` interface, like `pppoe_session`), PPP
  framing flags (ACFC/PFC as negotiated, needed for encap), counters.
  Decap key: (tunnel index, local session id).
- Session lookup: bihash 16_8 keyed on (peer ip4, peer port, tunnel id,
  session id) -> session index. One lookup per packet.

### 3b. Decap node `l2tp2-input`

Registered with `udp_register_dst_port(vm, 1701, l2tp2_input_node.index, 1)`
for IPv4 (IPv6 outer later).

1. Read L2TPv2 flags. `T` set (control), version != 2, `S` set (sequenced)
   or `O` set: punt.
2. Lookup (peer ip, peer port, tunnel id, session id). Miss: punt.
3. Skip optional Length, read PPP: optional `FF 03`, protocol 1 or 2 bytes
   (PFC). Protocol `0x0021` -> strip, `ip4-input`. `0x0057` -> `ip6-input`.
   Anything else (LCP `0xC021`, IPCP `0x8021`, IPV6CP `0x8057`, CHAP, PAP,
   echo) -> punt.
4. Set `vnet_buffer(b)->sw_if_index[VLIB_RX]` to the session interface so
   ACLs, counters and uRPF see the subscriber interface, not the LAC port.

Punt = rewrite nothing and enqueue to the node the vpp-cp punt uses for
the access interface (investigate in milestone 0 how VyOS wires the pppoe
punt; reuse that path so accel-ppp sees the frame exactly as it does today).

### 3c. Encap (session interface tx)

Session interface `tx` function, or an adjacency rewrite per session
(pppoe uses the interface tx). Prepends, in order: PPP protocol (2 bytes,
or 1 with PFC; `FF 03` unless ACFC), L2TPv2 header (flags 0x0002, tunnel id,
session id; no Length, no sequencing), UDP (src 1701 or the ephemeral port
accel-ppp chose, dst = peer port, checksum 0 or offloaded), IPv4 (DF clear,
so the LAC path can fragment when the transfer MTU is short), then hand to
`ip4-lookup` for the outer destination, or directly to the cached
adjacency of the LAC for speed (pppoe caches the adjacency; do the same).

Rewrite is precomputed per session at install time; the per-packet work is
a memcpy of the rewrite and two length/checksum fixups.

### 3d. Worker distribution

ConnectX-4 Lx RSS sees only the outer tuple, so one LAC = one worker on RX.
Add a handoff stage like `nat44-ed` does: `l2tp2-input` on the RX worker
parses just far enough to get the session index and enqueues the buffer to
worker `session_index % n_workers` via `vlib_buffer_enqueue_to_thread`;
that worker does decap and forwarding. Encap direction is already spread by
the uplink RSS. On an E810 the DDP L2TPv2 RSS profile replaces the handoff
(DPDK 22.03+, `RTE_ETH_RSS_L2TPV2`); keep the handoff optional via a CLI
flag so both can be benchmarked.

### 3e. API and CLI

`l2tp2.api`:
- `l2tp2_tunnel_add_del(local_ip, peer_ip, local_port, peer_port, local_tid, peer_tid, is_add) -> tunnel_index`
- `l2tp2_session_add_del(tunnel_index, local_sid, peer_sid, acfc, pfc, is_add) -> sw_if_index`
- `l2tp2_session_dump`, `l2tp2_tunnel_dump`
- `l2tp2_set_handoff(enable)`

CLI mirrors these: `l2tp2 tunnel add ...`, `l2tp2 session add ...`,
`show l2tp2 tunnel`, `show l2tp2 session`.

Routes to the subscriber (IPv4 /32, IPv6 /128 and delegated prefix) are
plain `ip_route_add_del` on the session interface, installed by the sync
daemon, so the plugin stays FIB-agnostic.

## 4. Sync daemon `l2tp2-syncd`

Python with `vpp_papi` for the first version (fast to iterate; the rate of
session events is RADIUS-bound, not a hot path). Rewrite in Go or C later if
setup rate needs it.

Event source, in order of preference (decide in milestone 0):
1. accel-ppp-ng's own VPP hook, if the PPPoE offload already lives inside
   accel-ppp-ng (then the L2TP case is an extension of that code, not a
   separate daemon).
2. accel-ppp `[pppd-compat]` `ip-up` / `ip-down` scripts, which expose
   `IFNAME`, `PEERNAME`, `IPLOCAL`, `IPREMOTE`; the L2TP tunnel/session ids
   and peer address then come from the kernel (`ip l2tp show session`,
   `/proc/net/pppol2tp`, or L2TP genetlink dump) matched on the ppp
   interface.
3. Polling `accel-cmd show sessions` plus the kernel L2TP tables.

For each session up: ensure tunnel in VPP, add session, add routes, record
the mapping. For each session down: remove in reverse. On daemon start:
reconcile VPP state against the kernel state so a restart is harmless.

Framing flags (ACFC/PFC) come from what accel-ppp negotiated; if they are
not exposed, force them off in accel-ppp's `[ppp]` section for the first
milestone, so encap always writes `FF 03 00 21`.

## 5. What stays in the kernel, and why that is fine

- LCP echo: accel-ppp sends every 30s per session, the LAC's echo requests
  arrive at the same rate. Thousands of sessions = tens of pps on the punt
  path. Nothing to worry about.
- Sequenced data sessions (S bit): punted until supported. Carrier LACs
  normally do not enable data sequencing; verify on the real LAC before
  caring.
- MPPE, multilink, compression: punted, which means effectively unsupported
  at speed. Out of scope.

## 6. Milestones

**M0, investigate (days)**: read `src/plugins/pppoe/`; find how VyOS builds
the VPP pppoe punt and how accel-ppp-ng installs pppoe sessions into VPP
(`vyos/accel-ppp-ng` source); confirm how to get tunnel/session ids for a
`pppN` from the kernel; pick the VPP version (the VyOS VPP build or upstream
stable for development). Output: M0 notes in `docs/`, decisions updated here.

**M1, static data path (1-2 weeks)**: plugin with tunnel/session objects,
decap to `ip4-input`, encap via session interface, CLI and API, no handoff.
Test with BNG Blaster in L2TP mode through mpd5 against a plain Linux
accel-ppp LNS: install the session by hand from the CLI after it comes up
in the kernel, watch `vppctl show l2tp2 session` counters move and the
kernel `pppN` counters stop. Benchmark single worker, one session.

**M2, sync daemon (1 week)**: automatic install/remove from accel-ppp
events, restart reconciliation, IPv6 and PD routes. Benchmark hundreds of
sessions, session churn, and verify LCP echo survives.

**M3, scale (1-2 weeks)**: worker handoff, multi-worker benchmark on the
EPYC with the ConnectX-4 Lx; measure against the kernel+XDP baseline
(`l2tp-xdp/`) and the 6WIND numbers in `bench/comparison-25g.md`. Then the
E810 RSS variant if a card is available.

**M4, VyOS integration (later)**: build the plugin into the VyOS VPP
package, wire the daemon into VyOS config (`set vpn l2tp remote-access
offload vpp` or similar), docs in `manuals/dp/en/` with the German pair.

## 7. Risks

- Punt plumbing on VyOS is the least documented part; M0 exists to de-risk
  it. Fallback is a plain `punt` to the LCP tap via the standard `punt`
  infrastructure.
- accel-ppp's kernel `pppN` keeps receiving nothing once VPP owns the data
  path, so accel-ppp idle-timeout or traffic-based accounting would see
  zero traffic. Accounting counters must come from VPP (M2: daemon pushes
  session counters into accel-ppp or RADIUS interim directly).
- Per-session interfaces: VPP handles tens of thousands, but interface
  creation is not free; measure setup rate in M2.
- UDP checksum: LACs may send outer UDP checksum 0 for IPv4; accept both.
  For encap, use 0 for IPv4 (allowed) unless the LAC rejects it.

## 8. Repo layout

```
lns-vpp/
  docs/design.md          this file
  docs/m0-notes.md        findings from M0
  plugin/l2tp2/           VPP plugin: CMakeLists.txt, l2tp2.api, l2tp2.h,
                          l2tp2.c (objects, API, CLI), node.c (decap, handoff),
                          encap.c (session interface tx)
  syncd/                  l2tp2-syncd (python, vpp_papi)
  lab/                    bngblaster + mpd5 + accel-ppp configs for M1/M2
  bench/                  results (md + html pairs)
```

## 9. References

- VPP pppoe plugin: https://github.com/FDio/vpp/tree/master/src/plugins/pppoe
- VPP udp port registration: https://github.com/FDio/vpp/blob/master/src/vnet/udp/udp.h
- VPP nat44-ed handoff node (worker distribution pattern): https://github.com/FDio/vpp/blob/master/src/plugins/nat/nat44-ed/nat44_ed_handoff.c
- DPDK 22.03 release notes, L2TPv2 RSS: https://doc.dpdk.org/guides/rel_notes/release_22_03.html
- RFC 2661 (L2TPv2), RFC 1661 (PPP), RFC 1662 (HDLC-like framing, ACFC/PFC)
- Related docs in this repo: `manuals/dgw/lns/config_manuals/vyos/vyos-vpp-pppoe-epyc-7f32.md`,
  `manuals/dgw/lns/config_manuals/vyos/vyos-l2tp-lns-tuning.md`,
  `6wind-vsr-lns-l2tp-bngblaster.md`, `l2tp-xdp/README.md`
