# LNS single-flow throughput: EPYC vs Xeon, and the fast-path work

Bench comparison of the l2tvpp L2TPv2 LNS data plane on two DUTs driven by a
Viavi tester that emulates the LAC and a single subscriber. The load is one
tunnel, one session, one inner 5-tuple with 64-byte inner frames. This is the
hardest case for a software LNS: a single flow cannot be spread across cores
in order, because the NIC hashes only the outer L2TP 4-tuple, which is
identical for every packet.

Management addresses are placeholders (`<lns-epyc>`, `<lns-xeon>`); lab bench
addressing (198.18.0.0/24, 10.66.0.0/24, 100.64.0.0/20) is the documented lab.

## 1. The two DUTs

| | DUT A `<lns-epyc>` | DUT B `<lns-xeon>` |
|---|---|---|
| CPU | AMD EPYC 7F32 | Intel Xeon E-2134 |
| Microarchitecture | Zen 2 (Rome), chiplet | Coffee Lake, monolithic |
| Cores / threads | 8 / 16 | 4 / 8 |
| Base / boost clock | 3.7 / 3.9 GHz | 3.5 / 4.5 GHz |
| L3 cache | 128 MB | 8 MB |
| NIC | ConnectX-4 Lx 25G | ConnectX-4 Lx 25G |
| VPP workers (VyOS max) | 6 (main + 5) | 2 (main + 1) |

Both run the same VyOS rolling l2tvpp image, VPP 25.10 on stable/2510, and the
same plugin build.

## 2. Data-plane optimizations applied

All are in the l2tvpp plugin or the VyOS VPP settings; see `design.md`.

1. **Vectorized mlx5 receive** (`no-multi-seg` in the VPP startup template).
   Turns the mlx5 Rx burst from Scalar to Vector SSE. Prerequisite for
   everything else; on its own it lifted decap from 5.7 to 6.3 Mpps and cut
   `dpdk-input` from ~130 to ~77 clocks.
2. **Decap fast path** (`l2tvpp flow-handoff <if> fastpath`). Validates the
   outer header in a device-input feature and delivers L2TP data straight to
   `l2tvpp-input`, skipping ethernet-input, ip4-input, ip4-lookup, ip4-receive
   and udp-local.
3. **Inner checksum off** (`l2tvpp inner-checksum off`). The decapsulated IPv4
   goes to `ip4-input-no-checksum`; the outer hop is FCS-protected.
4. **Spray** (`l2tvpp flow-handoff <if> workers <list> [fastpath] spray`).
   Round-robin per packet across a worker set, so one flow fans across cores.
   Reorders within the flow, so it is a tester/throughput tool only, never a
   production LNS.
5. **Encap fast path** (`l2tvpp encap-fastpath <uplink>`). A device-input
   feature on the uplink that caches subscriber IPv4 to the session's midchain
   adjacency and jumps straight to `ip4-midchain`, skipping ethernet-input,
   ip4-input and ip4-lookup. Balances the encap direction against the decap
   fast path.

## 3. Measured results

Rates are per direction, 64-byte inner frames. "Offered" is what the Viavi
put on the wire; loss is NIC receive-ring overflow (`rx_out_of_buffer`).

### EPYC, in-order fast path, one worker per direction

| Direction | Offered | Taken | Loss |
|---|---|---|---|
| decap | 6.26 Mpps | 6.23 Mpps | 0.37 - 0.48% |
| encap | 6.23 Mpps | 6.23 Mpps | 0% |

The Viavi against the EPYC stayed at ~5.5 Gbps (~6.2 Mpps), below one core's
ceiling, so neither direction was pushed to its limit. Spray runs spread both
directions across several workers and stayed clean at the same offered rate.

### Xeon, one worker for both directions (VyOS default on 4 cores)

| Direction | Offered | Taken | Loss |
|---|---|---|---|
| decap | 5.69 Mpps | 5.69 Mpps | 0.035% |
| encap | 5.69 Mpps | 3.70 Mpps | 34.9% |

One worker saturates at **9.38 Mpps aggregate**. Decap is serviced first,
encap takes what is left.

### Xeon, two workers (one per direction, after raising the VyOS core limit)

| Direction | Offered | Taken | Loss |
|---|---|---|---|
| decap | 8.45 Mpps | 8.45 Mpps | 0.056% |
| encap | 8.45 Mpps | 8.20 Mpps | 2.97% |

Decap is clean past 8.45 Mpps. The encap direction is the wall at ~8.2 Mpps
(~7.2 Gbps on these frames), because it lacked the fast path decap has. This
is what the encap fast path (optimization 5) addresses.

## 4. The single-flow ceiling

A single flow lands on a single NIC Rx queue, so one core must receive and
classify all of it. Effective cost per packet:

| | EPYC 7F32 | Xeon E-2134 |
|---|---|---|
| One worker, single flow | ~6.2 Mpps | ~9.4 Mpps |
| Effective cost per packet | ~594 clocks | ~400 - 480 clocks |

10G at 64 bytes needs ~9.2 Mpps on the encapsulated frames. The EPYC core
cannot reach it in order; the Xeon core is within reach for one direction.

## 5. Why the Xeon core is faster here

The clock difference (3.9 vs 4.5 GHz boost, ~15%) is smaller than the
throughput difference (~50%). The rest is cost per packet, which is
architecture:

- VPP's per-packet work is dominated by touching headers the NIC just DMA'd
  to DRAM. Those are cache misses, and their cost is memory latency.
- The EPYC 7F32 is a chiplet design: cores on compute dies reach memory
  across the Infinity Fabric through a separate I/O die. Every miss pays that
  hop.
- The Xeon E-2134 is a single monolithic die with an on-die memory
  controller, so the same miss costs fewer stall cycles.
- Neither chip has direct-to-cache I/O (Intel DDIO is Xeon Scalable only; AMD
  added SDCI only in Turin / Zen 5), so both pull packets from DRAM, but the
  Xeon's path is shorter.

The EPYC's 128 MB L3 does not help a single flow, because the packet data
lands in DRAM, not L3, and is read once. The big L3 is an asset at production
scale, where a large FIB, many sessions and many adjacencies for thousands of
subscribers all stay L3-resident. That is also the case where the EPYC's many
cores win outright, because thousands of subscribers are thousands of flows
that RSS spreads across all cores in order. The single-flow wall is specific
to this one-session test.

## 6. Can L3 be used to optimize further?

The ideal lever, making the NIC inject packets straight into L3 (DDIO /
SDCI), is not available on either CPU. What remains are two software levers
that keep the working set in cache and hide the DRAM latency the L3 would
otherwise absorb:

1. **Software prefetch distance.** The hot nodes already prefetch upcoming
   packets (`clib_prefetch_load` on b[i+2]/b[i+4]). On the EPYC's higher
   memory latency a longer prefetch distance may hide more of the stall.
   Testable: vary the distance and read `show runtime` clocks per vector.
2. **Right-size the Rx ring for cache residency.** The ring was raised to
   8192 descriptors to absorb bursts, which enlarges the descriptor and mbuf
   working set. A smaller ring keeps that set cache-hot and can lower
   per-packet latency, at the cost of burst tolerance. Testable A/B against
   loss and clocks per packet.

Both trade against burst loss, so they are bench experiments, not blanket
settings. Neither turns the EPYC single-flow core into a 10G core; the
architectural memory-latency gap is the limit without direct cache injection.

## 7. Conclusions

- For a single in-order flow, a higher-clock, lower-latency monolithic core
  (the Xeon) is the better fit and gets close to 10G per direction; the
  chiplet EPYC tops out lower per core.
- The decap and encap fast paths remove ~5 forwarding nodes each and are the
  main software gains; the encap fast path closes the asymmetry that showed up
  only when encap had one core and the load exceeded its ceiling.
- Spray reaches higher aggregate rates for one flow but reorders, so it is a
  test tool only.
- The many-core, large-L3 EPYC is the right production LNS, where thousands of
  subscribers are thousands of flows spread in order across all cores. The
  single-flow ceiling seen here does not apply to that workload.
