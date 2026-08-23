# l2tp_steer: XDP CPU steering for an L2TPv2 LNS on Linux / VyOS

## 1. Problem

All L2TP tunnels between one LAC and the LNS share a single UDP 4-tuple
(`LAC:1701 -> LNS:1701`). NIC RSS hashes the outer headers only, so every
session behind that LAC lands on one RX queue and one core. The kernel L2TP
code (`l2tp_core`, `pppol2tp`, used by accel-ppp and therefore by VyOS
`vpn l2tp remote-access`) scales per core, but never gets the chance.

`l2tp_steer` is an XDP program that runs before the kernel stack, reads the
L2TPv2 tunnel ID + session ID, and redirects the frame to a CPUMAP entry so
the rest of the receive path (L2TP decap, PPP, routing, tc) runs on that
core. Same session always goes to the same core, so ordering is preserved.
Control messages (T bit) and all non-L2TPv2 traffic are passed untouched.

Only applies when the Linux kernel owns the NIC. In VyOS VPP/DPDK mode the
port belongs to VPP and native XDP has nothing to attach to.

Related docs in this repo: `manuals/dgw/lns/config_manuals/vyos/vyos-l2tp-lns-tuning.md` (in the notes repo)
(the RSS/RPS analysis and what does not work), `epyc-7f32-h12ssl-pppoe-dut.md`
(the box), `vyos-l2tp-lns-bngblaster-epyc-7f32.md` (the measurement setup).

## 2. Files

- `/path/to/l2tp-xdp/l2tp_steer.bpf.c`: the XDP program (no CO-RE, no vmlinux.h)
- `/path/to/l2tp-xdp/l2tp_steer.c`: loader (attach, fill cpumap, pin maps, stats, detach)
- `/path/to/l2tp-xdp/Makefile`

## 3. Build (Debian 12 build host, VyOS 1.5 is Debian 12 based)

```
apt-get install -y clang llvm gcc make libbpf-dev linux-libc-dev
cd /path/to/l2tp-xdp
make
```

Produces `l2tp_steer.bpf.o` and `l2tp_steer`. The loader links against
`libbpf.so.1`, which VyOS 1.5 ships (`ls /usr/lib/x86_64-linux-gnu/libbpf.so.1`).
If it is missing, build the loader statically: `make CFLAGS="-O2 -static"`.

## 4. Install on the VyOS LNS

```
mkdir -p /config/l2tp-steer
scp l2tp_steer l2tp_steer.bpf.o vyos@lns:/config/l2tp-steer/
```

Attach to the LAC-facing interface, steering to cores 1..7 (keep core 0 for
the control channel, accel-ppp and RADIUS):

```
sudo /config/l2tp-steer/l2tp_steer -i eth8 -c 1-7
```

Check it is doing something while BNG Blaster pushes traffic:

```
sudo /config/l2tp-steer/l2tp_steer -s -w 1
mpstat -P ALL 1
```

`redirect` should climb, and `%soft` should now be spread over cores 1..7
instead of pegging one. The redirected packets are processed by kernel
threads named `cpumap/N/map:M`, visible in `top`.

Detach:

```
sudo /config/l2tp-steer/l2tp_steer -i eth8 -d
```

## 5. Persist across reboots

`/config` survives upgrades, the attach does not. Add to
`/config/scripts/vyos-postconfig-bootup.script`:

```
/config/l2tp-steer/l2tp_steer -i eth8 -c 1-7
```

## 6. ConnectX-4 Lx (mlx5) on the EPYC 7F32 box

The EPYC DUT (`manuals/dgw/lns/config_manuals/epyc-7f32-h12ssl-pppoe-dut.md`)
carries both test legs on a ConnectX-4 Lx (MT27710, `15b3:1015`, `mlx5_core`).
On VyOS the access leg is `eth1` (`0000:81:00.0`) and the uplink `eth2`, so the
attach line there is:

```
sudo /config/l2tp-steer/l2tp_steer -i eth1 -c 1-7
```

What matters for XDP on this card:

- mlx5 has native XDP including `XDP_REDIRECT`, so CPUMAP redirect works in
  driver mode; no firmware requirement beyond what the card already runs
  (`ethtool -i eth1` shows it; 14.32.1010 on the sister rig was fine).
- **MTU ceiling with XDP attached: 3498 bytes** on 4K pages (mlx5 switches to
  one page per packet for XDP). The 1508 / 1600 transfer-net MTUs from the
  LNS docs are far below that; the attach fails with an MTU error if someone
  sets jumbo 9000 on `eth1`.
- mlx5 keeps hardware VLAN stripping on with XDP, so a tagged frame reaches
  the program without its tag. The parser handles both the tagged and the
  stripped case, and on the EPYC rig the transfer net is untagged anyway.
- Attaching XDP re-creates the RX queues. Re-run the `ethtool -G` ring size,
  `ethtool -L` channel count and the IRQ pinning from
  `vyos/vyos-l2tp-lns-tuning.md` step 1 *before* attaching, and put the
  attach last in the boot script.
- The `ethtool -N eth1 rx-flow-hash udp4 sdfn` from the tuning doc stays
  useful: it spreads *tunnels* in hardware, XDP then spreads *sessions* within
  a tunnel. Both together give the finest spread.
- With 8C/16T, `-c 1-7` uses the physical cores' first threads; `-c 1-15`
  adds the SMT siblings. Benchmark both, SMT siblings do not give 2x for
  softirq work.

## 7. Tuning

- `-q QSIZE`: per-cpu queue (default 2048). Raise if `redirect_fail` grows or
  `cpumap` drops show up in `bpftool map` / `perf stat -e xdp:xdp_cpumap_kthread`.
- Hash is per session, so with few sessions the spread is uneven; with
  hundreds it evens out.
- Non-first IPv4 fragments and L2TP over IPv6 with extension headers are
  passed through (no UDP header to parse), so keep the outer MTU large enough
  that L2TP frames are not fragmented, as you should anyway.
- The LNS -> LAC direction is not touched: it runs on whichever core received
  the downstream packet on the core-facing side, where RSS already works.
- Native XDP needs a driver with XDP support (ixgbe, i40e, ice, mlx5, ...).
  `-S` (generic mode) works everywhere but costs an skb allocation first;
  use it only to validate the logic.

## 8. Debugging the verifier

If `load:` fails, rerun with `LIBBPF_LOG_LEVEL=debug` or load by hand:

```
sudo bpftool prog load /config/l2tp-steer/l2tp_steer.bpf.o /sys/fs/bpf/test
```

and read the verifier log it prints.
