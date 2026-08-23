# Rig test: BNG Blaster LAC -> VyOS LNS with the l2tvpp data plane (M1)

This is the hardware half of `design.md` milestone M1: the plugin has passed
`make test` (`first-test.md`), now it goes onto the real VyOS LNS and takes
over the data path of sessions that BNG Blaster, acting as LAC, brings up
through accel-ppp. The whole tester side and the kernel-LNS baseline are
already built and verified in
`manuals/dgw/lns/config_manuals/bngblaster/bngblaster-lac-l2tp-vyos-lns.md`
(2026-08-13: 500 sessions, 1000/1000 flows, 0 loss, ~213k pps ceiling in the
kernel). Nothing on the blaster changes. This doc only adds what is new on the
LNS and says what to measure.

```
+-----------------------------+                         +-------------------------------------+
| BNG Blaster (PR 387 LAC)    |   L2TP/UDP 1701         | VyOS LNS (DUT)                      |
| 5019D, ConnectX-4           |------------------------>| eth8 10.66.0.1 (VPP)                |
|  0000:65:00.0  tunnel       |   10.66.0.2/.3 -> .1    |   udp 1701 -> l2tvpp-input          |
|  0000:65:00.1  core         |<=======================>|     session hit: decap -> FIB -> eth9|
|  198.18.0.2                 |                         |     miss/control: ip4-punt -> tap ->|
+-----------------------------+                         |       kernel accel-ppp (as today)   |
                                                        | eth9 198.18.0.1 (VPP)               |
                                                        |   100.64.x.y/32 via l2tvppN -> encap|
                                                        +-------------------------------------+
```

Files in this repo for the rig: `lab/bngblaster/lac-test.json` (blaster),
`lab/vyos/lns.txt` (LNS control plane), `syncd/l2tvpp-install.py` (puts the
kernel's sessions into VPP).

## 1. What this run has to prove

1. The plugin loads inside the VyOS VPP and **does not break the kernel LNS**
   while no session is installed: every UDP 1701 packet now passes through
   `l2tvpp-input`, is punted, and accel-ppp must still bring up 500 sessions
   exactly as before. This is the `ip4-punt` wiring question from
   `m0-notes.md` step 2, answered on the real box.
2. An installed session forwards in VPP: `show l2tvpp session` counters
   climb, the kernel `pppN` counters stop, the blaster still verifies the flow
   in both directions.
3. LCP echo keeps the session alive while VPP owns the data path (echo is
   punted, design step 5).
4. A first number: pps and loss with all 500 sessions in VPP versus the
   kernel baseline from the same rig.

## 2. Build the VyOS-identical packages

On the Debian build host (`first-test.md` step 2), after `make test` is green:

```
/home/<user>/l2tvpp/build/build-vpp-debs.sh
ls -la /home/<user>/l2tvpp/build/out/
```

`build/package.toml` must match the VyOS image on the DUT: on the DUT
`vppctl show version` and `dpkg -l | grep vpp` give the version; the build
clones `vyos-build` `current`, so if the DUT runs an older rolling image,
either upgrade the DUT to a current rolling image first (cleanest, the ISO
route in `build/build-iso.sh`) or build from the matching `vyos-build`
commit. A plugin built against a different VPP ABI does not load.

Copy to the DUT:

```
scp /home/<user>/l2tvpp/build/out/vpp-plugin-core_*.deb vyos@<dut>:/tmp/
```

## 3. Install the plugin on the DUT

```
sudo dpkg -i /tmp/vpp-plugin-core_*.deb
ls -la /usr/lib/x86_64-linux-gnu/vpp_plugins/l2tvpp_plugin.so
sudo systemctl restart vpp
vppctl show plugins | grep -i l2tvpp
vppctl show udp punt 2>/dev/null; vppctl show node l2tvpp-input
```

If `show plugins` does not list it, the startup config disables plugins by
default. Find the file VPP was started with (`ps -o args= -C vpp` shows
`-c <file>`) and add

```
plugins {
    plugin l2tvpp_plugin.so { enable }
}
```

VyOS regenerates that file on commit, so for anything longer than one session
put the line into the template the VyOS `vpp` module renders, or re-add it
from `/config/scripts/vyos-postconfig-bootup.script` and restart VPP there.
Record which of the two was needed in `m0-notes.md` step 2.

**Restarting VPP drops eth8/eth9 and every L2TP session.** Do this before the
blaster is started, never mid-run.

## 4. LNS control plane and baseline

Paste `lab/vyos/lns.txt` in `configure` mode, `commit`, `save`. Then the
DUT checklist from the blaster doc step 8 (ports in VPP, hugepages, isolated
cores, 25G autoselect, no `disable-*` kernel toggles, no `service
pppoe-server`).

Record, before the first session, what VPP knows about the pool and the
tunnel endpoint, so the "after" state can be compared:

```
vppctl show ip fib 10.66.0.1/32
vppctl show ip fib 100.64.0.0/20
vppctl show ip fib 198.18.0.0/24
vppctl show interface
```

## 5. Sessions up through the kernel, plugin loaded, nothing installed

Blaster:

```
bngblaster -C /root/lac-test.json -S /run/bngblaster.sock -I \
  -L /root/lac-run.log -l error
```

(`lab/bngblaster/lac-test.json` copied to `/root/lac-test.json`; streams do
not autostart.)

DUT, expect exactly the kernel-LNS picture: 2 tunnels, 500 sessions.

```
show l2tp-server sessions | tail -3
show l2tp-server statistics
vppctl show node counters | grep -i l2tvpp
vppctl show errors | grep -i l2tvpp
```

The `l2tvpp-input` error counters must show only `control message, punted`
and `unknown session, punted` (plus `non-IP PPP protocol, punted` once
sessions run LCP/IPCP). If sessions do **not** come up with the plugin
loaded but do without it (`vppctl` `set interface` untouched, only the
plugin disabled and VPP restarted), the punt is wrong: `vppctl trace add
dpdk-input 50` on eth8 during an SCCRQ, `vppctl show trace`, and look at what
follows `l2tvpp-input`. The buffer must reach the linux-cp tap (`tap4096`
on this DUT) with `current_data` at the IP header. Fix in `node.c` and come
back to this step. This is the one place M1 can stall, so budget for it.

Start 1 pps streams to confirm the kernel path still verifies 1000/1000:

```
bngblaster-cli /run/bngblaster.sock stream-start
bngblaster-cli /run/bngblaster.sock stream-summary
```

## 6. Install the sessions into VPP

What the helper needs per session: LAC ip/port, local/peer tunnel id,
local/peer session id, the `pppN`, and the subscriber address. It reads
`/proc/net/pppol2tp` (one `SESSION` block per kernel session; the `interface
pppN` line inside it is what maps a session to its PPP interface, kernels
since 4.17) and `ip -4 addr show pppN` (the `peer` address is the
subscriber).

```
sudo head -20 /proc/net/pppol2tp
sudo python3 /config/l2tvpp/l2tvpp-install.py list
```

`list` must print 500 lines with an `ifname` and a `subscriber` on each. If
`ifname` reads `?`, this kernel's `/proc/net/pppol2tp` lacks the interface
line; the fallback is `ss -xp` / `ls -l /proc/$(pidof accel-pppd)/fd` to
match pppol2tp sockets to channels, or reading the session id out of
accel-ppp's log per `pppN` (`accel-cmd show sessions ifname,...` has no
session id column). Note the outcome in `m0-notes.md` step 3.

Also check the local UDP port the tunnels really use: `ss -ulnp | grep
1701` must show accel-pppd bound on `10.66.0.1:1701`. If accel-ppp runs with
ephemeral ports, pass `--local-port` and, more importantly, the plugin's
`udp_register_dst_port(1701)` would never see the data (design step 3b);
VyOS's accel-ppp template decides this.

Then install, first a dry run to read the commands, then for real:

```
sudo python3 /config/l2tvpp/l2tvpp-install.py apply --dry-run | head -20
sudo python3 /config/l2tvpp/l2tvpp-install.py apply
vppctl show l2tvpp tunnel
vppctl show l2tvpp session | head
vppctl show interface | grep -c l2tvpp
vppctl show ip fib 100.64.0.5/32
```

Expected: 2 tunnels, 500 sessions, 500 `l2tvppN` interfaces up, and the
subscriber `/32` resolving to a midchain adjacency on its `l2tvppN`, not to
the punt path. Setup rate: note how long 500 `vppctl` round trips take
(`time ... apply`); the API-based daemon (M2) replaces this, but the number
tells whether interface creation is a concern (design step 7).

## 7. Prove VPP owns the data path

With 1 pps streams running:

```
# VPP side: these must climb
vppctl show l2tvpp session | head -3
vppctl show interface l2tvpp0
vppctl show runtime | grep -A3 l2tvpp
vppctl show errors | grep -i l2tvpp

# kernel side: these must stop moving
ip -s link show ppp0
watch -n2 'ip -s link show ppp0 | tail -4'
```

Blaster: `stream-summary` still 1000/1000 verified, `rx-loss` 0.

Then leave it for 3 minutes (LCP echo interval on accel-ppp is 30 s,
`lcp-echo-failure` default 3): sessions must stay up.
`show l2tp-server sessions | wc -l` unchanged, `vppctl show errors` shows
`non-IP PPP protocol, punted` growing by ~500 every 30 s (the echo requests
from the LAC), nothing else.

If the kernel counters keep moving after install, the decap is punting:
`vppctl show errors` tells why (`unknown session` = key mismatch, compare
`show l2tvpp session` against `/proc/net/pppol2tp`; `sequenced/offset/v3` =
the LAC sets the S bit, then `l2tp-client` in the blaster needs
data sequencing off, or the plugin needs sequencing support before M3).

If the blaster loses the downstream flow after install but upstream
verifies: the encap. `vppctl trace add dpdk-input 20` on eth9,
`show trace`, and check the `l2tvpp` rewrite (PPP `FF 03 00 21`, L2TP flags
`0x0002`, tids/sids swapped to the peer's, UDP ports, outer IP). Capture
what the kernel sends for the same session before install
(`tcpdump -ni tap4096 udp port 1701 -c 5 -w /tmp/kernel-encap.pcap`) and diff
the headers.

## 8. Tear down and reinstall

```
sudo python3 /config/l2tvpp/l2tvpp-install.py remove
vppctl show l2tvpp session
```

Traffic must fall back to the kernel path immediately (the `pppN` counters
move again, streams still verify). This is the "stop the daemon and
everything runs in the kernel" property from design step 2; M1 is not done
until it holds. Then `apply` again and make sure nothing leaked
(`vppctl show interface | grep -c l2tvpp` back at 500, not 1000).

Session churn: on the blaster `bngblaster-cli /run/bngblaster.sock
session-stop` then `session-start`; after the sessions are back, `remove`
(state file still lists the old ids) and `apply`. Stale sessions in VPP are
harmless (nothing matches them) but the M2 daemon has to reconcile this;
note what the leftover looks like.

## 9. Numbers

Same sweep as the blaster doc step 12 (packet-size sweep at fixed pps, then
rate sweep at 1400 bytes), same harness, with one addition: after sessions
are established and **before** `stream-start`, run `apply`. The harness's
"wait for ALL SESSIONS ESTABLISHED" hook is where that line goes.

Three runs, same day, same box, so the comparison is one variable:

| Run | Data path | Expectation |
|---|---|---|
| A | kernel (plugin disabled) | the 2026-08-13 baseline, ~213k pps ceiling, 5-6 ms tail |
| B | kernel (plugin loaded, nothing installed) | identical to A; any difference is punt cost |
| C | VPP (all 500 installed) | single worker: bounded by one core doing decap+encap; read `show runtime` vectors/call |

Record in `bench/` as an md + html pair (`manuals` convention), with
`vppctl show runtime` and `show errors` for run C attached. The number that
matters for M3 planning is run C's pps per worker clock, since M3 adds the
handoff across workers.

MTU: the rig runs 1400-byte L3 streams, PPP MRU 1492, so the outer frame on
eth8 stays under 1508 (the ports' current MTU). For 1500-byte subscriber
frames the encap side adds 2 + 6 + 8 + 20 = 36 bytes; the plugin writes
the outer IP with DF clear (design step 3c) so the LAC side can fragment,
but on this rig raise the blaster ports and eth8/eth9 to 1600 instead.

## 10. What goes back into the repo

- `m0-notes.md`: punt path (step 3 here), session-id source (step 6), local
  port (step 6), S bit behaviour of the blaster LAC (step 7).
- `design.md` step 4: the event source for M2, now that the data per session
  is known to be available from `/proc/net/pppol2tp` plus `ip addr`, or not.
- `bench/`: the three-run table.
- Any `node.c` fix that step 5 or 7 needed, with a `test/` case that would
  have caught it.
