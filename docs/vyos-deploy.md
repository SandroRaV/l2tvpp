# Putting l2tvpp onto a VyOS LNS for testing

Two ways to get the plugin onto a VyOS box, then how to run it and check it.
Everything is built against the **same VPP the image ships** (FDio
`stable/2510` + `vyos-vpp-patches`), so there is no ABI guesswork: the
`l2tvpp` plugin is compiled inside VyOS's own build container, in-tree with
every other VPP plugin, and lands in the image's `vpp-plugin-core` package.

> Do NOT copy the plugin `.so` built by `dev-build.sh` (plain upstream VPP,
> no VyOS patches, possibly a different glibc) onto VyOS. Use one of the two
> paths below.

Prerequisites on the build host (a Linux box with Docker; the dev VM works
once `docker.io` is installed):

```
git clone https://github.com/SandroRaV/l2tvpp.git
cd l2tvpp
```

VyOS `current` and Stream both build `stable/2510` today; `build/package.toml`
tracks that and must be re-diffed against `build/package.toml.vyos-orig` if
VyOS bumps the VPP version (`docs/first-test.md`).

## 1. Quick path: drop-in the rebuilt plugin package (dev/test)

Build the VyOS VPP `.debs` with l2tvpp inside, then install just the plugin
package on a running VyOS box.

```
./build/build-vpp-debs.sh            # -> build/out/*.deb  (30-60 min first run)
ls build/out/vpp-plugin-core_*.deb
```

Copy the plugin package to the LNS and install it (it is the exact VPP
version already on the box, so it is a clean drop-in):

```
scp build/out/vpp-plugin-core_*.deb vyos@lns:/tmp/
```

On the VyOS box (get a real root shell first - VyOS's op-mode blocks raw
commands; see `vyos-vpp-pppoe-connectx-5019d-4c.md` step 4 in the rig notes):

```
sudo dpkg -i /tmp/vpp-plugin-core_*.deb
sudo systemctl restart vpp
vppctl show plugins | grep l2tvpp        # l2tvpp_plugin.so must be listed
```

Lost on the next `add system image` upgrade - fine for iterating. For a
persistent install use path 2.

## 2. Persistent path: build a VyOS image with l2tvpp baked in

```
./build/build-vpp-debs.sh            # produces the l2tvpp VPP debs
./build/build-iso.sh                 # rolls them into a VyOS ISO
ls build/work/vyos-build/build/*.iso
```

Install that ISO the normal way (`add system image <iso>` from a running
VyOS, or a fresh install). The plugin is part of the image's VPP and
survives upgrades within that image.

Upstreaming later: the clean way to get l2tvpp into stock VyOS is a patch to
`vyos-vpp-patches` (the same mechanism VyOS uses for its own VPP changes) or
an out-of-tree plugin package; `build/package.toml` shows the one-line
in-tree hook to adapt.

## 3. Bring the port into VPP and load the plugin

The plugin needs the LAC-facing interface owned by VPP (kernel-mode NICs
cannot reach the VPP data path). On VyOS that is the VPP dataplane config,
e.g. on the EPYC/ConnectX rig `eth8` = access, `eth9` = uplink
(`epyc-7f32-h12ssl-pppoe-dut.md`). Confirm VPP sees them:

```
vppctl show interface addr
vppctl show plugins | grep l2tvpp
```

The plugin registers UDP 1701 and its CLI as soon as it loads; nothing else
is needed to enable it. Check the CLI is present:

```
vppctl show l2tvpp tunnel        # "no l2tvpp tunnels" until sessions exist
vppctl l2tvpp handoff on         # spread decap across workers (optional)
```

## 4. Run the sync daemon

accel-ppp keeps terminating L2TP/PPP as today; `l2tvppd` mirrors each session
it brings up into VPP (`../syncd/`). Put the daemon on the box (persist under
`/config` on VyOS so it survives upgrades):

```
sudo mkdir -p /config/l2tvpp
scp syncd/l2tvppd.py vyos@lns:/config/l2tvpp/
# vpp_papi ships with VPP; if it is not importable, point PYTHONPATH at it:
vppctl show version                                   # confirm VPP is up
python3 -c 'import vpp_papi' || echo 'set PYTHONPATH to the VPP api dir'
```

One reconcile pass by hand first (safe, idempotent):

```
sudo python3 /config/l2tvpp/l2tvppd.py reconcile \
    --local-ip <accel-ppp outside-address> --local-port 1701 -v
vppctl show l2tvpp session                            # sessions now mirrored
```

Then run it as a service (`../syncd/l2tvppd.service`) and trigger an
immediate reconcile from accel-ppp's ip-up/ip-down
(`../syncd/accel-ppp-hooks.md`). On VyOS, keep the unit file and scripts
under `/config` and enable via `/config/scripts/vyos-postconfig-bootup.script`.

## 5. Verify the offload is live

With BNG Blaster (or the real LAC) bringing sessions up through accel-ppp:

```
show pppoe-server sessions 2>/dev/null                # kernel/control view
vppctl show l2tvpp session                            # MUST list the sessions
vppctl show l2tvpp tunnel
vppctl show runtime | grep l2tvpp                     # l2tvpp-input (+ -handoff)
vppctl clear runtime; # push traffic; then:
vppctl show runtime | grep -E 'l2tvpp|ip4-input'      # vectors climbing in VPP
```

If sessions appear under `vppctl show l2tvpp session` and the per-node
vectors climb there while the kernel `pppN` counters stay flat, traffic is
being forwarded by VPP, not punted to the kernel. Trace a few packets to be
sure of the path:

```
vppctl trace add dpdk-input 20      # or the RX node for your NIC
# push traffic, then:
vppctl show trace                   # expect udp-1701 -> l2tvpp-input ->
                                    # ip4-input (upstream), and for downstream
                                    # ip4-lookup -> ip4-midchain -> tunnel-output
```

Accounting caveat: once VPP forwards, the kernel `pppN` sees no traffic, so
accel-ppp's byte/idle accounting reads zero. Feed counters from
`vppctl show l2tvpp session` (or the `l2tvpp_session_dump` API) into RADIUS
interim accounting - a follow-up, see `../syncd/accel-ppp-hooks.md`.

## 6. Roll back

```
sudo systemctl stop l2tvppd          # kernel keeps forwarding (punt path)
sudo python3 /config/l2tvpp/l2tvppd.py reconcile   # (empty kernel -> clears VPP)
# or just remove the plugin package / boot the previous image
```

Stopping the daemon leaves whatever it installed in place until the next
reconcile; to hand the data path fully back to the kernel, reconcile against
an empty kernel session list or restart VPP.
