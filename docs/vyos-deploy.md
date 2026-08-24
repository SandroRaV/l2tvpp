# Putting l2tvpp onto a VyOS LNS for testing

Two ways to get the plugin onto a VyOS box, then how to run it and check it.
Everything is built against the **same VPP the image ships** (FDio
`stable/2510` + `vyos-vpp-patches`), so there is no ABI guesswork: the
`l2tvpp` plugin is compiled inside VyOS's own build container, in-tree with
every other VPP plugin, and lands in the image's `vpp-plugin-core` package.

> Do NOT copy the plugin `.so` built by `dev-build.sh` (plain upstream VPP,
> no VyOS patches, possibly a different glibc) onto VyOS. Use one of the two
> paths below.

**Control vs data.** accel-ppp still runs the L2TP/PPP *control* plane
(tunnel/session negotiation, LCP, auth, IPCP, RADIUS) - VPP cannot do that.
The *data* plane is VPP's: the plugin owns udp/1701, so once a session is
mirrored into VPP, subscriber packets are decapped/forwarded by VPP and only
control frames are punted to accel-ppp. accel-ppp never forwards subscriber
traffic. In the baked image (path 2) the sync daemon runs automatically, so
this happens with no configuration; the only window where a packet could
reach the kernel is the ~seconds before a brand-new session is mirrored.

Prerequisites on the build host (a Linux box with Docker; the dev VM works
once `docker.io` is installed):

```
git clone https://github.com/SandroRaV/l2tvpp.git
cd l2tvpp
```

VyOS `rolling` (the dev branch; the old `current` git branch is gone) and the
Stream builds both build `stable/2510` today; `build/package.toml`
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
commands - use `sudo su -` or the `configure` shell):

```
sudo dpkg -i /tmp/vpp-plugin-core_*.deb
# VyOS only loads an allowlist of VPP plugins, so enable l2tvpp in the
# template (persists within this image install):
sudo sed -i '/plugin pppoe_plugin.so { enable }/a\    plugin l2tvpp_plugin.so { enable }' \
  /usr/share/vyos/templates/vpp/startup.conf.j2
sudo sed -i '/plugin pppoe_plugin.so { enable }/a\    plugin l2tvpp_plugin.so { enable }' \
  /run/vpp/vpp.conf 2>/dev/null || true
sudo systemctl restart vpp
vppctl show plugins | grep l2tvpp        # l2tvpp_plugin.so must be listed
```

> VyOS renders `/run/vpp/vpp.conf` from
> `/usr/share/vyos/templates/vpp/startup.conf.j2` on every `vpp` commit, so
> editing the template is what makes the enable stick; editing `vpp.conf`
> directly only lasts until the next commit/reboot. The baked-ISO path (2)
> does this for you via the build hook.

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

`build-iso.sh` also bakes in a chroot hook
(`build/vyos-hooks/50-l2tvpp-enable-vpp-plugin.chroot`) that adds
`plugin l2tvpp_plugin.so { enable }` to VyOS's VPP `startup.conf` template -
necessary because VyOS uses `plugin default { disable }` plus an allowlist,
so an un-listed plugin ships but never loads.

Upstreaming later: the clean way to get l2tvpp into stock VyOS is a patch to
`vyos-vpp-patches` (the same mechanism VyOS uses for its own VPP changes) or
an out-of-tree plugin package; `build/package.toml` shows the one-line
in-tree hook to adapt.

## 3. Bring the port into VPP and load the plugin

The plugin needs the LAC-facing interface owned by VPP (kernel-mode NICs
cannot reach the VPP data path). On VyOS that is the VPP dataplane config,
e.g. `eth8` = access (LAC-facing), `eth9` = uplink. Confirm VPP sees them:

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

**In the baked image (path 2) this is already done:** `l2tvppd` is installed
at `/usr/libexec/l2tvpp/l2tvppd.py` and enabled as `l2tvppd.service`, running
`daemon --interval 5` with the LNS local IP auto-derived per tunnel from
`ip l2tp show tunnel` - zero config. Check it:

```
systemctl status l2tvppd
journalctl -u l2tvppd -f
```

Override args (rare) via `/config/l2tvpp/l2tvppd.env` (`L2TVPPD_ARGS=...`),
which persists across upgrades. Skip the rest of this section on a baked
image.

For the quick/dpkg path (path 1), put the daemon on the box yourself
(persist under `/config` so it survives upgrades):

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
