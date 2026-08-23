# First test

## 1. What "first test" means right now

The M1 plugin code exists (`plugin/l2tvpp/*.c`) but has never been compiled.
The first test is therefore: build it, get it past the compiler and VPP's
startup, then run the scapy suite in `test/test_l2tvpp.py`. Expect compile
errors on the first pass; paste them back and they get fixed.

## 2. Build host

A Debian 12 machine or VM with 8+ GB RAM, 40 GB disk, git, sudo. Docker only
for the VyOS-identical build later. The Mac cannot do any of this.

```
git clone git@github.com:SandroRaV/l2tvpp.git /home/<user>/l2tvpp
/home/<user>/l2tvpp/build/dev-build.sh
```

That clones FDio VPP `stable/2510` into `build/work/vpp`, installs the build
dependencies, symlinks `plugin/l2tvpp` into `src/plugins/`, builds a debug VPP
and runs `make test TEST=test_l2tvpp`.

## 3. Reading the result

- Compiler error: fix, rerun `/home/<user>/l2tvpp/build/dev-build.sh test`.
- VPP starts but the plugin does not load: `build-root/install-vpp_debug-native/vpp/bin/vpp` with
  `unix { interactive }` and `vppctl show plugins | grep l2tvpp`, check
  `show logging`.
- Tests: five cases. `test_upstream_decap` and `test_downstream_encap` are
  the data path; `test_control_is_punted`, `test_unknown_session_is_punted`,
  `test_lcp_is_punted` guard the boundary to the kernel control plane.
  Failures there are expected to be about the `ip4-punt` wiring
  (`docs/m0-notes.md` step 2), not the decap logic.

## 4. Poking at it by hand

```
cd /home/<user>/l2tvpp/build/work/vpp
make run        # debug VPP with an interactive CLI
```
```
create packet-generator interface pg0
set int ip address pg0 10.0.0.1/24
set int state pg0 up
l2tvpp tunnel local 10.0.0.1 peer 10.0.0.2 local-tid 100 peer-tid 200
l2tvpp session tunnel 0 local-sid 1000 peer-sid 2000
show l2tvpp tunnel
show l2tvpp session
ip route add 10.200.0.5/32 via l2tvpp0
show adj                   # expect a midchain adjacency on l2tvpp0
trace add pg-input 10       # then replay a pcap with packet-generator
```

## 5. After it is green

`build/build-vpp-debs.sh` for the VyOS-identical packages, then `dpkg -i` on
the VyOS LNS and the rig test from `docs/design.md` M1: BNG Blaster through
mpd5, session up in accel-ppp, install the same session by hand with
`vppctl l2tvpp ...`, watch `show l2tvpp session` counters move and the
kernel `pppN` counters stop.
