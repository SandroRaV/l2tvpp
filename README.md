# l2tvpp

L2TPv2 LNS data plane for VPP, so an LNS on commodity hardware forwards beyond
10G over L2TP. Control plane stays accel-ppp(-ng); this repo adds:

| Dir | What |
|---|---|
| `docs/` | `design.md` (architecture, milestones), `m0-notes.md` (open investigation items) |
| `plugin/l2tvpp/` | VPP plugin: L2TPv2 decap/encap, per-session interface, worker handoff |
| `syncd/` | daemon that installs accel-ppp sessions into VPP |
| `test/` | VPP `make test` suite for the plugin (scapy, no NIC needed) |
| `build/` | reproducible builds against VyOS's exact VPP (stable/2510 + vyos-vpp-patches), ISO build |
| `xdp/` | independent fallback: XDP cpumap steering for the *kernel* LNS path |
| `lab/`, `bench/` | test rig configs and results |

## Testing tiers

1. **Unit, no hardware**: `make test TEST=test_l2tvpp` inside the VPP tree the
   build script produces (`build/work/vyos-build/scripts/package-build/vpp/vpp/`).
   Runs in CI.
2. **VM lab**: VyOS ISO from `build/build-iso.sh` in KVM (virtio NICs), BNG
   Blaster + mpd5 VMs as LAC. Functional and churn tests.
3. **Hardware**: EPYC 7F32 / ConnectX-4 Lx, BNG Blaster DPDK rig. Numbers.

## Getting the plugin onto a VyOS box

- Proper: `build/build-vpp-debs.sh` then `build/build-iso.sh`, install the ISO
  (`add system image`). The plugin is inside the image's own VPP packages.
- Quick: `build/build-vpp-debs.sh`, copy `build/out/vpp-plugin-core_*.deb` to
  the box and `sudo dpkg -i` it (same VPP version, so it is a drop-in), then
  `sudo systemctl restart vpp`. Lost on image upgrade, fine for development.

VPP version tracking: VyOS `current` builds FDio `stable/2510`; `build/package.toml`
must be re-diffed against `package.toml.vyos-orig` whenever VyOS bumps it.

## License

- Everything except `xdp/` is **Apache-2.0** (`LICENSE`), the same license as
  VPP and the VyOS VPP patches, so the plugin can go upstream unchanged. Source
  files carry `SPDX-License-Identifier: Apache-2.0`.
- `xdp/` is **GPL-2.0** (`xdp/LICENSE`): the BPF program uses GPL-only kernel
  helpers and declares `"GPL"` to the verifier; the loader links libbpf
  (LGPL-2.1 OR BSD-2-Clause).
- Contributions use the Developer Certificate of Origin (`git commit -s`),
  as required by FD.io and VyOS.
