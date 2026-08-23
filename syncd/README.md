# l2tvpp-syncd

Installs sessions that accel-ppp brought up into the VPP `l2tvpp` plugin and
removes them on teardown. See `../docs/design.md` step 4.

- `l2tvpp-install.py` (M1, now): one-shot `list` / `apply` / `remove`. Reads
  `/proc/net/pppol2tp` and `ip addr` on the LNS, drives `vppctl`, keeps what
  it installed in `/run/l2tvpp-install.json`. Used by `../docs/rig-test.md`
  step 6. Copy it to `/config/l2tvpp/` on the VyOS box (survives image
  upgrades).
- The M2 daemon: same data, `vpp_papi` instead of vppctl, event-driven
  (accel-ppp ip-up/ip-down or netlink), `--reconcile` on start, systemd unit.
