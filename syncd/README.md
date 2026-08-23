# l2tp2-syncd

Installs sessions that accel-ppp brought up into the VPP `l2tp2` plugin and
removes them on teardown. See `../docs/design.md` step 4. Written in M2, after
M0 decides the event source (accel-ppp-ng hook, ip-up/ip-down scripts, or
polling).

Planned: Python 3 + `vpp_papi`, one file, systemd unit, `--reconcile` on start.
