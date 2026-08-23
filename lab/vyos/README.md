# VyOS LNS side of the l2tvpp rig

- `lns.txt`: the `set` commands for the L2TP LNS (accel-ppp control plane).
  Unchanged from the kernel-LNS rig; the plugin sits underneath it.
- Plugin enablement and the session install flow: `docs/rig-test.md`.
- `/proc/net/pppol2tp` is what `syncd/l2tvpp-install.py` reads to learn
  tunnel/session ids and the `pppN` per session.
