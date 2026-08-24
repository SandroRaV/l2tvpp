# Wiring accel-ppp to l2tvppd

`l2tvppd daemon` reconciles on start, on SIGHUP, and every `--interval`
seconds. The interval is only a safety net; to mirror a session the instant
it comes up (or goes down), poke the daemon from accel-ppp's per-session
scripts so it reconciles immediately.

accel-ppp runs `ip-up` / `ip-down` (and `ipv6-up` / `ipv6-down`) with the
session's `IFNAME`, `PEERNAME`, `IPLOCAL`, `IPREMOTE` in the environment. The
daemon does not need any of that (it re-reads `/proc/net/pppol2tp`), so the
hook is a one-liner that just kicks a reconcile.

`/etc/accel-ppp/ip-up` (and symlink `ip-down`, `ipv6-up`, `ipv6-down` to it):

```sh
#!/bin/sh
# nudge l2tvppd to reconcile now instead of waiting for the safety-net tick
systemctl kill -s HUP l2tvppd 2>/dev/null || \
  pkill -HUP -f 'l2tvppd.py daemon' 2>/dev/null || \
  /usr/bin/python3 /config/l2tvpp/l2tvppd.py reconcile
exit 0
```

In accel-ppp.conf enable the scripts:

```
[ppp]
...
[pppd-compat]
verbose=1
ip-up=/etc/accel-ppp/ip-up
ip-down=/etc/accel-ppp/ip-down
```

On VyOS (accel-ppp-ng driven by the config), the equivalent is the
`vpn l2tp` scripting hook; if the image does not expose one, run the daemon
with a short `--interval` (e.g. 2s) and skip the hook. A HUP-driven reconcile
of a few hundred sessions is a few milliseconds, so a chatty login storm is
fine; the daemon coalesces bursts (one reconcile per wake).

Accounting note: once VPP owns the data path, the kernel `pppN` sees no
traffic, so accel-ppp's traffic-based accounting and idle timeout read zero.
Feed counters from `l2tvpp_session_dump` (rx/tx packets/bytes per session)
into RADIUS interim accounting instead. That is an M2/M3 follow-up, not done
here.
