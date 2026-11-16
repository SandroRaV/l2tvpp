# l2tvppd: the l2tvpp sync daemon

Keeps the VPP `l2tvpp` data plane in step with the L2TP/PPP sessions
accel-ppp brings up in the kernel. See `../docs/design.md` step 4.

| File | What |
|---|---|
| `l2tvppd.py` | the daemon: `/proc/net/pppol2tp` parser + `Syncd.reconcile()` over the VPP binary API (vpp_papi) |
| `l2tvpp_acct.py` | RADIUS relay that puts the VPP counters into accel-ppp's accounting records; loaded by `l2tvppd.py` when `--radius-listen` is given |
| `l2tvppd.service` | systemd unit |
| `accel-ppp-hooks.md` | how to trigger an immediate reconcile from accel-ppp ip-up/ip-down |
| `test_parse.py` | pure-python unit tests for the kernel-side parsing and for `Syncd` against a fake VPP (no VPP needed) |
| `test_acct.py` | pure-python unit tests for the accounting relay (no VPP, no RADIUS server needed) |

The reconcile integration with the live plugin is tested by
`../test/test_l2tvpp_syncd.py` (a VPP make-test: feed a mock kernel session
list to `Syncd.reconcile()`, check the session dump, FIB, and a forwarded
packet).

## Run

```
# one full reconcile pass, then exit (idempotent; good for cron / by hand)
python3 l2tvppd.py reconcile

# long-running: reconcile on start, on SIGHUP, and every --interval seconds
python3 l2tvppd.py daemon --interval 30
```

The LNS local IP/port are auto-derived per tunnel from `ip l2tp show tunnel`,
so no addresses need configuring. State (what the daemon installed, for clean
teardown and restart) lives in `--state` (default `/run/l2tvppd.json`).

## What follows the kernel session netdev

Besides the session and its routes, every pass carries over what accel-ppp
set on the netdev (`../docs/design.md` step 5a):

- **VRF**: a netdev enslaved to a VRF (`Accel-VRF-Name` in the RADIUS reply
  or a CoA) puts the VPP session interface and its routes into the VPP table
  with that VRF's table id. Nothing to configure.
- **MTU**: the netdev MTU becomes the interface's L3 MTU.
- **Source validation**: `--urpf strict` (default), `loose` or `off`. Needs
  VPP's `urpf_plugin.so`; the image build enables it. If it is not loaded
  the daemon says so once and runs without the check.
- **The LNS's own address** on the session netdevs is registered with the
  plugin so a subscriber can ping its gateway.

## Accounting

Without the relay every interim and stop record reports the few packets the
kernel still saw. To get the VPP counters into RADIUS, let accel-ppp talk
to the relay and the relay to the real server.

`/config/l2tvpp/l2tvppd.env` (read by the unit of the image):

```
L2TVPPD_ARGS=--radius-listen 127.0.0.1 --radius-server <radius-server-1> --radius-server <radius-server-2> --radius-secret-file /config/l2tvpp/radius-secret --radius-source <nas-address>
```

`/config/l2tvpp/radius-secret` holds the shared secret (mode 600).
`--radius-source` is the address the RADIUS server knows this NAS by;
`--radius-device` binds the upstream sockets to an interface or VRF device.
A server is given as `HOST[:AUTHPORT[:ACCTPORT]]`; the relay moves to the
next one after three unanswered requests.

VyOS, with the same secret as before:

```
delete vpn l2tp remote-access authentication radius server <radius-server-1>
delete vpn l2tp remote-access authentication radius server <radius-server-2>
delete vpn l2tp remote-access authentication radius source-address
set vpn l2tp remote-access authentication radius server 127.0.0.1 key '<secret>'
```

`nas-ip-address`, `nas-identifier` and the dynamic-author (CoA) settings
stay as they are; CoA and Disconnect requests go from the server to
accel-ppp directly.

What the relay does and does not do:

- Access-Requests and all replies pass unchanged. In interim and stop
  records of a session VPP forwards, the VPP counters are added to what
  accel-ppp reported (the kernel netdev still counts what went through the
  kernel) and the authenticators are recomputed.
- A session the daemon has just removed keeps its last counters for 15
  minutes, so the stop record gets them whichever comes first.
- With a wrong secret the relay forwards unchanged and logs a warning.
- After a daemon restart, a session that stops before its next interim
  record reports the kernel counters only.
- `accel-cmd show sessions` and `Idle-Timeout` still see the kernel netdev.
  Do not send `Idle-Timeout` to an l2tvpp LNS.

## Test

```
python3 test_parse.py                              # parser + Syncd, anywhere
python3 test_acct.py                               # accounting relay, anywhere
make test TEST=test_l2tvpp_syncd                   # reconcile vs live VPP
```
