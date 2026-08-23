# l2tvppd: the l2tvpp sync daemon

Keeps the VPP `l2tvpp` data plane in step with the L2TP/PPP sessions
accel-ppp brings up in the kernel. See `../docs/design.md` step 4.

| File | What |
|---|---|
| `l2tvppd.py` | the daemon: `/proc/net/pppol2tp` parser + `Syncd.reconcile()` over the VPP binary API (vpp_papi) |
| `l2tvpp-install.py` | the M1 predecessor: same job by hand through `vppctl` (kept as a simple, dependency-free fallback) |
| `l2tvppd.service` | systemd unit |
| `accel-ppp-hooks.md` | how to trigger an immediate reconcile from accel-ppp ip-up/ip-down |
| `test_parse.py` | pure-python unit tests for the kernel-side parsing (no VPP needed) |

The reconcile integration with the live plugin is tested by
`../test/test_l2tvpp_syncd.py` (a VPP make-test: feed a mock kernel session
list to `Syncd.reconcile()`, check the session dump, FIB, and a forwarded
packet).

## Run

```
# one full reconcile pass, then exit (idempotent; good for cron / by hand)
python3 l2tvppd.py reconcile --local-ip 10.66.0.1

# long-running: reconcile on start, on SIGHUP, and every --interval seconds
python3 l2tvppd.py daemon --local-ip 10.66.0.1 --interval 30
```

`--local-ip` is the accel-ppp `outside-address` (the LNS tunnel endpoint);
`--local-port` is 1701 unless accel-ppp uses ephemeral ports. State (what the
daemon installed, for clean teardown and restart) lives in `--state`
(default `/run/l2tvppd.json`).

## Test

```
python3 test_parse.py                              # parser, anywhere
make test TEST=test_l2tvpp_syncd                   # reconcile vs live VPP
```

## Not done yet (needs the rig)

End-to-end against real accel-ppp on the VyOS LNS, and RADIUS interim
accounting fed from `l2tvpp_session_dump` (see `accel-ppp-hooks.md`). Those
need the hardware rig in `../docs/rig-test.md`.
