# BNG Blaster LAC config for the l2tvpp rig

`lac-test.json` is, line for line, the verified config from
`manuals/dgw/lns/config_manuals/bngblaster/bngblaster-lac-l2tp-vyos-lns.md`
step 7 (BNG Blaster PR 387 "L2TP LAC mode", with the step 5f and 5g patches),
with one addition: `"stream-autostart": false`, so sessions come up, get
installed into VPP, and only then does traffic start (`bngblaster-cli
/run/bngblaster.sock stream-start` or the sweep harness in that doc, step 12).

- PCI ids are the 5019D blaster's ConnectX-4 (`0000:65:00.0` tunnel port
  toward the LNS `eth8`, `0000:65:00.1` core port toward `eth9`). On the 5018
  X552 blaster they are `0000:04:00.0` / `0000:04:00.1` and the link-up patch
  from `bngblaster-500-pppoe-test-5018.md` step 4a is needed.
- 500 sessions over two tunnels (`lac-a` 10.66.0.2, `lac-b` 10.66.0.3), PAP,
  no tunnel secret, IPv4 only, 1400-byte streams. Identical addressing to the
  mpd5 and kernel-LNS runs so the numbers compare directly.
- Load config: copy and raise `pps` (per session per direction), see
  `docs/rig-test.md` step 9.
