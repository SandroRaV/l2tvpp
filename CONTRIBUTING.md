# Contributing

- Apache-2.0 for everything except `xdp/` (GPL-2.0). New source files get an
  SPDX header (copy one from `plugin/l2tvpp/l2tvpp.h`).
- Commits are signed off (`git commit -s`) under the Developer Certificate of
  Origin, https://developercertificate.org/ , because FD.io and VyOS require it
  and we want to be able to send this upstream without re-licensing.
- VPP code follows VPP's style: run `make checkstyle` in the VPP tree before
  submitting plugin changes.
