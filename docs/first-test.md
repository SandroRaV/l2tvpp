# First test

## 1. What "first test" means right now

The M1 plugin code exists (`plugin/l2tvpp/*.c`) but has never been compiled.
The first test is therefore: build it, get it past the compiler and VPP's
startup, then run the scapy suite in `test/test_l2tvpp.py`. Expect compile
errors on the first pass; paste them back and they get fixed.

## 2. Build host

A Debian 12 or 13 machine or VM with 8+ GB RAM, 40 GB disk. Docker only for
the VyOS-identical build later. The Mac cannot do any of this.

### 2a. Bootstrap an empty Debian (once, as root)

```
apt-get update
apt-get install -y git sudo build-essential curl ca-certificates vim
usermod -aG sudo <user>
```

Log out and back in as `<user>` so the sudo group applies. `make install-dep`
inside the build script uses sudo for the remaining ~60 packages (cmake,
ninja, clang, python3 venv, libbpf, ...).

### 2b. Clone

Over SSH you need a deploy key or your GitHub key on the box; over HTTPS a
personal access token. For a throwaway build VM HTTPS is simplest:

```
git clone https://github.com/SandroRaV/l2tvpp.git /home/<user>/l2tvpp
```

### 2c. Build and test

```
/home/<user>/l2tvpp/build/dev-build.sh
```

That clones FDio VPP `stable/2510` into `/home/<user>/l2tvpp/build/work/vpp`,
installs the build dependencies, symlinks `plugin/l2tvpp` into `src/plugins/`,
builds a debug VPP and runs `make test TEST=test_l2tvpp`. 20-40 minutes the
first time depending on cores; later runs with `dev-build.sh test` only
rebuild what changed.

### 2d. Docker (only for the VyOS-identical build, can wait)

```
sudo apt-get install -y docker.io
sudo usermod -aG docker <user>
```

Note: `make test` builds a second, separate VPP tree (release flags, all
CPU variants) the first time it runs, so the first `make test` costs another
full compile (~20 min on 8 cores) before any test output appears. Later runs
are incremental.

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
the VyOS LNS and the M1 test from `docs/design.md`: an L2TP LAC (e.g.
BNG Blaster) brings a session up in accel-ppp, install the same session by hand with
`vppctl l2tvpp ...`, watch `show l2tvpp session` counters move and the
kernel `pppN` counters stop.

## 6. Repeatable clean builds

Once the first build has been through the compiler, switch to the container
flow so every run is a clean plugin build against an unchanged VPP tree:

```
sudo apt-get install -y docker.io && sudo usermod -aG docker <user>   # re-login
cd /home/<user>/l2tvpp
docker build -f build/Dockerfile.base -t l2tvpp-base:2510 build/        # once, 30-60 min
./build/ci-test.sh                                                       # every time, minutes
```

`build/ci-test.sh` starts a throwaway container from `l2tvpp-base:2510`,
copies the plugin in, runs the incremental `make build` (only the plugin
compiles), `checkstyle`, and `make test TEST=test_l2tvpp`. The log lands in
`build/ci-logs/<timestamp>-<gitrev>.log`. `./build/ci-test.sh shell` gives
an interactive container for poking at a failure.

Rebuild the base image only when bumping VPP (`--build-arg VPP_COMMIT=...`)
or when `install-dep` changes; tag it with the VPP version so old logs stay
comparable.

For every push: register the build VM as a GitHub Actions self-hosted runner
(repo Settings > Actions > Runners, follow the generated commands) and
`.github/workflows/ci.yml` runs the same script automatically and uploads
the log. GitHub-hosted runners are not used on purpose: they would rebuild
VPP on every run.
