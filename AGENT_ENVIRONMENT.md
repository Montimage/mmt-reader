# AGENT_ENVIRONMENT.md

Agent-facing notes for building and testing mmtReader from a clean checkout.
Everything below was verified on the reference machine listed in
[Recorded environment](#recorded-environment); commands are copy-paste safe.
This file feeds `CLAUDE.md` (task Pre.2 of `MODERNIZATION_PLAN.md`) — keep it
factual and machine-checkable.

## Recorded environment

| Component | Version | How it was verified |
|---|---|---|
| OS / arch | Ubuntu 24.04, arm64 | `uname -a` |
| gcc | 13.3.0 | `gcc --version` |
| GNU make | 4.3 | `make --version` |
| libpcap (dev) | 1.10.4 | `dpkg -l libpcap-dev` |
| jq | 1.7 | `jq --version` |
| MMT-DPI SDK | 1.8.0 | see [MMT-DPI SDK](#mmt-dpi-sdk-proprietary) |

Any gcc ≥ 9 with a matching libpcap-dev works; the versions above are what
this repository is actually developed and tested against.

## Toolchain install

Debian/Ubuntu one-liner:

```sh
sudo apt-get update && sudo apt-get install -y gcc make libpcap-dev jq
```

- `gcc`, `make`, `libpcap-dev` are **build-time** requirements (`make` links
  `-lpcap`).
- `jq` is a **test-time** requirement only: several `make test` groups pipe the
  tool's JSON output through it. Without jq those groups fail even though the
  binary itself is fine.

There is no vendored dependency manager, no submodule bootstrap, and no
configure step — installing the four packages above is the whole setup.

## MMT-DPI SDK (proprietary)

The protocol-dissection engine comes from Montimage's **proprietary MMT-DPI
SDK**. It is *not* in this repository and *not* on any public package registry.

- **Install location:** `/opt/mmt/dpi`
  - headers: `/opt/mmt/dpi/include` (`mmt_core.h`, `tcpip/`, …)
  - libraries: `/opt/mmt/dpi/lib` (`libmmt_core.a/.so`, plus per-domain libs)
- **Version:** `1.8.0`, declared in `/opt/mmt/dpi/include/mmt_core.h`:

  ```sh
  grep '#define VERSION' /opt/mmt/dpi/include/mmt_core.h   # → "1.8.0"
  ```

- **Source:** sibling checkout `../mmt-dpi` next to this repository
  (Montimage-internal; not needed to build, only to modify the SDK).
- **Known quirk:** stale `1.7.10` shared objects sit alongside the current
  `1.8.0` ones in `/opt/mmt/dpi/lib`. The linker resolves `-lmmt_core` through
  the unversioned `.so` symlinks, which point at 1.8.0 — do not "clean up" the
  versioned files blindly.

If `/opt/mmt/dpi` is missing or empty, `make` fails at link time
(`mmt_core.h: No such file...` / `cannot find -lmmt_core`). Obtain an SDK
release from Montimage and unpack it so that `/opt/mmt/dpi/{include,lib}`
exist. The include/link paths are hardcoded in `Makefile:24-29`.

## Environment variables and config files

- **None required** for build or test. There is no `.env` file, nothing to
  `source`, and no secrets involved.
- Optional runtime knobs read by the binary itself (never needed for the test
  suite): `MMTREADER_JSON`, `MMTREADER_NO_COLOR`, `MMTREADER_QUIET` — see
  `./mmtReader --help`.
- Optional user config at `~/.mmtreader.conf` (absent on the reference
  machine); tests do not depend on it.

## Build

```sh
make
```

Single gcc invocation compiling all nine sources into `./mmtReader`, linking
against `-lmmt_core -ldl -lpcap` from `/opt/mmt/dpi/lib`. Exit code 0 and an
executable `./mmtReader` in the repo root = success (~2 s on the reference
machine). `make clean` removes the binary.

## Test

```sh
make test
```

Builds the binary first (`test:` depends on `build:`), then runs **13 numbered
test groups** (plus sub-group 2b) defined inline in `Makefile:49-116`:

| Group | What it exercises | Needs jq |
|---|---|---|
| Test 1 | Text output + summary printed exactly once | yes |
| Test 2 / 2b | JSON validity; `input_stats` vs `protocols[]` consistency | yes |
| Test 3 / 4 | `--sessions` flag (text and JSON) | Test 4 only |
| Tests 5–11 | Unit suites: config (40), parse (39), WiFi conversion (43), flows (38), capture dispatch (24), engine output (7), engine stats (3) asserts | no |
| Test 12 | CLI integration script `tests/test_cli.sh` — 27 checks | indirectly |
| Test 13 | Shell-completion files exist | no |

Expected success shape (reference run):

```
=== Test Summary ===        ← inside group 12
Passed: 27 / 27
...
All tests passed!           ← final banner, exit code 0
```

Totals to expect: **~194 unit asserts** across tests 5–11, **27/27 CLI
integration checks**, **0 failures**, exactly **one tolerated skip**:

```
SKIP: live capture on 'lo' unavailable — ... Operation not permitted
```

That skip is `tests/test_cli.sh`'s live-capture check: opening a capture
handle needs root or `cap_net_raw`, so under an unprivileged agent it skips by
design (test_cli.sh:212-225) and counts as passed. Running the suite as root
removes the skip but changes nothing else.

## Agent verification checklist

Run these in order from a clean checkout; all must succeed here:

```sh
make            # exit 0, produces ./mmtReader
make test       # exit 0, output ends with "All tests passed!"
```

Quick post-condition check used by the modernization plan:

```sh
grep '#define VERSION' /opt/mmt/dpi/include/mmt_core.h    # → 1.8.0
jq --version                                              # → jq-1.7 or newer
```

If any step fails, the likely culprits in order of probability: missing
`/opt/mmt/dpi` SDK (link errors), missing jq (JSON groups fail), missing
libpcap headers (compile error on `capture.c`).
