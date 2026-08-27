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
- **Minimum:** `1.8.0`. `make` runs a `check-sdk` step that aborts with an
  explicit error when the installed SDK is missing or older (override the
  install location with `make MMT_DPI=/path/to/sdk`).
- **Known quirk:** stale `1.7.10` shared objects sit alongside the current
  `1.8.0` ones in `/opt/mmt/dpi/lib`. The linker resolves `-lmmt_core` through
  `libmmt_core.so`, a symlink to `libmmt_core.so.auto` — currently the 1.8.0
  build. Do not "clean up" the versioned files or repoint the symlink blindly;
  check where it lands first (`readlink /opt/mmt/dpi/lib/libmmt_core.so`).

If `/opt/mmt/dpi` is missing or empty, `make` fails at link time
(`mmt_core.h: No such file...` / `cannot find -lmmt_core`). Obtain an SDK
release from Montimage and unpack it so that `/opt/mmt/dpi/{include,lib}`
exist. The include/link paths derive from the `MMT_DPI` variable (`Makefile:21`,
used in `Makefile:59-66`); override it with `make MMT_DPI=/path/to/sdk`.

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
executable `./mmtReader` in the repo root = success (<1 s on the reference
machine). `make clean` removes the binary.

The compile line is (`Makefile:59-66`):

```
MMT-DPI SDK 1.8.0 OK
cc -g -O2 -Wall -Wextra -DMMTREADER_VERSION='"0.3.0"' -o mmtReader mmtReader.c core/engine.c ...
```

Two flags are load-bearing and must stay in any hand-rolled build:

- `-Wall -Wextra` comes from `WARNFLAGS` (`Makefile:13-18`), kept out of
  `CFLAGS` so an external `make CFLAGS=...` cannot disable the warning gate.
  The tree is warning-free; a new warning is a regression.
- `-DMMTREADER_VERSION='"0.3.0"'` comes from `VERSION_DEFS`
  (`Makefile:24-28`) and injects mmtReader's product version, reported
  separately from the MMT-DPI SDK version. Without it `utils/version.c`
  falls back to `0.0.0-dev`.

## Test

```sh
make test
```

Builds the binary first (`test:` depends on `build:`), then runs **14 numbered
test groups** (plus sub-groups 2b and 5b) defined inline in `Makefile:86-165`:

| Group | What it exercises | Needs jq |
|---|---|---|
| Test 1 | Text output + summary printed exactly once | yes |
| Test 2 / 2b | JSON validity; `version` object separates product from SDK; `input_stats` vs `protocols[]` consistency | yes |
| Test 3 / 4 | `--sessions` flag (text and JSON) | Test 4 only |
| Tests 5–11 | Unit suites: config (40), anomaly detection (9, group 5b), parse (118), WiFi conversion (43), flows (38), capture dispatch (37), engine output (7), engine stats (5) asserts | no |
| Test 12 | CLI integration script `tests/test_cli.sh` — 52 checks | indirectly |
| Test 13 | Shell-completion files exist | no |
| Test 14 | SDK version gate — `tests/test_sdk_check.sh`, 6 asserts | no |

Expected success shape (reference run):

```
=== Test Summary ===        ← inside group 12
Passed: 52 / 52
...
All tests passed!           ← final banner, exit code 0
```

Totals to expect: **297 unit asserts** across tests 5–11 (incl. sub-group 5b),
**52/52 CLI integration checks**, **6/6 SDK-check asserts** (test 14), **0
failures**, exactly **one tolerated skip**:

```
SKIP: live capture on 'lo' unavailable — ... Operation not permitted
```

That skip is `tests/test_cli.sh`'s live-capture check: opening a capture
handle needs root or `cap_net_raw`, so under an unprivileged agent it skips by
design (`tests/test_cli.sh:230-243`) and counts as passed. Running the suite as root
removes the skip but changes nothing else.

## Coverage

```sh
make coverage
```

Wires gcov coverage around the existing suite (modernization task 3.1,
closes `F-TEST-002`): it cleans, reruns the **full** `make test` with the
unit-test binaries (tests 5–11) rebuilt via
`TEST_CFLAGS='-g --coverage -DCOVERAGE_BUILD'`,
then summarizes per-source line/branch coverage with plain `gcov`
(`gcovr`/`lcov` are not needed; plain gcov ships with gcc).

- Requires only tools already listed above: gcc's `gcov`, GNU make, jq.
- The default build is untouched — instrumentation reaches the suite only
  through the `TEST_CFLAGS` override; `make` / `make test` behave exactly as
  documented in the previous sections.
- Each unit-test binary produces its own `<exe>-<source>.gc{no,da}` pair in
  the repo root; the summary keeps each source file's best percentage across
  suites (a union approximation). Sources under `tests/` are excluded from
  the table; `mmtReader.c` is absent because the CLI integration group runs
  the uninstrumented binary.
- Exit code 0 and a concrete percentage in the output = success. Quick check
  used by milestone M3 of `MODERNIZATION_PLAN.md`:

```sh
make clean >/dev/null && make coverage 2>&1 | grep -o "[0-9]\+\(\.[0-9]\+\)\?%" | head -1
```

- All coverage artifacts (`.gcno`, `.gcda`, `.gcov`) and instrumented test
  binaries are deleted when the target finishes; they are also gitignored.

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
