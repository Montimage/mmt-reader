# MMT-Reader Development Guide

This document covers everything needed to build, extend, and maintain MMT-Reader.

---

## Prerequisites

### System Dependencies

**Debian / Ubuntu:**

```bash
sudo apt-get update
sudo apt-get install -y build-essential gcc make libpcap-dev jq
```

**RHEL / CentOS / Fedora:**

```bash
sudo yum group install "Development Tools"
sudo yum install libpcap-devel jq
```

Required packages:
- **build-essential / Development Tools** — `gcc`, `make`
- **libpcap-dev / libpcap-devel** — libpcap headers and library for packet capture
  (the build links `-lpcap`; `Makefile:59-66`)
- **jq** — **test-time only**: several `make test` groups pipe the tool's JSON
  output through it (`Makefile:88-114`). Not needed to build or run mmtReader.

There is no config-file dependency: `config.c` implements a hand-rolled INI
parser, so **no external configuration library is required** or linked.

### MMT-DPI Library

MMT-Reader depends on the [MMT-DPI](https://bitbucket.org/montimage/mmt-dpi) library, which must be installed at `/opt/mmt/dpi/`:

```
/opt/mmt/dpi/
├── include/
│   ├── mmt_core.h
│   └── tcpip/
│       └── mmt_tcpip.h
└── lib/
    ├── libmmt_core.so
    └── (other MMT libraries)
```

Install MMT-DPI following the upstream instructions before compiling MMT-Reader.

**Minimum version: 1.8.0.** `make` runs a `check-sdk` step first
(`Makefile:41-57`) that aborts with an explicit error when the SDK is missing
or older. Override the location with `make MMT_DPI=/path/to/sdk`.

---

## Build

### Using Makefile (recommended)

```bash
make build          # compile
sudo make install   # install to /usr/local
sudo make uninstall # remove
make clean          # remove binary
```

A single `gcc` invocation compiles all nine sources into `./mmtReader`
(`Makefile:30-31`, `Makefile:59-66`):

```makefile
SRCS      = mmtReader.c core/engine.c utils/version.c utils/colors.c cli/parse.c cli/output.c capture.c flows.c config.c
CC       ?= gcc
CFLAGS   ?= -g -O2
WARNFLAGS ?= -Wall -Wextra
MMTREADER_VERSION ?= 0.4.0
VERSION_DEFS = -DMMTREADER_VERSION='"$(MMTREADER_VERSION)"'
```

Two details matter when reproducing the build by hand:

- **`WARNFLAGS = -Wall -Wextra`** is a separate variable, appended to every
  compile recipe rather than folded into `CFLAGS`, so an external
  `make CFLAGS=...` override cannot silently disable the warning gate
  (`Makefile:13-18`). The tree must stay warning-free.
- **`-DMMTREADER_VERSION`** injects mmtReader's own product version, which is
  reported separately from the MMT-DPI SDK version (`Makefile:24-28`,
  `utils/version.c:20-21`). Without it the binary falls back to `0.0.0-dev`.

### Manual Compile

Equivalent to what `make` runs — note `flows.c`, the warning flags, and the
version define:

```bash
gcc -g -O2 -Wall -Wextra -DMMTREADER_VERSION='"0.4.0"' -o mmtReader \
    mmtReader.c core/engine.c utils/version.c utils/colors.c cli/parse.c cli/output.c capture.c flows.c config.c \
    -I. -I/opt/mmt/dpi/include -I./utils -I./cli \
    -L/opt/mmt/dpi/lib \
    -lmmt_core -ldl -lpcap
```

Omitting `flows.c` fails at link with `undefined reference to 'flows_create'`
(and the other `flows_*` symbols used by `mmtReader.c`).

### Build Verification

```bash
# Compile
make build

# Verify the binary
file mmtReader

# Run with the bundled test pcap
./mmtReader analyze -t smallFlows.pcap -a

# Check help
./mmtReader analyze --help
```

`make build` prints the SDK gate result, then the compile line:

```
MMT-DPI SDK 1.8.0 OK
cc -g -O2 -Wall -Wextra -DMMTREADER_VERSION='"0.4.0"' -o mmtReader mmtReader.c core/engine.c ...
```

`./mmtReader --version` prints the boxed MONTIMAGE banner, then reports the
product and SDK versions distinctly (tail of the output):

```
...
mmtReader version: 0.4.0
MMT-DPI SDK version: 1.8.0 (42cac8b7)
built Aug 27 2026 12:15:56
```

`./mmtReader analyze -t smallFlows.pcap -a` prints the same banner (boxed),
then the protocol-path table, the aggregated protocol table, and the input
statistics summary.

---

## Code Structure

MMT-Reader is a modular C application with clean separation of concerns:

```
mmtReader.c          — Thin CLI entry point: banner → parse → engine → dispatch → cleanup
core/engine.c/h      — MMT-DPI engine: packet processing, stats aggregation, session tracking
cli/parse.c/h        — Argument parsing (getopt_long), subcommand dispatch, validation
cli/output.c/h       — Text/JSON output rendering
capture.c/h          — Live pcap capture: handle creation, promiscuous mode, callback
flows.c/h            — Top-flow (session) tracking and reporting for `capture -F`
config.c/h           — Hand-rolled INI config file parsing (~/.mmtreader.conf)
utils/version.c/h    — Version banner and --version output
utils/colors.c/h     — ANSI color support (respects NO_COLOR env var)
```

### Execution Flow

```
main() (mmtReader.c)
  ├── colors_init()             — Initialize color support
  ├── parse_options()           — Parse CLI args (subcommand dispatch)
  ├── version_banner()          — Print banner (stderr for JSON mode)
  ├── engine_create()           — Create MMT-DPI engine (core/engine.c)
  ├── engine_set_*_classify()   — Configure classification modes
  ├── engine_set_output_format() — Set TEXT or JSON output
  ├── sigaction(SIGINT, SIGTERM) — Install shared signal handler
  ├── if (analyze):
  │     └── pcap_open_offline() + engine_process_packet() loop
  │         └── engine_print_stats()   — summary printed explicitly
  ├── else if (capture):
  │     ├── capture_init() + capture_set_processor(engine_process_packet_cb)
  │     ├── if (-F N): flows_create() + flows_attach()
  │     ├── pcap_loop(capture_callback → engine_process_packet_cb)
  │     └── engine_print_stats() + flows_print_top() + flows_destroy()
  └── engine_destroy()          — Cleanup all resources
```

### Key Types

| Type | Module | Purpose |
|------|--------|---------|
| `engine_t` | core/engine.h | Opaque MMT-DPI engine handle |
| `engine_stats_t` | core/engine.h | Statistics snapshot (packets, sessions, volume, duration) |
| `cli_options_t` | cli/parse.h | Parsed CLI options (input, mode, flags, format) |
| `cli_mode_t` | cli/parse.h | Named dispatch mode: `MODE_NONE`, `MODE_TRACE_FILE`, `MODE_LIVE_INTERFACE`, `MODE_VERSION` |
| `flows_t` | flows.h | Opaque top-flow tracker used by `capture -F` |
| `config_t` | config.h | Parsed INI config file values |
| `output_format_t` | core/engine.h | TEXT or JSON output format enum |

---

## Adding a New Protocol Handler

MMT-Reader uses the MMT-DPI callback registration pattern. To add processing for a new protocol or attribute:

### 1. Register a packet handler

```c
register_packet_handler(mmt_handler, 1, my_packet_handler, NULL);
```

### 2. Register an attribute handler for new sessions

```c
register_attribute_handler(mmt_handler, PROTO_IP, PROTO_SESSION,
                          my_session_handler, NULL, NULL);
```

### 3. Implement the callback

```c
void my_session_handler(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    // Process the new session
}
```

### 4. Register attributes for extraction

The `protocols_iterator` → `attributes_iterator` chain automatically registers all attributes. To add custom extraction:

```c
register_extraction_attribute(args, proto_id, attribute->id);
```

### 5. Access extracted data in handlers

```c
uint64_t *value = (uint64_t *)get_attribute_extracted_data(ipacket, PROTO_ID, ATTRIBUTE_ID);
if (value != NULL) {
    // Use *value
}
```

---

## Coding Conventions

- **Warning-free builds:** `make` compiles with `-Wall -Wextra` (`WARNFLAGS`); new code must not introduce warnings.
- **Modular architecture:** Code is split across `core/`, `cli/` and `utils/` plus the root-level `capture.c/h`, `flows.c/h` and `config.c/h` modules, with clear API boundaries via headers.
- **Naming:** `snake_case` for functions, variables and struct members; `UPPER_SNAKE_CASE` for macros and enum constants.
- **Error handling:** `fprintf(stderr, ...)` followed by `return EXIT_FAILURE` for fatal errors; return codes for recoverable errors.
- **Memory:** `malloc`/`free` used in the protocol statistics linked list (`proto_info_t`). Cleanup in `engine_destroy()`.
- **Signals:** `SIGINT` and `SIGTERM` are caught through a shared async-safe handler to ensure clean statistics output and resource cleanup before exit.
- **Output separation:** `cli/output.c/h` handles all output rendering, keeping `core/engine.c` focused on DPI logic.
- **Color support:** `utils/colors.c/h` provides ANSI color helpers that respect `NO_COLOR` env var and `--no-color` flag.

---

## Debugging

### With GDB

Build an unoptimized binary with the same source list, then run it under gdb:

```bash
gcc -g -O0 -Wall -Wextra -DMMTREADER_VERSION='"0.4.0"' -o mmtReader-debug \
    mmtReader.c core/engine.c utils/version.c utils/colors.c cli/parse.c cli/output.c capture.c flows.c config.c \
    -I. -I/opt/mmt/dpi/include -I./utils -I./cli \
    -L/opt/mmt/dpi/lib \
    -lmmt_core -ldl -lpcap
```

```
$ gdb ./mmtReader-debug
(gdb) run analyze -t smallFlows.pcap -a
(gdb) bt                # Backtrace on crash
(gdb) print opts        # Inspect the parsed cli_options_t
```

`analyze` and `capture` are subcommands: without one, mmtReader prints the
top-level help and exits 0, so `run -t smallFlows.pcap` never reaches the
analysis path. Exit code 2 comes from a recognized subcommand missing its
required argument (`analyze` without `-t`, `capture` without `-i`).

### Enable MMT-DPI Debug

Set environment variables or compile flags as documented in the MMT-DPI repository.

---

## Testing

### Test Suite

```bash
make clean && make test
```

`make test` builds first, then runs **14 numbered test groups** (plus
sub-groups 2b and 5b) defined inline in `Makefile:86-165`:

| Group | What it exercises |
|-------|-------------------|
| 1 | Text output; summary printed exactly once; JSON summary present |
| 2 / 2b | JSON validity; `version` object separates product from SDK; `input_stats` agrees with `protocols[]` |
| 3 / 4 | `--sessions` flag (text and JSON) |
| 5 / 5b | Unit suites: config (40 asserts), anomaly detection (9) |
| 6–11 | Unit suites: parse (120), WiFi conversion (43), flows (38), capture dispatch (37), engine output (7), engine stats (5) |
| 12 | CLI integration script `tests/test_cli.sh` — 52 checks |
| 13 | Shell-completion files exist (bash, zsh, fish) |
| 14 | SDK version-check unit tests — `tests/test_sdk_check.sh`, 6 checks |

Totals on a clean run: **299 unit asserts** (groups 5–11), **52/52** CLI
integration checks, **6/6** SDK-check assertions, **0 failures**, and the
final banner:

```
All tests passed!
```

Exactly one skip is tolerated — live capture on `lo` needs root or
`cap_net_raw`, so it skips by design under an unprivileged run
(`tests/test_cli.sh:230-243`):

```
SKIP: live capture on 'lo' unavailable — Couldn't activate device lo: socket: Operation not permitted
```

Coverage: `make coverage` reruns the same suite with the unit-test binaries
instrumented via `--coverage` and prints a per-source gcov summary. See
[TESTING.md](TESTING.md) for the per-suite breakdown.

### Manual Testing

```bash
# Analyze a pcap file
./mmtReader analyze -t smallFlows.pcap -a

# JSON output
./mmtReader analyze -t smallFlows.pcap --json -s

# Verbose mode
./mmtReader analyze -t smallFlows.pcap -v

# Live capture (requires root)
sudo ./mmtReader capture eth0 -a
```

For live testing, use a loopback or dedicated test interface:

```bash
sudo ./mmtReader capture lo -a
```

---

## Project Layout

```
mmtReader/
├── mmtReader.c        # Thin CLI entry point (~280 lines)
├── Makefile           # Build, install, test targets
├── install.sh         # Self-contained global installer
├── LICENSE            # Apache 2.0
├── README.md          # Quick start
├── CHANGELOG.md       # Live changelog (incl. [Unreleased])
├── mmtReader.1        # Man page
├── core/
│   ├── engine.c       # MMT-DPI engine: packet processing, stats
│   └── engine.h       # Engine API
├── cli/
│   ├── parse.c/h      # Argument parsing, subcommand dispatch
│   └── output.c/h     # Text/JSON output rendering
├── capture.c/h        # Live pcap capture operations
├── flows.c/h          # Top-flow tracking and reporting (capture -F)
├── config.c/h         # INI config file support (hand-rolled parser)
├── utils/
│   ├── version.c/h    # Version banner and display
│   └── colors.c/h     # ANSI color support
├── tests/
│   ├── test_config.c           # Config file parsing tests
│   ├── test_anomaly.c          # Anomaly detection tests
│   ├── test_parse.c            # CLI parsing tests
│   ├── test_wifi.c             # 802.11 → Ethernet conversion tests
│   ├── test_flows.c            # Top-flow reporting tests
│   ├── test_capture_dispatch.c # Capture dispatch tests
│   ├── test_engine_output.c    # Engine output tests
│   ├── test_engine_stats.c     # Engine statistics tests
│   ├── test_sdk_check.sh       # SDK version gate tests
│   ├── coverage-summary.awk    # gcov summary formatter
│   └── test_cli.sh             # CLI integration tests
├── completions/       # Shell completion scripts
│   ├── mmtReader.bash
│   ├── mmtReader.zsh
│   └── mmtReader.fish
├── docs/
│   ├── USER_GUIDE.md  # User-facing CLI reference
│   ├── DEVELOPMENT.md # You are here
│   ├── ARCHITECTURE.md
│   ├── CONFIG.md      # Config file reference
│   ├── TESTING.md     # Test suite guide
│   ├── PLAYBOOK.md    # End-to-end agent workflows
│   ├── DECISIONS.md   # Architecture decision log
│   └── CHANGELOG.md   # Historical release notes (live one is ../CHANGELOG.md)
└── smallFlows.pcap    # Test pcap
```
