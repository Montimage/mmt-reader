# MMT-Reader Development Guide

This document covers everything needed to build, extend, and maintain MMT-Reader.

---

## Prerequisites

### System Dependencies

**Debian / Ubuntu:**

```bash
sudo apt-get update
sudo apt-get install -y build-essential gcc g++ make libpcap-dev libconfuse-dev
```

**RHEL / CentOS / Fedora:**

```bash
sudo yum group install "Development Tools"
sudo yum install libpcap-devel
```

Required packages:
- **build-essential / Development Tools** — `gcc`, `g++`, `make`
- **libpcap-dev / libpcap-devel** — libpcap headers and library for packet capture
- **libconfuse-dev** — configuration parsing library (linked via `-lconfuse`)

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

---

## Build

### Using Makefile (recommended)

```bash
make build          # compile
sudo make install   # install to /usr/local
sudo make uninstall # remove
make clean          # remove binary
```

The Makefile compiles all source files with optimization (`-g -O2`):

```makefile
SRCS = mmtReader.c core/engine.c utils/version.c utils/colors.c cli/parse.c cli/output.c capture.c config.c
CC = gcc
CFLAGS = -g -O2
```

### Manual Compile

```bash
gcc -g -O2 -o mmtReader mmtReader.c core/engine.c utils/version.c utils/colors.c cli/parse.c cli/output.c capture.c config.c \
    -I. -I/opt/mmt/dpi/include -I./utils -I./cli \
    -L/opt/mmt/dpi/lib \
    -lmmt_core -ldl -lpcap
```

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

Expected output: A banner showing the mmtReader product version, the MMT-DPI SDK version, build date/time, and a stats table after processing.

---

## Code Structure

MMT-Reader is a modular C application with clean separation of concerns:

```
mmtReader.c          — Thin CLI entry point: banner → parse → engine → dispatch → cleanup
core/engine.c/h      — MMT-DPI engine: packet processing, stats aggregation, session tracking
cli/parse.c/h        — Argument parsing (getopt_long), subcommand dispatch, validation
cli/output.c/h       — Text/JSON output rendering
capture.c/h          — Live pcap capture: handle creation, promiscuous mode, callback
capture.c            — Live pcap capture: handle creation, promiscuous mode, callback
config.c/h           — INI config file parsing (~/.mmtreader.conf)
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
  ├── else if (capture):
  │     └── capture_init() + pcap_loop(capture_callback → engine_process_packet_cb)
  └── engine_destroy()          — Cleanup all resources
```

### Key Types

| Type | Module | Purpose |
|------|--------|---------|
| `engine_t` | core/engine.h | Opaque MMT-DPI engine handle |
| `engine_stats_t` | core/engine.h | Statistics snapshot (packets, sessions, volume, duration) |
| `cli_options_t` | cli/parse.h | Parsed CLI options (input, mode, flags, format) |
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

- **Modular architecture:** Code is split across modules (`core/`, `cli/`, `capture/`, `config/`, `utils/`) with clear API boundaries via headers.
- **Naming:** `snake_case` for functions and variables, `UPPER_SNAKE_CASE` for macros, `camelCase` for struct members.
- **Error handling:** `fprintf(stderr, ...)` followed by `return EXIT_FAILURE` for fatal errors; return codes for recoverable errors.
- **Memory:** `malloc`/`free` used in the protocol statistics linked list (`proto_info_t`). Cleanup in `engine_destroy()`.
- **Signals:** `SIGINT` and `SIGTERM` are caught through a shared async-safe handler to ensure clean statistics output and resource cleanup before exit.
- **Output separation:** `cli/output.c/h` handles all output rendering, keeping `core/engine.c` focused on DPI logic.
- **Color support:** `utils/colors.c/h` provides ANSI color helpers that respect `NO_COLOR` env var and `--no-color` flag.

---

## Debugging

### With GDB

```bash
gcc -g -o mmtReader mmtReader.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
gdb ./mmtReader
(gdb) run -t smallFlows.pcap -a
(gdb) bt          # Backtrace on crash
(gdb) print nb_packets  # Inspect variables
```

### Enable MMT-DPI Debug

Set environment variables or compile flags as documented in the MMT-DPI repository.

---

## Testing

### Unit Tests

```bash
make test
```

Runs 7 test targets:
1. Text output — `analyze -t smallFlows.pcap -a` produces expected output
2. JSON output — `--json` produces valid JSON parseable by `jq`
3. Sessions flag — `--sessions` includes IPv4 session counts
4. JSON sessions — `--json --sessions` includes per-protocol session counts
5. Config unit tests — `tests/test_config.c` validates config parsing
6. Parse unit tests — `tests/test_parse.c` validates CLI argument parsing
7. Completions exist — verifies bash, zsh, and fish completion files

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
├── mmtReader.c        # Thin CLI entry point (~150 lines)
├── Makefile           # Build, install, test targets
├── install.sh         # Self-contained global installer
├── LICENSE            # Apache 2.0
├── README.md          # Quick start
├── mmtReader.1        # Man page
├── core/
│   ├── engine.c       # MMT-DPI engine: packet processing, stats
│   └── engine.h       # Engine API
├── cli/
│   ├── parse.c/h      # Argument parsing, subcommand dispatch
│   └── output.c/h     # Text/JSON output rendering
├── capture.c/h        # Live pcap capture operations
├── config.c/h         # INI config file support
├── utils/
│   ├── version.c/h    # Version banner and display
│   └── colors.c/h     # ANSI color support
├── tests/
│   ├── test_config.c  # Config file parsing tests
│   ├── test_anomaly.c # Anomaly detection tests
│   ├── test_parse.c   # CLI parsing tests
│   └── test_cli.sh    # Integration tests
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
│   └── CHANGELOG.md
└── smallFlows.pcap    # Test pcap
```
