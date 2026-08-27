# MMT-Reader Test Suite Guide

MMT-Reader includes C unit suites for config parsing, CLI parsing, WiFi
conversion, flow reporting, capture dispatch and engine behavior, plus shell
integration tests for end-to-end CLI behavior and the SDK version gate.

## Quick Start

```bash
make clean && make test
```

`make test` builds the binary first, then runs **14 numbered test groups**
(plus sub-groups 2b and 5b) defined inline in `Makefile:86-165`. Every unit
suite is compiled with the same `-Wall -Wextra` warning gate as the product
build, and the suites that report versions also get
`-DMMTREADER_VERSION='"0.4.0"'`.

`jq` is required — groups 1, 2, 2b and 4 pipe the tool's JSON output
through it (group 3 greps the text output instead).

### Expected totals

| Signal | Value |
|--------|-------|
| Unit asserts (groups 5–11, incl. 5b) | **299** |
| CLI integration checks (group 12) | **52 / 52** |
| SDK version-gate checks (group 14) | **6 / 6** |
| Failures | **0** |
| Tolerated skips | **1** — live capture on `lo` |

The run ends with `All tests passed!` and exit code 0. The single tolerated
skip needs root or `cap_net_raw` to disappear (`tests/test_cli.sh:230-243`):

```
SKIP: live capture on 'lo' unavailable — Couldn't activate device lo: socket: Operation not permitted
```

## Coverage

```bash
make coverage
```

Reruns the suite with the unit-test binaries rebuilt via `--coverage`
(`TEST_CFLAGS='-g --coverage -DCOVERAGE_BUILD'`) and prints a per-source
line/branch summary using plain `gcov`. Forked-scenario suites
(`test_engine_output.c`, `test_engine_stats.c`) dump their counters explicitly
in coverage builds because `_exit()` skips libgcov's usual write. The default
build is untouched; artifacts are cleaned up when the target finishes.

## Test Targets

| Target | File | Type | Asserts | Description |
|--------|------|------|---------|-------------|
| Test 1 | — | Integration | — | Text output: `analyze -t smallFlows.pcap -a`; summary printed exactly once; JSON summary present |
| Test 2 | — | Integration | — | JSON valid and parseable by `jq`; `version` is an object separating `mmtreader` from `mmt_dpi` |
| Test 2b | — | Integration | — | `input_stats` agrees with `protocols[]` (volume, protocol count, bandwidth) |
| Test 3 | — | Integration | — | Sessions flag: `--sessions` includes IPv4 session counts |
| Test 4 | — | Integration | — | JSON sessions: `--json --sessions` includes per-protocol session counts |
| Test 5 | `tests/test_config.c` | Unit | 40 | Config file parsing (init, load, sections, comments, booleans) |
| Test 5b | `tests/test_anomaly.c` | Unit | 9 | Anomaly detection |
| Test 6 | `tests/test_parse.c` | Unit | 120 | CLI argument parsing (defaults, subcommands, flags, validation, config/env precedence) |
| Test 7 | `tests/test_wifi.c` | Unit | 43 | 802.11 → Ethernet frame conversion |
| Test 8 | `tests/test_flows.c` | Unit | 38 | Top-flow (session) reporting |
| Test 9 | `tests/test_capture_dispatch.c` | Unit | 37 | Capture dispatch and packet-data extraction |
| Test 10 | `tests/test_engine_output.c` | Unit | 7 | Engine output: one summary per run, TEXT/JSON honoured |
| Test 11 | `tests/test_engine_stats.c` | Unit | 5 | Engine statistics aggregation and extraction-failure accounting |
| Test 12 | `tests/test_cli.sh` | Integration | 52 | CLI end-to-end (env vars, quiet, verbose, input validation, capture contract, config/env output format and precedence) |
| Test 13 | — | Integration | — | Bash, zsh and fish completion files exist |
| Test 14 | `tests/test_sdk_check.sh` | Integration | 6 | `make check-sdk` accepts ≥ 1.8.0 and rejects older/missing SDKs |

## Unit Tests

### Config Tests (`tests/test_config.c`)

Tests for `config.c` — INI config file parsing:

Run from the repository root (same command shape `make test` uses):

```bash
gcc -g -Wall -Wextra -o test_config tests/test_config.c config.c -I. \
  && ./test_config && rm -f test_config
```

**Test coverage:**
- `config_init()` — default values (json=0, quiet=0, ip_classify=1, etc.)
- `config_load()` with nonexistent file — returns 1, loaded=0
- Global section parsing — `json`, `quiet`, `verbose`, `no_color`, `buffer`
- `[analyze]` section — `json`, `proto_path`, `sessions`, `buffer`
- `[capture]` section — `quiet`, `buffer`, `proto_path`
- Comments and blank lines — `;` and `#` comments, empty lines
- Boolean variations — `true`, `yes`, `on`, `0`, `1`, `false`
- `config_dump()` — doesn't crash

### Parse Tests (`tests/test_parse.c`)

Tests for `cli/parse.c` — CLI argument parsing:

`cli/parse.c` reads config defaults, so `config.c` must be linked in too:

```bash
gcc -g -Wall -Wextra -o test_parse tests/test_parse.c cli/parse.c config.c -I. -I./utils \
  && ./test_parse && rm -f test_parse
```

**Test coverage:**
- `parse_init()` — default values (input=NULL, buffer_mb=50, ip_classify=1, etc.)
- No subcommand — shows help
- `--help` flag — sets show_help=1
- `--version` flag — sets mode=MODE_VERSION
- `analyze -t` — sets mode=MODE_TRACE_FILE, input=file
- `capture -i` — sets mode=MODE_LIVE_INTERFACE, input=interface
- `capture eth0` (positional) — sets mode=MODE_LIVE_INTERFACE, input=interface
- `-q` (quiet) — sets quiet=1
- `-v` (verbose) — sets verbose=1
- `--json` — sets json=1
- `--no-color` — sets no_color=1
- `-b 100` — sets buffer_mb=100
- `-a` (proto-path) — sets proto_path=1
- `--config` / `-c` — all four spellings (`-c <path>`, `-c<path>`,
  `--config <path>`, `--config=<path>`), last occurrence wins, and every field
  a config file writes loses to its CLI flag and to the environment (issue #96)

## Integration Tests

### Shell Integration Tests (`tests/test_cli.sh`)

End-to-end CLI behavior tests:

```bash
./tests/test_cli.sh ./mmtReader
```

**Test coverage:**
- **Input validation** — missing `-t` for analyze, missing `-i` for capture, invalid buffer sizes
- **Quiet mode** — `--quiet` suppresses INFO messages, still shows results
- **Verbose mode** — `--verbose` shows DEBUG messages to stderr
- **Environment variables** — `MMTREADER_QUIET`, `MMTREADER_NO_COLOR`, `MMTREADER_JSON` (the JSON checks assert the produced output, not just the exit code)
- **Config file and precedence** — `--config` selects the output format, and CLI
  flags, then the environment, beat both config files (issue #96)
- **CLI overrides env vars** — `-v` overrides `MMTREADER_QUIET`
- **General options** — `--help`, `--version`, `-h`, `--json`, short flags
- **Capture output contract** — live capture on `lo` prints exactly one summary
  (skipped when the environment forbids opening a capture handle)
- **Extraction-failure summary** — failures are counted and summarized once

### Manual Integration Testing

```bash
# Text output
./mmtReader analyze -t smallFlows.pcap -a

# JSON output
./mmtReader analyze -t smallFlows.pcap --json -s

# Verbose mode
./mmtReader analyze -t smallFlows.pcap -v

# Quiet mode
./mmtReader analyze -t smallFlows.pcap -q

# Env var override
MMTREADER_JSON=1 ./mmtReader analyze -t smallFlows.pcap

# Combined
./mmtReader analyze -t smallFlows.pcap -a -j -s -v
```

## Test Data

| File | Description |
|------|-------------|
| `smallFlows.pcap` | Small pcap capture file for testing |
| `test.pcap` | 54-byte stub pcap used as a filename argument by `tests/test_parse.c` — parsing only, never analyzed |

## Adding New Tests

### Unit Tests

1. Add a new `test_*()` function to the appropriate test file
2. Use the `ASSERT_EQ`, `ASSERT_STR_EQ`, `ASSERT_TRUE`, `ASSERT_FALSE` macros
3. Call the new function from `main()`
4. Compile and run from the repo root:
   `gcc -g -Wall -Wextra -o test_xxx tests/test_xxx.c source.c -I. && ./test_xxx`
5. Add a numbered group to the `test:` target in the `Makefile` so `make test`
   runs it, and update the table above

### Integration Tests

1. Add a new test block in `tests/test_cli.sh`
2. Use `assert_exit_code`, `assert_output_contains`, `assert_output_not_contains` helpers
3. Run: `./tests/test_cli.sh ./mmtReader`

## Test Results

All tests use a simple pass/fail counter:

```
=== Results ===
Run:  40
Pass: 40
Fail: 0
```

Each suite exits with code 0 if all pass, code 1 if any fail, so the first
failing group aborts `make test`.
