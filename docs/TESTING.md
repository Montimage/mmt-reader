# MMT-Reader Test Suite Guide

MMT-Reader includes unit tests for config parsing and CLI argument parsing, plus integration tests for end-to-end CLI behavior.

## Quick Start

```bash
make test
```

This runs the full test suite: unit tests for config and parsing, integration tests for CLI behavior, and completion file checks.

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

| Target | File | Type | Description |
|--------|------|------|-------------|
| Test 1 | — | Integration | Text output: `analyze -t smallFlows.pcap -a` produces expected output |
| Test 2 | — | Integration | JSON output: `--json` produces valid JSON parseable by `jq` |
| Test 3 | — | Integration | Sessions flag: `--sessions` includes IPv4 session counts |
| Test 4 | — | Integration | JSON sessions: `--json --sessions` includes per-protocol session counts |
| Test 5 | `tests/test_config.c` | Unit | Config file parsing (init, load, sections, comments, booleans) |
| Test 6 | `tests/test_parse.c` | Unit | CLI argument parsing (defaults, subcommands, flags, validation) |
| Test 7 | `tests/test_cli.sh` | Integration | CLI end-to-end (env vars, quiet, verbose, input validation) |

## Unit Tests

### Config Tests (`tests/test_config.c`)

Tests for `config.c` — INI config file parsing:

```bash
gcc -g -o test_config test_config.c config.c -I. && ./test_config && rm -f test_config
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

```bash
gcc -g -o test_parse test_parse.c cli/parse.c -I./cli -I./utils && ./test_parse && rm -f test_parse
```

**Test coverage:**
- `parse_init()` — default values (input=NULL, buffer_mb=50, ip_classify=1, etc.)
- No subcommand — shows help
- `--help` flag — sets show_help=1
- `--version` flag — sets mode=3
- `analyze -t` — sets mode=1, input=file
- `capture -i` — sets mode=2, input=interface
- `capture eth0` (positional) — sets mode=2, input=interface
- `-q` (quiet) — sets quiet=1
- `-v` (verbose) — sets verbose=1
- `--json` — sets json=1
- `--no-color` — sets no_color=1
- `-b 100` — sets buffer_mb=100
- `-a` (proto-path) — sets proto_path=1

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
- **Environment variables** — `MMTREADER_QUIET`, `MMTREADER_NO_COLOR`, `MMTREADER_JSON`
- **CLI overrides env vars** — `-v` overrides `MMTREADER_QUIET`
- **General options** — `--help`, `--version`, `-h`, `--json`, short flags

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
| `test.pcap` | Referenced in tests (may be the same as smallFlows.pcap) |

## Adding New Tests

### Unit Tests

1. Add a new `test_*()` function to the appropriate test file
2. Use the `ASSERT_EQ`, `ASSERT_STR_EQ`, `ASSERT_TRUE`, `ASSERT_FALSE` macros
3. Call the new function from `main()`
4. Compile and run: `gcc -g -o test_xxx test_xxx.c source.c -I. && ./test_xxx`

### Integration Tests

1. Add a new test block in `tests/test_cli.sh`
2. Use `assert_exit_code`, `assert_output_contains`, `assert_output_not_contains` helpers
3. Run: `./tests/test_cli.sh ./mmtReader`

## Test Results

All tests use a simple pass/fail counter:

```
=== Results ===
Run:  42
Pass: 42
Fail: 0
```

The test exits with code 0 if all pass, code 1 if any fail.
