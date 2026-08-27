# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> This file keeps the historical release notes. Unreleased and recent changes
> are recorded in the repository-root [`CHANGELOG.md`](../CHANGELOG.md).

---

## [0.3.0] — 2025-08-12

### Added

- **v0.3.0 release** — Latest version update

---

## [0.2.0-beta.1] — 2025-07-13

### Added

- **Shell completions** — Bash, Zsh, and Fish tab-completion scripts ([#30](https://github.com/Montimage/mmt-reader/pull/30))
- **Config file support** — INI-style `~/.mmtreader.conf` with per-command sections ([#32](https://github.com/Montimage/mmt-reader/pull/32))
- **Anomaly detection hooks** — Extensible hook system for detecting network anomalies ([#31](https://github.com/Montimage/mmt-reader/pull/31))
- **`capture` subcommand** — Live interface monitoring via positional interface support ([#28](https://github.com/Montimage/mmt-reader/pull/28))
- **`--json` output** — Machine-consumable JSON output with `--sessions` flag ([#27](https://github.com/Montimage/mmt-reader/pull/27))
- **Environment variables** — `MMTREADER_JSON`, `MMTREADER_NO_COLOR`, `MMTREADER_QUIET` plus `--quiet`/`--verbose` flags ([#26](https://github.com/Montimage/mmt-reader/pull/26))
- **MMT-DPI engine** — Core deep packet inspection engine extracted into `core/engine.c` ([#21](https://github.com/Montimage/mmt-reader/pull/21))
- **Global installer** — Self-contained one-command installer script ([#16](https://github.com/Montimage/mmt-reader/issues/16))

### Changed

- **Architecture overhaul** — Split `mmtReader.c` into thin entry point with modular architecture: `cli/parse.c`, `cli/output.c`, `utils/colors.c`, `utils/version.c` ([#20](https://github.com/Montimage/mmt-reader/pull/20), [#23](https://github.com/Montimage/mmt-reader/pull/23), [#24](https://github.com/Montimage/mmt-reader/pull/24), [#25](https://github.com/Montimage/mmt-reader/pull/25), [#21](https://github.com/Montimage/mmt-reader/pull/21))
- **Makefile** — Updated for multi-file build

### Fixed

- **Config loading priority** — Custom config loaded after getopt loop so CLI flags take precedence ([#32](https://github.com/Montimage/mmt-reader/pull/32))
- **Input validation** — Proper error messages, file existence checks, verbose diagnostics ([#26](https://github.com/Montimage/mmt-reader/pull/26))
- **Exit codes** — `--help` returns 0, errors return 1/2 ([#8](https://github.com/Montimage/mmt-reader/pull/8))
- **Man page** — Removed invalid `-i` from analyze section, completed GLOBAL OPTIONS docs ([#29](https://github.com/Montimage/mmt-reader/pull/29))

### Documentation

- **Doc reconciliation** — Reconciled all docs with codebase and generated missing docs ([#33](https://github.com/Montimage/mmt-reader/pull/33))
- **OSS docs** — Added CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, and Apache 2.0 license ([#16](https://github.com/Montimage/mmt-reader/issues/16), [#15](https://github.com/Montimage/mmt-reader/issues/15))

### Miscellaneous

- Initial import from Bitbucket repository

---

## [0.2.0] — 2024

### Added

- **Subcommand interface** — `analyze` for pcap files, `capture` for live interfaces ([#23](https://github.com/Montimage/mmt-reader/pull/23))
- **JSON output** — Machine-readable statistics with `--json` / `-j` ([#27](https://github.com/Montimage/mmt-reader/pull/27))
- **Session counts** — Per-protocol session breakdown with `--sessions` / `-s` ([#27](https://github.com/Montimage/mmt-reader/pull/27))
- **Config file support** — INI-style `~/.mmtreader.conf` with per-command sections ([#32](https://github.com/Montimage/mmt-reader/pull/32))
- **Environment variables** — `MMTREADER_JSON`, `MMTREADER_NO_COLOR`, `MMTREADER_QUIET` ([#26](https://github.com/Montimage/mmt-reader/pull/26))
- **Quiet mode** — `--quiet` / `-q` to suppress progress output ([#26](https://github.com/Montimage/mmt-reader/pull/26))
- **Verbose mode** — `--verbose` / `-v` for debug output to stderr ([#26](https://github.com/Montimage/mmt-reader/pull/26))
- **Color support** — ANSI color output with `--no-color` / `-C` and `NO_COLOR` env var ([#25](https://github.com/Montimage/mmt-reader/pull/25))
- **Shell completions** — Bash, Zsh, and Fish tab-completion for subcommands, flags, and paths ([#30](https://github.com/Montimage/mmt-reader/pull/30))
- **Positional interface** — `capture eth0` as alternative to `--interface eth0` ([#28](https://github.com/Montimage/mmt-reader/pull/28))
- **Anomaly detection hooks** — Extensible anomaly detection context for future use ([#31](https://github.com/Montimage/mmt-reader/pull/31))
- **Man page** — Updated for subcommand interface and new options ([#29](https://github.com/Montimage/mmt-reader/pull/29))

### Changed

- **Modular architecture** — Split single-file app into modular components: `core/`, `cli/`, `capture/`, `config/`, `utils/` ([#20](https://github.com/Montimage/mmt-reader/pull/20))
- **CLI parsing** — Replaced inline `getopt()` with `getopt_long()`-based parsing in `cli/parse.c` ([#23](https://github.com/Montimage/mmt-reader/pull/23))
- **Output rendering** — Extracted text/JSON formatting into `cli/output.c` ([#24](https://github.com/Montimage/mmt-reader/pull/24))
- **Color utilities** — Extracted ANSI color support into `utils/colors.c` ([#25](https://github.com/Montimage/mmt-reader/pull/25))
- **Version handling** — Extracted version banner into `utils/version.c` ([#21](https://github.com/Montimage/mmt-reader/pull/21))
- **Engine API** — Extracted MMT-DPI engine into `core/engine.c` with clean API ([#21](https://github.com/Montimage/mmt-reader/pull/21))

### Technical Details

- **Commit** `b3abcac` — Split into thin entry point with modular architecture
- **Commit** `baa17cb` — Extract argument parsing into cli/parse.c with getopt_long and subcommand dispatch
- **Commit** `a7ad241` — Extract output formatting into cli/output.c
- **Commit** `40a1773` — Extract ANSI color support into utils/colors module
- **Commit** `e68e876` — Add env vars, quiet/verbose flags, input validation
- **Commit** `83781c0` — Add --json output format and --sessions flag
- **Commit** `abf579b` — Wire up capture subcommand with positional interface support
- **Commit** `57aea17` — Update man page for subcommands and new options
- **Commit** `0be3c14` — Add config file support for default options
- **Commit** `47da4a8` — Add anomaly detection hooks for future extension
- **Commit** `56eafa5` — Add shell completions for bash, zsh, and fish

---

## [0.1.0] — 2022-01-21

### Added

- **Initial release** — Imported from Bitbucket repository
- Single-file C CLI tool (`mmtReader.c`) for network traffic analysis
- Offline mode: read and analyze pcap capture files (`-t`)
- Online mode: live traffic capture from network interfaces (`-i`)
- Per-protocol statistics with packet counts, data volume, and payload volume
- Protocol path display with `-a` flag (DPI path hierarchy)
- Three classification modes: IP address (`-x`), hostname (`-y`), port (`-z`)
- Configurable pcap buffer size for live capture (`-b`)
- Input statistics: duration, bandwidth, pps, fps
- PCAP kernel/driver drop statistics (online mode)
- Graceful shutdown via SIGINT (Ctrl+C) with statistics output
- Apache 2.0 license

### Technical Details

- **Commit** `e246ce3` — Import from Bitbucket
- **Commit** `5631a7f` — Add Apache v2 license

---

## Versioning

This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

- **Major** (X.0.0): Breaking changes to the API or output format
- **Minor** (0.X.0): New features (e.g., new protocol handlers, new output format)
- **Patch** (0.0.X): Bug fixes, performance improvements, documentation updates
