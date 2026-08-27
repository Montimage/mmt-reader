# Changelog

## [Unreleased]

### Fixed

- Honor the `json` config-file key and the `MMTREADER_JSON` environment variable
  (#96). `cli_options_t` carried two fields meaning one thing — `output_format`,
  which every output decision reads, and `json`, whose only reader was a verbose
  debug printf. The config and environment paths wrote `json` alone, so
  `json = 1` and `MMTREADER_JSON=1` were silently ignored; only `-j/--json`,
  which wrote both, had any effect. `json` is gone and `output_format` is now
  the single carrier.
- Apply `-c/--config` files **before** the CLI flags are parsed (#96). The named
  config file used to be re-read after the option loop and re-copied
  unconditionally, so it beat explicit flags (`-b 100 --config <buffer=777>`
  used 777) and skipped the environment entirely — the opposite precedence from
  `~/.mmtreader.conf`. Both files now load before the flags, under one rule:
  compiled defaults < `~/.mmtreader.conf` < `--config` file < environment <
  CLI flags. See `docs/CONFIG.md`.

- Report mmtReader's own product version distinctly from the MMT-DPI SDK version
  (#70, `F-BUG-005`). `--version` and the startup banner now print two labeled
  lines, and the product version is injected at build time via
  `make MMTREADER_VERSION=...` (`-DMMTREADER_VERSION`).

### Changed

- **Breaking (JSON):** the `--json` `"version"` field changed from a bare string
  holding the SDK version to an object:
  `{"mmtreader": "0.3.0", "mmt_dpi": "1.8.0 (42cac8b7)"}`. Consumers reading
  `.version` as a string must read `.version.mmt_dpi` instead.

### Documentation

- Align README, `docs/DEVELOPMENT.md`, `docs/TESTING.md`, `AGENT_ENVIRONMENT.md`
  and the mmt-reader skill with the real build (#72, `F-DOCS-001`,
  `F-DOCS-002`): the manual compile command now names `flows.c` and links,
  `libconfuse` is gone as a prerequisite (`config.c` has its own INI parser),
  the `-Wall -Wextra` warning gate and `-DMMTREADER_VERSION` injection are
  documented, and every test total is re-measured from an actual run
  (14 numbered groups, 252 unit asserts, 35/35 CLI checks, 6/6 SDK checks).
- Replace the invented README sample output and JSON sample with output
  captured from `./mmtReader analyze -t smallFlows.pcap -a`, and drop a
  duplicated Usage Examples block.

## [v0.3.0] - 2026-01-01

### Added

- Add mmtReader AI agent skill for network traffic analysis (#34) (a154152)

### Fixed

- Stop `engine_destroy()` from printing the statistics summary (#39) (#42) (089be40)
- Take traffic statistics from the MMT-DPI API instead of recomputing them (#40) (c2927d4)
- Route live capture through the engine's packet accounting (#37) (ae0c0fb)
- Remove double quotes from Mermaid node labels and message text to fix parser errors (72ffba0)
- Use `<br/>` instead of `\n` for line breaks in Mermaid sequence diagrams (f32e946)

### Testing

- Pin `input_stats` to MMT-DPI's per-protocol accounting (#38) (#43) (045bce9)

### Documentation

- Fix README and PLAYBOOK to match actual binary output (3f503c0)
- Add Use Case 6 — AI Agent-Assisted Analysis (5a91a04)
- Add MMT-Reader AI Agent Playbook (b646712)
- Rewrite README as AI Agent-focused landing page with visual workflow (0277af4)
