# Changelog

## [v0.4.0] - 2026-01-01

### Features
- Add GitHub Actions workflow, retire Bitbucket notifications (#90)
- Wire gcov coverage into the build (#82)

### Bug Fixes
- Honor `json` from config file and `MMTREADER_JSON` environment variable (#98)
- Report product version distinctly from SDK version in `--version` banner (#93)
- Rename shadowed `rc` variable in online capture loop (#89)
- Restore `.deb` fallback via `compgen` glob expansion (#86)
- Remove `eval`-built command strings and add adversarial smoke proof (#85)
- Graceful SIGTERM stop and extraction-failure summary (#84)
- Fix config precedence for env vars and prevent buffer overflow (#83)
- Restore Jenkins test stage running `make test` (#79)
- Groundwork: Jenkins make, SDK pin, test wiring (#78)

### Refactoring
- Named dispatch modes, `PROTO_META`, `PRIu64` (#92)
- Split `parse_options` into layered helpers (#91)
- Dead-code sweep across engine, cli, config, colors (#88)
- Extract shared assert header `tests/test_util.h` (#80)

### Documentation
- Regenerate user-guide and architecture samples from real output (#99)
- Align README and DEVELOPMENT docs with the real build (#95)
- Document `cap_net_raw` capability tradeoff (#81)
- Add `CLAUDE.md` and `AGENTS.md` agent config files (#77)
- Document agent install/run notes for the C toolchain (#76)

### Build / CI
- Enable `-Wall -Wextra` and verify the tree is warning-free (#94)
- Pin base image and bump toolchain to current GCC (#87)

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
  `{"mmtreader": "0.4.0", "mmt_dpi": "1.8.0 (42cac8b7)"}`. Consumers reading
  `.version` as a string must read `.version.mmt_dpi` instead.

### Documentation

- Align README, `docs/DEVELOPMENT.md`, `docs/TESTING.md`, `AGENT_ENVIRONMENT.md`
  and the mmt-reader skill with the real build (#72, `F-DOCS-001`,
  `F-DOCS-002`): the manual compile command now names `flows.c` and links,
  `libconfuse` is gone as a prerequisite (`config.c` has its own INI parser),
  the `-Wall -Wextra` warning gate and `-DMMTREADER_VERSION` injection are
  documented, and every test total is re-measured from an actual run
  (14 numbered groups, 299 unit asserts, 52/52 CLI checks, 6/6 SDK checks).
- Replace the invented README sample output and JSON sample with output
  captured from `./mmtReader analyze -t smallFlows.pcap -a`, and drop a
  duplicated Usage Examples block.
- Regenerate every sample block in `docs/USER_GUIDE.md` from real output (#97).
  The guide was left out of #72 and still showed a `TCP.HTTP.Google` protocol
  path format, `Input:`/`Sessions:` labels that `cli/output.c` never prints, a
  JSON sample predating both the `protocol_paths[]` split and the `version`
  object from #70, and a whole "PCAP Statistics" section for a feature that
  does not exist — `pcap_stats()` is never called. Every block is now spliced
  from an actual `./mmtReader analyze -t smallFlows.pcap` run; every command
  shown carries its required `analyze`/`capture` subcommand and points at the
  bundled `smallFlows.pcap`, so it runs verbatim and exits 0. The config and
  environment sections now agree with `docs/CONFIG.md` on which keys are live
  and on the defaults < `~/.mmtreader.conf` < `--config` < environment < CLI
  precedence fixed in #96.
- Correct two identifiers in `docs/ARCHITECTURE.md` (#97): the sorted-list
  helper is `proto_info_insert()` (`cli/output.c:104`), not
  `insert_proto_info()`, and `engine_print_stats_ex()` lives in
  `core/engine.c:281`, not `cli/output.c`. Its output sequence also no longer
  lists the non-existent PCAP-statistics section.

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
