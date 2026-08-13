# Changelog

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
