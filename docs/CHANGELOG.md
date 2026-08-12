# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
