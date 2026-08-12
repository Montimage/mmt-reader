# Documentation Plan — mmt-reader

**Date:** 2026-01-21
**Source:** Audit 01-audit.md, branch inventory 02-branches.md
**Project:** Single-file C CLI tool (~530 lines) reading pcap files / live interfaces via MMT-DPI

---

## Summary Table

| # | File | Action | Rationale |
|---|------|--------|-----------|
| 1 | `docs/USER_GUIDE.md` | **create** | README has a single usage line; users need full CLI option docs, input modes (offline pcap vs live interface), output format, and examples. |
| 2 | `docs/DEVELOPMENT.md` | **create** | No build system (no Makefile/CMake); developers need dependency install steps, compile command, MMT-DPI prerequisite, and coding conventions for a single-C-file project. |
| 3 | `docs/DEPLOYMENT.md` | **skip** | Not applicable — this is a static binary with no runtime install, service, or packaging; the compile step *is* deployment. |
| 4 | `docs/ARCHITECTURE.md` | **create** | No architecture docs exist; the code has a clear flow (init MMT → register handlers → process packets → print stats) worth documenting with a diagram. |
| 5 | `docs/API.md` | **skip** | Not a library; no public C API to document. The MMT-DPI library API is external. |
| 6 | `docs/CHANGELOG.md` | **create** | Two commits exist with no version history; a changelog enables future release tracking. |
| 7 | `CONTRIBUTING.md` | **create** | Audit Section 4.2 — critical for OSS readiness; defines how to report issues, submit PRs, and code style for this C project. |
| 8 | `CODE_OF_CONDUCT.md` | **create** | Audit Section 4.3 — required for healthy GitHub community profile (Contributor Covenant v2.1). |
| 9 | `SECURITY.md` | **create** | Audit Section 4.4 — provides vulnerability reporting path (contact@montimage.com per README). |

---

## Detailed Rationale

### 1. `docs/USER_GUIDE.md` — CREATE

**Why:** The README lists only `-t`, `-i`, `-b`, `-a`, `-h` in one line each. The actual code supports `-x` (ip_address_classify), `-y` (hostname_classify), `-z` (port_classify) which are undocumented. Users need:
- Full CLI reference (all flags with defaults)
- Two input modes explained (offline pcap file vs live interface — requires sudo)
- Output format description (protocol stats table, input statistics, pcap stats, bandwidth/pps/fps)
- Concrete examples (e.g., `./mmtReader -t smallFlows.pcap -a`)
- Troubleshooting (pcap promiscuous mode requires root, Ethernet-only interface)

### 2. `docs/DEVELOPMENT.md` — CREATE

**Why:** No Makefile or CMakeLists.txt exists. The compile command is hardcoded in README and the source header. Developers need:
- Prerequisites: MMT-DPI installed at `/opt/mmt/dpi/`, libpcap-dev, libconfuse-dev
- Exact compile command with flags explained (`-g` for debug, `-I`, `-L`, `-lmmt_core -ldl -lpcap`)
- How to add a new protocol handler (register_packet_handler, register_attribute_handler pattern)
- Code structure walkthrough (main → parseOptions → init_mmt → process → clean)
- How to run with the bundled `smallFlows.pcap` test file

### 3. `docs/DEPLOYMENT.md` — SKIP

**Why:** This is a statically-linked C binary. There is no runtime installation, no service daemon, no package to publish. The "deploy" step is just copying the compiled binary. The compile instructions in DEVELOPMENT.md cover this adequately.

### 4. `docs/ARCHITECTURE.md` — CREATE

**Why:** The code has a recognizable architecture worth documenting:
- **Input layer:** pcap (offline file via `pcap_open_offline` or live interface via `pcap_create` + `pcap_loop`)
- **Processing layer:** MMT-DPI handler (`mmt_init_handler`, `packet_process`)
- **Statistics layer:** Protocol iteration, session tracking, bandwidth calculation
- **Output layer:** `mmt_reader_stats()` prints per-protocol and aggregate stats
- A Mermaid or ASCII diagram of the data flow would help newcomers understand the code in one glance.

### 5. `docs/API.md` — SKIP

**Why:** `mmtReader.c` is a standalone CLI application, not a library. It includes `mmt_core.h` and `tcpip/mmt_tcpip.h` (external MMT-DPI headers) but exports no public API. Documenting the MMT-DPI API is out of scope.

### 6. `docs/CHANGELOG.md` — CREATE

**Why:** Two commits exist:
- `e246ce3` — "import from bitbucket" (initial import)
- `5631a7f` — "Add Apache v2 license"

A changelog starting from v0.1.0 enables future releases. Format: keep it simple (date, version, changes).

### 7. `CONTRIBUTING.md` — CREATE

**Why:** Audit Section 4.2 (FAIL). Required for GitHub community profile health. Covers:
- How to report bugs (use GitHub issues, include pcap file if possible)
- How to submit PRs (fork, branch, commit, PR)
- Code style (C conventions for a single-file project)
- Build verification before submitting

### 8. `CODE_OF_CONDUCT.md` — CREATE

**Why:** Audit Section 4.3 (FAIL). Contributor Covenant v2.1 is the standard. Required for GitHub community profile to be marked "Healthy".

### 9. `SECURITY.md` — CREATE

**Why:** Audit Section 4.4 (FAIL). Provides a clear path for vulnerability reports. References contact@montimage.com from the README.

---

## Files to Keep (no change needed)

| File | Reason |
|------|--------|
| `README.md` | Keep as-is for now; will be updated separately (per audit item #6) with badges, features list, quick start, and broken link fix. |
| `LICENSE` | Full Apache 2.0 text, correctly placed. No changes needed. |
| `.gitignore` | Needs improvement (audit item #2.2) but handled separately in codebase cleanup. |

---

## Execution Order

1. **Phase 1 — Community docs** (CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md) — fast, template-driven, critical for OSS profile
2. **Phase 2 — Technical docs** (USER_GUIDE.md, DEVELOPMENT.md, ARCHITECTURE.md) — requires reading and understanding the code
3. **Phase 3 — History** (CHANGELOG.md) — simple, last
