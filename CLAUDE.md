# CLAUDE.md — mmtReader

C CLI (`./mmtReader`) that reads pcaps or live interfaces via Montimage's proprietary
MMT-DPI SDK and reports protocol stats as text or JSON.

## Critical commands

- Build: `make` — produces `./mmtReader`; exit 0 = success. `make clean` removes it.
- Test: `make test` — builds first, then runs 13 numbered test groups defined in `Makefile`.
- Coverage: `make coverage` — reruns the suite with instrumented unit-test binaries and prints a per-source gcov summary (see AGENT_ENVIRONMENT.md).
- Both commands are the whole verification loop; there is no lint/typecheck target.

## Prerequisites (not inferable from this repo)

- **MMT-DPI SDK (proprietary)** at `/opt/mmt/dpi` (`include/` + `lib/`). Not vendored,
  not on any registry; missing → link errors (`mmt_core.h: No such file`, `cannot find -lmmt_core`).
- **jq** is a *test-time-only* requirement: several `make test` groups pipe JSON through it.
- Build-time: gcc, make, libpcap-dev. No env vars, no `.env`, no configure step.
- Full recorded toolchain versions and expected output shapes: @AGENT_ENVIRONMENT.md

## Architecture map

- `mmtReader.c` — entry point / CLI dispatch; `config.c` — options & config file.
- `capture.c` — pcap input (live + file); `flows.c` — flow tracking.
- `core/engine.c` — MMT-DPI engine glue (protocol registration, stats).
- `cli/parse.c`, `cli/output.c` — argument parsing, text/JSON rendering.
- `utils/` — colors, version. `tests/` — C unit suites + `tests/test_cli.sh`.
- Deeper docs: @README.md, @docs/ARCHITECTURE.md, @docs/TESTING.md

## Hard rules

- IMPORTANT: never "clean up" versioned files under `/opt/mmt/dpi/lib` or blindly repoint
  its `libmmt_core.so` symlink — stale 1.7.x libs sit beside 1.8.0 ones. Check with
  `readlink` first (details in AGENT_ENVIRONMENT.md).
- YOU MUST keep `make && make test` green before committing; one tolerated skip is expected:
  live capture on `lo` (root-gated) skips by design under unprivileged runs.
- Never delete or overwrite fixture pcaps (`smallFlows.pcap`, `test.pcap`) — tests use them.
- No new external dependencies: SDK include/link paths default to `/opt/mmt/dpi`
  (overridable with `make MMT_DPI=...`); the build aborts when the SDK is
  missing or older than 1.8.0 (`make check-sdk`).
- Do not hand-edit one shell completion in `completions/` without updating all three.

## Workflow preferences

- Prefer minimal diffs; for C changes run `make && make test` immediately after editing.
- Env/toolchain facts belong in AGENT_ENVIRONMENT.md; do not duplicate them here.
- Commits follow Conventional Commits: `type(scope): description (#N)`.

## Token Efficiency
- Never re-read files you just wrote or edited. You know the contents.
- Never re-run commands to "verify" unless the outcome was uncertain.
- Don't echo back large blocks of code or file contents unless asked.
- Batch related edits into single operations. Don't make 5 edits when 1 handles it.
- Skip confirmations like "I'll continue..." Just do it.
- If a task needs 1 tool call, don't use 3. Plan before acting.
- Do not summarize what you just did unless the result is ambiguous or you need additional input.
