# Decisions Log

Every ambiguity resolved with the user, plus known discrepancies flagged during doc reconciliation.

## 2025-06-25

- **Q: Man page version says "1.0" but changelog uses "0.1.0" — which is correct?**
  - **A (pending):** The man page (`mmtReader.1:1`) says `"MMT-Reader 1.0"` while `docs/CHANGELOG.md` uses `[0.1.0]`. The git history shows this project was imported from Bitbucket as 0.1.0, then refactored significantly. The man page version may be outdated or set by a build system. **Action:** Verify with build system or user.
  - **Source:** `mmtReader.1:1`, `docs/CHANGELOG.md:3`

- **Q: Man page date says "August 2026" — is this correct?**
  - **A (pending):** The man page (`mmtReader.1:1`) says `"August 2026"` which is a future date. This is likely auto-generated or a placeholder. **Action:** Verify with build system or user.
  - **Source:** `mmtReader.1:1`

- **Q: README mentions `smallFlows.pcap` as "if bundled" but the file exists in the repo.**
  - **A (resolved):** The file `smallFlows.pcap` exists in the repo root. Updated README to remove "(if bundled)" qualifier.
  - **Source:** `README.md` (updated), `smallFlows.pcap` (verified present)

- **Q: Should the `-x`, `-y`, `-z` flags be documented in the main help text?**
  - **A (resolved):** These are hidden flags — intentionally not shown in `--help` but fully functional. All docs consistently note this. The man page documents them as global options, which is the most complete reference.
  - **Source:** `cli/parse.h:44-46`, `mmtReader.1`
