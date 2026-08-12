# Troubleshooting and edge cases

Read this when a run fails the success bar, or when one of the edge cases below applies. Verified against mmtReader 1.8.0 (42cac8b7).

## Errors

Map the failure to its fix, then retry **once** at most. If the same error recurs, report the exact stderr to the user instead of trying further variations.

| Error | Exit | Fix |
|-------|------|-----|
| `command not found: mmtReader` | 127 | Follow `installation.md` |
| `MMT-DPI library not found` | — | MMT-DPI is missing from `/opt/mmt/dpi/` — see `installation.md` |
| `Error: file not found: <path>` | 2 | Verify the pcap path; ask the user rather than guessing |
| `Permission denied` (analyze) | 2 | Check read permission on the pcap — do **not** escalate to `sudo` |
| `Couldn't activate device <if>: socket: Operation not permitted` | 1 | Live capture needs root or `cap_net_raw` — re-run under `sudo`, or install via `install.sh`, which grants the capability |
| `Couldn't activate device <if>: No such device` | 1 | Interface name is wrong — list valid ones with `ip link show` |

Exit codes: `0` success, `1` capture failure, `2` usage or input error.

## Edge cases

- **Large pcap files** — add `-q` to suppress per-packet progress output.
- **WiFi interfaces** — capture works, but 802.11 frames are passed through raw rather than converted to Ethernet, so DPI classification on a monitor-mode interface is unreliable. Prefer a managed-mode interface, and say so if results look sparse.
- **IPv6 traffic** — counted alongside IPv4 in `total_sessions`; report `ipv6_sessions` separately when it is non-zero.
- **Per-protocol `sessions` reads 0** — always, in current builds. Fall back to `input_stats.total_sessions` and say the per-protocol split is unavailable.
- **Top talkers by host** — `sudo mmtReader capture <if> -F <seconds> -a -s` runs a timed capture and prints the top 15 flows by volume (5-tuple with byte and packet counts). Live capture only: `-F` appears in `analyze --help` but is silently ignored on pcap files.
- **Live capture** — press `Ctrl+C` to stop; final statistics print on exit, so never kill the process with `SIGKILL`.
- **Empty `protocols[]`** — you forgot `-a`. Re-run with **the standard run** flags.
