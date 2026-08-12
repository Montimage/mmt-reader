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
- **Top talkers by host** — `mmtReader capture <if> -F <seconds> -a -s` runs a timed capture and prints the top 15 flows by volume (5-tuple with byte and packet counts), then exits on its own. Two constraints: `-F` is **live capture only** (`analyze` rejects it with `Error: --flows is only supported by the 'capture' subcommand (live interfaces).` and exit code 2), and it is **text-only** — the flow table is plain text on stdout, so combining it with `--json` yields unparseable output even with `-q`. Run `-F` without `--json` and read the table, or run a separate `--json` pass for protocol stats.
- **Live capture stats are unreliable** — `input_stats.packets` is `0` and `duration_seconds` is `1.0` regardless of what was captured, which also makes `bandwidth` and `pps` meaningless. Only `total_sessions` and `protocols[]` are trustworthy live. In text mode the whole stats block prints twice; that is cosmetic.
- **Wide addresses break the flow table** — IPv6 addresses overflow the fixed-width columns in the `-F` output, so rows wrap. Read by field order (proto, src, sport, dst, dport, bytes, pkts), not by column position.
- **Live capture** — press `Ctrl+C` to stop; final statistics print on exit, so never kill the process with `SIGKILL`.
- **Empty `protocols[]`** — you forgot `-a`. Re-run with **the standard run** flags.
