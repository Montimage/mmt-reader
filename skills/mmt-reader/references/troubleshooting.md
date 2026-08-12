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

A run that fails to start — unreadable pcap, unopenable interface — writes **nothing** to stdout. Check the exit code rather than treating an empty stdout as a parse problem. Earlier versions emitted a fully zeroed JSON document on these paths, which read like a successful capture of no traffic.

## Edge cases

- **Large pcap files** — add `-q` to suppress per-packet progress output.
- **WiFi interfaces** — capture works, but 802.11 frames are passed through raw rather than converted to Ethernet, so DPI classification on a monitor-mode interface is unreliable. Prefer a managed-mode interface, and say so if results look sparse.
- **IPv6 traffic** — counted alongside IPv4 in `total_sessions`; report `ipv6_sessions` separately when it is non-zero.
- **Per-protocol `sessions` reads 0 for everything but `ip`/`ipv6`** — MMT-DPI books a session against the IP layer that owns it, so there is no per-application split to report. Use `input_stats.total_sessions` for the total.
- **Top talkers by host** — `mmtReader capture <if> -F <seconds> -a -s` runs a timed capture and prints the top 15 sessions by volume (application protocol, client and server endpoints, byte and packet counts), then exits on its own. Two constraints: `-F` is **live capture only** (`analyze` rejects it with `Error: --flows is only supported by the 'capture' subcommand (live interfaces).` and exit code 2), and it is **text-only** — there is no JSON form of the flow table, so under `--json` it is written to stderr and stdout stays a single valid JSON document. To read the table, run `-F` without `--json`; to capture both, redirect the two streams separately.
- **Wide addresses widen the flow table** — the `-F` columns are `proto`, `client`, `server`, `bytes`, `pkts`, with each endpoint written `address:port` (IPv6 bracketed, `[2001:db8::1]:443`). Long IPv6 endpoints push the trailing columns right, so read by field order rather than column position.
- **Live capture** — press `Ctrl+C` to stop; final statistics print on exit, so never kill the process with `SIGKILL`.
- **Empty `protocols[]`** — the DPI classified nothing, which on a non-empty capture means the link type is unsupported (see the WiFi note above). It is not a missing flag: `protocols[]` is populated with or without `-a`.
