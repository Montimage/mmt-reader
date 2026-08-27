# MMT-Reader User Guide

MMT-Reader is a lightweight CLI tool that analyzes network traffic and produces
per-protocol statistics. It reads traffic from either a pcap capture file
(offline mode) or a live network interface (online mode) and leverages the
[MMT-DPI](https://bitbucket.org/montimage/mmt-dpi) library for deep packet
inspection and protocol classification.

> **About the samples in this guide.** Every output block below was captured by
> running the command shown directly above it against this repository's
> `smallFlows.pcap` fixture, with color disabled (`MMTREADER_NO_COLOR=1`).
> Nothing is hand-written. Long tables are truncated at an explicit `...` row
> and the true row count is stated; the values shown are real. Your own traffic
> will produce different numbers, and the version banner's build timestamp and
> SDK build hash differ per build.

---

## Quick Start

```bash
# Offline mode — analyze a pcap file
./mmtReader analyze -t smallFlows.pcap -a

# Online mode — monitor a live interface (requires root)
sudo ./mmtReader capture -i eth0 -a
```

The subcommand is not optional. `./mmtReader -t smallFlows.pcap -a` — the
pre-subcommand form — exits 0 but only prints the help screen; it analyzes
nothing.

---

## Usage

MMT-Reader uses a **subcommand-based** interface:

```
mmtReader <command> [OPTIONS]
```

| Subcommand | Description |
|------------|-------------|
| `analyze` | Analyze a PCAP trace file (offline mode) |
| `capture` | Capture and analyze live network traffic (online mode) |

`./mmtReader --help` prints:

```
Usage: ./mmtReader <command> [OPTIONS]

MMT-READER — Network protocol analyzer

Commands:
  analyze   Analyze a PCAP trace file
  capture   Capture and analyze live network traffic

Use "./mmtReader <command> --help" for command-specific help.

General options:
  -q, --quiet              Suppress progress output
  -v, --verbose            Show verbose debug output
  -b, --buffer <MB>        PCAP buffer size in MB (1-10000, default: 50)
  -h, --help       Show this help message
  -V, --version    Print version information

  -c, --config <file>      Use config file for default options
                           (default: ~/.mmtreader.conf)
                           CLI flags override config file values.

Environment variables:
  MMTREADER_JSON=1         Force JSON output
  MMTREADER_NO_COLOR=1     Disable color output
  MMTREADER_QUIET=1        Enable quiet mode

Hidden flags (available with any command):
  -x, --ip-classify <0|1>         IP address classification (default: 1)
  -y, --hostname-classify <0|1>   Hostname classification (default: 1)
  -z, --port-classify <0|1>       Port number classification (default: 1)

Exit codes:
  0  Success or --help requested
  2  Usage error
```

### Options available with either subcommand

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `-b, --buffer <MB>` | `1`–`10000` | `50` | Pcap handler buffer size. Read by `capture`; an `analyze` run goes through `pcap_open_offline()` and ignores it. |
| `-a, --proto-path` | None | off | Show per-protocol-path statistics. |
| `-s, --sessions` | None | off | Show per-protocol session counts. |
| `-j, --json` | None | off | Output statistics in JSON format. |
| `-T, --text` | None | on | Explicitly select text output (the default). |
| `-q, --quiet` | None | off | Suppress progress output. Only `capture` prints `INFO:` lines, so an `analyze` run looks the same either way. |
| `-v, --verbose` | None | off | Verbose debug output to stderr. |
| `-C, --no-color` | None | off | Disable ANSI color output. |
| `-c, --config <file>` | Path | `~/.mmtreader.conf` | Read defaults from a config file. |
| `-h, --help` | None | — | Print help for the current command and exit 0. |
| `-V, --version` | None | — | Print version information and exit 0. |
| `-x <0\|1>` | `0`/`1` | `1` | IP address classification. |
| `-y <0\|1>` | `0`/`1` | `1` | Hostname classification. |
| `-z <0\|1>` | `0`/`1` | `1` | Port number classification. |

> **Note:** `-x`, `-y` and `-z` are omitted from `capture --help` but work with
> both subcommands. They are listed under *Hidden flags* in `./mmtReader --help`
> and `./mmtReader analyze --help`.

### `analyze` Subcommand

```
mmtReader analyze [OPTIONS] -t <trace.pcap>
```

| Flag | Argument | Description |
|------|----------|-------------|
| `-t, --trace <file>` | Path to a pcap file | **Required** — the trace to analyze. No root privileges needed. |
| `-i, --interface <iface>` | Interface name | **Rejected here.** `analyze --help` lists it, but the parser exits 2 with ``Error: -i/--interface is for 'capture' only`` (`cli/parse.c:394`). Use `capture -i` for live input. |

`./mmtReader analyze --help` prints the following. Note that its `-i` line is
inaccurate — the flag is listed as an alternative to `-t`, but `analyze`
rejects it (see the table above); this is the tool's own help text, reproduced
verbatim:

```
Usage: ./mmtReader analyze [OPTIONS] -t <trace.pcap>

Analyze a PCAP trace file for protocol identification.

Options:
  -t, --trace <file>       Trace file to analyze (required)
  -i, --interface <iface>  Live network interface (alternative to -t)
  -b, --buffer <MB>        PCAP buffer size in MB (1-10000, default: 50)
  -a, --proto-path         Show per-protocol-path statistics
  -s, --sessions           Show per-protocol session counts
  -j, --json               Output statistics in JSON format
  -T, --text               Explicitly set text output format (default)
  -q, --quiet              Suppress progress output
  -v, --verbose            Show verbose debug output
  -C, --no-color           Disable ANSI color output
  -h, --help               Show this help message
  -V, --version            Print version information

  -c, --config <file>      Use config file for default options
                           (default: ~/.mmtreader.conf)
                           CLI flags override config file values.

Environment variables:
  MMTREADER_JSON=1         Force JSON output
  MMTREADER_NO_COLOR=1     Disable color output
  MMTREADER_QUIET=1        Enable quiet mode

Hidden flags:
  -x, --ip-classify <0|1>  IP address classification (default: 1)
  -y, --hostname-classify <0|1>  Hostname classification (default: 1)
  -z, --port-classify <0|1>    Port number classification (default: 1)

Exit codes:
  0  Success or --help requested
  2  Usage error
```

### `capture` Subcommand

```
mmtReader capture [OPTIONS] -i <interface>
```

| Flag | Argument | Description |
|------|----------|-------------|
| `-i, --interface <iface>` | Interface name | **Required** — interface to capture from. |
| `interface` (positional) | Interface name | Alternative form: `mmtReader capture eth0`. |
| `-F, --flows <seconds>` | Seconds | Capture for *n* seconds, then report the top flows by volume. |

Live capture requires root (or `CAP_NET_RAW`). Ethernet (`DLT_EN10MB`) and
WiFi (`DLT_IEEE802_11`, `DLT_IEEE802_11_RADIO`) interfaces are both supported —
WiFi frames are converted to Ethernet framing before being handed to MMT-DPI
(`capture.c:289-314`).

`./mmtReader capture --help` prints:

```
Usage: ./mmtReader capture [OPTIONS] -i <interface>

Capture and analyze live network traffic from an interface.

Options:
  -i, --interface <iface>  Network interface to capture from (required)
  -b, --buffer <MB>        PCAP buffer size in MB (1-10000, default: 50)
  -a, --proto-path         Show per-protocol-path statistics
  -s, --sessions           Show per-protocol session counts
  -F, --flows <seconds>    Capture for <seconds>, then report top flows by volume
  -j, --json               Output statistics in JSON format
  -T, --text               Explicitly set text output format (default)
  -q, --quiet              Suppress progress output
  -v, --verbose            Show verbose debug output
  -C, --no-color           Disable ANSI color output
  -h, --help               Show this help message
  -V, --version            Print version information

  -c, --config <file>      Use config file for default options
                           (default: ~/.mmtreader.conf)
                           CLI flags override config file values.

Environment variables:
  MMTREADER_JSON=1         Force JSON output
  MMTREADER_NO_COLOR=1     Disable color output
  MMTREADER_QUIET=1        Enable quiet mode

Exit codes:
  0  Success or --help requested
  2  Usage error
```

---

## Output Format

A text-mode run prints a version banner, then the statistics report. Unless a
subsection names a different command, the blocks below come from:

```bash
MMTREADER_NO_COLOR=1 ./mmtReader analyze -t smallFlows.pcap -a
```

### Version banner

```
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
|		 MONTIMAGE
|	 mmtReader version: 0.3.0
|	 MMT-DPI SDK version: 1.8.0 (42cac8b7)
|	 ./mmtReader: built Aug 27 2026 16:24:52
|	 http://montimage.com
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
```

The two version lines and the build stamp are the only part of this guide that
changes without the code changing: `built ...` is the timestamp of *your* build
and the `(42cac8b7)` suffix is the SDK's build hash, so expect both to differ.

In text mode the banner goes to **stdout**. With `--json` it is written to
**stderr** instead, so stdout stays valid JSON. The `Enable classification by
...` progress lines always go to stderr.

### 1. Protocol statistics with the protocol path (`-a` only)

```
	#pkts	#volume	#payload	#proto_path
         7       3392       3014                                      ethernet.ip.tcp.unknown
       119      16053      11055                                      ethernet.ip.udp.unknown
        18        918        666                                                 ethernet.arp
       357     307843     288565                              ethernet.ip.tcp.http.craigslist
         3       1026        900                                         ethernet.ip.udp.dhcp
        87      15154      11500                                          ethernet.ip.udp.dns
         4       3167       2951                             ethernet.ip.tcp.http.doubleclick
         4        604        388                                 ethernet.ip.tcp.http.dropbox
        16       2592       1920                                      ethernet.ip.udp.dropbox
     14261    9216531    9216531                                                     ethernet
      ...        ...        ...                                                          ...
```

Truncated after 10 of 37 rows.

Columns:

- **#pkts** — packets matching this exact protocol path
- **#volume** — data volume in bytes (headers + payload)
- **#payload** — payload volume in bytes (headers excluded)
- **#proto_path** — the full DPI stack, dotted and lowercase

A protocol path reads left to right down the stack:
`ethernet.ip.tcp.http.msn` means an Ethernet frame carried IP, carrying TCP,
carrying HTTP, classified as MSN traffic. Rows are emitted grouped by the
leaf protocol, not sorted by packet count.

### 2. Protocol statistics (aggregated)

```
	#pkts	#volume	#payload	#proto_name
     14261    9216531    9216531 ethernet
     14243    9215613    9016211 ip
     13708    9135182    8669110 tcp
      5287    5967094    5681596 http
      3735    4259140    4057450 msn
      3090    2771386    2604526 ssl
      1422    1427322    1350534 salesforce
       620     326550     293070 google
       501      75353      58319 udp
       474     417015     391419 skype
       357     307843     288565 craigslist
       284     415889     400553 photobucket
      ...        ...        ... ...
```

Truncated after 12 of 28 rows.

Aggregated per protocol name across every path it appears in, sorted by packet
count descending. Because a packet is counted once per layer it traverses,
these rows overlap by design: the `ethernet` row counts every packet, `ip`
counts every packet that had an IP header, and so on.

### 3. Input statistics

```
>>>>>> INPUT STATISTICS <<<<<< 

	Packets: 14261
	Data: 9216531 bytes
	Total Sessions: 679
	Protocols: 28
	Duration: 299 seconds
	Bandwidth: 30875.60 bytes/second
	pps: 47.77 packets/second
	fps: 2.27 sessions/second
```

Metrics:

- **Packets** — total packets processed by MMT-DPI
- **Data** — total data volume in bytes
- **Total Sessions** — IPv4 + IPv6 sessions
- **Protocols** — distinct protocols detected
- **Duration** — first packet to last packet, rounded to whole seconds
- **Bandwidth** — `Data / Duration`, bytes per second
- **pps** — packets per second
- **fps** — sessions per second

There is no `Input:` line; the source file or interface is not echoed here.

Adding `-s/--sessions` inserts three further lines
(`MMTREADER_NO_COLOR=1 ./mmtReader analyze -t smallFlows.pcap -s`):

```
>>>>>> INPUT STATISTICS <<<<<< 

	Packets: 14261
	Data: 9216531 bytes
	IPv4 Sessions: 679
	IPv6 Sessions: 0
	Active Sessions: 168
	Total Sessions: 679
	Protocols: 28
	Duration: 299 seconds
	Bandwidth: 30875.60 bytes/second
	pps: 47.77 packets/second
	fps: 2.27 sessions/second
```

- **IPv4 Sessions** / **IPv6 Sessions** — per-family session counts
- **Active Sessions** — sessions still open when the run ended

`-s` also appends a `#sessions` column to the aggregated protocol table.

### JSON output

```bash
MMTREADER_NO_COLOR=1 ./mmtReader analyze -t smallFlows.pcap -a -j -s
```

```json
{
  "version": {
    "mmtreader": "0.3.0",
    "mmt_dpi": "1.8.0 (42cac8b7)"
  },
  "input_stats": {
    "packets": 14261,
    "data_volume": 9216531,
    "duration_seconds": 298.51,
    "bandwidth_bytes_per_sec": 30875.60,
    "packets_per_sec": 47.77,
    "ipv4_sessions": 679,
    "ipv6_sessions": 0,
    "active_sessions": 168,
    "total_sessions": 679,
    "protocols": 28
  },
  "protocol_paths": [
    {
      "packets": 7,
      "data_volume": 3392,
      "payload_volume": 3014,
      "path": "ethernet.ip.tcp.unknown"
    },
    {
      "packets": 119,
      "data_volume": 16053,
      "payload_volume": 11055,
      "path": "ethernet.ip.udp.unknown"
    },
    {
      "packets": 18,
      "data_volume": 918,
      "payload_volume": 666,
      "path": "ethernet.arp"
    },
    {
      "packets": 357,
      "data_volume": 307843,
      "payload_volume": 288565,
      "path": "ethernet.ip.tcp.http.craigslist"
    }
  ],
  "protocols": [
    {
      "name": "ethernet",
      "packets": 14261,
      "data_volume": 9216531,
      "payload_volume": 9216531,
      "sessions": 0
    },
    {
      "name": "ip",
      "packets": 14243,
      "data_volume": 9215613,
      "payload_volume": 9016211,
      "sessions": 679
    },
    {
      "name": "tcp",
      "packets": 13708,
      "data_volume": 9135182,
      "payload_volume": 8669110,
      "sessions": 0
    },
    {
      "name": "http",
      "packets": 5287,
      "data_volume": 5967094,
      "payload_volume": 5681596,
      "sessions": 0
    }
  ]
,
  "anomalies": []
}
```

Only the array lengths were changed: `protocol_paths` and `protocols` are cut
to 4 entries each, where the full run emits 37 paths and
28 protocols. Key order, indentation and every value are as the tool
printed them.

Schema notes:

- `version` is an **object** with `mmtreader` (this tool) and `mmt_dpi` (the
  SDK). It was a bare SDK version string until #70 — consumers reading
  `.version` as a string must read `.version.mmt_dpi` instead.
- `protocol_paths` is a **separate top-level array**, not a field inside
  `protocols`, and appears only with `-a/--proto-path`. Path entries carry
  `path`; protocol entries carry `name`.
- `-s/--sessions` adds `ipv4_sessions`, `ipv6_sessions` and `active_sessions` to
  `input_stats`, and a `sessions` key to every `protocols[]` entry. Without it
  none of those four keys are emitted.
- `input_stats` has no `fps` key — the text report's `fps:` line has no JSON
  counterpart. `pps` is spelled `packets_per_sec`, and `duration_seconds` keeps
  two decimals where the text report rounds to whole seconds.
- `anomalies` is always present, empty when nothing was flagged.
- JSON goes to stdout while the banner and progress lines go to stderr, so
  `./mmtReader analyze -t smallFlows.pcap -j 2>/dev/null | jq .` is safe.

---

## Usage Examples

Every `analyze` example below runs verbatim from the repository root against the
repository's own `smallFlows.pcap` and exits 0. The `capture` examples need root
and a real interface — substitute yours for `eth0`.

### Example 1 — Analyze a pcap file with protocol paths

```bash
./mmtReader analyze -t smallFlows.pcap -a
```

### Example 2 — Live capture on eth0 with a custom buffer

```bash
sudo ./mmtReader capture -i eth0 -b 100 -a
# Press Ctrl+C to stop and print statistics
```

### Example 3 — Disable IP classification (faster, less accurate)

```bash
./mmtReader analyze -t smallFlows.pcap -a -x 0
```

### Example 4 — Disable all classification

```bash
./mmtReader analyze -t smallFlows.pcap -a -x 0 -y 0 -z 0
```

### Example 5 — View built-in help

```bash
./mmtReader analyze --help
```

### Example 6 — JSON output with session counts

```bash
./mmtReader analyze -t smallFlows.pcap --json -s
```

### Example 7 — Quiet run, color disabled

```bash
./mmtReader analyze -t smallFlows.pcap -q -C
```

### Example 8 — Capture for 30 seconds and report top flows

```bash
sudo ./mmtReader capture -i eth0 -F 30
```

---

## Environment Variables

| Variable | Values | Description |
|----------|--------|-------------|
| `MMTREADER_JSON` | `0`/`1` | Select JSON (`1`) or text (`0`) output |
| `MMTREADER_NO_COLOR` | `1` | Disable color output (same as `-C/--no-color`) |
| `MMTREADER_QUIET` | `1` | Enable quiet mode (same as `-q/--quiet`) |

```bash
MMTREADER_JSON=1 ./mmtReader analyze -t smallFlows.pcap
```

`MMTREADER_JSON` was inert before issue #96 — it wrote a field no output
decision read. It now selects the output format, as does the `json` config-file
key.

Values are resolved in this order, highest priority first:

1. **CLI flags** — `--json`, `--text`, `-b 100`, `-C`
2. **Environment variables** — the three above
3. **The `-c`/`--config` file**, when one is named
4. **`~/.mmtreader.conf`** — the default config file
5. **Compiled defaults**

---

## Config File Support

MMT-Reader reads an INI-style config file — `~/.mmtreader.conf` by default, or
whatever `-c/--config` names. A missing file is not an error.

```ini
; Global defaults (apply to all commands)
json = 0
quiet = 0
verbose = 0
no_color = 0

; Per-command sections
[analyze]
json = 1

[capture]
quiet = 1
```

```bash
./mmtReader analyze -t smallFlows.pcap -c ~/.mmtreader.conf
```

Two behaviours surprise people, so they are worth stating here:

- **Sections are thinner than they look.** `json`, `quiet`, `verbose` and
  `no_color` share one global slot whichever section they appear in, so
  `json = 1` under `[analyze]` also applies to `capture` — the last value
  parsed wins.
- **Several keys are parsed and then ignored.** `proto_path`, `sessions`,
  `output_format`, `ip_classify`, `hostname_classify`, `port_classify` and a
  per-section `buffer` are read into the config struct and never used. Pass the
  corresponding flag (`-a`, `-s`, `-j`/`-T`, `-x`, `-y`, `-z`, `-b`) instead.

CLI flags always override config file values, and the environment sits between
the two — see *Environment Variables* above.

**[docs/CONFIG.md](CONFIG.md) is the authoritative reference** for the config
file: it lists every key with an *Effective?* column and documents the full
precedence rules.

---

## Troubleshooting

The messages below are the ones the tool actually emits.

All the messages below go to **stderr**, and every usage error exits **2**.

### Missing input

```
$ ./mmtReader analyze
Error: missing --trace file path
Use "./mmtReader --help" for usage information
Use "./mmtReader --help" for usage information
```

`analyze` needs a trace: pass `-t <file>`. The two input flags are gated to
their own subcommand, so `analyze -i` and `capture -t` are each rejected with
exit 2. The `capture` equivalent of the message above is:

```
$ ./mmtReader capture
Error: missing --interface name
Use "./mmtReader --help" for usage information
Use "./mmtReader --help" for usage information
```

### The trace file does not exist

```
$ ./mmtReader analyze -t capture.pcap
Error: file not found: capture.pcap
Use "./mmtReader --help" for usage information
```

`capture.pcap` is a placeholder that does not ship with this repository — the
bundled fixture is `smallFlows.pcap`.

### Bad buffer size

```
$ ./mmtReader analyze -t smallFlows.pcap -b 0
Error: buffer size must be a positive integer (1-10000)
Use "./mmtReader --help" for usage information
```

`-b/--buffer` takes an integer from `1` to `10000` (MB).

### The interface cannot be opened

Two different messages, from two different libpcap stages:

- `[error] Couldn't open device <iface>: <reason>` (`capture.c:199`) — the
  handle could not be created, usually a wrong interface name. List the real
  ones with `ip link show`.
- `[error] Couldn't activate device <iface>: <reason>` (`capture.c:220`) — the
  handle exists but could not be activated. Live capture needs root or
  `CAP_NET_RAW`; unprivileged, the reason reads
  `socket: Operation not permitted`:

```
$ ./mmtReader capture -i nosuchiface0
Enable classification by IP address
Enable classification by Hostname
Enable classification by Port number
INFO: Use default buffer size: 50 (MB)
[error] Couldn't activate device nosuchiface0: socket: Operation not permitted
[error] Creating pcap handle failed
```

### The command printed help instead of analyzing

You omitted the subcommand. `./mmtReader -t smallFlows.pcap -a` exits 0 and
prints the help screen without reading the trace. Use
`./mmtReader analyze -t smallFlows.pcap -a`.

### Dropped packets during live capture

mmtReader does not report kernel or driver drop counts — `pcap_stats()` is never
called, so there is no PCAP-statistics section in the output. If you suspect
loss on a busy link, raise the capture buffer and compare packet totals between
runs:

```bash
sudo ./mmtReader capture -i eth0 -b 200 -a
```

---

## Output Interpretation

- **#volume** is every byte attributed to that protocol (headers + payload)
- **#payload** is the application-layer bytes only
- A protocol appears only if it was actually detected in the traffic
- Protocol paths (`-a`) show the DPI stack in dotted lowercase, so
  `ethernet.ip.tcp.ssl.salesforce` means TLS over TCP over IP over Ethernet,
  classified as Salesforce traffic
- The aggregated table double-counts by design — see *2. Protocol statistics*
