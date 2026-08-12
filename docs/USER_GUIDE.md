# MMT-Reader User Guide

MMT-Reader is a lightweight CLI tool that analyzes network traffic and produces per-protocol statistics. It reads traffic from either a pcap capture file (offline mode) or a live network interface (online mode) and leverages the [MMT-DPI](https://bitbucket.org/montimage/mmt-dpi) library for deep packet inspection and protocol classification.

---

## Quick Start

```bash
# Offline mode — analyze a pcap file
./mmtReader -t capture.pcap -a

# Online mode — monitor a live interface (requires root)
sudo ./mmtReader -i eth0 -a
```

---

## Usage

MMT-Reader uses a **subcommand-based** interface. Available commands:

| Subcommand | Description |
|------------|-------------|
| `analyze` | Analyze a PCAP trace file (offline mode) |
| `capture` | Capture and analyze live network traffic (online mode) |

```
mmtReader <command> [OPTIONS]
```

### Global Options

These options are available with any subcommand:

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `-q, --quiet` | None | `0` | Suppress progress output. Only final results are shown. |
| `-v, --verbose` | None | `0` | Verbose debug output to stderr (does not affect stdout). |
| `-h, --help` | None | — | Print help for the current command and exit. |
| `-V, --version` | None | — | Print version information and exit. |
| `-x <0\|1>` | `1` = enable, `0` = disable | `1` | IP address classification. |
| `-y <0\|1>` | `1` = enable, `0` = disable | `1` | Hostname classification. |
| `-z <0\|1>` | `1` = enable, `0` = disable | `1` | Port number classification. |
| `-j, --json` | None | `0` | Output statistics in JSON format. |
| `-T, --text` | None | `0` | Explicitly set text output format (default). |
| `-C, --no-color` | None | `0` | Disable ANSI color output. |

> **Note:** `-x`, `-y`, and `-z` are hidden from `--help` but fully functional. They accept `1` (enable) or `0` (disable).

### `analyze` Subcommand

```bash
mmtReader analyze [OPTIONS]
```

| Flag | Argument | Description |
|------|----------|-------------|
| `-t, --trace <file>` | Path to pcap file | **Required** — analyze a pcap capture file. No root privileges required. |
| `-b, --buffer <MB>` | Buffer size in MB | For live capture (default: 50). |
| `-a, --proto-path` | None | Show per-protocol-path statistics (e.g., `TCP.HTTP.Google`). |
| `-s, --sessions` | None | Show per-protocol session counts. |
| `-j, --json` | None | Output statistics in JSON format. |

### `capture` Subcommand

```bash
mmtReader capture [OPTIONS] [interface]
```

| Flag | Argument | Description |
|------|----------|-------------|
| `-i, --interface <iface>` | Interface name | Network interface to capture from. |
| `interface` (positional) | Interface name | Alternative: `mmtReader capture eth0`. |
| `-b, --buffer <MB>` | Buffer size in MB | Pcap handler buffer (default: 50). |
| `-a, --proto-path` | None | Show per-protocol-path statistics. |
| `-s, --sessions` | None | Show per-protocol session counts. |
| `-j, --json` | None | Output statistics in JSON format. |

Requires root/administrator privileges. Interface must be Ethernet (DLT_EN10MB).

---

## Output Format

MMT-Reader produces a structured statistics report at the end of execution (or when interrupted with Ctrl+C). The output consists of four sections:

### 1. Protocol Statistics (with path, if `-a` is used)

```
Protocol statistics with the protocol path:

       #pkts     #volume    #payload                          #proto_path
     123456     12345678      9876543                          TCP.HTTP.Google
      98765      8765432      7654321                              TCP.HTTP.Facebook
```

Columns:
- **#pkts** — Total packets matching this protocol/path
- **#volume** — Total data volume (bytes)
- **#payload** — Total payload volume (bytes, excluding headers)
- **#proto_path** — Full DPI path hierarchy (only with `-a`)

### 2. Protocol Statistics (aggregated)

```
Protocol statistics:

       #pkts     #volume    #payload                   #proto_name
     123456     12345678      9876543                         TCP.HTTP
      98765      8765432      7654321                                TCP
```

Aggregated per top-level protocol name, sorted by packet count (descending).

### 3. Input Statistics

```
>>>>>> INPUT STATISTICS <<<<<<

        Input: capture.pcap
      Packets: 500000
         Data: 1234567890 bytes
     Sessions: 12345
    Protocols: 23
     Duration: 300 seconds
    Bandwidth: 4115226.30 bytes/second
        pps: 1666.67 packets/second
        fps: 41.13 sessions/second
```

Metrics:
- **Input** — The source file or interface name
- **Packets** — Total packets processed by MMT-DPI
- **Data** — Total data volume in bytes
- **Sessions** — Combined IPv4 + IPv6 session count
- **Protocols** — Number of distinct protocols detected
- **Duration** — Analysis window in seconds (first packet to last packet)
- **Bandwidth** — Average bytes/second over the analysis window
- **pps** — Packets per second
- **fps** — Sessions per second

### 4. PCAP Statistics (online mode only)

```
>>>> PCAP STATISTICS <<<<

         500000 Received
              0 Dropped by kernel ( 0.00%)
              0 Dropped by driver ( 0.00%)
```

Kernel and driver drop counts for live capture.

### JSON Output

With `--json`, the statistics are output as structured JSON to stdout:

```json
{
  "protocols": [
    {
      "name": "TCP",
      "path": "TCP.HTTP.Google",
      "packets": 123456,
      "data_volume": 12345678,
      "payload_volume": 9876543,
      "sessions": 1234
    }
  ],
  "input_stats": {
    "packets": 500000,
    "data_volume": 1234567890,
    "sessions": 12345,
    "protocols": 23,
    "duration": 300,
    "bandwidth": 4115226.30,
    "pps": 1666.67,
    "fps": 41.13
  }
}
```

JSON output keeps stdout clean — banner and debug messages go to stderr.

---

## Usage Examples

### Example 1 — Analyze a pcap file with protocol paths

```bash
./mmtReader -t smallFlows.pcap -a
```

### Example 2 — Live capture on eth0 with custom buffer

```bash
sudo ./mmtReader -i eth0 -b 100 -a
# Press Ctrl+C to stop and print statistics
```

### Example 3 — Disable IP classification (faster, less accurate)

```bash
./mmtReader -t capture.pcap -a -x 0
```

### Example 4 — Disable all classification (MMP-only mode)

```bash
./mmtReader -t capture.pcap -a -x 0 -y 0 -z 0
```

### Example 5 — View built-in help

```bash
./mmtReader analyze --help
```

### Example 6 — JSON output with session counts

```bash
./mmtReader analyze -t capture.pcap --json -s
```

### Example 7 — Verbose mode with quiet output

```bash
./mmtReader analyze -t capture.pcap -v -q
```

---

## Environment Variables

The following environment variables can override defaults (CLI flags take precedence):

| Variable | Values | Description |
|----------|--------|-------------|
| `MMTREADER_JSON` | `1` | Force JSON output mode |
| `MMTREADER_NO_COLOR` | `1` | Disable color output (same as `--no-color`) |
| `MMTREADER_QUIET` | `1` | Enable quiet mode (same as `--quiet`) |

---

## Config File Support

MMT-Reader supports an INI-style configuration file (`~/.mmtreader.conf`) that sets defaults for each command section.

### Config File Format

```ini
# Global defaults (applied to all commands)
json = 0
quiet = 0
verbose = 0
no_color = 0
ip_classify = 1
hostname_classify = 1
port_classify = 1

# Per-command overrides
[analyze]
json = 1
buffer = 50
proto_path = 0
sessions = 0

[capture]
json = 0
quiet = 1
verbose = 0
buffer = 100
```

### Config File Behavior

- Options before any section header apply globally
- `[analyze]` and `[capture]` sections override global defaults for those commands
- **CLI flags always override config file values**
- If the file does not exist, no error is raised (config loading is optional)
- Use `--config <path>` to specify a custom config file location

---

## Troubleshooting

### "is not an Ethernet" error

```
[error] eth0 is not an Ethernet (Make sure you run with administrator permission! )
```

The tool requires an Ethernet-type interface (DLT_EN10MB). This typically means:
- You did not run with `sudo` / root privileges
- The interface is not Ethernet (e.g., a tunnel or virtual interface)

**Fix:** Run with `sudo` and ensure the interface is a physical or bridged Ethernet device.

### "Couldn't open device" error

```
[error] Couldn't open device <errbuf>
```

The interface name is incorrect or the interface does not exist.

**Fix:** List available interfaces with `ip link show` or `ifconfig` and use the correct name.

### "Missing trace file name" / "Missing network interface name"

You specified `-t` or `-i` without a following argument.

**Fix:** Provide the required argument, e.g., `./mmtReader -t file.pcap`.

### High kernel drop rate in online mode

If the PCAP statistics show a high drop percentage, increase the buffer size:

```bash
sudo ./mmtReader -i eth0 -b 200 -a
```

---

## Output Interpretation

- **#volume** includes all bytes in the protocol payload (headers + application data)
- **#payload** is the application-layer data only (headers stripped)
- A protocol appears in the output only if it was actually detected in the traffic
- Protocol paths (with `-a`) show the DPI stack, e.g., `TCP.HTTP.Google` means TCP carried HTTP which was classified as Google traffic
