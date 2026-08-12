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

```
./mmtReader [OPTION]
```

The tool requires exactly one input source: either `-t` for a pcap file or `-i` for a live interface. All other options are optional modifiers.

### Input Options

| Flag | Argument | Description |
|------|----------|-------------|
| `-t <file>` | Path to a pcap file | **Offline mode** — reads and replays traffic from the given pcap file. No root privileges required. |
| `-i <iface>` | Network interface name (e.g. `eth0`, `enp3s0`) | **Online mode** — captures traffic live from the specified interface. Requires root/administrator privileges. Interface must be Ethernet (DLT_EN10MB). |

### Modifier Options

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `-a` | None | `0` (off) | Show per-protocol-path statistics. When enabled, each protocol entry includes its full DPI path (e.g. `TCP.HTTP.Google`). |
| `-b <value>` | Buffer size in MB | `50` | Set the pcap handler buffer size for live capture. Only meaningful in online mode (`-i`). |
| `-x <0\|1>` | `1` = enable, `0` = disable | `1` (on) | Enable or disable IP address classification. `0` disables IP-based fingerprinting. |
| `-y <0\|1>` | `1` = enable, `0` = disable | `1` (on) | Enable or disable hostname classification. `0` disables SNI/hostname-based fingerprinting. |
| `-z <0\|1>` | `1` = enable, `0` = disable | `1` (on) | Enable or disable port number classification. `0` disables port-based fingerprinting. |
| `-h` | None | — | Print help message and exit. |

> **Note:** `-x`, `-y`, and `-z` are undocumented in the built-in `-h` help. They accept `1` (enable) or `0` (disable).

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
- **Sessions** — Combined IPv4 + IPv4 session count
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
./mmtReader -h
```

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
