# MMT-Reader

Lightweight CLI tool for deep packet inspection and per-protocol network statistics via MMT-DPI.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-blue)](https://www.linux.org/)
[![Language](https://img.shields.io/badge/language-C-brightgreen.svg)](https://en.wikipedia.org/wiki/C_(programming_language))

MMT-Reader analyzes network traffic from pcap capture files or live network interfaces and produces per-protocol statistics including packet counts, data volume, payload volume, and protocol path hierarchies. It leverages the [MMT-DPI](https://bitbucket.org/montimage/mmt-dpi) library for deep packet inspection and protocol classification.

![MMT-Reader](mmt-reader.png)

## Key Features

- **Dual input modes** — Read from pcap files (offline) or live network interfaces (online)
- **Per-protocol statistics** — Packet count, data volume, and payload volume for every detected protocol
- **Protocol path display** — Full DPI path hierarchy (e.g. `TCP.HTTP.Google`) with the `-a` flag
- **Three classification strategies** — IP address (`-x`), hostname (`-y`), and port (`-z`) fingerprinting, each independently toggleable
- **Real-time monitoring** — Live capture with configurable buffer size (`-b`) and kernel/driver drop reporting
- **IPv4 & IPv6 session tracking** — Automatic session counting for both address families
- **Graceful shutdown** — Press Ctrl+C to stop live capture and print final statistics
- **Single-file, zero-dependency on project** — All logic in one C source file; only system libraries required

## Quick Start

```bash
# Compile (see Installation below for dependencies)
gcc -g -o mmtReader mmtReader.c \
    -I /opt/mmt/dpi/include \
    -L /opt/mmt/dpi/lib \
    -lmmt_core -ldl -lpcap

# Analyze a pcap file
./mmtReader -t smallFlows.pcap -a

# Monitor a live interface (requires root)
sudo ./mmtReader -i eth0 -a
```

## Installation

### System Dependencies

**Debian / Ubuntu:**

```bash
sudo apt-get update
sudo apt-get install -y build-essential gcc g++ make libpcap-dev libconfuse-dev
```

**RHEL / CentOS / Fedora:**

```bash
sudo yum group install "Development Tools"
sudo yum install libpcap-devel
```

### MMT-DPI Library

MMT-Reader requires the [MMT-DPI](https://bitbucket.org/montimage/mmt-dpi) library installed at `/opt/mmt/dpi/`:

```
/opt/mmt/dpi/
├── include/
│   ├── mmt_core.h
│   └── tcpip/
│       └── mmt_tcpip.h
└── lib/
    ├── libmmt_core.so
```

Install MMT-DPI following the upstream instructions before compiling.

### Compile

```bash
gcc -g -o mmtReader mmtReader.c \
    -I /opt/mmt/dpi/include \
    -L /opt/mmt/dpi/lib \
    -lmmt_core -ldl -lpcap
```

## Usage

### Offline Mode (pcap file)

```bash
./mmtReader -t <path_to_pcap_file> [OPTIONS]
```

No root privileges required. Reads and replays traffic deterministically.

### Online Mode (live interface)

```bash
sudo ./mmtReader -i <interface_name> [OPTIONS]
```

Requires root/administrator privileges. Interface must be Ethernet (DLT_EN10MB).

### CLI Options Reference

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `-t <file>` | Path to pcap file | — | **Offline mode** — analyze a pcap capture file |
| `-i <iface>` | Interface name (e.g. `eth0`) | — | **Online mode** — live traffic capture |
| `-b <MB>` | Buffer size in MB | 50 | Pcap handler buffer for live capture |
| `-a` | None | off | Show per-protocol-path statistics |
| `-x <0|1>` | `1` = enable, `0` = disable | 1 | IP address classification |
| `-y <0|1>` | `1` = enable, `0` = disable | 1 | Hostname classification |
| `-z <0|1>` | `1` = enable, `0` = disable | 1 | Port number classification |
| `-h` | None | — | Print help and exit |

> **Note:** `-x`, `-y`, and `-z` are undocumented in the built-in `-h` help but are fully functional.

### Usage Examples

```bash
# Analyze a pcap file with protocol paths
./mmtReader -t smallFlows.pcap -a

# Live capture with custom 100 MB buffer
sudo ./mmtReader -i eth0 -b 100 -a

# Disable IP classification (faster, less accurate)
./mmtReader -t capture.pcap -a -x 0

# MMP-only mode (disable all classification)
./mmtReader -t capture.pcap -a -x 0 -y 0 -z 0
```

### Output Format

MMT-Reader prints four sections at the end of execution:

1. **Protocol statistics with path** (if `-a` is set) — per-path breakdown of packets, volume, and payload
2. **Protocol statistics (aggregated)** — per-protocol totals sorted by packet count
3. **Input statistics** — summary: packets, data volume, sessions, protocols, duration, bandwidth, pps, fps
4. **PCAP statistics** (online mode only) — received packets and kernel/driver drop counts

## Project Structure

```
mmtReader/
├── mmtReader.c        # Single source file (~530 lines)
├── LICENSE            # Apache License 2.0
├── README.md          # This file
├── mmt-reader.png     # Screenshot
├── smallFlows.pcap    # Test pcap (if bundled)
├── CONTRIBUTING.md    # How to contribute
├── CODE_OF_CONDUCT.md # Contributor Covenant v2.1
├── SECURITY.md        # Vulnerability reporting
└── docs/
    ├── USER_GUIDE.md      # Full CLI reference and examples
    ├── DEVELOPMENT.md     # Build, extend, and debug guide
    ├── ARCHITECTURE.md    # 4-layer architecture diagram
    └── CHANGELOG.md       # Version history
```

## Documentation

| Document | Description |
|----------|-------------|
| [USER_GUIDE.md](docs/USER_GUIDE.md) | Full CLI reference, output format, usage examples, and troubleshooting |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | Build instructions, code structure, adding protocol handlers, debugging |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | 4-layer architecture diagram and data flow |
| [CHANGELOG.md](docs/CHANGELOG.md) | Version history and release notes |

## Related Publications

> _To be filled in step 5 with links to papers, presentations, or blog posts about MMT-DPI and MMT-Reader._

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting bugs, submitting feature requests, and code style conventions.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

## Acknowledgments

- **[MMT-DPI](https://bitbucket.org/montimage/mmt-dpi)** — Deep packet inspection library providing protocol classification and attribute extraction
- **libpcap** — Portable packet capture library
- **Montimage** — Original author and maintainer

For questions or support, contact: [contact@montimage.com](mailto:contact@montimage.com)
