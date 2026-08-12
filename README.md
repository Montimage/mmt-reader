# MMT-Reader

Lightweight CLI tool for deep packet inspection and per-protocol network statistics via MMT-DPI.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-blue)](https://www.linux.org/)
[![Language](https://img.shields.io/badge/language-C-brightgreen.svg)](https://en.wikipedia.org/wiki/C_(programming_language))

MMT-Reader analyzes network traffic from pcap capture files or live network interfaces and produces per-protocol statistics including packet counts, data volume, payload volume, and protocol path hierarchies. It leverages the [MMT-DPI](https://bitbucket.org/montimage/mmt-dpi) library for deep packet inspection and protocol classification.

![MMT-Reader](mmt-reader.png)

## Key Features

- **Subcommand interface** — `analyze` for pcap files, `capture` for live interfaces
- **Dual input modes** — Read from pcap files (offline) or live network interfaces (online)
- **Per-protocol statistics** — Packet count, data volume, and payload volume for every detected protocol
- **Protocol path display** — Full DPI path hierarchy (e.g. `TCP.HTTP.Google`) with the `-a/--proto-path` flag
- **JSON output** — Machine-readable statistics with `--json`
- **Three classification strategies** — IP address (`-x`), hostname (`-y`), and port (`-z`) fingerprinting, each independently toggleable
- **Real-time monitoring** — Live capture with configurable buffer size (`-b`) and kernel/driver drop reporting
- **IPv4 & IPv6 session tracking** — Per-protocol session counts with `-s/--sessions`
- **Config file support** — INI-style `~/.mmtreader.conf` with per-command sections
- **Environment variables** — `MMTREADER_JSON`, `MMTREADER_NO_COLOR`, `MMTREADER_QUIET`
- **Graceful shutdown** — Press Ctrl+C to stop live capture and print final statistics
- **Modular architecture** — Clean separation: engine (core/), CLI parsing (cli/), output rendering (cli/), capture (capture/), config (config/), utilities (utils/)

## Quick Start

```bash
# Build (requires MMT-DPI installed)
make build

# Analyze a pcap file
./mmtReader analyze -t smallFlows.pcap -a

# Monitor a live interface (requires root)
sudo ./mmtReader capture eth0 -a
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
make build
```

### Install Globally

Make `mmtReader` available system-wide with the **self-contained installer** — it installs everything on a fresh machine:

```bash
# Full install: system deps + MMT-DPI + mmtReader (requires root)
sudo ./install.sh

# Install only mmtReader (MMT-DPI must already be present)
sudo ./install.sh --mmt-reader-only

# Custom install prefix (no root needed)
./install.sh --prefix ~/local --mmt-reader-only

# Verify
mmtReader -h
```

The installer handles:
1. **System dependencies** — gcc, make, libpcap-dev, etc.
2. **MMT-DPI library** — builds from the sibling `mmt-dpi/` repo (or uses a pre-built copy)
3. **mmtReader binary** — compiles and installs to your chosen prefix
4. **Man page** — installs to `man1/` for `man mmtReader`
5. **Shell completions** — installs bash completion to `share/bash-completion/completions/`

Alternatively, use **make** (requires MMT-DPI pre-installed):

```bash
make build          # compile
sudo make install   # install to /usr/local
sudo make uninstall # remove
```

## Shell Completions

Install shell completions for tab-completion of subcommands, flags, and file paths.

### Automatic (via installer)

The `install.sh` script and `make install` both install bash completions automatically.

### Manual Installation

**Bash** — copy to your system completions directory:
```bash
sudo cp completions/mmtReader.bash /usr/share/bash-completion/completions/mmtReader
```

Or add to `~/.bashrc`:
```bash
echo 'source "$(dirname "$(readlink -f "$0")")/completions/mmtReader.bash"' >> ~/.bashrc
source ~/.bashrc
```

**Zsh** — copy to your fpath:
```bash
mkdir -p ~/.zsh/completions
cp completions/mmtReader.zsh ~/.zsh/completions/_mmtReader
echo 'fpath+=(~/.zsh/completions)' >> ~/.zshrc
source ~/.zshrc
```

**Fish** — copy to completions directory:
```bash
mkdir -p ~/.config/fish/completions
cp completions/mmtReader.fish ~/.config/fish/completions/mmtReader.fish
```

## Usage

MMT-Reader uses a subcommand-based interface. Available commands:

| Subcommand | Description |
|------------|-------------|
| `analyze` | Analyze a PCAP trace file (offline mode) |
| `capture` | Capture and analyze live network traffic (online mode) |

### Global Options

| Flag | Argument | Default | Description |
|------|----------|---------|-------------|
| `-q, --quiet` | None | 0 | Suppress progress output |
| `-v, --verbose` | None | 0 | Verbose debug output to stderr |
| `-h, --help` | None | — | Print help and exit |
| `-V, --version` | None | — | Print version and exit |
| `-x <0|1>` | `1` = enable, `0` = disable | 1 | IP address classification |
| `-y <0|1>` | `1` = enable, `0` = disable | 1 | Hostname classification |
| `-z <0|1>` | `1` = enable, `0` = disable | 1 | Port number classification |
| `-j, --json` | None | 0 | JSON output format |
| `-T, --text` | None | 0 | Explicit text output (default) |
| `-C, --no-color` | None | 0 | Disable ANSI color output |

> **Note:** `-x`, `-y`, and `-z` are hidden from `--help` but fully functional.

### `analyze` Subcommand

```bash
./mmtReader analyze [OPTIONS]
```

| Flag | Argument | Description |
|------|----------|-------------|
| `-t, --trace <file>` | Path to pcap file | **Required** — analyze a pcap capture file |
| `-b, --buffer <MB>` | Buffer size in MB | For live capture (default: 50) |
| `-a, --proto-path` | None | Show per-protocol-path statistics |
| `-s, --sessions` | None | Show per-protocol session counts |
| `-j, --json` | None | JSON output format |

No root privileges required. Reads and replays traffic deterministically.

### `capture` Subcommand

```bash
./mmtReader capture [OPTIONS] [interface]
```

| Flag | Argument | Description |
|------|----------|-------------|
| `-i, --interface <iface>` | Interface name | Network interface to capture from |
| `interface` (positional) | Interface name | Alternative: `mmtReader capture eth0` |
| `-b, --buffer <MB>` | Buffer size in MB | Pcap handler buffer (default: 50) |
| `-a, --proto-path` | None | Show per-protocol-path statistics |
| `-s, --sessions` | None | Show per-protocol session counts |
| `-j, --json` | None | JSON output format |

Requires root/administrator privileges. Interface must be Ethernet (DLT_EN10MB).

### Usage Examples

```bash
# Analyze a pcap file with protocol paths
./mmtReader analyze -t smallFlows.pcap -a

# Live capture with custom 100 MB buffer
sudo ./mmtReader capture eth0 -b 100 -a

# Disable IP classification (faster, less accurate)
./mmtReader analyze -t capture.pcap -a -x 0

# MMP-only mode (disable all classification)
./mmtReader analyze -t capture.pcap -a -x 0 -y 0 -z 0

# JSON output with session counts
./mmtReader analyze -t capture.pcap --json -s

# Verbose mode with quiet output
./mmtReader analyze -t capture.pcap -v -q
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
├── mmtReader.c        # Thin CLI entry point (~150 lines)
├── mmtReader.1        # Man page
├── Makefile           # Build, install, uninstall targets
├── install.sh         # Self-contained global installer
├── LICENSE            # Apache License 2.0
├── README.md          # This file
├── mmt-reader.png     # Screenshot
├── smallFlows.pcap    # Test pcap
├── CONTRIBUTING.md    # How to contribute
├── CODE_OF_CONDUCT.md # Contributor Covenant v2.1
├── SECURITY.md        # Vulnerability reporting
├── completions/       # Shell completion scripts
│   ├── mmtReader.bash # Bash completion
│   ├── mmtReader.zsh  # Zsh completion
│   └── mmtReader.fish # Fish completion
├── core/
│   ├── engine.c       # MMT-DPI engine: packet processing, stats
│   └── engine.h       # Engine API
├── cli/
│   ├── parse.c/h      # Argument parsing, subcommand dispatch
│   └── output.c/h     # Text/JSON output rendering
├── capture.c/h        # Live pcap capture operations
├── config.c/h         # INI config file support
├── utils/
│   ├── version.c/h    # Version banner and display
│   └── colors.c/h     # ANSI color support
├── tests/
│   ├── test_config.c  # Config file parsing tests
│   ├── test_anomaly.c # Anomaly detection tests
│   ├── test_parse.c   # CLI parsing tests
│   └── test_cli.sh    # Integration tests
└── docs/
    ├── USER_GUIDE.md      # Full CLI reference and examples
    ├── DEVELOPMENT.md     # Build, extend, and debug guide
    ├── ARCHITECTURE.md    # 4-layer architecture diagram
    ├── CHANGELOG.md       # Version history
    ├── CONFIG.md          # Config file reference
    └── TESTING.md         # Test suite guide
```

## Documentation

| Document | Description |
|----------|-------------|
| [USER_GUIDE.md](docs/USER_GUIDE.md) | Full CLI reference, output format, usage examples, and troubleshooting |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | Build instructions, code structure, adding protocol handlers, debugging |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | 4-layer architecture diagram and data flow |
| [CONFIG.md](docs/CONFIG.md) | INI config file reference (`~/.mmtreader.conf`) |
| [TESTING.md](docs/TESTING.md) | Test suite guide and how to run tests |
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
