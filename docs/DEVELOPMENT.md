# MMT-Reader Development Guide

This document covers everything needed to build, extend, and maintain MMT-Reader.

---

## Prerequisites

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

Required packages:
- **build-essential / Development Tools** — `gcc`, `g++`, `make`
- **libpcap-dev / libpcap-devel** — libpcap headers and library for packet capture
- **libconfuse-dev** — configuration parsing library (linked via `-lconfuse`)

### MMT-DPI Library

MMT-Reader depends on the [MMT-DPI](https://bitbucket.org/montimage/mmt-dpi) library, which must be installed at `/opt/mmt/dpi/`:

```
/opt/mmt/dpi/
├── include/
│   ├── mmt_core.h
│   └── tcpip/
│       └── mmt_tcpip.h
└── lib/
    ├── libmmt_core.so
    └── (other MMT libraries)
```

Install MMT-DPI following the upstream instructions before compiling MMT-Reader.

---

## Build

### Compile Command

```bash
gcc -g -o mmtReader mmtReader.c \
    -I /opt/mmt/dpi/include \
    -L /opt/mmt/dpi/lib \
    -lmmt_core -ldl -lpcap
```

**Flag explanation:**

| Flag | Meaning |
|------|---------|
| `-g` | Include debug symbols (useful with `gdb`) |
| `-o mmtReader` | Output binary name |
| `-I /opt/mmt/dpi/include` | MMT-DPI header path |
| `-L /opt/mmt/dpi/lib` | MMT-DPI library path |
| `-lmmt_core` | Link against libmmt_core |
| `-ldl` | Dynamic loading (required by MMT-DPI) |
| `-lpcap` | Packet capture library |

### Build Verification

```bash
# Compile
gcc -g -o mmtReader mmtReader.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap

# Verify the binary
file mmtReader

# Run with the bundled test pcap (if available)
./mmtReader -t smallFlows.pcap -a

# Check help
./mmtReader -h
```

Expected output: A banner showing MMT-SDK version, build date/time, and a stats table after processing.

---

## Code Structure

MMT-Reader is a single-file C application (`mmtReader.c`, ~530 lines). The execution flow:

```
main()
  ├── parseOptions()          — Parse CLI arguments (-t, -i, -b, -a, -x, -y, -z, -h)
  ├── init_extraction()       — Initialize MMT-DPI extraction framework
  ├── mmt_init_handler()      — Create MMT handler with DLT_EN10MB
  ├── enable/disable_*_classify()  — Configure classification modes
  ├── iterate_through_protocols() — Register all protocol attributes for extraction
  ├── register_packet_handler()   — Register packet callback
  ├── register_attribute_handler() — Register session callbacks (IPv4/IPv6)
  ├── sigfillset() + signal()   — Install SIGINT handler for clean shutdown
  ├── if (TRACE_FILE):
  │     └── pcap_open_offline() + pcap_next() loop  — Offline mode
  ├── else if (LIVE_INTERFACE):
  │     └── init_pcap() + pcap_loop() + live_capture_callback()  — Online mode
  └── clean()
        ├── mmt_reader_stats()    — Print statistics
        ├── mmt_close_handler()   — Close MMT handler
        ├── close_extraction()    — Close extraction framework
        ├── pcap_stats()          — Print kernel drop stats
        └── pcap_close()          — Close pcap handle
```

### Key Global Variables

| Variable | Type | Purpose |
|----------|------|---------|
| `mmt_handler` | `mmt_handler_t*` | MMT-DPI handler instance |
| `pcap` | `pcap_t*` | libpcap handle |
| `nb_packets` | `uint64_t` | Total packet count |
| `nb_ipv4_sessions` / `nb_ipv6_sessions` | `uint64_t` | Session counters |
| `nb_protocols` | `uint64_t` | Distinct protocol count |
| `data_volume` | `uint64_t` | Total bytes processed |
| `proto_path_detail` | `int` | Toggle protocol path display (`-a`) |
| `ip_address_classify` / `hostname_classify` / `port_classify` | `int` | Classification toggles (`-x`, `-y`, `-z`) |

---

## Adding a New Protocol Handler

MMT-Reader uses the MMT-DPI callback registration pattern. To add processing for a new protocol or attribute:

### 1. Register a packet handler

```c
register_packet_handler(mmt_handler, 1, my_packet_handler, NULL);
```

### 2. Register an attribute handler for new sessions

```c
register_attribute_handler(mmt_handler, PROTO_IP, PROTO_SESSION,
                          my_session_handler, NULL, NULL);
```

### 3. Implement the callback

```c
void my_session_handler(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    // Process the new session
}
```

### 4. Register attributes for extraction

The `protocols_iterator` → `attributes_iterator` chain automatically registers all attributes. To add custom extraction:

```c
register_extraction_attribute(args, proto_id, attribute->id);
```

### 5. Access extracted data in handlers

```c
uint64_t *value = (uint64_t *)get_attribute_extracted_data(ipacket, PROTO_ID, ATTRIBUTE_ID);
if (value != NULL) {
    // Use *value
}
```

---

## Coding Conventions

- **Single file:** All code lives in `mmtReader.c`. No header files are used.
- **Naming:** `snake_case` for functions and variables, `UPPER_SNAKE_CASE` for macros.
- **Error handling:** `fprintf(stderr, ...)` followed by `exit()` for fatal errors; return codes for recoverable errors.
- **Memory:** `malloc`/`free` used in the protocol statistics linked list (`proto_info_t`). No memory leak handling beyond cleanup in `clean()`.
- **Signals:** `SIGINT` is caught to ensure clean statistics output and resource cleanup before exit.

---

## Debugging

### With GDB

```bash
gcc -g -o mmtReader mmtReader.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
gdb ./mmtReader
(gdb) run -t smallFlows.pcap -a
(gdb) bt          # Backtrace on crash
(gdb) print nb_packets  # Inspect variables
```

### Enable MMT-DPI Debug

Set environment variables or compile flags as documented in the MMT-DPI repository.

---

## Testing

The simplest test is to run against a known pcap file:

```bash
./mmtReader -t smallFlows.pcap -a
```

For live testing, use a loopback or dedicated test interface:

```bash
sudo ./mmtReader -i lo -a
```

---

## Project Layout

```
mmtReader/
├── mmtReader.c        # Single source file (~530 lines)
├── LICENSE            # Apache 2.0
├── README.md          # Quick start
├── docs/
│   ├── USER_GUIDE.md  # This file's companion — user-facing docs
│   ├── DEVELOPMENT.md # You are here
│   ├── ARCHITECTURE.md
│   └── CHANGELOG.md
└── smallFlows.pcap    # Test pcap (if bundled)
```
