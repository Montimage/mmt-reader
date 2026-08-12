# MMT-Reader Architecture

MMT-Reader is a single-file C CLI tool that performs deep packet inspection (DPI) using the MMT-DPI library and outputs per-protocol network statistics.

---

## High-Level Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        MMT-Reader                              │
│                                                                 │
│  ┌──────────┐    ┌──────────────────┐    ┌──────────────────┐  │
│  │  INPUT   │───>│  MMT-DPI         │───>│  STATISTICS      │  │
│  │  LAYER   │    │  PROCESSING      │    │  LAYER           │  │
│  │          │    │  LAYER           │    │                  │  │
│  │ • pcap   │    │ • Protocol       │    │ • Per-protocol   │  │
│  │   file   │    │   classification │    │   aggregation    │  │
│  │ • Live   │    │ • Attribute      │    │ • Session tracking│  │
│  │ interface│    │   extraction     │    │ • Bandwidth calc │  │
│  └──────────┘    └──────────────────┘    └────────┬─────────┘  │
│                                                    │             │
│                                            ┌───────▼────────┐  │
│                                            │    OUTPUT      │  │
│                                            │    LAYER       │  │
│                                            │                │  │
│                                            │ • Protocol     │  │
│                                            │   stats table  │  │
│                                            │ • Input summary│  │
│                                            │ • PCAP drops   │  │
│                                            └────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Layer 1 — Input Layer

The input layer provides two modes of traffic ingestion:

### Offline Mode (pcap file)

```c
pcap = pcap_open_offline(filename, mmt_errbuf);
while ((data = pcap_next(pcap, &p_pkthdr))) {
    // Build pkthdr and call packet_process()
}
```

- Opens the pcap file with libpcap
- Reads packets one at a time via `pcap_next()`
- Converts libpcap's `pcap_pkthdr` to MMT's `pkthdr` structure
- Passes raw packet data to the processing layer

**Characteristics:** Deterministic, repeatable, no root required.

### Online Mode (live interface)

```c
pcap = capture_init(iface, buffer_mb, 65535);
pcap_loop(pcap, -1, engine_live_callback, (u_char*)eng);
```

- Creates a pcap handle via `capture_init()` (`capture.c`)
- Sets promiscuous mode (`pcap_set_promisc(my_pcap, 1)`)
- Sets buffer size (default 50 MB, configurable via `-b`)
- Captures with snaplen 65535
- Registers `engine_live_callback` for `pcap_loop()`

**Characteristics:** Real-time, requires root/admin privileges, Ethernet-only (DLT_EN10MB check).

---

## Layer 2 — MMT-DPI Processing Layer

This layer delegates the heavy lifting to the MMT-DPI library (`libmmt_core`).

### Initialization

```c
init_extraction();
mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
```

- `init_extraction()` — Initializes the MMT-DPI extraction framework
- `mmt_init_handler()` — Creates the main DPI handler with Ethernet link type

### Classification Configuration

```c
enable_ip_address_classify(mmt_handler);   // -x 1 (default)
enable_hostname_classify(mmt_handler);     // -y 1 (default)
enable_port_classify(mmt_handler);         // -z 1 (default)
```

Three classification strategies can be independently enabled/disabled:
1. **IP address classification** — Fingerprinting based on source/destination IP
2. **Hostname classification** — Fingerprinting based on SNI/hostname
3. **Port classification** — Fingerprinting based on port numbers

### Attribute Registration

```c
iterate_through_protocols(protocols_iterator, mmt_handler);
```

Iterates all known protocols and registers their attributes for extraction via `register_extraction_attribute()`. This tells MMT-DPI which fields to pull from each packet.

### Packet Processing

```c
engine_process_packet(eng, &header, data);
```

The core DPI call. `engine_process_packet()` (`core/engine.c`) delegates to MMT-DPI which analyzes the packet, classifies protocols, extracts attributes, and triggers registered callbacks.

### Callbacks

| Callback | Module | Trigger | Purpose |
|----------|--------|---------|---------|
| `packet_handler` | core/engine.c | Every processed packet | Updates global counters (packets, data volume, timestamps) |
| `new_ipv4_session_handler` | core/engine.c | New IPv4 session created | Increments `nb_ipv4_sessions` |
| `new_ipv6_session_handler` | core/engine.c | New IPv6 session created | Increments `nb_ipv6_sessions` |
| `engine_live_callback` | core/engine.c | Every raw packet (online) | Converts raw pcap packet to MMT format and calls `engine_process_packet()` |

---

## Layer 3 — Statistics Layer

The statistics layer aggregates and ranks protocol data.

### Per-Protocol Statistics

```c
engine_print_stats_ex(eng, stdout, OUTPUT_FORMAT_TEXT, show_sessions);
```

For each protocol (inside `cli/output.c`):
1. Gets `proto_statistics_t` via `get_protocol_stats()`
2. Accumulates `packets_count`, `data_volume`, `payload_volume`
3. If `-a` is set, retrieves and formats the protocol path hierarchy
4. Creates a `proto_info_t` node and inserts it into a sorted linked list

### Sorted Linked List

Protocols are stored in a singly-linked list (`proto_info_t`) sorted by packet count descending:

```c
insert_proto_info(p_info);
// Comparison: p_info->pkts > current->pkts → insert before
```

This produces a ranked output: highest-traffic protocols first.

### Aggregate Statistics

Computed in `engine_print_stats_ex()` (`cli/output.c`):

| Metric | Formula |
|--------|---------|
| Duration | `end_time - init_time` (seconds) |
| Bandwidth | `data_volume / duration` (bytes/sec) |
| pps | `nb_packets / duration` (packets/sec) |
| fps | `(nb_ipv4_sessions + nb_ipv6_sessions) / duration` (sessions/sec) |

---

## Layer 4 — Output Layer

The output layer formats and prints the final report.

### Output Sequence

1. **Banner** — MMT-SDK version, build date, Montimage branding (`utils/version.c`)
2. **Protocol stats (with path)** — If `-a` is set, prints per-path breakdown (`cli/output.c`)
3. **Protocol stats (aggregated)** — Sorted by packet count, prints per-protocol totals (`cli/output.c`)
4. **Input statistics** — Summary: packets, data, sessions, protocols, duration, bandwidth, pps, fps (`cli/output.c`)
5. **PCAP statistics** — Kernel/driver drop counts (online mode only) (`core/engine.c`)

### JSON Output

When `--json` is used, `cli/output.c` renders the same statistics as structured JSON to stdout, while banner and debug messages go to stderr.

### Signal Handling

```c
signal(SIGINT, signal_handler);
```

Ctrl+C triggers `signal_handler()`, which calls `clean()`:
1. Print statistics (same as normal exit)
2. Close MMT handler (`mmt_close_handler`)
3. Close extraction framework (`close_extraction`)
4. Print PCAP drop stats
5. Close pcap handle (`pcap_close`)

The `cleaned` guard prevents double-cleanup.

---

## Data Flow Summary

```
[pcap file / network interface]
        │
        ▼
  mmtReader.c (entry point)
  ├── pcap_open_offline() / capture_init()
        │
        ▼
  core/engine.c
  ├── engine_process_packet() — MMT-DPI classification + extraction
  ├── packet_handler() — update counters
  ├── new_ipv4_session_handler() — count sessions
  └── new_ipv6_session_handler() — count sessions
        │
        ▼
  core/engine.c (stats aggregation)
  ├── get_protocol_stats() — per-instance stats
  ├── proto_hierarchy_ids_to_str() — path formatting
  └── insert_proto_info() — sorted linked list
        │
        ▼
  cli/output.c
  ├── output_print_stats_ex() — format and print (TEXT or JSON)
  └── engine_print_pcap_stats() — drop counts
        │
        ▼
  engine_destroy() — cleanup resources
```

---

## External Dependencies

| Library | Role |
|---------|------|
| **MMT-DPI (libmmt_core)** | Core DPI engine: protocol classification, attribute extraction, protocol statistics |
| **libpcap** | Packet capture: file reading (`pcap_open_offline`) and live capture (`pcap_create`, `pcap_loop`) |
| **libdl** | Dynamic symbol loading (required by MMT-DPI) |
