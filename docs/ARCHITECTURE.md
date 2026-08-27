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
capture_set_processor(engine_process_packet_cb, eng);
pcap_loop(pcap, -1, capture_callback, NULL);
```

- Creates a pcap handle via `capture_init()` (`capture.c`)
- Sets promiscuous mode (`pcap_set_promisc(my_pcap, 1)`)
- Sets buffer size (default 50 MB, configurable via `-b`)
- Captures with snaplen 65535
- Registers `capture_callback` for `pcap_loop()`; it converts each
  libpcap header to MMT format and dispatches to
  `engine_process_packet_cb()` (`core/engine.c`)

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
register_extraction_attribute(mmt, PROTO_IP, IP_CLIENT_ADDR);
```

Attributes are registered only where a report needs them. `flows.c` registers the session endpoints (client/server address and port, for IPv4 and IPv6) when `-F` is used; the protocol tables need no attributes at all, since they read MMT-DPI's protocol statistics directly.

### Packet Processing

```c
engine_process_packet(eng, &header, data);
```

The core DPI call. `engine_process_packet()` (`core/engine.c`) delegates to MMT-DPI which analyzes the packet, classifies protocols, extracts attributes, and triggers registered callbacks.

### Callbacks

| Callback | Module | Trigger | Purpose |
|----------|--------|---------|---------|
| `engine_process_packet_cb` | core/engine.c | Every captured frame (online) | Records the packet in the capture window, then hands it to MMT-DPI |
| `flows_packet_handler` | flows.c | Every processed packet, when `-F` is used | Records the packet's DPI session for the top-talker report |

Packet, session and volume counters are **not** maintained here: MMT-DPI keeps them, and `engine_get_stats()` reads them back (see below).

---

## Layer 3 — Statistics Layer

The statistics layer aggregates and ranks protocol data.

### Per-Protocol Statistics

```c
engine_print_stats_ex(eng, stdout, output_format, show_sessions);
```

The summary is printed by whichever call site wants it — `engine_destroy()`
performs no output, so freeing the engine has no effect on stdout.

For each protocol (inside `cli/output.c`):
1. Gets `proto_statistics_t` via `get_protocol_stats()` — one instance per protocol path
2. Accumulates `packets_count`, `data_volume`, `payload_volume`, `sessions_count`
3. If `-a` is set, formats the path with MMT-DPI's `proto_hierarchy_to_str()`
4. Creates a `proto_info_t` node and inserts it into a sorted linked list

### Whole-capture Statistics

`engine_get_stats()` (`core/engine.c`) reads the totals back from MMT-DPI rather than counting in parallel:

| Field | Source |
|-------|--------|
| `data_volume` | `get_protocol_stats(mmt, PROTO_META)` — the root of every protocol path |
| `nb_ipv4_sessions` / `nb_ipv6_sessions` | `sessions_count` of `PROTO_IP` / `PROTO_IPV6` |
| `nb_active_sessions` | `get_active_session_count()` |
| `nb_protocols` | Protocols with a touched statistics instance, via `iterate_through_protocols()` |
| `nb_packets`, `init_time`, `end_time` | The input loop — what was read from the file or interface |

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

1. **Banner** — mmtReader product version, MMT-DPI SDK version, build date, Montimage branding (`utils/version.c`)
2. **Protocol stats (with path)** — If `-a` is set, prints per-path breakdown (`cli/output.c`)
3. **Protocol stats (aggregated)** — Sorted by packet count, prints per-protocol totals (`cli/output.c`)
4. **Input statistics** — Summary: packets, data, sessions, protocols, duration, bandwidth, pps, fps (`cli/output.c`)
5. **PCAP statistics** — Kernel/driver drop counts (online mode only) (`core/engine.c`)

### JSON Output

When `--json` is used, `cli/output.c` renders the same statistics as structured JSON to stdout, while banner and debug messages go to stderr.

### Signal Handling

```c
struct sigaction sa;
memset(&sa, 0, sizeof(sa));
sa.sa_handler = signal_handler;
sigemptyset(&sa.sa_mask);
sigaction(SIGINT, &sa, NULL);
sigaction(SIGTERM, &sa, NULL);
```

Ctrl+C (`SIGINT`) and `SIGTERM` (systemd stop, plain `kill`) share the
same async-safe handler. It sets a flag and breaks `pcap_loop`, so the
run ends through the normal shutdown path:

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
  └── flows.c: flows_packet_handler() — record the session (-F only)
        │
        ▼
  core/engine.c (stats aggregation)
  ├── engine_get_stats() — totals read back from MMT-DPI
  ├── get_protocol_stats() — per-instance stats
  ├── proto_hierarchy_to_str() — path formatting (MMT-DPI)
  └── proto_info_insert() — sorted linked list
        │
        ▼
  cli/output.c
  └── output_print_stats_ex() — format and print (TEXT or JSON)
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
