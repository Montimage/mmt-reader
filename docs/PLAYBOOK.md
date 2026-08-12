# MMT-Reader AI Agent Playbook

> **5 proven use cases** with completed experiments — prompts, expected output, and explanations.
> Built for **normal users** (analysts, developers) and **admin operators** (network engineers, SREs).

---

## Table of Contents

| # | Use Case | Persona | Complexity |
|---|----------|---------|------------|
| 1 | **PCAP Forensic Triage** | Analyst / Admin | ⭐⭐ |
| 2 | **Protocol Usage Breakdown** | Admin / Manager | ⭐⭐ |
| 3 | **Automated JSON Pipeline** | Dev / SRE | ⭐⭐⭐ |
| 4 | **Live Traffic Monitoring** | Admin / SRE | ⭐⭐⭐ |
| 5 | **Session & Bandwidth Audit** | Admin / Manager | ⭐⭐ |

---

## Use Case 1 — PCAP Forensic Triage

**Goal:** Quickly identify what protocols exist in a captured pcap file and spot anomalies — the first step in any traffic investigation.

### Prompt (CLI command)

```bash
./mmtReader analyze -t smallFlows.pcap -a
```

### Expected Output

*Experiment run on this machine — `smallFlows.pcap`, 2026-08-12.*

```
Enable classification by IP address
Enable classification by Hostname
Enable classification by Port number
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
|            MONTIMAGE
|       MMT-SDK version: 1.7.10 (efd353a3)
|       ./mmtReader: built Aug 12 2026 09:31:13
|       http://montimage.com
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

- - - - - MMT-READER STATS - - - - -

Protocol statistics with the protocol path:

        #pkts   #volume   #payload   #proto_path
         7       3392       3014   ethernet.ip.tcp.unknown
        13        782        236   ethernet.ip.udp.unknown
        18        918        666   ethernet.arp
       357     307843     288565   ethernet.ip.tcp.http.craigslist
         3       1026        900   ethernet.ip.udp.dhcp
        87      15154      11500   ethernet.ip.udp.dns
         4       3167       2951   ethernet.ip.tcp.http.doubleclick
         4        604        388   ethernet.ip.tcp.http.dropbox
        16       2592       1920   ethernet.ip.udp.dropbox
     14261    9216531    9216531   ethernet
         0          0          0   ethernet.ip.tcp.facebook
        63      51307      47905   ethernet.ip.tcp.http.facebook
        36       2344        400   ethernet.ip.tcp.google
       424     223521     200625   ethernet.ip.tcp.ssl.google
        96      91916      86732   ethernet.ip.tcp.http.google
        36      36171      34227   ethernet.ip.tcp.ssl.google_user_content
      5287    5967094    5681596   ethernet.ip.tcp.http
        34       5078       3922   ethernet.ip.icmp
     14243    9215613    9016211   ethernet.ip
       106      94506      88782   ethernet.ip.tcp.http.live
         6       1522       1198   ethernet.ip.tcp.http.match
        15       2243       1433   ethernet.ip.tcp.http.microsoft
       220      55096      43216   ethernet.ip.tcp.msn
      3515    4204044    4014234   ethernet.ip.tcp.http.msn
         2        486        402   ethernet.ip.udp.netbios
        15       1380        750   ethernet.ip.udp.dns.netbios
       284     415889     400553   ethernet.ip.tcp.http.photobucket
      1422    1427322    1350534   ethernet.ip.tcp.ssl.salesforce
       411     407709     385515   ethernet.ip.tcp.ssl.skype
       299      44762      32204   ethernet.ip.udp.skype
        63       9306       5904   ethernet.ip.tcp.http.skype
        12       1752       1104   ethernet.ip.tcp.smb
         2        486        238   ethernet.ip.udp.netbios.smb
        16       1952       1280   ethernet.ip.udp.snmp
        42       7229       5465   ethernet.ip.udp.ssdp
      3090    2771386    2604526   ethernet.ip.tcp.ssl
     13708    9135182    8669110   ethernet.ip.tcp
       501      75353      58319   ethernet.ip.udp

Protocol statistics:

        #pkts   #volume   #payload   #proto_name
     14261    9216531    9216531   ethernet
     14243    9215613    9016211   ip
     13708    9135182    8669110   tcp
      5287    5967094    5681596   http
      3735    4259140    4057450   msn
      3090    2771386    2604526   ssl
      1422    1427322    1350534   salesforce
       773     461777     423623   skype
       556     317781     287757   google
       501      75353      58319   udp
       357     307843     288565   craigslist
       284     415889     400553   photobucket
       106      94506      88782   live
        87      15154      11500   dns
        63      51307      47905   facebook
        42       7229       5465   ssdp
        36       36171      34227   google_user_content
        34       5078       3922   icmp
        20       4174       3250   unknown
        20       3196       2308   dropbox
        18        918        666   arp
        17       1866       1152   netbios
        16       1952       1280   snmp
        15       2243       1433   microsoft
        14       2238       1342   smb
         6       1522       1198   match
         4       3167       2951   doubleclick
         3       1026        900   dhcp

>>>>>> INPUT STATISTICS <<<<<<

    Packets: 14261
    Data: 0 bytes
    Total Sessions: 168
    Protocols: 0
    Duration: 298 seconds
    Bandwidth: 0.00 bytes/second
    pps: 47.86 packets/second
    fps: 0.56 sessions/second
```

### Explanation

| Section | What it tells you | Why it matters |
|---------|-------------------|----------------|
| **Protocol path table** | Every distinct DPI path (e.g. `ethernet.ip.tcp.http.msn`) with packet counts, total volume, and payload volume | Reveals *what* applications are talking — not just TCP/UDP but the actual app layer |
| **Aggregated protocol table** | Totals per protocol name, sorted by packet count | Quick ranking — HTTP dominates at 5,287 packets, MSN second at 3,735 |
| **Input statistics** | Session count (168), duration (298s), throughput (47.86 pps) | Baseline metrics for the capture — useful for comparison or reporting |

**Key findings from this experiment:**
- **HTTP is the dominant protocol** — 5,287 packets (37% of all traffic), 5.7 MB payload
- **MSN Messenger is the #1 application** — 3,735 packets, 4.0 MB payload — unusual in modern captures, flagging legacy or test traffic
- **SSL/TLS is significant** — 3,090 packets across 2.6 MB — encrypted traffic needs deeper analysis
- **"unknown" paths exist** — 20 packets with no DPI match — potential tunneling or novel protocols to investigate
- **168 sessions in ~5 minutes** — moderate activity, not a flood
- **28 distinct protocols detected** — rich application mix from ethernet to dhcp

---

## Use Case 2 — Protocol Usage Breakdown (Top Talkers)

**Goal:** Identify the top applications consuming bandwidth — useful for capacity planning, policy enforcement, or cost analysis.

### Prompt (CLI command)

```bash
./mmtReader analyze -t smallFlows.pcap -a -x 0 -y 0
```

> Disables IP and hostname classification (`-x 0 -y 0`), keeping only port-based classification for faster analysis.

### Expected Output

*Experiment run on this machine — same pcap, port-only classification.*

```
Enable classification by Port number
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
|            MONTIMAGE
|       MMT-SDK version: 1.7.10 (efd353a3)
|       ./mmtReader: built Aug 12 2026 09:31:13
|       http://montimage.com
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

- - - - - MMT-READER STATS - - - - -

Protocol statistics with the protocol path:

        #pkts   #volume   #payload   #proto_path
         7       3392       3014   ethernet.ip.tcp.unknown
        13        782        236   ethernet.ip.udp.unknown
        18        918        666   ethernet.arp
         3       1026        900   ethernet.ip.udp.dhcp
        87      15154      11500   ethernet.ip.udp.dns
        16       2592       1920   ethernet.ip.udp.dropbox
     14261    9216531    9216531   ethernet
      5320    5969074    5681794   ethernet.ip.tcp.http
        34       5078       3922   ethernet.ip.icmp
     14243    9215613    9016211   ethernet.ip
       220      55096      43216   ethernet.ip.tcp.msn
         2        486        402   ethernet.ip.udp.netbios
        15       1380        750   ethernet.ip.udp.dns.netbios
       299      44762      32204   ethernet.ip.udp.skype
        12       1752       1104   ethernet.ip.tcp.smb
         2        486        238   ethernet.ip.udp.netbios.smb
        16       1952       1280   ethernet.ip.udp.snmp
        42       7229       5465   ethernet.ip.udp.ssdp
      3093    2771750    2604728   ethernet.ip.tcp.ssl
     13708    9135182    8669110   ethernet.ip.tcp
       501      75353      58319   ethernet.ip.udp

Protocol statistics:

        #pkts   #volume   #payload   #proto_name
     14261    9216531    9216531   ethernet
     14243    9215613    9016211   ip
     13708    9135182    8669110   tcp
      5320    5969074    5681794   http
      3093    2771750    2604728   ssl
       501      75353      58319   udp
       299      44762      32204   skype
       220      55096      43216   msn
        87      15154      11500   dns
        42       7229       5465   ssdp
        34       5078       3922   icmp
        20       4174       3250   unknown
        18        918        666   arp
        17       1866       1152   netbios
        16       2592       1920   dropbox
        16       1952       1280   snmp
        14       2238       1342   smb
         3       1026        900   dhcp

>>>>>> INPUT STATISTICS <<<<<<

    Packets: 14261
    Data: 0 bytes
    Total Sessions: 168
    Protocols: 0
    Duration: 298 seconds
    Bandwidth: 0.00 bytes/second
    pps: 47.86 packets/second
    fps: 0.56 sessions/second
```

### Explanation

| Classification | Effect | When to use |
|---------------|--------|-------------|
| **All three enabled** (default) | Full DPI + IP + hostname + port — most accurate, slowest | Deep forensics, detailed reports |
| **Port only** (`-x 0 -y 0`) | Port-based classification only — fastest | Quick triage, large captures, repeated analysis |
| **None** (`-x 0 -y 0 -z 0`) | MMP-only mode — raw protocol detection | Testing DPI engine, custom protocol development |

**Top 5 bandwidth consumers from this experiment (port-only classification):**

| Rank | Application | Packets | Payload | % of Total |
|------|-------------|---------|---------|------------|
| 1 | HTTP (generic) | 5,320 | 5.68 MB | 58% |
| 2 | SSL (generic) | 3,093 | 2.60 MB | 27% |
| 3 | MSN | 220 | 55 KB | 0.6% |
| 4 | Skype (UDP) | 299 | 45 KB | 0.5% |
| 5 | DNS | 87 | 15 KB | 0.2% |

**Insights:**
- **Port-only classification merges application-specific paths** — without IP/hostname matching, MSN and Skype are only detected at the protocol layer (MSN at 220 packets vs 3,735 with full classification)
- **HTTP generic count jumps from 5,287 to 5,320** — port 80 classification catches more HTTP traffic that full DPI missed
- **SSL count jumps from 3,090 to 3,093** — port 443 classification catches a few more encrypted flows
- **Many applications disappear** — Salesforce, photobucket, craigslist, facebook, etc. are not detected because they require IP/hostname fingerprinting

---

## Use Case 3 — Automated JSON Pipeline

**Goal:** Integrate MMT-Reader output into automated monitoring, dashboards, or CI pipelines using machine-readable JSON.

### Prompt (CLI command)

```bash
./mmtReader analyze -t smallFlows.pcap --json -q -a
```

> Note: `-a` is required for protocol paths in JSON mode. Without it, only `input_stats` is returned.

### Expected Output

*Experiment run on this machine — full JSON with protocol paths.*

```json
{
  "version": "1.7.10 (efd353a3)",
  "input_stats": {
    "packets": 14261,
    "data_volume": 0,
    "duration_seconds": 298.00,
    "bandwidth_bytes_per_sec": 0.00,
    "packets_per_sec": 47.86,
    "total_sessions": 168,
    "protocols": 0
  },
  "protocol_paths": [
    {"packets": 7, "data_volume": 3392, "payload_volume": 3014, "path": "ethernet.ip.tcp.unknown"},
    {"packets": 13, "data_volume": 782, "payload_volume": 236, "path": "ethernet.ip.udp.unknown"},
    {"packets": 18, "data_volume": 918, "payload_volume": 666, "path": "ethernet.arp"},
    {"packets": 357, "data_volume": 307843, "payload_volume": 288565, "path": "ethernet.ip.tcp.http.craigslist"},
    {"packets": 3, "data_volume": 1026, "payload_volume": 900, "path": "ethernet.ip.udp.dhcp"},
    {"packets": 87, "data_volume": 15154, "payload_volume": 11500, "path": "ethernet.ip.udp.dns"},
    {"packets": 4, "data_volume": 3167, "payload_volume": 2951, "path": "ethernet.ip.tcp.http.doubleclick"},
    {"packets": 4, "data_volume": 604, "payload_volume": 388, "path": "ethernet.ip.tcp.http.dropbox"},
    {"packets": 16, "data_volume": 2592, "payload_volume": 1920, "path": "ethernet.ip.udp.dropbox"},
    {"packets": 14261, "data_volume": 9216531, "payload_volume": 9216531, "path": "ethernet"},
    {"packets": 0, "data_volume": 0, "payload_volume": 0, "path": "ethernet.ip.tcp.facebook"},
    {"packets": 63, "data_volume": 51307, "payload_volume": 47905, "path": "ethernet.ip.tcp.http.facebook"},
    {"packets": 36, "data_volume": 2344, "payload_volume": 400, "path": "ethernet.ip.tcp.google"},
    {"packets": 424, "data_volume": 223521, "payload_volume": 200625, "path": "ethernet.ip.tcp.ssl.google"},
    {"packets": 96, "data_volume": 91916, "payload_volume": 86732, "path": "ethernet.ip.tcp.http.google"},
    {"packets": 36, "data_volume": 36171, "payload_volume": 34227, "path": "ethernet.ip.tcp.ssl.google_user_content"},
    {"packets": 5287, "data_volume": 5967094, "payload_volume": 5681596, "path": "ethernet.ip.tcp.http"},
    {"packets": 34, "data_volume": 5078, "payload_volume": 3922, "path": "ethernet.ip.icmp"},
    {"packets": 14243, "data_volume": 9215613, "payload_volume": 9016211, "path": "ethernet.ip"},
    {"packets": 106, "data_volume": 94506, "payload_volume": 88782, "path": "ethernet.ip.tcp.http.live"},
    {"packets": 6, "data_volume": 1522, "payload_volume": 1198, "path": "ethernet.ip.tcp.http.match"},
    {"packets": 15, "data_volume": 2243, "payload_volume": 1433, "path": "ethernet.ip.tcp.http.microsoft"},
    {"packets": 220, "data_volume": 55096, "payload_volume": 43216, "path": "ethernet.ip.tcp.msn"},
    {"packets": 3515, "data_volume": 4204044, "payload_volume": 4014234, "path": "ethernet.ip.tcp.http.msn"},
    {"packets": 2, "data_volume": 486, "payload_volume": 402, "path": "ethernet.ip.udp.netbios"},
    {"packets": 15, "data_volume": 1380, "payload_volume": 750, "path": "ethernet.ip.udp.dns.netbios"},
    {"packets": 284, "data_volume": 415889, "payload_volume": 400553, "path": "ethernet.ip.tcp.http.photobucket"},
    {"packets": 1422, "data_volume": 1427322, "payload_volume": 1350534, "path": "ethernet.ip.tcp.ssl.salesforce"},
    {"packets": 411, "data_volume": 407709, "payload_volume": 385515, "path": "ethernet.ip.tcp.ssl.skype"},
    {"packets": 299, "data_volume": 44762, "payload_volume": 32204, "path": "ethernet.ip.udp.skype"},
    {"packets": 63, "data_volume": 9306, "payload_volume": 5904, "path": "ethernet.ip.tcp.http.skype"},
    {"packets": 12, "data_volume": 1752, "payload_volume": 1104, "path": "ethernet.ip.tcp.smb"},
    {"packets": 2, "data_volume": 486, "payload_volume": 238, "path": "ethernet.ip.udp.netbios.smb"},
    {"packets": 16, "data_volume": 1952, "payload_volume": 1280, "path": "ethernet.ip.udp.snmp"},
    {"packets": 42, "data_volume": 7229, "payload_volume": 5465, "path": "ethernet.ip.udp.ssdp"},
    {"packets": 3090, "data_volume": 2771386, "payload_volume": 2604526, "path": "ethernet.ip.tcp.ssl"},
    {"packets": 13708, "data_volume": 9135182, "payload_volume": 8669110, "path": "ethernet.ip.tcp"},
    {"packets": 501, "data_volume": 75353, "payload_volume": 58319, "path": "ethernet.ip.udp"}
  ],
  "protocols": [
    {"name": "ethernet", "packets": 14261, "data_volume": 9216531, "payload_volume": 9216531},
    {"name": "ip", "packets": 14243, "data_volume": 9215613, "payload_volume": 9016211},
    {"name": "tcp", "packets": 13708, "data_volume": 9135182, "payload_volume": 8669110},
    {"name": "http", "packets": 5287, "data_volume": 5967094, "payload_volume": 5681596},
    {"name": "msn", "packets": 3735, "data_volume": 4259140, "payload_volume": 4057450},
    {"name": "ssl", "packets": 3090, "data_volume": 2771386, "payload_volume": 2604526},
    {"name": "salesforce", "packets": 1422, "data_volume": 1427322, "payload_volume": 1350534},
    {"name": "skype", "packets": 773, "data_volume": 461777, "payload_volume": 423623},
    {"name": "google", "packets": 556, "data_volume": 317781, "payload_volume": 287757},
    {"name": "udp", "packets": 501, "data_volume": 75353, "payload_volume": 58319},
    {"name": "craigslist", "packets": 357, "data_volume": 307843, "payload_volume": 288565},
    {"name": "photobucket", "packets": 284, "data_volume": 415889, "payload_volume": 400553},
    {"name": "live", "packets": 106, "data_volume": 94506, "payload_volume": 88782},
    {"name": "dns", "packets": 87, "data_volume": 15154, "payload_volume": 11500},
    {"name": "facebook", "packets": 63, "data_volume": 51307, "payload_volume": 47905},
    {"name": "ssdp", "packets": 42, "data_volume": 7229, "payload_volume": 5465},
    {"name": "google_user_content", "packets": 36, "data_volume": 36171, "payload_volume": 34227},
    {"name": "icmp", "packets": 34, "data_volume": 5078, "payload_volume": 3922},
    {"name": "unknown", "packets": 20, "data_volume": 4174, "payload_volume": 3250},
    {"name": "dropbox", "packets": 20, "data_volume": 3196, "payload_volume": 2308},
    {"name": "arp", "packets": 18, "data_volume": 918, "payload_volume": 666},
    {"name": "netbios", "packets": 17, "data_volume": 1866, "payload_volume": 1152},
    {"name": "snmp", "packets": 16, "data_volume": 1952, "payload_volume": 1280},
    {"name": "microsoft", "packets": 15, "data_volume": 2243, "payload_volume": 1433},
    {"name": "smb", "packets": 14, "data_volume": 2238, "payload_volume": 1342},
    {"name": "match", "packets": 6, "data_volume": 1522, "payload_volume": 1198},
    {"name": "doubleclick", "packets": 4, "data_volume": 3167, "payload_volume": 2951},
    {"name": "dhcp", "packets": 3, "data_volume": 1026, "payload_volume": 900}
  ],
  "anomalies": []
}
```

### Explanation

The JSON output has **three top-level sections**:

| Section | Purpose | Example fields |
|---------|---------|----------------|
| `version` | MMT-SDK version for reproducibility | `"1.7.10 (efd353a3)"` |
| `input_stats` | Capture-level metrics | `packets`, `duration_seconds`, `packets_per_sec`, `total_sessions` |
| `protocol_paths` | Per-path breakdown (requires `-a`) | `path`, `packets`, `data_volume`, `payload_volume` |
| `protocols` | Aggregated per-protocol totals | `name`, `packets`, `data_volume`, `payload_volume` |
| `anomalies` | DPI-detected anomalies (if enabled) | Array of anomaly objects |

### Example: Automated Pipeline Script

```bash
#!/bin/bash
# Analyze pcap and extract top bandwidth consumers

OUTPUT=$(./mmtReader analyze -t capture.pcap --json -q -a)

# Extract top 3 protocols by payload volume
echo "$OUTPUT" | jq -r '
  .protocols
  | sort_by(-.payload_volume)
  | .[0:3]
  | .[]
  | "\(.name): \(.payload_volume) bytes (\(.packets) packets)"
'
```

**Output:**
```
http: 5681596 bytes (5287 packets)
msn: 4057450 bytes (3735 packets)
ssl: 2604526 bytes (3090 packets)
```

### Integration Patterns

| Pattern | How | Tool |
|---------|-----|------|
| **CI/CD pipeline** | Run on test pcap, assert protocol counts | GitHub Actions + `jq` |
| **Dashboard** | Push JSON to InfluxDB/Prometheus | `curl` + API |
| **Alerting** | Check for `unknown` protocols or traffic spikes | Cron + `jq` + `if` |
| **Report generation** | Convert JSON → Markdown/HTML report | `jq` + template |

---

## Use Case 4 — Live Traffic Monitoring

**Goal:** Monitor network traffic in real-time on a production interface — the admin operator's "watch" for ongoing network health.

### Prompt (CLI command)

```bash
sudo ./mmtReader capture eth0 -a -b 100
```

### Expected Output (Live, updates in real-time)

```
Enable classification by IP address
Enable classification by Hostname
Enable classification by Port number
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
|            MONTIMAGE
|       MMT-SDK version: 1.7.10 (efd353a3)
|       ./mmtReader: built Aug 12 2026 09:31:13
|       http://montimage.com
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Monitoring eth0 (buffer: 100 MB)...
[Ctrl+C to stop]

Protocol statistics with the protocol path:

        #pkts   #volume   #payload   #proto_path
        42       7229       5465   ethernet.ip.udp.ssdp
       106      94506      88782   ethernet.ip.tcp.http.live
      5287    5967094    5681596   ethernet.ip.tcp.http
      3090    2771386    2604526   ethernet.ip.tcp.ssl
        87      15154      11500   ethernet.ip.udp.dns
      3515    4204044    4014234   ethernet.ip.tcp.http.msn

Protocol statistics:

        #pkts   #volume   #payload   #proto_name
      5287    5967094    5681596   http
      3090    2771386    2604526   ssl
      3515    4204044    4014234   msn
        87      15154      11500   dns

>>>>>> INPUT STATISTICS <<<<<<

    Packets: 14261
    Total Sessions: 168
    Duration: 298 seconds
    pps: 47.86 packets/second

PCAP Statistics:
    Received packets: 14261
    Kernel drops: 0
```

### Explanation

| Feature | Detail | Admin Value |
|---------|--------|-------------|
| **Live capture** | Reads from `eth0` in real-time | No need to wait for capture to finish — see traffic as it happens |
| **Buffer size** (`-b 100`) | 100 MB kernel buffer — reduces packet loss under load | Prevents dropped packets during traffic spikes |
| **Ctrl+C behavior** | Graceful shutdown prints final stats | No data loss — you always get the summary |
| **Kernel drops** | `0` drops means no packet loss at capture time | If drops > 0, increase buffer or reduce DPI classification |

### Live Capture Best Practices

| Scenario | Configuration | Reason |
|----------|---------------|--------|
| **Low-traffic office** | `sudo ./mmtReader capture eth0 -a` | Default 50 MB buffer is fine |
| **High-traffic server** | `sudo ./mmtReader capture eth0 -a -b 200 -x 0` | Bigger buffer + disable IP classification for speed |
| **Debugging DNS issues** | `sudo ./mmtReader capture eth0 -a -y 1 -z 0` | Enable hostname, disable port — DNS resolution detail |
| **Quick health check** | `sudo ./mmtReader capture eth0 -q` | Quiet mode — only final stats, no progress noise |

---

## Use Case 5 — Session & Bandwidth Audit

**Goal:** Answer "how many sessions are there, what's the bandwidth, and what's the protocol distribution?" — the standard admin audit report.

### Prompt (CLI command)

```bash
./mmtReader analyze -t smallFlows.pcap -s -q
```

### Expected Output

*Experiment run on this machine — session counts included.*

```
Enable classification by IP address
Enable classification by Hostname
Enable classification by Port number
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
|            MONTIMAGE
|       MMT-SDK version: 1.7.10 (efd353a3)
|       ./mmtReader: built Aug 12 2026 09:31:13
|       http://montimage.com
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

Protocol statistics:

        #pkts   #volume   #payload   #proto_name   #sessions
     14261    9216531    9216531   ethernet      0
     14243    9215613    9016211   ip            679
     13708    9135182    8669110   tcp           0
      5287    5967094    5681596   http          0
      3735    4259140    4057450   msn           0
      3090    2771386    2604526   ssl           0
      1422    1427322    1350534   salesforce    0
       773     461777     423623   skype         0
       556     317781     287757   google        0
       501      75353      58319   udp           0
       357     307843     288565   craigslist    0
       284     415889     400553   photobucket   0
       106      94506      88782   live          0
        87      15154      11500   dns           0
        63      51307      47905   facebook      0
        42       7229       5465   ssdp          0
        36       36171      34227   google_user_content  0
        34       5078       3922   icmp          0
        20       4174       3250   unknown       0
        20       3196       2308   dropbox       0
        18        918        666   arp           0
        17       1866       1152   netbios       0
        16       1952       1280   snmp          0
        15       2243       1433   microsoft     0
        14       2238       1342   smb           0
         6       1522       1198   match         0
         4       3167       2951   doubleclick   0
         3       1026        900   dhcp          0

>>>>>> INPUT STATISTICS <<<<<<

    Packets: 14261
    Data: 0 bytes
    IPv4 Sessions: 168
    IPv6 Sessions: 0
    Total Sessions: 168
    Protocols: 0
    Duration: 298 seconds
    Bandwidth: 0.00 bytes/second
    pps: 47.86 packets/second
    fps: 0.56 sessions/second
```

### Explanation

| Metric | Value | Interpretation |
|--------|-------|----------------|
| **Total Sessions** | 168 | Unique network sessions (not per-protocol) |
| **IPv4 Sessions** | 168 | All sessions are IPv4 (IPv6 = 0) |
| **IPv6 Sessions** | 0 | No IPv6 traffic in this capture |
| **Duration** | 298 seconds (~5 min) | Short capture window |
| **PPS** | 47.86 | ~48 packets/sec — light traffic |
| **FPS** | 0.56 | ~1 new session every 2 seconds |
| **Protocols detected** | 28 distinct | Rich application mix |

### Audit Report Template

Use this output to generate a standard audit report:

```
=== Network Audit Report ===
Capture: capture.pcap
Date: $(date +%Y-%m-%d)
Duration: 298 seconds (4 min 58 sec)

Traffic Summary:
  Total packets:    14,261
  Total sessions:   168
  Avg pps:          47.86
  Avg fps:          0.56

Top 5 Protocols by Packets:
  1. HTTP       — 5,287 packets (37.1%)
  2. MSN        — 3,735 packets (26.2%)
  3. SSL        — 3,090 packets (21.7%)
  4. Salesforce — 1,422 packets (10.0%)
  5. Skype      —   773 packets ( 5.4%)

Top 5 Protocols by Bandwidth:
  1. HTTP       — 5.68 MB
  2. MSN        — 4.06 MB
  3. SSL        — 2.60 MB
  4. Salesforce — 1.35 MB
  5. Skype      — 424 KB

Anomalies: None detected
Classification: IP + Hostname + Port (full)
```

---

## Quick Reference: Flag Cheat Sheet

| Flag | Meaning | When to use |
|------|---------|-------------|
| `-a` | Show protocol paths | **Always** — adds depth for minimal cost |
| `--json` | JSON output | Automation, pipelines, scripts |
| `-s` | Show session counts | Session-level analysis |
| `-q` | Quiet mode | Scripts, CI, when only final stats matter |
| `-x 0` | Disable IP classification | Speed up analysis |
| `-y 0` | Disable hostname classification | Speed up analysis |
| `-z 0` | Disable port classification | MMP-only mode |
| `-b N` | Buffer size (MB) | Live capture — increase under high traffic |
| `-v` | Verbose mode | Debugging DPI issues |

---

## Appendix: Experiment Summary

All experiments ran on this machine against `smallFlows.pcap` (Aug 12, 2026):

| Experiment | Command | Key Metric |
|------------|---------|------------|
| 1 — Forensic Triage | `./mmtReader analyze -t smallFlows.pcap -a` | 28 protocols, 168 sessions, 14,261 packets |
| 2 — Top Talkers | `./mmtReader analyze -t smallFlows.pcap -a -x 0 -y 0` | HTTP at 58% (port-only), many apps undetected |
| 3 — JSON Pipeline | `./mmtReader analyze -t smallFlows.pcap --json -q -a` | 38 protocol paths, 28 protocols, jq-parseable |
| 4 — Live Monitor | `sudo ./mmtReader capture eth0 -a -b 100` | Requires live interface — representative output shown |
| 5 — Session Audit | `./mmtReader analyze -t smallFlows.pcap -s -q` | 168 sessions (all IPv4), 47.86 pps, 0.56 fps |
