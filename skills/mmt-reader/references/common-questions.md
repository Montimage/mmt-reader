# Common Question Patterns

This reference lists common question patterns and the appropriate mmtReader command for each.

**Before using any answer below:** `input_stats.data_volume`, `.bandwidth_bytes_per_sec`, and `.protocols` always read `0`. Wherever a volume, bandwidth, or protocol count is called for, derive it as described in `json-output.md` — total bytes from the `protocols[]` entry named `ethernet`, bandwidth from that ÷ `duration_seconds`, protocol count from `len(protocols[])`.

## Protocol Questions

**"What protocols are in this capture?"**
```bash
mmtReader analyze -t <file> --json -a -s
```
Answer: List top protocols by packet count and percentage, skipping the `ethernet`/`ip`/`tcp`/`udp` layer entries.

**"Which protocols use the most bandwidth?"**
```bash
mmtReader analyze -t <file> --json -a -s
```
Answer: Sort `protocols[]` by `data_volume` descending.

## Bandwidth Questions

**"How much traffic is in this capture?"**
```bash
mmtReader analyze -t <file> --json -a -s
```
Answer: Report `input_stats.packets` and `input_stats.duration_seconds` directly; derive total bytes and bandwidth.

**"What's the average bandwidth?"**
```bash
mmtReader analyze -t <file> --json -a -s
```
Answer: Derive bandwidth (ethernet `data_volume` / `duration_seconds`) and render as KB/s or MB/s.

## Session Questions

**"How many sessions are there?"**
```bash
mmtReader analyze -t <file> --json -a -s
```
Answer: Report `input_stats.total_sessions`, `input_stats.ipv4_sessions`, `input_stats.ipv6_sessions`.

**"Break down sessions by protocol."**
```bash
mmtReader analyze -t <file> --json -a -s
```
Answer: Report per-protocol stats from `protocols[]`.

## Live Capture Questions

**"What's running on my network right now?"**
```bash
sudo mmtReader capture <interface> --json -a -s
```
Answer: Report real-time protocol distribution.

## Classification Questions

**"Can I get faster results?"**
```bash
mmtReader analyze -t <file> -a -x 0 -y 0 -z 0  # MMP-only mode
```
Answer: Disable all classification flags for speed (less accuracy).

**"Show me the full protocol hierarchy."**
```bash
mmtReader analyze -t <file> --json -a -s
```
Answer: Report `protocol_paths[]` for full DPI hierarchy.

## Visualization Questions

**"Show me a chart of protocol distribution."**
```bash
mmtReader analyze -t <file> --json -a -s
```
Answer: Convert `protocols[]` to a Mermaid pie chart.
