# Common Question Patterns

This reference lists common question patterns and the appropriate mmtReader command for each.

**Before using any answer below:** `input_stats` carries the whole-capture totals — `data_volume`, `bandwidth_bytes_per_sec` and `protocols` (the count of distinct protocols) are reported directly, no derivation needed. See `json-output.md` for what each session field means.

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
Answer: Report `input_stats.packets`, `.data_volume` and `.duration_seconds` directly.

**"What's the average bandwidth?"**
```bash
mmtReader analyze -t <file> --json -a -s
```
Answer: Report `input_stats.bandwidth_bytes_per_sec`, rendered as KB/s or MB/s.

## Session Questions

**"How many sessions are there?"**
```bash
mmtReader analyze -t <file> --json -a -s
```
Answer: Report `input_stats.total_sessions`, `.ipv4_sessions` and `.ipv6_sessions` — every session seen. Add `.active_sessions` when the user asks what was still open at the end.

**"Break down sessions by protocol."**
```bash
mmtReader analyze -t <file> --json -a -s
```
Answer: Report per-protocol stats from `protocols[]`. Only the `ip`/`ipv6` entries carry a `sessions` count — the DPI books a session against the IP layer that owns it.

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
