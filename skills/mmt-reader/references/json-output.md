# mmtReader JSON output

Full shape returned by `--json`. Read this when you need a field the table in SKILL.md does not cover.

```json
{
  "version": {
    "mmtreader": "0.4.0",
    "mmt_dpi": "1.8.0 (42cac8b7)"
  },
  "input_stats": {
    "packets": 14261,
    "data_volume": 9216531,
    "duration_seconds": 298.51,
    "bandwidth_bytes_per_sec": 30875.60,
    "packets_per_sec": 47.77,
    "ipv4_sessions": 679,
    "ipv6_sessions": 0,
    "active_sessions": 168,
    "total_sessions": 679,
    "protocols": 28
  },
  "protocol_paths": [
    {
      "packets": 5287,
      "data_volume": 5967094,
      "payload_volume": 5681596,
      "path": "ethernet.ip.tcp.http"
    }
  ],
  "protocols": [
    {
      "name": "http",
      "packets": 5287,
      "data_volume": 5967094,
      "payload_volume": 5681596,
      "sessions": 0
    }
  ],
  "anomalies": []
}
```

## Section notes

| Section | Notes |
|---------|-------|
| `version` | Object with two labeled fields: `mmtreader` (the product release) and `mmt_dpi` (the SDK version and build hash). Quote both when reporting a version-dependent quirk. Before mmtReader 0.4.0 this was a bare string holding the SDK version only. |
| `input_stats` | Whole-capture summary, taken from MMT-DPI's own accounting. `data_volume` is bytes on the wire; `duration_seconds` is wall-clock span of the capture, not analysis time. |
| `protocol_paths` | One entry per distinct DPI path, emitted only with `-a`. `path` is dot-separated bottom-up (`ethernet.ip.tcp.http`). |
| `protocols` | Aggregated per top-level protocol, sorted by `packets` descending. `data_volume` includes headers; `payload_volume` excludes them. |
| `anomalies` | Detected anomalies. Empty in most healthy captures — an empty array is not an error. |

## Field gotchas

Verified against mmtReader 0.4.0 (MMT-DPI SDK 1.8.0 (42cac8b7)) on `smallFlows.pcap`.

- **The session fields say different things.** `ipv4_sessions`/`ipv6_sessions`/`total_sessions` count every session seen over the whole capture; `active_sessions` counts only those that had not timed out when the run ended, so it is always the smaller number. The `ipv4_*`, `ipv6_*` and `active_*` fields appear only with `-s`.
- **`-a` adds `protocol_paths`, nothing else.** Without it the document has no `protocol_paths` key at all; `protocols[]` is populated either way.
- **`protocols[].sessions` is only non-zero for `ip`/`ipv6`.** MMT-DPI counts a session against the protocol that owns it, which is the IP layer — a `sessions` of `0` on `http` does not mean there were no HTTP sessions.
- `data_volume` minus `payload_volume` is protocol overhead — useful for "how much is header vs data" questions.
- Percentages are never precomputed. Derive them from `packets` or `data_volume` against the matching `input_stats` field.
- Layer entries (`ethernet`, `ip`, `tcp`, `udp`) are nested totals, not peers of application protocols. When listing "top protocols" for a user, skip them and report application-level names (`http`, `msn`, `ssl`, …).
