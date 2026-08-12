# mmtReader JSON output

Full shape returned by `--json`. Read this when you need a field the table in SKILL.md does not cover.

```json
{
  "version": "1.8.0 (42cac8b7)",
  "input_stats": {
    "packets": 14261,
    "data_volume": 0,
    "duration_seconds": 298.0,
    "bandwidth_bytes_per_sec": 0.0,
    "packets_per_sec": 47.86,
    "ipv4_sessions": 168,
    "ipv6_sessions": 0,
    "total_sessions": 168,
    "protocols": 0
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
| `version` | mmtReader version and build hash. Quote it when reporting a version-dependent quirk. |
| `input_stats` | Whole-capture summary. `data_volume` is bytes on the wire; `duration_seconds` is wall-clock span of the capture, not analysis time. |
| `protocol_paths` | One entry per distinct DPI path, emitted only with `-a`. `path` is dot-separated bottom-up (`ethernet.ip.tcp.http`). |
| `protocols` | Aggregated per top-level protocol, sorted by `packets` descending. `data_volume` includes headers; `payload_volume` excludes them. |
| `anomalies` | Detected anomalies. Empty in most healthy captures — an empty array is not an error. |

## Field gotchas

Verified against mmtReader 1.8.0 (42cac8b7) on `smallFlows.pcap`.

- **`input_stats.data_volume`, `.bandwidth_bytes_per_sec`, and `.protocols` are always `0`.** Never quote them. Derive: bytes from the `protocols[]` entry named `ethernet` (its `data_volume` is the whole-capture total), bandwidth from that ÷ `duration_seconds`, protocol count from `len(protocols[])`.
- **`-a` is mandatory.** Without it `protocols[]` is empty and `protocol_paths` is absent from the document entirely. `-s` currently changes nothing — `protocols[].sessions` is `0` either way.
- `input_stats.packets`, `.duration_seconds`, `.packets_per_sec`, and the three session counts are reliable.
- `data_volume` minus `payload_volume` is protocol overhead — useful for "how much is header vs data" questions.
- Percentages are never precomputed. Derive them from `packets` against `input_stats.packets`, or from `data_volume` against the `ethernet` entry.
- Layer entries (`ethernet`, `ip`, `tcp`, `udp`) are nested totals, not peers of application protocols. When listing "top protocols" for a user, skip them and report application-level names (`http`, `msn`, `ssl`, …).
