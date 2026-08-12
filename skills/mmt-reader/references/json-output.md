# mmtReader JSON output

Full shape returned by `--json`. Read this when you need a field the table in SKILL.md does not cover.

```json
{
  "version": "1.8.0 (42cac8b7)",
  "input_stats": {
    "packets": 14261,
    "data_volume": 9216531,
    "duration_seconds": 298.0,
    "bandwidth_bytes_per_sec": 30926.5,
    "packets_per_sec": 47.86,
    "ipv4_sessions": 168,
    "ipv6_sessions": 0,
    "total_sessions": 168,
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
| `version` | mmtReader version and build hash. Quote it when reporting a version-dependent quirk. |
| `input_stats` | Whole-capture summary. `data_volume` is bytes on the wire; `duration_seconds` is wall-clock span of the capture, not analysis time. |
| `protocol_paths` | One entry per distinct DPI path, emitted only with `-a`. `path` is dot-separated bottom-up (`ethernet.ip.tcp.http`). |
| `protocols` | Aggregated per top-level protocol, sorted by `packets` descending. `data_volume` includes headers; `payload_volume` excludes them. |
| `anomalies` | Detected anomalies. Empty in most healthy captures — an empty array is not an error. |

## Field gotchas

- `protocols[].sessions` is `0` in some builds even with `-s`. Fall back to `input_stats.total_sessions` and say the per-protocol split is unavailable.
- `protocol_paths` is absent without `-a`, and `protocols[].sessions` is absent without `-s`. **The standard run** passes both.
- `data_volume` minus `payload_volume` is protocol overhead — useful for "how much is header vs data" questions.
- Percentages are never precomputed. Derive them from `packets` or `data_volume` against `input_stats`.
