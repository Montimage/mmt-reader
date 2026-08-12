# MMT-Reader Config File Reference

MMT-Reader supports an INI-style configuration file that sets defaults for each command section. CLI flags always override config file values.

## Default Location

```
~/.mmtreader.conf
```

The config file is loaded automatically if it exists. If the file is not found, no error is raised (config loading is optional).

## Format

```ini
; Comment lines start with ; or #
# Another comment style

; Global options (apply to all commands)
json = 0
quiet = 0
verbose = 0
no_color = 0
ip_classify = 1
hostname_classify = 1
port_classify = 1

; Per-command overrides
[analyze]
json = 1
buffer = 50
proto_path = 0
sessions = 0

[capture]
json = 0
quiet = 1
buffer = 100
```

### Syntax Rules

- **Comments**: Lines starting with `;` or `#` are ignored
- **Section headers**: `[section_name]` — starts a new section
- **Key-value pairs**: `key = value` — options and their defaults
- **Whitespace**: Leading/trailing whitespace on keys and values is trimmed
- **Blank lines**: Ignored

### Sections

| Section | Description |
|---------|-------------|
| *(none / before any header)* | **Global** — options apply to all commands |
| `[analyze]` | Overrides for `mmtReader analyze` |
| `[capture]` | Overrides for `mmtReader capture` |

Options before any section header are **global defaults** — they apply to all commands. Section-specific options override the global defaults for that command only.

## Supported Keys

### Global Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `json` | Boolean (`0`/`1`) | `0` | JSON output format |
| `quiet` | Boolean (`0`/`1`) | `0` | Suppress progress output |
| `verbose` | Boolean (`0`/`1`) | `0` | Verbose debug output to stderr |
| `no_color` | Boolean (`0`/`1`) | `0` | Disable ANSI color output |
| `ip_classify` | Integer (`0`/`1`) | `1` | IP address classification |
| `hostname_classify` | Integer (`0`/`1`) | `1` | Hostname classification |
| `port_classify` | Integer (`0`/`1`) | `1` | Port number classification |

### Per-Section Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `buffer` | Integer (MB) | `50` | Pcap handler buffer size |
| `proto_path` | Boolean (`0`/`1`) | `0` | Show per-protocol-path statistics |
| `sessions` | Boolean (`0`/`1`) | `0` | Show per-protocol session counts |
| `output_format` | Integer (`0`/`1`) | `0` | Output format (`0`=text, `1`=json) |

### Boolean Values

Booleans accept: `0`, `1`, `true`, `false`, `yes`, `no`, `on`, `off` (case-insensitive).

### Key Naming

Keys use `snake_case` (e.g., `no_color`, `ip_classify`). Hyphenated variants are also accepted (e.g., `no-color`, `ip-classify`).

## Priority Order

Config values are resolved in this order (highest priority first):

1. **CLI flags** — e.g., `--json`, `-x 0`
2. **Environment variables** — e.g., `MMTREADER_JSON=1`
3. **Section-specific config** — e.g., `[analyze]` section
4. **Global config** — options before any section header
5. **Compiled defaults** — hardcoded defaults in the binary

## Example Config

```ini
; ~/.mmtreader.conf

; Global defaults
json = 0
quiet = 0
verbose = 0
no_color = 0
ip_classify = 1
hostname_classify = 1
port_classify = 1

; Analyze mode defaults
[analyze]
json = 1
proto_path = 1
sessions = 1
buffer = 50

; Capture mode defaults
[capture]
quiet = 1
buffer = 100
proto_path = 1
```

With this config:
- `mmtReader analyze -t file.pcap` → JSON output, proto paths, session counts
- `mmtReader capture eth0` → quiet mode, 100 MB buffer, proto paths
- `mmtReader analyze -t file.pcap --text` → CLI overrides JSON to text

## Debugging

Use `--verbose` to see if the config file was loaded:

```bash
mmtReader analyze -t file.pcap -v
```

Verbose mode prints startup diagnostics to stderr, including whether the config file was loaded and its values.
