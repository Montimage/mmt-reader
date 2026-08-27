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

Options before any section header are **global defaults** — they apply to all commands.

> **Note.** Sections are thinner than they look. `json`, `quiet`, `verbose` and
> `no_color` are stored in one global slot whichever section they appear in, so a
> value set under `[analyze]` also applies to `capture` (the last one parsed
> wins). The per-section `buffer`, `proto_path`, `sessions` and `output_format`
> slots are written but never read. See the *Effective?* column below.

## Supported Keys

### Global Options

| Key | Type | Default | Effective? | Description |
|-----|------|---------|-----------|-------------|
| `json` | Boolean (`0`/`1`) | `0` | Yes | JSON output format |
| `quiet` | Boolean (`0`/`1`) | `0` | `capture` only | Suppress progress output; `analyze` prints no `INFO:` lines either way |
| `verbose` | Boolean (`0`/`1`) | `0` | Yes | Verbose debug output to stderr |
| `no_color` | Boolean (`0`/`1`) | `0` | Yes | Disable ANSI color output |
| `ip_classify` | Integer (`0`/`1`) | `1` | **No** — parsed, never read (use `-x`) | IP address classification |
| `hostname_classify` | Integer (`0`/`1`) | `1` | **No** — parsed, never read (use `-y`) | Hostname classification |
| `port_classify` | Integer (`0`/`1`) | `1` | **No** — parsed, never read (use `-z`) | Port number classification |

`json` was itself inert until issue #96: the config file and `MMTREADER_JSON`
wrote a field no output decision read. Both now select the output format.

### Per-Section Options

| Key | Type | Default | Effective? | Description |
|-----|------|---------|-----------|-------------|
| `buffer` | Integer (MB) | `50` | Global section only, `capture` only | Pcap handler buffer size; a `[analyze]`/`[capture]` `buffer` is stored per section and never read, and `analyze` ignores the buffer entirely |
| `proto_path` | Boolean (`0`/`1`) | `0` | **No** — parsed, never read (use `-a`) | Show per-protocol-path statistics |
| `sessions` | Boolean (`0`/`1`) | `0` | **No** — parsed, never read (use `-s`) | Show per-protocol session counts |
| `output_format` | Integer (`0`/`1`) | `0` | **No** — parsed, never read (use `json`, `-j`/`-T`) | Output format (`0`=text, `1`=json) |

### Boolean Values

Booleans accept: `0`, `1`, `true`, `false`, `yes`, `no`, `on`, `off` (case-insensitive).

### Key Naming

Keys use `snake_case` (e.g., `no_color`, `ip_classify`). Hyphenated variants are also accepted (e.g., `no-color`, `ip-classify`).

## Priority Order

There is **one** rule, and both config files obey it. Values are resolved in
this order (highest priority first):

1. **CLI flags** — e.g., `--json`, `--text`, `-b 100`, `-C`
2. **Environment variables** — `MMTREADER_JSON`, `MMTREADER_NO_COLOR`, `MMTREADER_QUIET`
3. **The `-c`/`--config` file**, when one is named
4. **`~/.mmtreader.conf`** — the default config file
5. **Compiled defaults** — hardcoded defaults in the binary

Within a single file, a later assignment wins over an earlier one, so a key in
a `[analyze]`/`[capture]` section overrides the same key set before any section
header (subject to the *Note* above about which slots are actually read).

A `--config` file **replaces** the five values `~/.mmtreader.conf` supplied
rather than merging with them: keys it omits fall back to the compiled
defaults, not to the default file. Passing `-c`/`--config` more than once uses
the last one. An unreadable or missing config path is ignored silently, exactly
as a missing `~/.mmtreader.conf` is.

Before issue #96 the two config files had **opposite** precedence: the
`--config` file was re-read *after* the option loop and silently beat explicit
CLI flags, while `~/.mmtreader.conf` lost to them. Both now load before the
flags are parsed.

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

; Capture mode defaults
[capture]
quiet = 1
```

With this config:
- `mmtReader analyze -t file.pcap` → JSON output
- `mmtReader capture eth0` → JSON output and quiet mode — `json = 1` under
  `[analyze]` is not scoped to `analyze`, and `[capture]` does not reset it
- `mmtReader analyze -t file.pcap --text` → text: an explicit CLI flag wins
- `MMTREADER_JSON=0 mmtReader analyze -t file.pcap` → text: the environment
  beats both config files
- `mmtReader analyze -t file.pcap -c other.conf` → whatever `other.conf` says,
  overriding this file — with CLI flags still winning over it

The keys marked **No** in the tables above (`proto_path`, `sessions`,
`output_format`, `ip_classify`, `hostname_classify`, `port_classify`, and the
per-section `buffer`) are parsed and then ignored; pass the corresponding flag
instead.

## Debugging

Use `--verbose` to see if the config file was loaded:

```bash
mmtReader analyze -t file.pcap -v
```

Verbose mode prints startup diagnostics to stderr, including whether the config file was loaded and its values.
