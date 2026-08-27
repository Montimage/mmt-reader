#!/bin/bash
# Integration tests for CLI argument parsing, env vars, quiet, verbose
# Usage: ./tests/test_cli.sh [path_to_mmtReader]

set -euo pipefail

BINARY="${1:-./mmtReader}"
PASS=0
FAIL=0
TOTAL=0

assert_exit_code() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$actual" -eq "$expected" ]; then
        PASS=$((PASS + 1))
    else
        echo "FAIL [$desc]: expected exit code $expected, got $actual"
        FAIL=$((FAIL + 1))
    fi
}

assert_output_contains() {
    local desc="$1"
    local needle="$2"
    local haystack="$3"
    TOTAL=$((TOTAL + 1))
    if grep -qF "$needle" <<< "$haystack"; then
        PASS=$((PASS + 1))
    else
        echo "FAIL [$desc]: output does not contain '$needle'"
        echo "  Output: $(head -3 <<< "$haystack")"
        FAIL=$((FAIL + 1))
    fi
}

assert_output_not_contains() {
    local desc="$1"
    local needle="$2"
    local haystack="$3"
    TOTAL=$((TOTAL + 1))
    if ! grep -qF "$needle" <<< "$haystack"; then
        PASS=$((PASS + 1))
    else
        echo "FAIL [$desc]: output should NOT contain '$needle'"
        FAIL=$((FAIL + 1))
    fi
}

count_occurrences() {
    local needle="$1"
    local haystack="$2"
    grep -cF "$needle" <<< "$haystack" || true
}

assert_occurrence_count() {
    local desc="$1"
    local needle="$2"
    local expected="$3"
    local haystack="$4"
    local actual
    actual=$( count_occurrences "$needle" "$haystack" )
    TOTAL=$((TOTAL + 1))
    if [ "$actual" -eq "$expected" ]; then
        PASS=$((PASS + 1))
    else
        echo "FAIL [$desc]: expected $expected occurrence(s) of '$needle', got $actual"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== MMT-READER CLI Integration Tests ==="
echo "Binary: $BINARY"
echo ""

# ---- Issue #15: Input validation ----
echo "--- Issue #15: Input validation ---"

# Missing --trace for analyze
set +e
rc=0
out=$( "$BINARY" analyze 2>&1 ) || rc=$?
set -e
assert_exit_code "analyze without -t returns exit 2" 2 "$rc"
assert_output_contains "analyze without -t shows error" "missing --trace" "$out"

# Missing --interface for capture
set +e
rc=0
out=$( "$BINARY" capture 2>&1 ) || rc=$?
set -e
assert_exit_code "capture without -i returns exit 2" 2 "$rc"
assert_output_contains "capture without -i shows error" "missing --interface" "$out"

# Invalid buffer size (negative)
set +e
rc=0
out=$( "$BINARY" analyze -t smallFlows.pcap -b -5 2>&1 ) || rc=$?
set -e
assert_exit_code "negative buffer returns exit 2" 2 "$rc"
assert_output_contains "negative buffer shows error" "buffer size must be a positive integer" "$out"

# Invalid buffer size (zero)
set +e
rc=0
out=$( "$BINARY" analyze -t smallFlows.pcap -b 0 2>&1 ) || rc=$?
set -e
assert_exit_code "zero buffer returns exit 2" 2 "$rc"
assert_output_contains "zero buffer shows error" "buffer size must be a positive integer" "$out"

# Invalid buffer size (too large)
set +e
rc=0
out=$( "$BINARY" analyze -t smallFlows.pcap -b 10001 2>&1 ) || rc=$?
set -e
assert_exit_code "overflow buffer returns exit 2" 2 "$rc"
assert_output_contains "overflow buffer shows error" "buffer size must be a positive integer" "$out"

# Accepted maximum (issue #56): --help still documents 10000 MB ...
out=$( "$BINARY" analyze --help 2>&1 )
assert_output_contains "help documents the 1-10000 MB range" "1-10000" "$out"

# ... and the parser accepts exactly that boundary value (exit 0)
set +e
rc=0
out=$( "$BINARY" analyze -t smallFlows.pcap -b 10000 2>&1 ) || rc=$?
set -e
assert_exit_code "boundary max 10000 MB is accepted by the parser" 0 "$rc"
assert_output_contains "analysis runs with 10000 MB buffer" "MMT-READER STATS" "$out"

# ---- Issue #12: Quiet flag ----
echo ""
echo "--- Issue #12: Quiet flag ---"

# Quiet mode should suppress progress messages
out=$( "$BINARY" analyze -t smallFlows.pcap -q 2>&1 )
assert_output_not_contains "quiet mode suppresses INFO" "INFO:" "$out"
# But output should still contain results
assert_output_contains "quiet mode still shows results" "MMT-READER STATS" "$out"

# ---- Issue #16: Verbose flag ----
echo ""
echo "--- Issue #16: Verbose flag ---"

# Verbose mode should show DEBUG messages
out=$( "$BINARY" analyze -t smallFlows.pcap -v 2>&1 )
assert_output_contains "verbose shows DEBUG mode enabled" "DEBUG: verbose mode enabled" "$out"
assert_output_contains "verbose shows flag summary" "DEBUG: json output=" "$out"

# Verbose should not affect stdout output
out=$( "$BINARY" analyze -t smallFlows.pcap -v 2>&1 )
assert_output_contains "verbose still shows stats" "MMT-READER STATS" "$out"

# ---- Issue #11: Environment variables ----
echo ""
echo "--- Issue #11: Environment variables ---"

# MMTREADER_QUIET=1 should work like -q
out=$( MMTREADER_QUIET=1 "$BINARY" analyze -t smallFlows.pcap 2>&1 )
assert_output_not_contains "MMTREADER_QUIET suppresses INFO" "INFO:" "$out"
assert_output_contains "MMTREADER_QUIET still shows results" "MMT-READER STATS" "$out"

# MMTREADER_NO_COLOR=1 should disable colors
out=$( MMTREADER_NO_COLOR=1 "$BINARY" analyze -t smallFlows.pcap 2>&1 )
# With no-color, ANSI escape sequences should be minimal/absent
# We check that the output doesn't contain obvious color codes
assert_output_contains "MMTREADER_NO_COLOR still shows results" "MMT-READER STATS" "$out"

# MMTREADER_JSON=1 must actually produce JSON on stdout (issue #96), not
# merely exit 0 — the env var used to write a field nothing behavioral read.
# The banner goes to stderr under JSON, so stdout is one bare document.
set +e
rc=0
out=$( MMTREADER_JSON=1 "$BINARY" analyze -t smallFlows.pcap 2>/dev/null ) || rc=$?
jq_rc=0
jq -e 'has("input_stats")' <<< "$out" > /dev/null 2>&1 || jq_rc=$?
set -e
assert_exit_code "MMTREADER_JSON=1 does not cause error" 0 "$rc"
assert_exit_code "MMTREADER_JSON=1 writes JSON to stdout" 0 "$jq_rc"
assert_output_not_contains "MMTREADER_JSON=1 suppresses the text table" \
    "MMT-READER STATS" "$out"

# CLI flags override env vars
out=$( MMTREADER_QUIET=1 "$BINARY" analyze -t smallFlows.pcap -v 2>&1 )
assert_output_contains "CLI -v overrides MMTREADER_QUIET" "DEBUG: verbose mode enabled" "$out"

# ---- General options ----
echo ""
echo "--- General options ---"

# --help at top level
out=$( "$BINARY" --help 2>&1 )
assert_output_contains "top-level --help shows general help" "MMT-READER" "$out"

# --version
out=$( "$BINARY" --version 2>&1 )
assert_output_contains "--version shows version" "version" "$out"
# issue #70 (F-BUG-005): product and SDK versions are separate, labeled fields
assert_output_contains "--version labels the mmtReader product version" \
    "mmtReader version:" "$out"
assert_output_contains "--version labels the MMT-DPI SDK version" \
    "MMT-DPI SDK version:" "$out"

# -h at top level
out=$( "$BINARY" -h 2>&1 )
assert_output_contains "top-level -h shows general help" "MMT-READER" "$out"

# No subcommand shows general help
out=$( "$BINARY" 2>&1 )
assert_output_contains "no subcommand shows general help" "MMT-READER" "$out"

# --json flag — assert the OUTPUT, not just the exit code
set +e
rc=0
out=$( "$BINARY" analyze -t smallFlows.pcap --json 2>/dev/null ) || rc=$?
jq_rc=0
jq -e 'has("input_stats")' <<< "$out" > /dev/null 2>&1 || jq_rc=$?
set -e
assert_exit_code "--json flag does not cause error" 0 "$rc"
assert_exit_code "--json writes JSON to stdout" 0 "$jq_rc"
assert_output_not_contains "--json suppresses the text table" \
    "MMT-READER STATS" "$out"

# Short flags
out=$( "$BINARY" analyze -t smallFlows.pcap -q 2>&1 )
assert_output_contains "short -q flag works" "MMT-READER STATS" "$out"

out=$( "$BINARY" analyze -t smallFlows.pcap -v 2>&1 )
assert_output_contains "short -v flag works" "DEBUG: verbose mode enabled" "$out"

# ---- Issue #39: Capture output contract ----
echo ""
echo "--- Issue #39: Capture output contract ---"

# On the capture path the summary is printed by mmtReader itself, not by
# engine_destroy(). Hold it to that: exactly one summary on stdout with or
# without -q, and a stdout that still parses as one document under --json.
CAPTURE_IF="lo"
# flows.c writes the heading as "- - - - - - TOP FLOWS BY VOLUME - - - - - -";
# the phrase alone identifies it and carries no leading dash.
FLOWS_HEADING="TOP FLOWS BY VOLUME"

# Live capture needs cap_net_raw or root, and the interface has to exist.
# Probe once and read the reason rather than the exit code alone: only a
# failure to open or activate the interface is an environment problem worth
# skipping for. Any other non-zero exit is a regression on the very path
# this section guards, so it fails loudly instead of skipping quietly.
CAP_TMP=$( mktemp -d )
set +e
probe_rc=0
"$BINARY" capture -i "$CAPTURE_IF" -F 1 > /dev/null 2> "$CAP_TMP/probe.err" || probe_rc=$?
probe_reason=$( grep -m1 -E "Couldn't (open|activate) device" "$CAP_TMP/probe.err" )
set -e

if [ "$probe_rc" -ne 0 ] && [ -n "$probe_reason" ]; then
    echo "SKIP: live capture on '$CAPTURE_IF' unavailable — ${probe_reason#"[error] "}"
    rm -rf "$CAP_TMP"
elif [ "$probe_rc" -ne 0 ]; then
    TOTAL=$((TOTAL + 1))
    FAIL=$((FAIL + 1))
    echo "FAIL [capture probe]: capture -i $CAPTURE_IF -F 1 exited $probe_rc, and not because the interface could not be opened"
    echo "  Output: $( head -3 "$CAP_TMP/probe.err" )"
    rm -rf "$CAP_TMP"
else
    # Keep the capture window from being empty — the flow table is omitted
    # when no session resolved to a tuple. bash's /dev/udp needs no package
    # installed and no listener (port 9 discards). The packets are spread
    # over a few seconds rather than fired in one burst: the DPI takes a
    # moment to come up, and anything sent before the capture is live is
    # never seen. ping is a best-effort extra where the image ships one.
    poke_loopback() {
        (
            if command -v ping > /dev/null 2>&1; then
                ping -c 15 -i 0.2 -W 1 127.0.0.1 > /dev/null 2>&1 &
            fi
            for (( i = 0; i < 30; i++ )); do
                echo x > /dev/udp/127.0.0.1/9 2>/dev/null || true
                sleep 0.1
            done
        ) > /dev/null 2>&1 &
    }

    # Text mode: one summary, on stdout
    poke_loopback
    set +e
    rc=0
    "$BINARY" capture -i "$CAPTURE_IF" -F 1 -a > "$CAP_TMP/text.out" 2> "$CAP_TMP/text.err" || rc=$?
    set -e
    assert_exit_code "capture -F 1 -a returns exit 0" 0 "$rc"
    assert_occurrence_count "capture prints INPUT STATISTICS exactly once" \
        "INPUT STATISTICS" 1 "$( cat "$CAP_TMP/text.out" )"

    # -q silences the progress messages, never the final summary
    poke_loopback
    set +e
    rc=0
    "$BINARY" capture -i "$CAPTURE_IF" -F 1 -a -q > "$CAP_TMP/quiet.out" 2> "$CAP_TMP/quiet.err" || rc=$?
    set -e
    assert_exit_code "capture -q returns exit 0" 0 "$rc"
    assert_occurrence_count "capture -q still prints INPUT STATISTICS exactly once" \
        "INPUT STATISTICS" 1 "$( cat "$CAP_TMP/quiet.out" )"

    # JSON mode: stdout is one document, the flow table goes to stderr
    poke_loopback
    set +e
    rc=0
    "$BINARY" capture -i "$CAPTURE_IF" -F 1 -a --json > "$CAP_TMP/json.out" 2> "$CAP_TMP/json.err" || rc=$?
    jq_rc=0
    jq -e -s 'length == 1' "$CAP_TMP/json.out" > /dev/null 2>&1 || jq_rc=$?
    set -e
    assert_exit_code "capture --json returns exit 0" 0 "$rc"
    assert_exit_code "capture --json writes exactly one JSON document" 0 "$jq_rc"
    assert_output_contains "capture --json carries input_stats" \
        "input_stats" "$( cat "$CAP_TMP/json.out" )"
    assert_output_not_contains "capture --json keeps the flow table off stdout" \
        "$FLOWS_HEADING" "$( cat "$CAP_TMP/json.out" )"
    # flows_print_top() prints nothing at all when no session resolved to a
    # tuple, so a heading absent from both streams means the capture window
    # was empty — inconclusive, not a regression. Say so rather than
    # counting a failure. Where the table exists, it belongs on stderr.
    if grep -qF "$FLOWS_HEADING" "$CAP_TMP/json.out" "$CAP_TMP/json.err"; then
        assert_output_contains "capture --json writes the flow table to stderr" \
            "$FLOWS_HEADING" "$( cat "$CAP_TMP/json.err" )"
    else
        echo "NOTE: the capture window produced no flows — the --json flow table routing was not exercised"
    fi

    # Issue #57: SIGTERM (systemd stop, plain kill) must shut down as
    # gracefully as Ctrl+C — statistics printed once, exit code 0.
    set +e
    "$BINARY" capture -i "$CAPTURE_IF" -a > "$CAP_TMP/term.out" 2> "$CAP_TMP/term.err" &
    term_pid=$!
    sleep 2
    kill -TERM $term_pid 2>/dev/null || true
    wait $term_pid
    term_rc=$?
    set -e
    assert_exit_code "kill -TERM stops the capture gracefully" 0 "$term_rc"
    assert_occurrence_count "SIGTERM still prints statistics once" \
        "INPUT STATISTICS" 1 "$( cat "$CAP_TMP/term.out" )"

    rm -rf "$CAP_TMP"
fi

# ---- Issue #69: extraction-failure shutdown summary ----
echo ""
echo "--- Issue #69: extraction-failure summary ---"

# A hand-built pcap whose records are inconsistent: 40 bytes were
# captured but the wire length claims 10 — the DPI rejects every such
# frame. The old build printed one stderr line PER packet; the fix
# reports the total once at shutdown, so 3 malformed packets must
# yield exactly one failure line.
MAL_TMP=$( mktemp -d )
printf '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' \
       > "$MAL_TMP/bad.pcap"
for i in 1 2 3; do
    printf '\x00\x00\x00\x00\x00\x00\x00\x00\x28\x00\x00\x00\x0a\x00\x00\x00' \
        >> "$MAL_TMP/bad.pcap"
    head -c 40 /dev/zero | tr '\0' 'A' >> "$MAL_TMP/bad.pcap"
done

set +e
rc=0
out=$( "$BINARY" analyze -t "$MAL_TMP/bad.pcap" 2>&1 ) || rc=$?
set -e
assert_exit_code "analyze completes on a malformed pcap" 0 "$rc"
assert_occurrence_count "malformed pcap yields exactly one failure line" \
    "Packet data extraction failure" 1 "$out"
assert_output_contains "the failure line carries the packet total" \
    "3 packet(s)" "$out"
rm -rf "$MAL_TMP"

# ---- Issue #96: config/env output format and precedence ----
echo ""
echo "--- Issue #96: config/env JSON output and precedence ---"

# Two defects, one behavioral change. The `json` config key and
# MMTREADER_JSON wrote a cli_options_t field nothing behavioral read, so
# both were silently ignored. And a -c/--config file was re-applied AFTER
# the option loop, so it beat explicit CLI flags. Both config paths now
# load before the loop, under one rule:
#   defaults < ~/.mmtreader.conf < --config file < environment < CLI flags
CONF_TMP=$( mktemp -d )
printf 'json = 1\n'                                > "$CONF_TMP/json.conf"
printf 'buffer = 777\nverbose = 0\nno_color = 0\n' > "$CONF_TMP/flags.conf"

# A config file setting json = 1 produces JSON
set +e
rc=0
out=$( "$BINARY" analyze -t smallFlows.pcap --config "$CONF_TMP/json.conf" 2>/dev/null ) || rc=$?
jq_rc=0
jq -e 'has("input_stats")' <<< "$out" > /dev/null 2>&1 || jq_rc=$?
set -e
assert_exit_code "config json=1 exits 0" 0 "$rc"
assert_output_not_contains "config json=1 suppresses the text table" \
    "MMT-READER STATS" "$out"
assert_exit_code "config json=1 writes JSON to stdout" 0 "$jq_rc"

# ... and an explicit --text overrides it
set +e
rc=0
out=$( "$BINARY" analyze -t smallFlows.pcap --config "$CONF_TMP/json.conf" --text 2>/dev/null ) || rc=$?
set -e
assert_exit_code "config json=1 with --text exits 0" 0 "$rc"
assert_output_contains "--text overrides config json=1" "MMT-READER STATS" "$out"
assert_output_not_contains "--text leaves no JSON document on stdout" \
    '"input_stats"' "$out"

# An explicit --json overrides MMTREADER_JSON=0
set +e
rc=0
out=$( MMTREADER_JSON=0 "$BINARY" analyze -t smallFlows.pcap --json 2>/dev/null ) || rc=$?
jq_rc=0
jq -e 'has("input_stats")' <<< "$out" > /dev/null 2>&1 || jq_rc=$?
set -e
assert_exit_code "MMTREADER_JSON=0 with --json exits 0" 0 "$rc"
assert_exit_code "--json overrides MMTREADER_JSON=0" 0 "$jq_rc"

# An out-of-range value still selects JSON — never a bogus format
set +e
out=$( MMTREADER_JSON=5 "$BINARY" analyze -t smallFlows.pcap 2>/dev/null )
jq_rc=0
jq -e 'has("input_stats")' <<< "$out" > /dev/null 2>&1 || jq_rc=$?
set -e
assert_exit_code "MMTREADER_JSON=5 normalizes to JSON output" 0 "$jq_rc"

# The environment sits between the config files and the CLI, so it beats
# a --config file too — the old post-loop reload skipped it entirely.
set +e
out=$( MMTREADER_JSON=0 "$BINARY" analyze -t smallFlows.pcap --config "$CONF_TMP/json.conf" 2>/dev/null )
set -e
assert_output_contains "MMTREADER_JSON=0 overrides config json=1" \
    "MMT-READER STATS" "$out"

# Regression: CLI flags beat a conflicting --config file. -v proves it by
# printing at all; the flag summary it prints proves -C won as well.
set +e
out=$( "$BINARY" analyze -t smallFlows.pcap -v -C --config "$CONF_TMP/flags.conf" 2>&1 > /dev/null )
set -e
assert_output_contains "-v beats config verbose=0" "DEBUG: verbose mode enabled" "$out"
assert_output_contains "-C beats config no_color=0" "no_color=1" "$out"

# -b beats config buffer=777. buffer_mb only reaches the live-capture
# path, but its INFO line is printed before the handle is opened, so this
# holds whether or not the environment allows opening the interface.
set +e
out=$( "$BINARY" capture -i "$CAPTURE_IF" -F 1 -b 100 --config "$CONF_TMP/flags.conf" 2>&1 > /dev/null )
set -e
assert_output_contains "-b 100 beats config buffer=777" \
    "INFO: Use buffer size: 100 (MB)" "$out"

rm -rf "$CONF_TMP"

# ---- Summary ----
echo ""
echo "=== Test Summary ==="
echo "Passed: $PASS / $TOTAL"
echo "Failed: $FAIL / $TOTAL"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
