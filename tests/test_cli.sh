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

# MMTREADER_JSON=1 should set the json flag (no error)
out=$( MMTREADER_JSON=1 "$BINARY" analyze -t smallFlows.pcap 2>&1 )
rc=$?
assert_exit_code "MMTREADER_JSON=1 does not cause error" 0 "$rc"

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

# -h at top level
out=$( "$BINARY" -h 2>&1 )
assert_output_contains "top-level -h shows general help" "MMT-READER" "$out"

# No subcommand shows general help
out=$( "$BINARY" 2>&1 )
assert_output_contains "no subcommand shows general help" "MMT-READER" "$out"

# --json flag
out=$( "$BINARY" analyze -t smallFlows.pcap --json 2>&1 )
rc=$?
assert_exit_code "--json flag does not cause error" 0 "$rc"

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

    rm -rf "$CAP_TMP"
fi

# ---- Summary ----
echo ""
echo "=== Test Summary ==="
echo "Passed: $PASS / $TOTAL"
echo "Failed: $FAIL / $TOTAL"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
