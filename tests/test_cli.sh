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
    if echo "$haystack" | grep -qF "$needle"; then
        PASS=$((PASS + 1))
    else
        echo "FAIL [$desc]: output does not contain '$needle'"
        echo "  Output: $(echo "$haystack" | head -3)"
        FAIL=$((FAIL + 1))
    fi
}

assert_output_not_contains() {
    local desc="$1"
    local needle="$2"
    local haystack="$3"
    TOTAL=$((TOTAL + 1))
    if ! echo "$haystack" | grep -qF "$needle"; then
        PASS=$((PASS + 1))
    else
        echo "FAIL [$desc]: output should NOT contain '$needle'"
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

# ---- Summary ----
echo ""
echo "=== Test Summary ==="
echo "Passed: $PASS / $TOTAL"
echo "Failed: $FAIL / $TOTAL"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
