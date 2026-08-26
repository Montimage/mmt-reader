#!/usr/bin/env bash
#
# test_sdk_check.sh — Tests for the Makefile `check-sdk` target
# (minimum MMT-DPI SDK pin, issue #51).
#
# Builds throwaway SDK header fixtures in a temp dir and runs
# `make -s check-sdk MMT_DPI=<fixture>` against each, asserting both the
# exit status and the error text. Never touches the real /opt/mmt/dpi.
#
# Usage: bash tests/test_sdk_check.sh   (wired into `make test` as Test 14)

set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR_FIXTURES="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_FIXTURES"' EXIT

tests_run=0
tests_pass=0
tests_fail=0

report_pass() { tests_pass=$((tests_pass + 1)); echo "PASS: $1"; }
report_fail() { tests_fail=$((tests_fail + 1)); echo "FAIL: $1"; }

assert_check() {
    local desc="$1" version="$2" want_rc="$3" want_pattern="$4"
    local fixture="$TMPDIR_FIXTURES/$version"
    mkdir -p "$fixture/include"
    if [ "$version" != "NO_HEADER_FILE" ]; then
        printf '#ifndef MMT_CORE_H\n#define MMT_CORE_H\n#define VERSION "%s"\n#endif\n' \
            "$version" >"$fixture/include/mmt_core.h"
    fi

    local output rc
    output="$(cd "$ROOT" && make -s check-sdk "MMT_DPI=$fixture" 2>&1)"
    rc=$?
    tests_run=$((tests_run + 1))

    # A failed recipe makes the sub-make exit 2 regardless of the recipe's
    # own exit status, so failure cases assert any non-zero status.
    if [ "$want_rc" = "0" ]; then
        if [ "$rc" -ne 0 ]; then
            report_fail "$desc (expected exit 0, got $rc; output: $output)"
            return
        fi
    elif [ "$rc" -eq 0 ]; then
        report_fail "$desc (expected non-zero exit, got 0)"
        return
    fi
    if [ -n "$want_pattern" ] && ! printf '%s' "$output" | grep -qE "$want_pattern"; then
        report_fail "$desc (exit OK but output missing /$want_pattern/: $output)"
        return
    fi
    report_pass "$desc"
}

echo "=== SDK Version Check Unit Tests ==="
echo ""

# Too old → abort with an explicit requirement message.
assert_check "SDK 1.7.10 is rejected with explicit message" \
    "1.7.10" 1 'SDK ≥ 1\.8\.0 required'

# Exactly the minimum and newer → accepted.
assert_check "SDK 1.8.0 is accepted"        "1.8.0"  0 '1\.8\.0 OK'
assert_check "SDK 1.9.1 is accepted"        "1.9.1"  0 ''
assert_check "SDK 1.10.0 is accepted (sort -V)" "1.10.0" 0 ''

# Broken installs → clear errors instead of cryptic link failures.
assert_check "Missing mmt_core.h reports SDK not found" \
    "NO_HEADER_FILE" 1 'not found at'
assert_check "Header without VERSION define is rejected" \
    "no-version-macro" 1 'cannot read SDK version'

echo ""
echo "=== Results ==="
echo "Run:  $tests_run"
echo "Pass: $tests_pass"
echo "Fail: $tests_fail"

[ "$tests_fail" -eq 0 ]
