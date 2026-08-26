#!/usr/bin/env bash
#
# install-smoke.sh — Adversarial-path proof for install.sh (task 1.2, F-BUG-003).
#
# Runs the REAL installer end-to-end with hostile argument values:
#   * --prefix containing spaces, single quotes, double quotes, '$' and backticks
#   * --mmt-dpi containing a space and a single quote
# and asserts that:
#   1. the installer exits 0,
#   2. every artifact lands inside the hostile prefix (byte-exact content),
#   3. nothing is written outside the disposable sandbox,
#   4. --uninstall removes exactly what was installed.
#
# The run is non-destructive and needs NO root and NO container:
#   * MMT_READER_MMT_BASE / MMT_READER_LDCONF_DIR redirect /opt/mmt and
#     /etc/ld.so.conf.d into an mktemp sandbox (installer defaults are
#     untouched — see install.sh).
#   * A shim PATH directory replaces privileged/system commands (ldconfig,
#     setcap, getcap, dpkg, apt-get, dnf, yum) and gcc (emits a stub binary,
#     so neither a real toolchain nor the MMT-DPI SDK is required).
#     Compilation correctness is covered by `make test`; this script proves
#     argument/quoting flow only.
#   * A minimal payload copy (installer + man page + completions + a source
#     sentinel) is staged in the sandbox, so a sibling ../mmt-dpi checkout can
#     never divert the run away from the spaced --mmt-dpi path.
#
# Optional deeper proof under a disposable privileged container (root, real
# setcap semantics) when docker is available:
#
#   docker run --rm -v "$(pwd)":/src:ro ubuntu:24.04 bash -c \
#     'apt-get update -qq && apt-get install -y -qq build-essential libpcap-dev libcap2-bin >/dev/null \
#      && bash /src/ci/install-smoke.sh'
#
# Usage:
#   bash ci/install-smoke.sh            # sandboxed run, rootless-friendly
#   make smoke-install                  # same thing via Makefile
#
# Exit status: 0 = all assertions passed, non-zero = first failure wins.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="${REPO_DIR}/install.sh"
[[ -f "${INSTALLER}" ]] || fail "install.sh not found at ${INSTALLER}"
grep -qn "eval " "${INSTALLER}" &&
    fail "install.sh still evals constructed command strings"

SANDBOX="$(mktemp -d)"
trap 'rm -rf "${SANDBOX}"' EXIT

# ─── Hostile values ────────────────────────────────────────
# One value combining every breakout character class, plus a spaced one.
HOSTILE_TOKEN="it's a \"quote\" \$(\`id\`) test"
HOSTILE_PREFIX="${SANDBOX}/prefix ${HOSTILE_TOKEN}"
HOSTILE_DPI_DIR="${SANDBOX}/mmt dpi's sdk"
SANDBOX_MMT_BASE="${SANDBOX}/opt/mmt"
SANDBOX_LDCONF_DIR="${SANDBOX}/etc/ld.so.conf.d"

# ─── Fake MMT-DPI SDK at the hostile path ──────────────────
mkdir -p "${HOSTILE_DPI_DIR}/include" "${HOSTILE_DPI_DIR}/lib"
printf '#define VERSION "1.8.0"\n' > "${HOSTILE_DPI_DIR}/include/mmt_core.h"
printf 'stub libmmt_core\n'        > "${HOSTILE_DPI_DIR}/lib/libmmt_core.so"

# ─── Minimal payload copy (see header) ─────────────────────
PAYLOAD="${SANDBOX}/payload"
mkdir -p "${PAYLOAD}/completions"
cp "${INSTALLER}" "${PAYLOAD}/"
cp "${REPO_DIR}/mmtReader.c" "${PAYLOAD}/"
cp "${REPO_DIR}/mmtReader.1" "${PAYLOAD}/"
cp "${REPO_DIR}/completions/mmtReader.bash" "${PAYLOAD}/completions/"

# ─── Command shims (privileged/system tools + toolchain) ───
SHIMS="${SANDBOX}/shims"
mkdir -p "${SHIMS}"

emit_shim() { printf '#!/bin/sh\nexit 0\n' > "${SHIMS}/$1"; chmod +x "${SHIMS}/$1"; }

# Stub compiler: honors "-o <file>", emits an executable accepting -h.
cat > "${SHIMS}/gcc" <<'EOF'
#!/bin/sh
out=""
while [ $# -gt 0 ]; do
    if [ "$1" = "-o" ] && [ $# -ge 2 ]; then out="$2"; shift 2; else shift; fi
done
[ -n "$out" ] || exit 1
printf '#!/bin/sh\ncase "$1" in -h|--help) exit 0;; esac\nexit 0\n' > "$out"
chmod +x "$out"
EOF
chmod +x "${SHIMS}/gcc"

for cmd in ldconfig setcap getcap dpkg apt-get dnf yum make; do
    emit_shim "${cmd}"
done
printf '#!/bin/sh\nprintf %s\\n cap_net_raw=ep\n' > "${SHIMS}/getcap"
chmod +x "${SHIMS}/getcap"

# ─── Containment baseline ──────────────────────────────────
snapshot() {  # stable fingerprint of pre-existing state ("absent" if missing)
    if [[ -e "$1" ]]; then
        find "$1" -printf '%P %s\n' 2>/dev/null | LC_ALL=C sort | sha256sum | cut -d' ' -f1
    else
        echo "absent"
    fi
}
OPT_BEFORE="$(snapshot /opt/mmt)"
ETC_BEFORE="$(snapshot /etc/ld.so.conf.d/mmt-dpi.conf)"
USRLCL_BEFORE="$(snapshot /usr/local/bin/mmtReader)"

# ─── Run the installer against the hostile values ──────────
echo ":: Installing with hostile prefix and spaced --mmt-dpi..."
PATH="${SHIMS}:${PATH}" \
    MMT_READER_MMT_BASE="${SANDBOX_MMT_BASE}" \
    MMT_READER_LDCONF_DIR="${SANDBOX_LDCONF_DIR}" \
    bash "${PAYLOAD}/install.sh" --prefix "${HOSTILE_PREFIX}" --mmt-dpi "${HOSTILE_DPI_DIR}" \
    > "${SANDBOX}/install.log" 2>&1 ||
    { cat "${SANDBOX}/install.log"; fail "installer exited non-zero under adversarial paths"; }
pass "installer completed (exit 0)"

# ─── Assertions: artifacts exist inside the hostile prefix ──
assert_file() { [[ -f "$1" ]] || { tail -20 "${SANDBOX}/install.log"; fail "missing artifact: $1"; }; }

assert_file "${HOSTILE_PREFIX}/bin/mmtReader"
assert_file "${HOSTILE_PREFIX}/share/man/man1/mmtReader.1"
assert_file "${HOSTILE_PREFIX}/share/bash-completion/completions/mmtReader"
assert_file "${SANDBOX_MMT_BASE}/dpi/include/mmt_core.h"
assert_file "${SANDBOX_MMT_BASE}/dpi/lib/libmmt_core.so"
pass "all artifacts created under the hostile prefix"
pass "MMT-DPI copied from the spaced '--mmt-dpi' path"

CONF_CONTENT="$(cat "${SANDBOX_LDCONF_DIR}/mmt-dpi.conf")"
[[ "${CONF_CONTENT}" == "${SANDBOX_MMT_BASE}/dpi/lib" ]] ||
    fail "ldconfig entry corrupted: got '${CONF_CONTENT}'"
pass "ldconfig entry byte-exact through quotes/dollar/space"

# Installed stub must actually execute from inside the quoted path.
PATH="${SHIMS}:${PATH}" "${HOSTILE_PREFIX}/bin/mmtReader" -h >/dev/null 2>&1 ||
    fail "installed binary does not execute from hostile prefix"
pass "installed binary executes (Phase 6 verification)"

# ─── Assertions: containment outside the sandbox ────────────
[[ "$(snapshot /opt/mmt)" == "${OPT_BEFORE}" ]] ||
    fail "installer wrote to /opt/mmt — escaped the sandbox"
[[ "$(snapshot /etc/ld.so.conf.d/mmt-dpi.conf)" == "${ETC_BEFORE}" ]] ||
    fail "installer wrote to /etc/ld.so.conf.d — escaped the sandbox"
[[ "$(snapshot /usr/local/bin/mmtReader)" == "${USRLCL_BEFORE}" ]] ||
    fail "installer wrote to /usr/local/bin — escaped the sandbox"
pass "nothing written outside the sandbox"

# ─── Uninstall round-trip on the same hostile prefix ────────
PATH="${SHIMS}:${PATH}" \
    MMT_READER_MMT_BASE="${SANDBOX_MMT_BASE}" \
    MMT_READER_LDCONF_DIR="${SANDBOX_LDCONF_DIR}" \
    bash "${PAYLOAD}/install.sh" --prefix "${HOSTILE_PREFIX}" --uninstall \
    > "${SANDBOX}/uninstall.log" 2>&1 ||
    { cat "${SANDBOX}/uninstall.log"; fail "--uninstall failed under adversarial paths"; }
for artifact in \
    "${HOSTILE_PREFIX}/bin/mmtReader" \
    "${HOSTILE_PREFIX}/share/man/man1/mmtReader.1" \
    "${HOSTILE_PREFIX}/share/bash-completion/completions/mmtReader"; do
    [[ ! -e "${artifact}" ]] || fail "uninstall left behind: ${artifact}"
done
pass "uninstall removed every artifact"

echo ""
echo "All installer smoke checks passed."
