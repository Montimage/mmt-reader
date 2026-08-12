#!/usr/bin/env bash
#
# install.sh — Fully self-contained installer for MMT-Reader.
#
# Installs EVERYTHING on a fresh machine:
#   1. System dependencies  (gcc, make, libpcap-dev, …)
#   2. MMT-DPI library      (builds from source if not present)
#   3. mmtReader binary     (compiles and installs)
#   4. Man page
#   5. Shell capabilities   (cap_net_raw — no sudo for live capture)
#   6. Shell completions (bash)
#
# Usage:
#   sudo ./install.sh                    # Install everything (default)
#   sudo ./install.sh --mmt-dpi /path    # Use pre-built MMT-DPI at /path
#   sudo ./install.sh --mmt-reader-only  # Skip MMT-DPI, only install mmtReader
#   sudo ./install.sh --uninstall        # Remove everything
#
# After install, live capture works WITHOUT sudo:
#   mmtReader capture eth0 -a -s
#
# Requirements:
#   - Root (sudo) — needed for system-wide installation
#   - Internet connection (to install system packages)
#

set -euo pipefail

# ─── Colors & logging ─────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; }
step()  { echo -e "${BLUE}━━━${NC} $*"; }

# ─── Defaults ─────────────────────────────────────────────
PREFIX="/usr/local"
BINDIR="${PREFIX}/bin"
MANDIR="${PREFIX}/share/man"
MAN1DIR="${MANDIR}/man1"
COMPLETIONS_DIR="${PREFIX}/share/bash-completion/completions"
MMT_BASE="/opt/mmt"
MMT_DPI_DIR="${MMT_BASE}/dpi"
MMT_DPI_INC="${MMT_DPI_DIR}/include"
MMT_DPI_LIB="${MMT_DPI_DIR}/lib"

SKIP_MMT_DPI=false
MMT_DPI_PATH=""
UNINSTALL=false
DRY_RUN=false

# Resolve script directory early (needed for non-root sudo runs)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Parse args ───────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mmt-dpi)         MMT_DPI_PATH="$2"; shift 2 ;;
        --mmt-reader-only) SKIP_MMT_DPI=true; shift ;;
        --uninstall)       UNINSTALL=true; shift ;;
        --prefix)          PREFIX="$2"; BINDIR="${2}/bin"; MANDIR="${2}/share/man"; MAN1DIR="${MANDIR}/man1"; COMPLETIONS_DIR="${2}/share/bash-completion/completions"; shift 2 ;;
        --dry-run)         DRY_RUN=true; shift ;;
        *)                 error "Unknown option: $1"; echo "Usage: sudo $0 [--mmt-dpi /path] [--mmt-reader-only] [--uninstall] [--prefix /path]"; exit 1 ;;
    esac
done

# ─── Helpers ──────────────────────────────────────────────
needs_sudo() {
    if [[ $EUID -ne 0 ]]; then
        # Allow non-root if using a custom prefix outside system dirs
        if [[ "$PREFIX" != "/usr/local" && "$PREFIX" != "/usr" && "$PREFIX" != "/opt" ]]; then
            warn "Running as non-root with custom prefix ${PREFIX} — no system-wide changes made."
            return 1
        fi
        if $DRY_RUN; then
            warn "Not running as root — adding sudo for privileged commands."
        else
            error "This script requires root privileges for prefix ${PREFIX}."
            error "Run: sudo $0 $*"
            exit 1
        fi
    fi
}

run() {
    if $DRY_RUN; then
        echo -e "${YELLOW}[DRY-RUN]${NC} $*"
    else
        eval "$@"
    fi
}

# ─── Detect OS ────────────────────────────────────────────
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
    elif command -v lsb_release &>/dev/null; then
        OS_ID="$(lsb_release -si | tr '[:upper:]' '[:lower:]')"
        OS_VERSION="$(lsb_release -sr)"
    else
        OS_ID="unknown"
        OS_VERSION="unknown"
    fi
    OS_NAME="${OS_ID} ${OS_VERSION}"
}

get_package_manager() {
    if command -v apt-get &>/dev/null; then
        PM="apt"
    elif command -v dnf &>/dev/null; then
        PM="dnf"
    elif command -v yum &>/dev/null; then
        PM="yum"
    else
        error "No supported package manager found (apt, dnf, yum)."
        exit 1
    fi
}

# ─── Check setcap availability ────────────────────────────
HAS_SETCAP=false
command -v setcap &>/dev/null && HAS_SETCAP=true

# ─── Uninstall ────────────────────────────────────────────
if $UNINSTALL; then
    step "Uninstalling MMT-Reader and MMT-DPI..."
    needs_sudo || true

    # Remove capabilities from mmtReader binary
    if [[ -f "${BINDIR}/mmtReader" ]]; then
        run "setcap -r '${BINDIR}/mmtReader' 2>/dev/null || true"
    fi

    # Remove mmtReader binary
    if [[ -f "${BINDIR}/mmtReader" ]]; then
        run "rm -f '${BINDIR}/mmtReader'"
        info "Removed ${BINDIR}/mmtReader"
    fi

    # Remove man page
    if [[ -f "${MAN1DIR}/mmtReader.1" ]]; then
        run "rm -f '${MAN1DIR}/mmtReader.1'"
        info "Removed man page"
    fi

    # Remove bash completion
    if [[ -f "${COMPLETIONS_DIR}/mmtReader" ]]; then
        run "rm -f '${COMPLETIONS_DIR}/mmtReader'"
        info "Removed bash completion"
    fi

    # Remove MMT-DPI
    if [[ -d "${MMT_BASE}" ]]; then
        run "rm -rf '${MMT_BASE}'"
        info "Removed ${MMT_BASE}"
    fi

    # Remove ldconfig entry
    if [[ -f /etc/ld.so.conf.d/mmt-dpi.conf ]]; then
        run "rm -f /etc/ld.so.conf.d/mmt-dpi.conf"
        run "ldconfig"
        info "Removed ldconfig entry"
    fi

    info "MMT-Reader uninstalled successfully."
    exit 0
fi

# ─── Pre-flight ───────────────────────────────────────────
step "MMT-Reader Self-Contained Installer"
echo ""
detect_os
echo "  OS:        ${OS_NAME}"
echo "  Arch:      $(uname -m)"
echo "  Install:   ${PREFIX}"
echo "  MMT-DPI:   ${MMT_DPI_DIR}"
echo ""

get_package_manager
needs_sudo || true

# ─── Phase 1: System Dependencies ─────────────────────────
step "Phase 1: Checking system dependencies..."

# Check if dependencies are already available (skip install if non-root)
HAS_GCC=false
HAS_LIBPCAP=false
HAS_MAKE=false

command -v gcc &>/dev/null && HAS_GCC=true
dpkg -l libpcap-dev &>/dev/null && HAS_LIBPCAP=true
command -v make &>/dev/null && HAS_MAKE=true

if $HAS_GCC && $HAS_LIBPCAP && $HAS_MAKE; then
    info "All system dependencies already installed."
else
    if [[ $EUID -eq 0 ]]; then
        # Root — install missing packages
        if [[ "$PM" == "apt" ]]; then
            run "apt-get update -qq"
            SYSTEM_PKGS=()
            $HAS_GCC    || SYSTEM_PKGS+=(build-essential gcc g++ make)
            $HAS_LIBPCAP || SYSTEM_PKGS+=(libpcap-dev)
            $HAS_MAKE   || SYSTEM_PKGS+=(make)
            if [[ ${#SYSTEM_PKGS[@]} -gt 0 ]]; then
                run "apt-get install -y -qq ${SYSTEM_PKGS[@]}"
            fi
            info "System dependencies installed (apt)."
        elif [[ "$PM" == "dnf" || "$PM" == "yum" ]]; then
            SYSTEM_PKGS=()
            $HAS_GCC    || SYSTEM_PKGS+=(gcc gcc-c++)
            $HAS_LIBPCAP || SYSTEM_PKGS+=(libpcap-devel)
            $HAS_MAKE   || SYSTEM_PKGS+=(make)
            if [[ ${#SYSTEM_PKGS[@]} -gt 0 ]]; then
                if [[ "$PM" == "dnf" ]]; then
                    run "dnf install -y ${SYSTEM_PKGS[@]}"
                else
                    run "yum install -y ${SYSTEM_PKGS[@]}"
                fi
            fi
            info "System dependencies installed (${PM})."
        fi
    else
        # Non-root — warn but continue if gcc is available
        if ! $HAS_GCC; then
            error "gcc not found. Install it manually: sudo apt-get install build-essential"
            exit 1
        fi
        if ! $HAS_LIBPCAP; then
            warn "libpcap-dev not found via dpkg. Assuming it's installed (non-root check)."
        fi
        info "Skipping system package installation (non-root). gcc $(gcc -dumpversion) found."
    fi
fi

# ─── Phase 2: MMT-DPI Library ────────────────────────────
if $SKIP_MMT_DPI; then
    step "Phase 2: Skipping MMT-DPI (--mmt-reader-only)."
    if [[ ! -f "${MMT_DPI_LIB}/libmmt_core.so" ]]; then
        error "MMT-DPI not found at ${MMT_DPI_LIB}/libmmt_core.so"
        error "Run without --mmt-reader-only to install it, or use --mmt-dpi /path"
        exit 1
    fi
    info "Using existing MMT-DPI at ${MMT_DPI_DIR}."
else
    step "Phase 2: Installing MMT-DPI library..."

    # Check if MMT-DPI source is available locally
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    MMT_DPI_SRC="${SCRIPT_DIR}/../mmt-dpi"

    if [[ -f "${MMT_DPI_SRC}/sdk/Makefile" ]]; then
        # Use local MMT-DPI source
        info "Found local MMT-DPI source at ${MMT_DPI_SRC}"
        MMT_DPI_BUILD_DIR="${MMT_DPI_SRC}/sdk"
        MMT_DPI_SRC="${MMT_DPI_BUILD_DIR}/.."  # fix: re-resolve for sibling detection
        MMT_DPI_VERSION="auto"
        MMT_DPI_GIT_VERSION="$(cd "${MMT_DPI_SRC}" && git log --format="%h" -n 1 2>/dev/null || echo "local")"

        run "cd '${MMT_DPI_BUILD_DIR}' && make VERSION=${MMT_DPI_VERSION} GIT_VERSION=${MMT_DPI_GIT_VERSION} MMT_BASE=${MMT_BASE} install"

        # Run ldconfig
        if [[ ! $DRY_RUN ]]; then
            echo "${MMT_DPI_LIB}" > /etc/ld.so.conf.d/mmt-dpi.conf
            ldconfig
        fi

        info "MMT-DPI built and installed to ${MMT_DPI_DIR}."

    elif [[ -n "${MMT_DPI_PATH}" && -f "${MMT_DPI_PATH}/lib/libmmt_core.so" ]]; then
        # Use pre-built MMT-DPI at custom path
        info "Using pre-built MMT-DPI from ${MMT_DPI_PATH}"
        run "cp -r '${MMT_DPI_PATH}/include' '${MMT_DPI_PATH}/lib' '${MMT_DPI_DIR}/'"
        if [[ ! $DRY_RUN ]]; then
            echo "${MMT_DPI_LIB}" > /etc/ld.so.conf.d/mmt-dpi.conf
            ldconfig
        fi
        info "MMT-DPI installed from ${MMT_DPI_PATH}."

    elif [[ -f "${MMT_DPI_SRC}/sdk/mmt-dpi_*.deb" ]]; then
        # Use pre-built .deb from local repo
        DEB_FILE="$(ls "${MMT_DPI_SRC}/sdk/mmt-dpi_*.deb" | head -1)"
        info "Installing MMT-DPI from ${DEB_FILE}"
        run "dpkg -i '${DEB_FILE}'"
        run "ldconfig"
        info "MMT-DPI installed from .deb package."

    else
        error "MMT-DPI source not found."
        error "Provide it with: --mmt-dpi /path/to/mmt-dpi/sdk"
        error "Or place the mmt-dpi repo as a sibling directory to mmt-reader."
        exit 1
    fi

    # Verify MMT-DPI
    if [[ ! -f "${MMT_DPI_LIB}/libmmt_core.so" ]]; then
        error "MMT-DPI library not found after installation."
        exit 1
    fi
    info "MMT-DPI verified: ${MMT_DPI_LIB}/libmmt_core.so"
fi

# ─── Phase 3: Compile mmtReader ───────────────────────────
step "Phase 3: Compiling mmtReader..."

# cd to script dir — sudo may have changed cwd to /root
if [[ ! -f "${SCRIPT_DIR}/mmtReader.c" ]]; then
    error "mmtReader.c not found. Working directory is $(pwd)."
    error "This script must be run from its own directory: cd ${SCRIPT_DIR} && sudo ./install.sh"
    exit 1
fi
cd "${SCRIPT_DIR}"

CC="gcc"
CFLAGS="-g -O2"

# All source files (matches Makefile)
SRCS="mmtReader.c core/engine.c utils/version.c utils/colors.c cli/parse.c cli/output.c capture.c flows.c config.c"

if ! ${CC} ${CFLAGS} -o mmtReader ${SRCS} \
        -I"." -I"${MMT_DPI_INC}" -I"./utils" -I"./cli" \
        -L"${MMT_DPI_LIB}" \
        -lmmt_core -ldl -lpcap; then
    error "Compilation failed. Check your MMT-DPI installation."
    exit 1
fi
info "Compiled mmtReader."

# ─── Phase 4: Install mmtReader ───────────────────────────
step "Phase 4: Installing mmtReader..."

run "mkdir -p '${BINDIR}'"
run "install -m 755 mmtReader '${BINDIR}/mmtReader'"
info "Binary → ${BINDIR}/mmtReader"

if [[ -f "mmtReader.1" ]]; then
    run "mkdir -p '${MAN1DIR}'"
    run "install -m 644 mmtReader.1 '${MAN1DIR}/mmtReader.1'"
    info "Man page → ${MAN1DIR}/mmtReader.1"
else
    warn "mmtReader.1 not found — skipping man page."
fi

# Install shell completions
if [[ -d "completions" ]]; then
    run "mkdir -p '${COMPLETIONS_DIR}'"
    if [[ -f "completions/mmtReader.bash" ]]; then
        run "install -m 644 completions/mmtReader.bash '${COMPLETIONS_DIR}/mmtReader'"
        info "Bash completion → ${COMPLETIONS_DIR}/mmtReader"
    fi
    if [[ -f "completions/mmtReader.zsh" ]]; then
        info "Zsh completion available in completions/mmtReader.zsh (manual install)"
    fi
    if [[ -f "completions/mmtReader.fish" ]]; then
        info "Fish completion available in completions/mmtReader.fish (manual install)"
    fi
else
    warn "completions/ directory not found — skipping shell completions."
fi

# ─── Phase 5: Set capabilities (live capture without sudo) ──
if $HAS_SETCAP; then
    step "Phase 5: Setting capabilities for live capture (no sudo needed)..."
    # Grant CAP_NET_RAW so mmtReader can open interfaces in promiscuous mode
    # without requiring root. This enables: ./mmtReader capture eth0 -a
    if $DRY_RUN; then
        echo -e "${YELLOW}[DRY-RUN]${NC} setcap 'cap_net_raw+ep' '${BINDIR}/mmtReader'"
        info "Capabilities would be set (dry-run)."
    elif setcap 'cap_net_raw+ep' "${BINDIR}/mmtReader" 2>/dev/null; then
        info "Capabilities set: cap_net_raw"
    else
        echo ""
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║  MANUAL STEP REQUIRED: Set capabilities for live capture ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${YELLOW}setcap${NC} failed (likely because sudo didn't have a TTY)."
        echo "  Live capture will still require ${RED}sudo${NC} until you run this manually:"
        echo ""
        echo -e "    ${GREEN}sudo setcap 'cap_net_raw+ep' ${BINDIR}/mmtReader${NC}"
        echo ""
        echo "  This lets mmtReader open interfaces in promiscuous mode"
        echo "  without needing root — so you can run:"
        echo ""
        echo -e "    ${GREEN}mmtReader capture eth0 -a -s${NC}"
        echo ""
    fi
else
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  MANUAL STEP REQUIRED: Install setcap utility            ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${RED}setcap${NC} not found. Install it to enable live capture without sudo:"
    echo ""
    echo -e "    ${GREEN}sudo apt-get install libcap2-bin${NC}"
    echo ""
    echo "  Then set capabilities:"
    echo ""
    echo -e "    ${GREEN}sudo setcap 'cap_net_raw+ep' ${BINDIR}/mmtReader${NC}"
    echo ""
fi

# ─── Phase 6: Verify ──────────────────────────────────────
step "Phase 6: Verifying installation..."

if "${BINDIR}/mmtReader" -h &>/dev/null; then
    info "✅ mmtReader is installed and working!"
    echo ""
    echo "  Quick start:"
    echo "    mmtReader -t your_file.pcap -a"
    echo ""

    # Check if capabilities are already set
    # getcap exits 0 even when the file has no capabilities — test its output
    if [[ -n "$(getcap "${BINDIR}/mmtReader" 2>/dev/null)" ]]; then
        echo "  Live capture (no sudo needed):"
        echo "    mmtReader capture eth0 -a -s"
        echo ""
    else
        echo "  ⚠️  Live capture still requires sudo. To remove that restriction, run manually:"
        echo ""
        echo -e "    ${GREEN}sudo setcap 'cap_net_raw+ep' ${BINDIR}/mmtReader${NC}"
        echo ""
    fi

    echo "  Uninstall:"
    echo "    sudo $0 --uninstall"
    echo ""
else
    error "Installation verification failed."
    exit 1
fi
