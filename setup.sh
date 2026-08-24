#!/bin/sh
# honeywatch — Linux venv provisioning.
#
# Creates a Python virtualenv, installs honeywatch editable with the optional
# extras (full + c2 + dev), and checks the external binaries the different
# chain phases shell out to. Idempotent: safe to re-run.
#
# Usage:
#   ./setup.sh                         # .venv/ + [full,c2,dev]
#   VENV=/opt/hw ./setup.sh             # custom venv path
#   HONEYWATCH_EXTRAS=full ./setup.sh   # only the paramiko extra (no c2/dev)
#   SKIP_BINARY_CHECK=1 ./setup.sh      # skip the masscan/hashcat/etc. probe
#
# Environment overrides:
#   VENV               venv location (default: ./.venv)
#   HONEYWATCH_EXTRAS   pip extras (default: full,c2,dev)
#   PYTHON             python interpreter to build the venv from (default: python3)
set -eu

VENV="${VENV:-.venv}"
HONEYWATCH_EXTRAS="${HONEYWATCH_EXTRAS:-full,c2,dev}"
PYTHON="${PYTHON:-python3}"

# -- colors (only when stdout is a tty) ------------------------------------ #
if [ -t 1 ]; then
    C_BOLD="\033[1m"; C_GREEN="\033[32m"; C_YELLOW="\033[33m"; C_RED="\033[31m"
    C_DIM="\033[2m"; C_RESET="\033[0m"
else
    C_BOLD=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_DIM=""; C_RESET=""
fi
info()  { printf "${C_BOLD}[*]${C_RESET} %s\n" "$*"; }
ok()    { printf "${C_GREEN}[+]${C_RESET} %s\n" "$*"; }
warn()  { printf "${C_YELLOW}[!]${C_RESET} %s\n" "$*"; }
err()   { printf "${C_RED}[x]${C_RESET} %s\n" "$*"; }

# -- 1. python present + version >= 3.10 ----------------------------------- #
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    err "no '$PYTHON' on PATH; install Python >= 3.10 first"
    exit 1
fi
PY_VER="$("$PYTHON" -c 'import sys;print("%d.%d"%(sys.version_info[:2]))')"
PY_MAJOR="${PY_VER%%.*}"; PY_MINOR="${PY_VER##*.}"
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    err "Python $PY_VER found; honeywatch needs >= 3.10"
    exit 1
fi
ok "Python $PY_VER ($("$PYTHON" -c 'import sys;print(sys.executable)'))"

# -- 2. venv (create if missing, ensure pip + uv-friendly) ----------------- #
if [ -d "$VENV" ] && [ -x "$VENV/bin/python" ]; then
    info "venv already exists at $VENV; reusing"
else
    info "creating venv at $VENV"
    "$PYTHON" -m venv "$VENV"
fi
# venv on some distros ships without pip bootstrapped; ensure it.
if ! "$VENV/bin/python" -m pip --version >/dev/null 2>&1; then
    warn "pip missing in venv; bootstrapping via ensurepip"
    "$VENV/bin/python" -m ensurepip --upgrade || {
        err "could not bootstrap pip in $VENV"
        exit 1
    }
fi
"$VENV/bin/python" -m pip install --upgrade pip >/dev/null 2>&1 || \
    warn "pip self-upgrade skipped (offline?)"
ok "venv ready: $VENV/bin/python"

# -- 3. install honeywatch editable + extras ------------------------------- #
info "installing honeywatch editable with extras [$HONEYWATCH_EXTRAS]"
# shellcheck disable=SC2086
"$VENV/bin/python" -m pip install -e ".[${HONEYWATCH_EXTRAS}]" || {
    err "pip install failed; see output above"
    exit 1
}
ok "honeywatch installed: $("$VENV/bin/honeywatch" --version 2>/dev/null || echo 'present')"

# -- 4. external binary check (the real capability gate) ------------------- #
if [ "${SKIP_BINARY_CHECK:-0}" = "1" ]; then
    warn "SKIP_BINARY_CHECK=1; skipping external binary probe"
else
    info "checking external binaries the chain phases shell out to"
    # name|package-hint|phase
    BINS="masscan|masscan|recon
zmap|zmap|recon
nmap|nmap|recon/enumerate
sshpass|sshpass|spray/foothold/deploy
hashcat|hashcat|escalate
john|john|escalate"
    missing=0
    printf "%-10s %-8s %-22s %s\n" "BINARY" "STATUS" "PHASE" "INSTALL HINT"
    while IFS='|' read -r bin pkg phase; do
        if command -v "$bin" >/dev/null 2>&1; then
            status="${C_GREEN}ok${C_RESET}      "
        else
            status="${C_RED}MISSING${C_RESET} "
            missing=$((missing + 1))
        fi
        printf "%-10s %-15s %-22s %s\n" "$bin" "$status" "$phase" "$pkg (apt/dnf/pacman)"
    done <<EOF
$BINS
EOF
    if [ "$missing" -gt 0 ]; then
        warn "$missing external binary/binaries missing -- the chain degrades gracefully"
        warn "(phases that need them report the gap and the run continues), but for the"
        warn "full pipeline install them, e.g. Debian/Ubuntu:"
        printf "    sudo apt-get install -y masscan zmap nmap sshpass hashcat john\n"
    else
        ok "all external binaries present -- full pipeline available"
    fi
fi

# -- 5. next steps --------------------------------------------------------- #
cat <<EOF

${C_BOLD}Done.${C_RESET} Activate the venv before running honeywatch:

    . $VENV/bin/activate

Then (Linux, full chain):

    honeywatch scan 10.0.0.0/24 --skip-vpn-check --no-ai
    honeywatch botnet 10.0.0.0/24 --pool stratum+tcp://... --wallet ... --skip-vpn-check

Tests:

    pytest -q

Re-run this script any time to upgrade honeywatch + extras in place.
EOF