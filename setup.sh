#!/usr/bin/env bash
# honeywatch — Linux/Kali setup: venv provisioning + editable install.
#
# One command for a fresh Kali/Debian user:
#
#     ./setup.sh
#
# What it does, in order:
#   0. refuse to run as root/sudo (creates root-owned .venv + egg-info, which
#      breaks pip). It escalates to sudo ONLY for the apt step.
#   1. install the mandatory Python build/run system packages via apt (array,
#      no fragile backslash-continuation comments).
#   2. create a user-owned .venv, verify it, and bootstrap pip if missing.
#   3. detect & clean stale build metadata; refuse (with the exact fix) if any
#      is root-owned from a prior sudo run.
#   4. pip install -e .[full,c2,dev] (editable, no sudo).
#   5. validate: import honeywatch + `honeywatch --version` console entry point.
#   6. probe the external binaries the chain shells out to (+ hashcat GPU
#      runtime check), reporting missing ones instead of failing.
#
# Idempotent: safe to re-run. Never uses chmod 777, --break-system-packages,
# global pip, or sudo for anything inside .venv.
#
# Environment overrides (all optional):
#   VENV                   venv location (default: ./.venv)
#   HONEYWATCH_EXTRAS      pip extras (default: full,c2,dev)
#   PYTHON                 interpreter to build the venv from (default: python3)
#   SKIP_BINARY_CHECK=1    skip the masscan/hashcat/etc. probe
#   HONEYWATCH_ALLOW_ROOT=1  override the root guard (root-only containers)
set -Eeuo pipefail

VENV="${VENV:-.venv}"
HONEYWATCH_EXTRAS="${HONEYWATCH_EXTRAS:-full,c2,dev}"
PYTHON="${PYTHON:-python3}"
SKIP_BINARY_CHECK="${SKIP_BINARY_CHECK:-0}"
HONEYWATCH_ALLOW_ROOT="${HONEYWATCH_ALLOW_ROOT:-0}"

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
err()   { printf "${C_RED}[x]${C_RESET} %s\n" "$*" >&2; }

# -- error trap: readable message instead of a bare stack trace ------------- #
trap 'err "setup failed unexpectedly (exit $?). Re-run with: bash -x ./setup.sh"' ERR

# ========================================================================= #
# 0. root guard
# ========================================================================= #
if [ "$(id -u)" -eq 0 ]; then
    if [ "$HONEYWATCH_ALLOW_ROOT" != "1" ]; then
        err "setup.sh must NOT be run as root / with sudo."
        cat >&2 <<'EOF'

    Running the whole installer as root creates .venv/, *.egg-info, and
    repository files owned by root. pip then fails with
    "Cannot update time stamp of directory honeywatch.egg-info", ensurepip
    fails on the root-owned .venv/lib/, and the console script can't import
    the package.

    This script escalates to sudo ONLY for the apt step. Run it as a normal
    user:

        ./setup.sh

    Root-only container? Override with:  HONEYWATCH_ALLOW_ROOT=1 ./setup.sh
    (the resulting venv will be root-owned and not portable to other users.)
EOF
        exit 1
    fi
    warn "running as root (HONEYWATCH_ALLOW_ROOT=1); venv files will be root-owned"
fi

# ========================================================================= #
# project root (so `./setup.sh` works from any cwd)
# ========================================================================= #
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Normalize VENV to an absolute path. The venv-validation step below runs the
# venv's python and checks that `sys.executable` (always absolute) starts with
# $VENV — if VENV stays relative (the default ".venv") that check always fails
# on a real install, rejecting a perfectly good venv.
if command -v realpath >/dev/null 2>&1; then
    VENV="$(realpath -m "$VENV")"
else
    case "$VENV" in
        /*) : ;;
        *)  VENV="$(pwd)/$VENV" ;;
    esac
fi

# ========================================================================= #
# 1. Python present + version >= 3.10
# ========================================================================= #
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

# ========================================================================= #
# 2. system packages (apt — mandatory Python build/run deps)
#    Optional chain binaries are checked separately in step 6, never forced.
# ========================================================================= #
APT_PACKAGES=(
    python3
    python3-venv
    python3-pip
    python3-dev
    build-essential
    libssl-dev
    libffi-dev
)
if command -v apt-get >/dev/null 2>&1; then
    missing=()
    for p in "${APT_PACKAGES[@]}"; do
        if ! dpkg -s "$p" >/dev/null 2>&1; then
            missing+=("$p")
        fi
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        # Pick the escalation prefix: root needs none; passwordless sudo works;
        # otherwise we can't install non-interactively and just tell the user.
        if [ "$(id -u)" -eq 0 ]; then
            APT_CMD=(apt-get)
        elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
            APT_CMD=(sudo apt-get)
        else
            APT_CMD=()
        fi
        if [ "${#APT_CMD[@]}" -eq 0 ]; then
            warn "missing system packages, and sudo is not available non-interactively:"
            warn "    ${missing[*]}"
            warn "install them yourself, then re-run setup.sh:"
            printf "    sudo apt-get install -y --no-install-recommends %s\n" "${missing[*]}" >&2
        else
            info "installing system packages: ${missing[*]}"
            if ! "${APT_CMD[@]}" update -qq; then
                warn "apt-get update had a problem (continuing)"
            fi
            if ! "${APT_CMD[@]}" install -y --no-install-recommends "${missing[@]}"; then
                err "apt-get install failed; install these manually: ${missing[*]}"
                exit 1
            fi
            ok "system packages installed"
        fi
    else
        ok "all required system packages already present"
    fi
else
    info "apt-get not found (non-Debian/Kali); skipping system-package step"
    info "(make sure your Python ships venv+pip; on Fedora: python3-devel openssl-devel libffi-devel gcc)"
fi

# ========================================================================= #
# 3. stale / root-owned build metadata (the "cannot update time stamp" cause)
# ========================================================================= #
shopt -s nullglob
stale_dirs=()
for d in *.egg-info build dist; do
    [ -e "$d" ] && stale_dirs+=("$d")
done
shopt -u nullglob
if [ "${#stale_dirs[@]}" -gt 0 ]; then
    root_owned=()
    for d in "${stale_dirs[@]}"; do
        owner="$(stat -c %u "$d" 2>/dev/null || echo "")"
        if [ "$owner" = "0" ] && [ "$(id -u)" -ne 0 ]; then
            root_owned+=("$d")
        fi
    done
    if [ "${#root_owned[@]}" -gt 0 ]; then
        err "build-metadata directories are owned by root (from a prior sudo run):"
        printf "    %s\n" "${root_owned[@]}" >&2
        cat >&2 <<EOF

    pip cannot update them ("Cannot update time stamp of directory
    honeywatch.egg-info"). Fix with ONE of:

        sudo rm -rf ${root_owned[*]}
        sudo chown -R "$(id -un):$(id -gn)" ${root_owned[*]}

    Then re-run:  ./setup.sh
EOF
        exit 1
    fi
    # Ours (user-owned): a stale egg-info can confuse an editable reinstall;
    # clean it so the install below starts from a known-good state.
    info "removing stale build metadata: ${stale_dirs[*]}"
    rm -rf "${stale_dirs[@]}"
fi

# ========================================================================= #
# 4. venv: create if missing, verify ownership + pip, recreate if invalid
# ========================================================================= #
recreate_venv() {
    info "creating fresh venv at $VENV"
    "$PYTHON" -m venv "$VENV"
}

if [ -d "$VENV" ]; then
    venv_python="$VENV/bin/python"
    if [ ! -x "$venv_python" ]; then
        warn "venv exists at $VENV but has no usable python; recreating"
        recreate_venv
    else
        venv_owner="$(stat -c %u "$venv_python" 2>/dev/null || echo "")"
        if [ "$venv_owner" = "0" ] && [ "$(id -u)" -ne 0 ]; then
            err ".venv is owned by root (created by a prior sudo run):"
            cat >&2 <<EOF

    pip inside it cannot write and ensurepip fails on the root-owned
    .venv/lib/pythonX.Y. Remove it and let setup build a fresh, user-owned one:

        sudo rm -rf "$VENV"

    Then re-run:  ./setup.sh
EOF
            exit 1
        fi
        info "venv already exists at $VENV; reusing"
    fi
else
    recreate_venv
fi

# Verify the venv python actually runs.
if ! "$VENV/bin/python" -c 'import sys; sys.exit(0 if sys.executable.startswith("'"$VENV"'") else 1)' >/dev/null 2>&1; then
    err "venv python at $VENV/bin/python does not run correctly"
    err "remove it and re-run:  rm -rf \"$VENV\" && ./setup.sh"
    exit 1
fi

# Ensure pip is present (Debian/Kali venvs ship without pip unless
# python3-venv is installed — the apt step above handles that, ensurepip
# is the fallback).
if ! "$VENV/bin/python" -m pip --version >/dev/null 2>&1; then
    warn "pip missing in venv; bootstrapping via ensurepip"
    if ! "$VENV/bin/python" -m ensurepip --upgrade >/dev/null 2>&1; then
        err "could not bootstrap pip in $VENV"
        err "on Debian/Kali:  sudo apt-get install -y python3-venv python3-pip"
        err "then:  rm -rf \"$VENV\" && ./setup.sh"
        exit 1
    fi
fi
ok "venv ready: $VENV/bin/python"

# ========================================================================= #
# 5. upgrade pip/setuptools/wheel, then install honeywatch editable + extras
# ========================================================================= #
info "upgrading pip, setuptools, wheel in the venv"
if ! "$VENV/bin/python" -m pip install --upgrade pip setuptools wheel >/dev/null 2>&1; then
    warn "could not upgrade pip/setuptools/wheel (offline? continuing with bundled versions)"
fi

info "installing honeywatch editable with extras [$HONEYWATCH_EXTRAS]"
# shellcheck disable=SC2086
if ! "$VENV/bin/python" -m pip install -e ".[${HONEYWATCH_EXTRAS}]"; then
    err "pip install -e . failed; see output above"
    err "common causes: missing build deps (python3-dev / build-essential),"
    err "no network for build isolation, or a stale egg-info (cleaned in step 3)."
    exit 1
fi

# ========================================================================= #
# 6. post-install validation (do not claim success without proving it)
# ========================================================================= #
info "validating the install"
if ! "$VENV/bin/python" -c "import honeywatch; print('honeywatch', honeywatch.__version__)" >/dev/null; then
    err "validation failed: 'import honeywatch' did not succeed inside the venv"
    err "the editable install is broken; try a clean rebuild:"
    err "    rm -rf \"$VENV\" honeywatch.egg-info && ./setup.sh"
    exit 1
fi
if ! "$VENV/bin/honeywatch" --version >/dev/null 2>&1; then
    err "validation failed: the 'honeywatch' console command did not run"
    err "the console entry point (honeywatch = honeywatch.cli:main) is broken"
    err "try:  rm -rf \"$VENV\" honeywatch.egg-info && ./setup.sh"
    exit 1
fi
ok "validated: import honeywatch + 'honeywatch' console entry point"

# ========================================================================= #
# 7. external binary probe (+ hashcat GPU/OpenCL runtime check)
# ========================================================================= #
if [ "$SKIP_BINARY_CHECK" = "1" ]; then
    warn "SKIP_BINARY_CHECK=1; skipping external binary probe"
else
    info "checking external binaries the chain phases shell out to"
    # name|apt-package|phase
    BINSPEC=(
        "masscan|masscan|recon"
        "zmap|zmap|recon"
        "nmap|nmap|recon/enumerate"
        "sshpass|sshpass|spray/foothold/deploy"
        "hashcat|hashcat|escalate"
        "john|john|escalate"
    )
    missing=0
    printf "%-10s %-9s %-22s %s\n" "BINARY" "STATUS" "PHASE" "INSTALL HINT"
    for spec in "${BINSPEC[@]}"; do
        IFS='|' read -r bin pkg phase <<<"$spec"
        if command -v "$bin" >/dev/null 2>&1; then
            status="${C_GREEN}ok${C_RESET}      "
        else
            status="${C_RED}MISSING${C_RESET} "
            missing=$((missing + 1))
        fi
        printf "%-10s %-9s %-22s %s\n" "$bin" "$status" "$phase" "$pkg (apt/dnf/pacman)"
    done
    if [ "$missing" -gt 0 ]; then
        warn "$missing external binary/binaries missing -- the chain degrades gracefully"
        warn "(phases that need them report the gap and continue). For the full pipeline:"
        printf "    sudo apt-get install -y masscan zmap nmap sshpass hashcat john\n" >&2
    else
        ok "all external binaries present -- full pipeline available"
    fi

    # hashcat alone is not enough: it needs an OpenCL/CUDA/HIP runtime to
    # actually crack. Detect the common runtime markers and warn if absent.
    if command -v hashcat >/dev/null 2>&1; then
        has_gpu_runtime=0
        if compgen -G "/etc/OpenCL/vendors/*.icd" >/dev/null 2>&1; then
            has_gpu_runtime=1
        fi
        if command -v nvidia-smi >/dev/null 2>&1; then
            has_gpu_runtime=1
        fi
        if command -v clinfo >/dev/null 2>&1; then
            has_gpu_runtime=1
        fi
        if [ "$has_gpu_runtime" -eq 0 ]; then
            warn "hashcat is installed but no OpenCL/CUDA/HIP runtime was detected."
            warn "hashcat will fail to crack until a GPU compute runtime is present:"
            printf "    sudo apt-get install -y ocl-icd-opencl-dev mesa-opencl-icd\n" >&2
            printf "    # NVIDIA: nvidia-cuda-toolkit   |   AMD: rocm-opencl\n" >&2
        else
            ok "hashcat + a GPU/OpenCL runtime detected"
        fi
    fi
fi

# ========================================================================= #
# 8. next steps
# ========================================================================= #
cat <<EOF

${C_BOLD}Done.${C_RESET} Activate the venv before running honeywatch:

    . $VENV/bin/activate
    honeywatch --help

Configure once (persists Ollama key + Monero wallet/pool/worker/TLS):

    honeywatch setup

Then (Linux, full chain):

    honeywatch scan 10.0.0.0/24 --skip-vpn-check --no-ai
    honeywatch botnet 10.0.0.0/24 --payload xmrig --skip-vpn-check
    # --pool/--wallet/--worker/--tls default from `honeywatch setup`; pass them to override

Tests:

    pytest -q

Re-run ${C_BOLD}./setup.sh${C_RESET} any time to upgrade honeywatch + extras in place.
EOF