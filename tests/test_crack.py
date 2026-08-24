"""Tests for the SSH password cracker and credential persistence.

The online login path is exercised by injecting a fake ``paramiko`` module
into ``sys.modules`` and stubbing ``socket.create_connection`` so no real
network is touched. The credential store is tested against a temp sqlite db.
"""

from __future__ import annotations

import asyncio
import socket
import sys
import types

import pytest

from honeywatch import crack as crack_mod
from honeywatch.crack import (
    CrackTarget,
    candidate_passwords,
    crack_host,
    crack_targets,
    default_users,
    load_wordlist,
)
from honeywatch.store import Store


# --------------------------------------------------------------------------- #
# Wordlist / candidate generation
# --------------------------------------------------------------------------- #


def test_load_wordlist_missing_returns_empty(tmp_path):
    assert load_wordlist(str(tmp_path / "nope.txt")) == []


def test_load_wordlist_reads_and_skips_comments(tmp_path):
    p = tmp_path / "wl.txt"
    p.write_text("# comment\nalpha\n\nbeta\n# tail\n", encoding="utf-8")
    assert load_wordlist(str(p)) == ["alpha", "beta"]


def test_default_users_is_defensive_copy():
    a = default_users()
    b = default_users()
    assert a == b
    a.append("custom")
    assert "custom" not in default_users()


def test_candidate_passwords_unique_and_includes_mutations():
    cands = list(candidate_passwords(wordlist=["summer"], mutations=True))
    # No duplicates.
    assert len(cands) == len(set(cands))
    # Seed verbatim present.
    assert "summer" in cands
    # Case mutations present.
    assert "Summer" in cands
    assert "SUMMER" in cands
    # Year/suffix mutations present.
    assert "summer2024" in cands
    assert "summer123" in cands
    # Built-in defaults also present (builtins=True default).
    assert "password" in cands


def test_candidate_passwords_no_mutations():
    cands = list(candidate_passwords(wordlist=["alpha", "beta"], mutations=False, builtins=False))
    assert cands == ["alpha", "beta"]


def test_candidate_passwords_lazy_no_buffer():
    """The generator must dedupe without fully materializing the population."""
    gen = candidate_passwords(wordlist=["x"] * 1000, mutations=False, builtins=False)
    # Only one "x" survives dedupe.
    assert list(gen) == ["x"]


# --------------------------------------------------------------------------- #
# Fake paramiko harness
# --------------------------------------------------------------------------- #


def _install_fake_paramiko(monkeypatch, winner=None, ssh_exc=None):
    """Inject a fake paramiko so _attempt_login never touches the network.

    ``winner`` is an optional (user, password) pair that authenticates; every
    other pair raises the fake AuthenticationException. ``ssh_exc`` (if set)
    makes every attempt raise SSHException (a transport-level failure) so the
    error-recording path can be checked.
    """

    class AuthenticationException(Exception):
        pass

    class SSHException(Exception):
        pass

    class FakeSock:
        def settimeout(self, _t):
            pass

    class FakeTransport:
        def __init__(self, sock):
            self.sock = sock

        def start_client(self, timeout=None):
            if ssh_exc is not None:
                raise SSHException(ssh_exc)

        def auth_password(self, user, password):
            if winner is not None and (user, password) == winner:
                return None
            raise AuthenticationException()

        def close(self):
            pass

    fake = types.SimpleNamespace(
        Transport=FakeTransport,
        AuthenticationException=AuthenticationException,
        SSHException=SSHException,
    )
    monkeypatch.setitem(sys.modules, "paramiko", fake)
    # Stub the network so create_connection returns a dummy socket.
    monkeypatch.setattr(
        crack_mod.socket, "create_connection", lambda *a, **k: FakeSock()
    )
    return fake


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_crack_host_finds_winner(monkeypatch):
    _install_fake_paramiko(monkeypatch, winner=("root", "summer2024"))
    target = CrackTarget(
        ip="10.0.0.5",
        port=22,
        users=["root"],
        wordlist=["summer"],
        mutations=True,
        banner="SSH-2.0-test",  # skip banner grab
        timeout_s=2.0,
    )
    res = _run(crack_host(target, concurrency=4))
    assert res.success is True
    assert res.user == "root"
    assert res.password == "summer2024"
    assert res.attempts >= 1


def test_crack_host_failure_records_errors(monkeypatch):
    _install_fake_paramiko(monkeypatch, winner=None, ssh_exc="kex broken")
    target = CrackTarget(
        ip="10.0.0.6",
        port=22,
        users=["root"],
        passwords=["pw1", "pw2", "pw3"],
        banner="SSH-2.0-test",
        timeout_s=2.0,
    )
    res = _run(crack_host(target, concurrency=2))
    assert res.success is False
    assert res.attempts == 3
    # Every attempt recorded a transport-level error.
    assert res.errors and all("kex broken" in e for e in res.errors)
    assert len(res.transcript) == 3


def test_crack_host_max_attempts_caps(monkeypatch):
    _install_fake_paramiko(monkeypatch, winner=None)
    target = CrackTarget(
        ip="10.0.0.7",
        port=22,
        users=["root", "admin"],
        passwords=[f"p{i}" for i in range(50)],
        max_attempts=5,
        banner="SSH-2.0-test",
        timeout_s=2.0,
    )
    res = _run(crack_host(target, concurrency=2))
    assert res.attempts == 5


def test_crack_host_stop_on_success(monkeypatch):
    _install_fake_paramiko(monkeypatch, winner=("admin", "pw1"))
    target = CrackTarget(
        ip="10.0.0.8",
        port=22,
        users=["admin"],
        passwords=["pw1", "pw2", "pw3"],
        stop_on_success=True,
        banner="SSH-2.0-test",
        timeout_s=2.0,
    )
    res = _run(crack_host(target, concurrency=1))
    assert res.success is True
    assert res.password == "pw1"
    # Single-threaded + stop-on-success => exactly one attempt.
    assert res.attempts == 1


def test_crack_targets_multi_host(monkeypatch):
    _install_fake_paramiko(monkeypatch, winner=("root", "letmein"))
    targets = [
        CrackTarget(
            ip=f"10.0.0.{i}", port=22, users=["root"],
            passwords=["letmein", "nope"], banner="SSH-2.0-test", timeout_s=2.0,
        )
        for i in range(1, 4)
    ]
    results = _run(crack_targets(targets, concurrency=2, host_concurrency=3))
    assert len(results) == 3
    assert all(r.success for r in results)
    assert all(r.password == "letmein" for r in results)


def test_crack_targets_forwards_on_attempt(monkeypatch):
    """Regression: `crack_targets` must accept and forward ``on_attempt``.

    The CLI handler passes ``on_attempt=...`` for live per-attempt progress.
    Before the fix, ``crack_targets`` only declared ``on_result``, so every
    ``honeywatch crack`` invocation raised ``TypeError`` 100% of the time —
    a bug no unit test caught because the tests called ``crack_targets``
    directly without ``on_attempt``.
    """
    _install_fake_paramiko(monkeypatch, winner=("root", "letmein"))
    targets = [
        CrackTarget(
            ip="10.0.0.7", port=22, users=["root"],
            passwords=["letmein", "nope"], banner="SSH-2.0-test", timeout_s=2.0,
        )
    ]
    seen = []

    def on_attempt(attempt, result):
        seen.append((attempt.user, attempt.password, attempt.success))

    results = _run(
        crack_targets(targets, concurrency=2, host_concurrency=3, on_attempt=on_attempt)
    )

    # No TypeError, the host cracked, and the per-attempt callback actually fired.
    assert len(results) == 1
    assert results[0].success is True
    assert seen, "on_attempt was never invoked"
    assert any(u == "root" and pw == "letmein" and ok for u, pw, ok in seen)


# --------------------------------------------------------------------------- #
# Credential persistence in the store
# --------------------------------------------------------------------------- #


@pytest.fixture
def cred_store(tmp_path):
    return Store(str(tmp_path / "creds.db"))


def test_upsert_and_query_credentials(cred_store):
    cred_store.upsert_credential("1.2.3.4", 22, "root", "summer2024", banner="SSH-2.0-x", attempts=12)
    rows = cred_store.query_credentials()
    assert len(rows) == 1
    row = rows[0]
    assert row["ip"] == "1.2.3.4"
    assert row["port"] == 22
    assert row["user"] == "root"
    assert row["password"] == "summer2024"
    assert row["attempts"] == 12
    assert row["banner"] == "SSH-2.0-x"


def test_upsert_credential_replaces_in_place(cred_store):
    cred_store.upsert_credential("1.2.3.4", 22, "root", "old")
    cred_store.upsert_credential("1.2.3.4", 22, "root", "new")
    rows = cred_store.query_credentials()
    assert len(rows) == 1
    assert rows[0]["password"] == "new"


def test_query_credentials_filters(cred_store):
    cred_store.upsert_credential("1.1.1.1", 22, "root", "a")
    cred_store.upsert_credential("2.2.2.2", 2222, "admin", "b")
    cred_store.upsert_credential("1.1.1.1", 22, "admin", "c")
    assert len(cred_store.query_credentials(ip="1.1.1.1")) == 2
    assert len(cred_store.query_credentials(user="admin")) == 2
    assert len(cred_store.query_credentials(port=2222)) == 1


def test_credential_for_returns_most_recent(cred_store):
    cred_store.upsert_credential("9.9.9.9", 22, "root", "first")
    cred_store.upsert_credential("9.9.9.9", 22, "admin", "second")
    cred = cred_store.credential_for("9.9.9.9", 22)
    assert cred is not None
    # Most recently inserted wins (discovered_at ordering).
    assert cred["user"] in {"root", "admin"}
    assert cred["password"] in {"first", "second"}


def test_credential_for_missing_returns_none(cred_store):
    assert cred_store.credential_for("0.0.0.0", 22) is None


def test_crack_result_credential_dict(monkeypatch):
    _install_fake_paramiko(monkeypatch, winner=("root", "letmein"))
    target = CrackTarget(
        ip="10.0.0.9", port=22, users=["root"],
        passwords=["letmein"], banner="SSH-2.0-test", timeout_s=2.0,
    )
    res = _run(crack_host(target, concurrency=1))
    cred = res.credential()
    assert cred == {
        "ip": "10.0.0.9",
        "port": 22,
        "user": "root",
        "password": "letmein",
        "banner": "SSH-2.0-test",
        "success": True,
        "attempts": 1,
    }