"""Tests for the opsec primitives and the lockout-aware sprayer.

Network is never touched: the sshpass/paramiko backends and the auth-method
precheck are monkeypatched, so the test exercises the timing, rotation, and
lockout-aware cadence logic deterministically.
"""

from __future__ import annotations

import asyncio
import random

import pytest

from honeywatch import opsec
from honeywatch.opsec import (
    LoginAttempt,
    ProxyPool,
    jitter_delay,
    within_business_hours,
)
from honeywatch.spray import (
    SprayHost,
    SprayPlan,
    spray_plan,
)


# --------------------------------------------------------------------------- #
# Timing
# --------------------------------------------------------------------------- #


def test_jitter_delay_nonnegative():
    rng = random.Random(0)
    for _ in range(50):
        d = jitter_delay(0.5, 0.5, rng)
        assert d >= 0.0


def test_jitter_delay_zero_jitter_is_base():
    assert jitter_delay(1.0, 0.0) == 1.0


def test_business_hours_window():
    from datetime import datetime

    # Tuesday 10:00 is inside the default 08:00-18:00 window.
    assert within_business_hours(datetime(2024, 1, 16, 10, 0)) is True
    # Sunday any time is excluded (weekdays_only default).
    assert within_business_hours(datetime(2024, 1, 21, 12, 0)) is False
    # 02:00 Tuesday is outside the window.
    assert within_business_hours(datetime(2024, 1, 16, 2, 0)) is False


# --------------------------------------------------------------------------- #
# Source rotation
# --------------------------------------------------------------------------- #


def test_proxy_pool_round_robin(tmp_path):
    pf = tmp_path / "proxies.txt"
    pf.write_text("socks5://1.1.1.1:1080\n# comment\nsocks5://2.2.2.2:1080\n", encoding="utf-8")
    pool = ProxyPool.from_files(proxy_file=str(pf))
    assert bool(pool) is True
    a = pool.next()
    b = pool.next()
    c = pool.next()
    # Two distinct proxies round-robin, then wrap.
    assert a["proxy"] != b["proxy"]
    assert c["proxy"] == a["proxy"]
    assert a["jump"] is None and b["jump"] is None


def test_proxy_pool_empty_is_direct():
    pool = ProxyPool()
    assert bool(pool) is False
    assert pool.next() == {"proxy": None, "jump": None}


def test_proxy_pool_missing_file_is_empty():
    pool = ProxyPool.from_files(proxy_file="nope.txt", jump_file="nope2.txt")
    assert bool(pool) is False


# --------------------------------------------------------------------------- #
# Spray orchestration (mocked backends)
# --------------------------------------------------------------------------- #


def _winning_sshpass(ip, port, user, password, timeout_s=15.0, proxy=None, jump=None,
                     ssh_bin="ssh", sshpass_bin="sshpass"):
    return LoginAttempt(user=user, password=password, success=True,
                        backend="sshpass", source=proxy or jump)


def _failing_sshpass(ip, port, user, password, timeout_s=15.0, proxy=None, jump=None,
                     ssh_bin="ssh", sshpass_bin="sshpass"):
    return LoginAttempt(user=user, password=password, success=False,
                        backend="sshpass", error="denied", source=proxy or jump)


def _no_password_auth(ip, port, user, timeout_s=6.0):
    return opsec.AuthMethods(ip=ip, port=port, user=user,
                             methods=["publickey"], offers_password=False)


def _password_auth(ip, port, user, timeout_s=6.0):
    return opsec.AuthMethods(ip=ip, port=port, user=user,
                             methods=["publickey", "password"], offers_password=True)


# spray.py imported these names at load time, so they must be patched in the
# spray module's namespace (not opsec's) for the monkeypatch to take effect.
import honeywatch.spray as spray_mod


def _patch_backends(monkeypatch, auth=_password_auth, attempt=None):
    monkeypatch.setattr(spray_mod, "auth_methods", auth)
    if attempt is not None:
        monkeypatch.setattr(spray_mod, "attempt_sshpass", attempt)
    monkeypatch.setattr(spray_mod, "_sshpass_available", lambda: True)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_spray_skips_publickey_only_host(monkeypatch):
    called = {"n": 0}

    def boom(*a, **k):
        called["n"] += 1
        return LoginAttempt(user="x", password="y", success=True)

    _patch_backends(monkeypatch, auth=_no_password_auth, attempt=boom)
    host = SprayHost(ip="10.0.0.5", port=22, users=["root", "admin"])
    plan = SprayPlan(password="Summer2024!", hosts=[host], delay=0.0, jitter=0.0)
    res = _run(spray_plan(plan, pool=ProxyPool(), use_sshpass=True))
    assert res[0].skipped is True
    assert "no password auth" in (res[0].skip_reason or "")
    assert called["n"] == 0


def test_spray_recovers_and_stops_on_success(monkeypatch):
    attempts = {"order": []}

    def fake(ip, port, user, password, timeout_s=15.0, proxy=None, jump=None,
             ssh_bin="ssh", sshpass_bin="sshpass"):
        attempts["order"].append(user)
        ok = user == "admin"
        return LoginAttempt(user=user, password=password, success=ok,
                            backend="sshpass", source=proxy or jump)

    _patch_backends(monkeypatch, auth=_password_auth, attempt=fake)
    host = SprayHost(ip="10.0.0.5", port=22, users=["root", "admin", "ops"])
    plan = SprayPlan(password="Summer2024!", hosts=[host], delay=0.0, jitter=0.0,
                     stop_on_success=True)
    res = _run(spray_plan(plan, pool=ProxyPool(), use_sshpass=True))
    assert res[0].success is True
    assert res[0].user == "admin"
    assert res[0].password == "Summer2024!"
    assert attempts["order"] == ["root", "admin"]
    assert res[0].attempts == 2


def test_spray_no_precheck_sprays_anyway(monkeypatch):
    _patch_backends(monkeypatch, auth=_no_password_auth, attempt=_failing_sshpass)
    host = SprayHost(ip="10.0.0.6", port=22, users=["root", "admin"])
    plan = SprayPlan(password="x", hosts=[host], delay=0.0, jitter=0.0,
                     skip_publickey_only=False)
    res = _run(spray_plan(plan, pool=ProxyPool(), use_sshpass=True))
    assert res[0].skipped is False
    assert res[0].attempts == 2
    assert res[0].success is False


def test_spray_rotates_source_per_attempt(monkeypatch):
    seen_sources: list = []

    def fake(ip, port, user, password, timeout_s=15.0, proxy=None, jump=None,
             ssh_bin="ssh", sshpass_bin="sshpass"):
        seen_sources.append(proxy or jump)
        return LoginAttempt(user=user, password=password, success=False,
                            backend="sshpass", source=proxy or jump)

    _patch_backends(monkeypatch, auth=_password_auth, attempt=fake)
    pool = ProxyPool(proxies=["socks5://1.1.1.1:1080", "socks5://2.2.2.2:1080"])
    host = SprayHost(ip="10.0.0.7", port=22, users=["a", "b", "c", "d"])
    plan = SprayPlan(password="x", hosts=[host], delay=0.0, jitter=0.0)
    _run(spray_plan(plan, pool=pool, use_sshpass=True))
    assert seen_sources == ["socks5://1.1.1.1:1080", "socks5://2.2.2.2:1080",
                            "socks5://1.1.1.1:1080", "socks5://2.2.2.2:1080"]


def test_spray_credential_dict():
    from honeywatch.spray import SprayResult
    r = SprayResult(ip="1.2.3.4", port=22, success=True, user="root",
                    password="pw", attempts=1)
    d = r.credential()
    assert d == {"ip": "1.2.3.4", "port": 22, "user": "root", "password": "pw",
                 "success": True, "attempts": 1}