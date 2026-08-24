"""Regression tests for the full-code-review fixes.

Each test pins the exact behavior a review finding described, so a future
refactor that reintroduces the bug fails loudly:

    H1  farm detection must require the same host key on 2+ hosts
    H2  instant-banner uses time-to-banner, not TCP connect latency
    M1  scanner subprocess timeout flows from config through to the runner
    M2  AI batch scoring is chunked, not one unbounded chat call
    M3  the Mullvad gate is enforced in Pipeline.scan, with opt-outs
    L2  store hydration skips rows it cannot reconstruct
    L3  `honeywatch --version` actually works
    L6  masscan excludes flow from config through to the argv
"""

from __future__ import annotations

import asyncio
import copy
import json
import re
import sqlite3

import pytest

from honeywatch import cli
from honeywatch.ai.ollama import OllamaClient
from honeywatch.ai.scorer import AiScorer, profile_key
from honeywatch.fingerprint.features import analyze
from honeywatch.fingerprint.probe import probe_ssh
from honeywatch.models import Fingerprint, Score, Signals
from honeywatch.pipeline import Pipeline
from honeywatch.store import Store
from honeywatch.vpn import VpnError
from honeywatch.config import Config, default_config


def _ssh_fp(ip: str, key: str | None = None, **kw) -> Fingerprint:
    fields = dict(
        ip=ip,
        port=22,
        banner="SSH-2.0-OpenSSH_8.9p1",
        protocol="2.0",
        software="OpenSSH",
        software_version="8.9p1",
    )
    if key is not None:
        fields["host_key_sha256"] = key
    fields.update(kw)
    return Fingerprint(**fields)


def _pipe() -> Pipeline:
    """A pipeline with the AI stage off (no network calls) and VPN on."""
    cfg = Config(default_config())
    cfg.ai.enabled = False
    return Pipeline(cfg)


# --------------------------------------------------------------------------
# H1: farm detection must require the SAME key on 2+ hosts
# --------------------------------------------------------------------------


def test_farm_flagged_when_same_key_on_two_hosts():
    pipe = _pipe()
    fps = [_ssh_fp("1.1.1.1", "a" * 64), _ssh_fp("2.2.2.2", "a" * 64)]
    scores = asyncio.run(pipe.analyze_and_score(fps))
    assert all("farm.hostkey_reuse" in s.signals.flags for s in scores)


def test_distinct_host_keys_are_not_farms():
    pipe = _pipe()
    fps = [_ssh_fp("1.1.1.1", "a" * 64), _ssh_fp("2.2.2.2", "b" * 64)]
    scores = asyncio.run(pipe.analyze_and_score(fps))
    assert all("farm.hostkey_reuse" not in s.signals.flags for s in scores)


def test_single_host_own_key_is_not_a_farm():
    # Regression: the old known_hashes set included each host's own key, so
    # every host in a scan was flagged as a farm.
    pipe = _pipe()
    scores = asyncio.run(pipe.analyze_and_score([_ssh_fp("1.1.1.1", "a" * 64)]))
    assert "farm.hostkey_reuse" not in scores[0].signals.flags


# --------------------------------------------------------------------------
# H2: instant-banner uses time-to-banner, not TCP connect latency
# --------------------------------------------------------------------------


def test_instant_banner_fires_on_fast_time_to_banner():
    sig = analyze(_ssh_fp("1.1.1.1", time_to_banner_ms=0.8))
    assert "timing.instant_banner" in sig.flags


def test_instant_banner_ignores_low_connect_ms():
    # Regression: the old signal fired on connect_ms (TCP path latency),
    # which flagged close hosts instead of instant responders.
    sig = analyze(_ssh_fp("1.1.1.1", connect_ms=0.8))
    assert "timing.instant_banner" not in sig.flags


def test_instant_banner_absent_for_normal_latency():
    sig = analyze(_ssh_fp("1.1.1.1", time_to_banner_ms=40.0))
    assert "timing.instant_banner" not in sig.flags


async def _banner_server():
    """A loopback server that answers with a real SSH identification line."""

    async def handle(reader, writer):
        writer.write(b"SSH-2.0-OpenSSH_8.9p1\r\n")
        await writer.drain()
        await asyncio.sleep(0.1)
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


def test_probe_records_time_to_banner():
    async def go():
        server, port = await _banner_server()
        try:
            fp = await probe_ssh("127.0.0.1", port=port, timeout=2.0)
            assert fp.banner == "SSH-2.0-OpenSSH_8.9p1"
            assert fp.time_to_banner_ms is not None
            assert fp.time_to_banner_ms >= 0.0
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(go())


# --------------------------------------------------------------------------
# M2: AI batch scoring is chunked
# --------------------------------------------------------------------------


def _scorer(model="test-model") -> OllamaClient:
    return OllamaClient(
        base_url="http://127.0.0.1:1",
        api_key=None,
        model=model,
        timeout=5,
    )


def test_scorer_batch_chunks_large_profile_sets(monkeypatch, openssh_fp):
    calls: list[str] = []

    def fake_chat(self, messages, json_mode=False):
        content = messages[-1]["content"]
        calls.append(content)
        keys = re.findall(r"\[profile ([0-9a-f]{64})\]", content)
        return json.dumps(
            {
                k: {"classification": "uncertain", "confidence": 0.5, "reasons": []}
                for k in keys
            }
        )

    monkeypatch.setattr(OllamaClient, "chat", fake_chat)
    monkeypatch.setattr(OllamaClient, "is_reachable", lambda self: True)

    profiles: dict[str, tuple[Fingerprint, object]] = {}
    for i in range(150):
        fp = copy.deepcopy(openssh_fp)
        fp.host_key_sha256 = f"{i:064x}"  # distinct profile per host
        profiles[profile_key(fp)] = (fp, analyze(fp))
    assert len(profiles) == 150

    verdicts = asyncio.run(AiScorer(_scorer(), batch=True).score(profiles))
    assert len(verdicts) == 150
    assert len(calls) == 2  # 150 profiles -> ceil(150/100) chunked calls


# --------------------------------------------------------------------------
# M3: the VPN gate is enforced in Pipeline.scan
# --------------------------------------------------------------------------


def test_scan_raises_without_vpn(monkeypatch):
    import honeywatch.vpn as vpn_mod

    monkeypatch.setattr(
        vpn_mod, "require_mullvad", lambda timeout=8.0, quiet=False: False
    )
    pipe = _pipe()  # vpn.required defaults to True
    with pytest.raises(VpnError):
        asyncio.run(pipe.scan(["192.0.2.0/24"]))


def test_scan_bypasses_vpn_with_flag(monkeypatch):
    import honeywatch.pipeline as pipe_mod

    async def fake_to_thread(fn, *a, **k):
        return []

    monkeypatch.setattr(pipe_mod.asyncio, "to_thread", fake_to_thread)
    pipe = _pipe()
    scores = asyncio.run(pipe.scan(["192.0.2.0/24"], skip_vpn_check=True))
    assert scores == []


def test_scan_bypasses_vpn_when_required_false(monkeypatch):
    import honeywatch.pipeline as pipe_mod

    async def fake_to_thread(fn, *a, **k):
        return []

    monkeypatch.setattr(pipe_mod.asyncio, "to_thread", fake_to_thread)
    cfg = Config(default_config())
    cfg.ai.enabled = False
    cfg.vpn.required = False
    scores = asyncio.run(Pipeline(cfg).scan(["192.0.2.0/24"]))
    assert scores == []


# --------------------------------------------------------------------------
# M1 / L6: scanner timeout and excludes flow through Pipeline.scan
# --------------------------------------------------------------------------


def test_scan_passes_scanner_timeout(monkeypatch):
    import honeywatch.pipeline as pipe_mod

    captured: dict = {}

    async def fake_to_thread(fn, *a, **k):
        captured["args"] = (fn, a, k)
        return []

    monkeypatch.setattr(pipe_mod.asyncio, "to_thread", fake_to_thread)
    cfg = Config(default_config())
    cfg.ai.enabled = False
    cfg.vpn.required = False
    cfg.scanners.masscan.timeout_s = 123
    asyncio.run(Pipeline(cfg).scan(["192.0.2.0/24"]))

    fn, args, kwargs = captured["args"]
    assert args[3] == 123  # timeout_s positional arg
    assert "excludes" not in kwargs


def test_scan_passes_masscan_excludes(monkeypatch):
    import honeywatch.pipeline as pipe_mod

    captured: dict = {}

    async def fake_to_thread(fn, *a, **k):
        captured["args"] = (fn, a, k)
        return []

    monkeypatch.setattr(pipe_mod.asyncio, "to_thread", fake_to_thread)
    cfg = Config(default_config())
    cfg.ai.enabled = False
    cfg.vpn.required = False
    cfg.scanners.masscan.exclude = ["10.0.0.0/8", "127.0.0.0/8"]
    asyncio.run(Pipeline(cfg).scan(["0.0.0.0/0"]))

    fn, args, kwargs = captured["args"]
    assert kwargs["excludes"] == ["10.0.0.0/8", "127.0.0.0/8"]


def test_zmap_never_receives_excludes(monkeypatch):
    import honeywatch.pipeline as pipe_mod

    captured: dict = {}

    async def fake_to_thread(fn, *a, **k):
        captured["kwargs"] = k
        return []

    monkeypatch.setattr(pipe_mod.asyncio, "to_thread", fake_to_thread)
    cfg = Config(default_config())
    cfg.ai.enabled = False
    cfg.vpn.required = False
    cfg.scanners.masscan.exclude = ["10.0.0.0/8"]
    asyncio.run(Pipeline(cfg).scan(["192.0.2.0/24"], tool="zmap"))
    assert captured["kwargs"] == {}


# --------------------------------------------------------------------------
# L2: store hydration survives schema drift
# --------------------------------------------------------------------------


def test_query_scores_skips_incompatible_row(tmp_path):
    store = Store(str(tmp_path / "t.db"))
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    conn.execute(
        "INSERT INTO hosts (ip, port, final_label, final_confidence, json, scanned_at) "
        "VALUES (?,?,?,?,?,?)",
        ("9.9.9.9", 1, "uncertain", 0.5, '{"fingerprint": {"bogus": 1}}', "now"),
    )
    conn.commit()
    conn.close()
    assert store.query_scores(limit=10) == []


def test_query_scores_round_trips_valid_row(tmp_path):
    fp = _ssh_fp("5.6.7.8", "c" * 64)
    sig = Signals(
        anomalies=["legacy"],
        flags=["crypto.legacy_cipher"],
        heuristic_score=0.3,
        evidence={"banner": fp.banner},
    )
    score = Score(
        ip="5.6.7.8",
        port=22,
        fingerprint=fp,
        signals=sig,
        final_confidence=0.5,
        final_label="uncertain",
    )
    store = Store(str(tmp_path / "t2.db"))
    store.upsert_scores([score])

    rows = store.query_scores(limit=10)
    assert len(rows) == 1
    assert rows[0].ip == "5.6.7.8"
    assert rows[0].fingerprint.host_key_sha256 == "c" * 64
    assert "crypto.legacy_cipher" in rows[0].signals.flags


# --------------------------------------------------------------------------
# L3: `honeywatch --version` works
# --------------------------------------------------------------------------


def test_version_flag_returns_zero():
    assert cli.main(["--version"]) == 0
