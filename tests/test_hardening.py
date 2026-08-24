"""Tests for the final hardening pass: integrity, SQL resume, config key
consumption, HTTP conformance, and the masscan --wait accuracy fix."""

from __future__ import annotations

import asyncio
import hashlib
import json

import pytest

from honeywatch.config import Config, default_config
from honeywatch.models import HostHit, Target
from honeywatch.ops import build_manifest
from honeywatch.payloads.integrity import (
    expected_for,
    load_integrity,
    verify_bytes,
    verify_file,
)
from honeywatch.pipeline import Pipeline
from honeywatch.store import Store


# ---------------------------------------------------------------------------
# C3: artifact integrity
# ---------------------------------------------------------------------------

def test_integrity_helpers():
    data = b"hello"
    digest = hashlib.sha256(data).hexdigest()
    assert verify_bytes(data, digest) is True
    assert verify_bytes(data, "0" * 64) is False
    assert verify_bytes(data, "") is False


def test_load_integrity_reads_toml(tmp_path):
    p = tmp_path / "integrity.toml"
    p.write_text('xmrig = "abc123"\nupx = "deadbeef"\n', encoding="utf-8")
    manifest = load_integrity(str(p))
    assert manifest == {"xmrig": "abc123", "upx": "deadbeef"}
    assert load_integrity(None) == {}
    assert load_integrity("/does/not/exist.toml") == {}


def test_build_manifest_injects_pinned_sha256_from_manifest():
    manifest = build_manifest(
        "xmrig",
        [Target(ip="10.0.0.1", port=22)],
        {"pool": "stratum+tcp://p:3333", "wallet": "w"},
        integrity_manifest={"xmrig": "abc123"},
    )
    script = manifest.per_host_scripts["10.0.0.1"]
    assert "abc123" in script
    assert "sha256sum -c" in script
    assert "INTEGRITY FAILURE" in script


def test_build_manifest_warns_when_no_hash_pinned():
    manifest = build_manifest(
        "xmrig",
        [Target(ip="10.0.0.1", port=22)],
        {"pool": "stratum+tcp://p:3333", "wallet": "w"},
    )
    script = manifest.per_host_scripts["10.0.0.1"]
    # No hash -> the rendered script carries the UNVERIFIED warning, not a hash.
    assert "WITHOUT integrity verification" in script
    assert "sha256sum -c" in script  # the verify branch is still present


def test_build_manifest_require_integrity_refuses_without_hash():
    with pytest.raises(ValueError, match="no pinned sha256"):
        build_manifest(
            "xmrig",
            [Target(ip="10.0.0.1", port=22)],
            {"pool": "stratum+tcp://p:3333", "wallet": "w"},
            require_integrity=True,
        )


def test_build_manifest_require_integrity_passes_with_hash():
    manifest = build_manifest(
        "xmrig",
        [Target(ip="10.0.0.1", port=22)],
        {"pool": "stratum+tcp://p:3333", "wallet": "w"},
            integrity_manifest={"xmrig": "abc123"},
        require_integrity=True,
    )
    assert "abc123" in manifest.per_host_scripts["10.0.0.1"]


def test_build_manifest_var_expected_sha256_overrides_manifest():
    manifest = build_manifest(
        "xmrig",
        [Target(ip="10.0.0.1", port=22)],
        {"pool": "stratum+tcp://p:3333", "wallet": "w",
         "expected_sha256": "fromvar"},
        integrity_manifest={"xmrig": "frommanifest"},
    )
    script = manifest.per_host_scripts["10.0.0.1"]
    assert "fromvar" in script
    assert "frommanifest" not in script


def test_expected_for_falls_back_to_known_hashes():
    from honeywatch.payloads import integrity
    assert expected_for("xmrig", {"xmrig": "x"}) == "x"
    assert expected_for("xmrig", {}) == ""
    # KNOWN_HASHES stays empty by default (we never vouch for hashes we
    # haven't verified against the real artifact).
    assert integrity.KNOWN_HASHES == {}


# ---------------------------------------------------------------------------
# L4: SQL temp-table resume
# ---------------------------------------------------------------------------

def test_filter_unscored_keeps_only_new_hosts(tmp_path):
    store = Store(str(tmp_path / "r.db"))
    from honeywatch.models import Score, Signals
    store.upsert_scores([
        Score(ip="10.0.0.1", port=22, signals=Signals(heuristic_score=0.1),
              final_label="real", final_confidence=0.1),
    ])
    hits = [
        HostHit(ip="10.0.0.1", port=22),   # already scored -> drop
        HostHit(ip="10.0.0.2", port=22),   # new -> keep
        HostHit(ip="10.0.0.3", port=22),   # new -> keep
    ]
    new = store.filter_unscored(hits)
    assert [h.ip for h in new] == ["10.0.0.2", "10.0.0.3"]


def test_filter_unscored_preserves_order_and_handles_empty(tmp_path):
    store = Store(str(tmp_path / "r2.db"))
    assert store.filter_unscored([]) == []
    hits = [HostHit(ip="1.1.1.1", port=22), HostHit(ip="2.2.2.2", port=22)]
    assert [h.ip for h in store.filter_unscored(hits)] == ["1.1.1.1", "2.2.2.2"]


def test_scan_resume_uses_sql_filter(tmp_path, monkeypatch):
    # Resume now goes through Store.filter_unscored (SQL), not scored_hosts().
    store = Store(str(tmp_path / "res.db"))
    from honeywatch.models import Score, Signals
    store.upsert_scores([Score(ip="10.0.0.1", port=22, signals=Signals(heuristic_score=0.1),
                                final_label="real", final_confidence=0.1)])

    seen: list = []

    async def fake_probe_hosts(self, hosts, port=None, only_ssh=None, on_result=None):
        seen.extend((h.ip, h.port) for h in hosts)
        return []

    monkeypatch.setattr(Pipeline, "probe_hosts", fake_probe_hosts)

    async def fake_runner(fn, targets, ports, rate, timeout_s, bin_path, **kw):
        return [HostHit(ip="10.0.0.1", port=22), HostHit(ip="10.0.0.2", port=22)]

    import honeywatch.pipeline as pipe_mod
    monkeypatch.setattr(pipe_mod.asyncio, "to_thread", fake_runner)

    cfg = Config(default_config())
    cfg.ai.enabled = False
    cfg.vpn.required = False
    pipe = Pipeline(cfg, store=store)
    asyncio.run(pipe.scan(["10.0.0.0/24"], resume=True))
    assert ("10.0.0.1", 22) not in seen
    assert ("10.0.0.2", 22) in seen


# ---------------------------------------------------------------------------
# M4: ai.api_key config field is consumed (not dead)
# ---------------------------------------------------------------------------

def test_pipeline_consumes_config_api_key(monkeypatch):
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    cfg = Config(default_config())
    cfg.ai.enabled = True
    cfg.ai.api_key = "config-key-xyz"
    cfg.ai.api_key_env = "OLLAMA_API_KEY"
    pipe = Pipeline(cfg)
    assert pipe.ai_client is not None
    assert pipe.ai_client.api_key == "config-key-xyz"


def test_pipeline_falls_back_to_env_when_config_key_absent(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "env-key-abc")
    cfg = Config(default_config())
    cfg.ai.enabled = True
    cfg.ai.api_key = None
    pipe = Pipeline(cfg)
    assert pipe.ai_client.api_key == "env-key-abc"


# ---------------------------------------------------------------------------
# L3: no-task claim returns a bodyless 204
# ---------------------------------------------------------------------------

def test_claim_no_task_returns_conformant_204(tmp_path):
    try:
        from honeywatch.c2.controller import Controller, HAS_AIOHTTP
    except Exception:
        pytest.skip("aiohttp not installed")
    if not HAS_AIOHTTP:
        pytest.skip("aiohttp not installed")
    from honeywatch.c2.store import C2Store
    store = C2Store(str(tmp_path / "c.db"))
    controller = Controller(store, host="127.0.0.1", port=0)
    from aiohttp.test_utils import TestServer, TestClient

    async def go():
        server = TestServer(controller.app)
        client = TestClient(server)
        await client.start_server()
        try:
            resp = await client.post("/api/tasks/claim",
                                     json={"worker_id": "w1", "categories": ["miner"]})
            assert resp.status == 204
            body = await resp.read()
            assert body == b""  # conformant: no body on 204
        finally:
            await client.close()

    asyncio.run(go())


# ---------------------------------------------------------------------------
# Potency: masscan --wait flows from config
# ---------------------------------------------------------------------------

def test_masscan_wait_s_flows_from_config(monkeypatch):
    captured: dict = {}

    def fake_run(targets, ports, rate, timeout_s, bin_path, **kw):
        captured["kw"] = kw
        return []

    import honeywatch.scanners.masscan as mmod
    monkeypatch.setattr(mmod, "run", fake_run)

    cfg = Config(default_config())
    cfg.ai.enabled = False
    cfg.vpn.required = False
    cfg.scanners.masscan.wait_s = 7
    pipe = Pipeline(cfg)

    async def fake_to_thread(fn, *a, **k):
        return fn(*a, **k)

    monkeypatch.setattr("honeywatch.pipeline.asyncio.to_thread", fake_to_thread)
    asyncio.run(pipe.scan(["10.0.0.0/24"], tool="masscan", skip_vpn_check=True))
    assert captured["kw"].get("wait_s") == 7


def test_masscan_argv_uses_wait_s(monkeypatch, tmp_path):
    import honeywatch.scanners.masscan as mmod
    captured_argv: list = []

    class _Proc:
        returncode = 0
        stderr = b""

    def fake_run_subprocess(argv, **kw):
        captured_argv.extend(argv)
        return _Proc()

    monkeypatch.setattr(mmod.subprocess, "run", fake_run_subprocess)
    mmod.run(["10.0.0.0/24"], [22], 1000, None, bin_path="masscan", wait_s=9)
    # find --wait and the next token
    i = captured_argv.index("--wait")
    assert captured_argv[i + 1] == "9"