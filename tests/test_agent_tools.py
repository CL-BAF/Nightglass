"""Tests for honeywatch.agent.tools."""

from __future__ import annotations

import pytest

from honeywatch.agent.setup import AgentConfig, SetupStore
from honeywatch.agent.tools import TOOL_REGISTRY, ToolContext, execute_tool
from honeywatch.models import Fingerprint, Score, Signals
from honeywatch.store import Store


def _make_score(ip, label, confidence):
    return Score(
        ip=ip,
        port=22,
        fingerprint=Fingerprint(ip=ip, port=22, banner="SSH-2.0-OpenSSH_9.0"),
        signals=Signals(flags=[], heuristic_score=confidence),
        final_label=label,
        final_confidence=confidence,
    )


@pytest.fixture
def ctx(tmp_path):
    db = tmp_path / "agent.db"
    store = SetupStore(str(db))
    cfg = AgentConfig(
        ollama_api_key="k",
        pool="stratum+tcp://pool.example.com:3333",
        wallet="wallet123",
        pass_="x",
        worker="hw",
    )
    store.save_config(cfg)
    # Seed some hosts.
    score_store = Store(str(db))
    score_store.upsert_scores(
        [
            _make_score("10.0.0.1", "real", 0.95),
            _make_score("10.0.0.2", "honeypot", 0.92),
        ]
    )
    return ToolContext(db_path=str(db), agent_config=cfg, skip_vpn_check=True)


def test_list_payloads_tool(ctx):
    result = execute_tool("list_payloads", {"category": "miner"}, ctx)
    ids = {p["id"] for p in result["payloads"]}
    assert ids == {"xmrig", "xmrigcc", "stratum"}


def test_get_status_tool(ctx):
    result = execute_tool("get_status", {}, ctx)
    assert result["status"]["total"] == 2


def test_deploy_tool_autofills_wallet(ctx):
    result = execute_tool(
        "deploy",
        {"payload_id": "xmrig", "target_label": "real", "limit": 1},
        ctx,
    )
    assert "operation_id" in result
    assert result["targets"] == 1
    # Verify the task was created with wallet auto-filled.
    tasks = ctx.c2_store.list_tasks(operation_id=result["operation_id"])
    assert len(tasks) == 1
    assert tasks[0].variables["wallet"] == "wallet123"
    assert tasks[0].variables["pool"] == "stratum+tcp://pool.example.com:3333"


def test_set_wallet_tool(ctx):
    result = execute_tool(
        "set_wallet",
        {"wallet": "new-wallet", "pool": "stratum+tcp://new.pool:3333"},
        ctx,
    )
    assert result["ok"] is True
    loaded = SetupStore(ctx.db_path).load_config()
    assert loaded.wallet == "new-wallet"
    assert loaded.pool == "stratum+tcp://new.pool:3333"


def test_report_tool(ctx):
    result = execute_tool("report", {"format": "json", "limit": 10}, ctx)
    assert result["rows"] == 2


def test_get_operations_tool(ctx):
    result = execute_tool("get_operations", {"limit": 10}, ctx)
    assert result["operations"] == []
