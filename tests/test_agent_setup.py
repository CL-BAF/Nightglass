"""Tests for honeywatch.agent.setup wizard and store."""

from __future__ import annotations

import pytest

from honeywatch.agent.setup import AgentConfig, SetupStore, run_setup_wizard


@pytest.fixture
def store(tmp_path):
    db = tmp_path / "agent.db"
    return SetupStore(str(db))


def test_store_set_get(store):
    store.set("wallet", "abc123")
    assert store.get("wallet") == "abc123"
    assert store.get("missing", "default") == "default"


def test_store_load_and_save_config(store):
    cfg = AgentConfig(
        ollama_api_key="key",
        ollama_base_url="https://x/v1",
        ollama_model="llama3",
        pool="stratum+tcp://p:3333",
        wallet="w",
        pass_="x",
        worker="hw",
        tls=True,
    )
    store.save_config(cfg)
    loaded = store.load_config()
    assert loaded.ollama_api_key == "key"
    assert loaded.ollama_base_url == "https://x/v1"
    assert loaded.pool == "stratum+tcp://p:3333"
    assert loaded.wallet == "w"
    assert loaded.pass_ == "x"
    assert loaded.worker == "hw"
    assert loaded.tls is True


def test_run_setup_wizard_non_interactive(store):
    cfg = run_setup_wizard(
        store=store,
        non_interactive={
            "ollama_api_key": "k",
            "ollama_model": "m",
            "pool": "p",
            "wallet": "w",
        },
    )
    assert cfg.ollama_api_key == "k"
    assert cfg.wallet == "w"
    loaded = store.load_config()
    assert loaded.wallet == "w"


def test_agent_config_round_trip():
    cfg = AgentConfig(
        ollama_api_key="k",
        pool="p",
        wallet="w",
        pass_="p",
    )
    d = cfg.to_dict()
    assert d["pass"] == "p"
    restored = AgentConfig.from_dict(d)
    assert restored.pass_ == "p"
