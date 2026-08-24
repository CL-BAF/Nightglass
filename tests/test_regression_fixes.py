"""Regression tests pinning high-severity fixes that previously had no coverage.

Each test here exists because a real defect was fixed in the review pass but no
test guarded the fix. A future refactor that reverts the fix fails loudly here
instead of silently reintroducing the bug.

Covers:
  G1  agent DONE-flag string coercion (_signal_done: "done":"true"/"false")
  G2  assistant-turn history recorded before tool results
  G3  worker WebSocket pushed-task execution + task_result echo
  G4  worker success computation: dry_run (no returncode) reported as success
  G5  config env-override precedence beats a TOML file
  G6  hashcrack stop_on_success across multiple batches
  G7  opsec ProxyCommand shell-injection hardening (shlex.quote)
  G8  chain phase_persist enqueued accumulation + dedup across rounds
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import types

import pytest

from honeywatch.agent.ollama_agent import ChatAgent, _signal_done
from honeywatch.agent.setup import AgentConfig
from honeywatch.chain import ChainConfig, ChainOrchestrator
from honeywatch.config import load_config
import honeywatch.c2.worker as worker_mod
from honeywatch.crack import CrackTarget, crack_host
import honeywatch.crack as crack_mod
import honeywatch.opsec as opsec_mod
from honeywatch.opsec import attempt_sshpass


# ---------------------------------------------------------------------------
# G1: DONE-flag string coercion
# ---------------------------------------------------------------------------


def test_signal_done_coerces_string_values():
    """Models emit ``"done"`` as strings ("true"/"false"/"True"); bool() would
    treat any non-empty string -- including "false" -- as truthy and halt."""
    assert _signal_done({"done": True}) is True
    assert _signal_done({"done": False}) is False
    assert _signal_done({"done": "true"}) is True
    assert _signal_done({"done": "false"}) is False
    assert _signal_done({"done": "True"}) is True
    assert _signal_done({"done": "yes"}) is True
    assert _signal_done({"done": "done"}) is True
    assert _signal_done({"DONE": "true"}) is True  # uppercase key
    assert _signal_done({}) is False
    assert _signal_done({"done": 0}) is False
    assert _signal_done({"done": 1}) is True


def _make_agent(tmp_path):
    cfg = AgentConfig(ollama_api_key="k", ollama_base_url="http://localhost",
                      ollama_model="test-model")
    return ChatAgent(config=cfg, db_path=str(tmp_path / "hw.db"),
                     skip_vpn_check=True, autonomous=True)


def _scripted_client(responses):
    queue = list(responses)

    def chat(messages, json_mode=False):
        if not queue:
            return json.dumps({"thoughts": "", "speak": "done", "tools": [], "done": True})
        return queue.pop(0)

    return types.SimpleNamespace(chat=chat)


def test_autonomous_done_string_true_halts_loop(tmp_path):
    """A string ``"done":"true"`` must halt the loop, not be ignored."""
    agent = _make_agent(tmp_path)
    # Model emits DONE as a *string* with no tool calls.
    agent.client = _scripted_client([
        json.dumps({"thoughts": "goal met", "speak": "all done",
                    "tools": [], "done": "true"}),
    ])
    summary = agent.run_autonomous(goal="test", max_cycles=5)
    assert summary["done"] is True
    assert summary["cycles"] == 1
    assert summary["stop_reason"].startswith("DONE")


def test_autonomous_done_string_false_does_not_halt(tmp_path):
    """A string ``"done":"false"`` must NOT halt -- the bug would either halt
    on a truthy string or, if over-corrected, ignore a real "true"."""
    agent = _make_agent(tmp_path)
    agent.client = _scripted_client([
        json.dumps({"thoughts": "keep going", "speak": "scanning",
                    "tools": [{"name": "get_status", "arguments": {}}],
                    "done": "false"}),
        json.dumps({"thoughts": "now done", "speak": "finished",
                    "tools": [], "done": "true"}),
    ])
    summary = agent.run_autonomous(goal="test", max_cycles=5)
    assert summary["cycles"] == 2
    assert summary["done"] is True
    assert summary["tool_calls"] == 1


# ---------------------------------------------------------------------------
# G2: assistant-turn history recorded before tool results
# ---------------------------------------------------------------------------


def test_assistant_turn_recorded_before_tool_results(tmp_path):
    """The model's own assistant turn must be appended to history before the
    tool-results user message, so it retains its reasoning across rounds."""
    agent = _make_agent(tmp_path)
    agent.client = _scripted_client([
        json.dumps({"thoughts": "check fleet", "speak": "getting status",
                    "tools": [{"name": "get_status", "arguments": {}}],
                    "done": "true"}),
    ])
    agent.run_autonomous(goal="test", max_cycles=5)

    roles = [m["role"] for m in agent.messages]
    assert "assistant" in roles, "no assistant turn recorded in history"
    # The first assistant turn must precede the Tool results user message.
    asst_idx = roles.index("assistant")
    tool_result_idx = None
    for i, m in enumerate(agent.messages):
        if m["role"] == "user" and m["content"].startswith("Tool results:"):
            tool_result_idx = i
            break
    assert tool_result_idx is not None, "no tool-results message in history"
    assert asst_idx < tool_result_idx, "assistant turn must precede tool results"
    # And the assistant content is the model's speech, not empty.
    assert agent.messages[asst_idx]["content"]


# ---------------------------------------------------------------------------
# G3 + G4: WebSocket pushed-task execution + dry_run success
# ---------------------------------------------------------------------------


class _FakeConnectionClosed(Exception):
    """Stand-in for websockets.exceptions.ConnectionClosed."""


def test_worker_websocket_executes_pushed_task(tmp_path, monkeypatch):
    """A task pushed over WebSocket is executed and a task_result echoed.

    Pins both the WS task-execution path (G3) and the success computation for a
    dry_run result that carries no ``returncode`` (G4): a dry_run with no error
    must be reported as success, not failure.
    """
    captured: dict = {"sent": []}

    class _WS:
        def __init__(self, worker, task_payload):
            self.worker = worker
            self.task_payload = task_payload
            self._recv_done = False

        async def send(self, raw):
            msg = json.loads(raw)
            captured["sent"].append(msg)
            if msg.get("type") == "task_result":
                self.worker.stop()

        async def recv(self):
            if not self._recv_done:
                self._recv_done = True
                return json.dumps(self.task_payload)
            raise _FakeConnectionClosed("done")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    worker = worker_mod.Worker("ws://127.0.0.1:8443", worker_id="w1",
                               categories=["miner"], exec_mode="dry_run",
                               poll_interval=5.0)
    task_payload = {
        "type": "task",
        "task": {
            "id": "task-xyz", "operation_id": "op-1", "payload_id": "xmrig",
            "category": "miner",
            "target": {"ip": "10.0.0.1", "port": 22},
            "script": "echo hello",
        },
    }

    class _Connect:
        async def __aenter__(self):
            return _WS(worker, task_payload)

        async def __aexit__(self, *a):
            return False

    fake_ws_mod = types.SimpleNamespace(connect=lambda uri: _Connect())
    monkeypatch.setattr(worker_mod, "websockets", fake_ws_mod)
    monkeypatch.setattr(worker_mod, "ConnectionClosed", _FakeConnectionClosed)

    asyncio.run(worker._run_websocket())

    sent = captured["sent"]
    assert any(m.get("type") == "register_worker" for m in sent)
    results = [m for m in sent if m.get("type") == "task_result"]
    assert len(results) == 1
    assert results[0]["task_id"] == "task-xyz"
    # G4: dry_run (no returncode) + no error => success True, not False.
    assert results[0]["success"] is True
    assert results[0]["result"]["mode"] == "dry_run"


# ---------------------------------------------------------------------------
# G5: config env-override precedence
# ---------------------------------------------------------------------------


def test_config_env_override_beats_toml_file(tmp_path, monkeypatch):
    """Env vars are applied last (highest precedence): they must override a
    value set in an explicit TOML file, not the other way around."""
    toml_path = tmp_path / "cfg.toml"
    toml_path.write_text(
        '[ai]\nmodel = "from-file"\nbase_url = "http://file.example"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("HONEYWATCH_MODEL", "from-env")
    monkeypatch.setenv("HONEYWATCH_AI_BASE", "http://env.example")
    # Don't let a real OLLAMA_API_KEY leak into the ai.api_key slot.
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    monkeypatch.delenv("HONEYWATCH_CONFIG", raising=False)

    cfg = load_config(path=str(toml_path))
    assert cfg.ai.model == "from-env"
    assert cfg.ai.base_url == "http://env.example"


def test_config_toml_used_when_no_env_override(tmp_path, monkeypatch):
    """Without an env override, the TOML file value wins over the built-in
    default -- proving the precedence chain is defaults < file < env."""
    toml_path = tmp_path / "cfg2.toml"
    toml_path.write_text('[ai]\nmodel = "from-file"\n', encoding="utf-8")
    monkeypatch.delenv("HONEYWATCH_MODEL", raising=False)
    monkeypatch.delenv("HONEYWATCH_AI_BASE", raising=False)
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    monkeypatch.delenv("HONEYWATCH_CONFIG", raising=False)

    cfg = load_config(path=str(toml_path))
    assert cfg.ai.model == "from-file"


# ---------------------------------------------------------------------------
# G6: hashcrack stop_on_success across multiple batches
# ---------------------------------------------------------------------------


def _install_fake_paramiko(monkeypatch, winner=None):
    """Inject a fake paramiko so crack_host never touches the network."""

    class AuthenticationException(Exception):
        pass

    class FakeSock:
        def settimeout(self, _t):
            pass

    class FakeTransport:
        def __init__(self, sock):
            self.sock = sock

        def start_client(self, timeout=None):
            pass

        def auth_password(self, user, password):
            if winner is not None and (user, password) == winner:
                return None
            raise AuthenticationException()

        def close(self):
            pass

    fake = types.SimpleNamespace(
        Transport=FakeTransport,
        AuthenticationException=AuthenticationException,
        SSHException=type("SSHException", (Exception,), {}),
    )
    monkeypatch.setitem(__import__("sys").modules, "paramiko", fake)
    monkeypatch.setattr(crack_mod.socket, "create_connection",
                        lambda *a, **k: FakeSock())
    return fake


def test_crack_host_stop_on_success_multi_batch(monkeypatch):
    """stop_on_success must halt the run mid-wordlist when the winner sits in a
    *later* batch -- not just when it is the first attempt (which the existing
    single-batch test already covers)."""
    # Winner is the 41st password -> past the batch boundary (batch size
    # max(concurrency*2,16) == 16 at concurrency=1), so at least batch 3.
    passwords = [f"p{i}" for i in range(60)]
    winner = ("admin", "p40")
    _install_fake_paramiko(monkeypatch, winner=winner)

    target = CrackTarget(
        ip="10.0.0.9", port=22, users=["admin"], passwords=passwords,
        stop_on_success=True, banner="SSH-2.0-test", timeout_s=2.0,
    )
    res = asyncio.new_event_loop().run_until_complete(
        crack_host(target, concurrency=1)
    )
    assert res.success is True
    assert res.password == "p40"
    # The winner is in a later batch, so more than one batch's worth of
    # attempts ran before the winner was found ...
    assert res.attempts > 16
    # ... but stop_on_success cancelled the rest and never drained the wordlist.
    assert res.attempts < len(passwords)


# ---------------------------------------------------------------------------
# G7: opsec ProxyCommand shell-injection hardening
# ---------------------------------------------------------------------------


def test_opsec_proxy_command_is_shell_quoted(monkeypatch):
    """A proxy spec containing shell metacharacters must be shlex-quoted in the
    ssh ProxyCommand, not interpolated raw -- otherwise the operator-supplied
    proxy string runs arbitrary shell commands."""
    captured: dict = {}

    def fake_run(argv, **kw):
        captured["argv"] = list(argv)
        return subprocess.CompletedProcess(args=argv, returncode=5,
                                           stdout="", stderr="")

    monkeypatch.setattr(opsec_mod.subprocess, "run", fake_run)

    malicious = "evil-host;rm -rf /"
    attempt_sshpass("10.0.0.1", 22, "root", "pw",
                    proxy=f"socks5://{malicious}")
    argv = captured["argv"]
    proxy_cmd = next((a for a in argv if a.startswith("ProxyCommand=")), None)
    assert proxy_cmd is not None, "no ProxyCommand option emitted"
    # shlex.quote wraps the metachar-bearing host in single quotes so it is
    # passed literally to `nc` and cannot break out into a shell command.
    assert "'evil-host;rm -rf /'" in proxy_cmd, (
        f"proxy host not shell-quoted in ProxyCommand: {proxy_cmd!r}"
    )
    # The socks5:// scheme prefix must be stripped before quoting.
    assert "socks5://" not in proxy_cmd


# ---------------------------------------------------------------------------
# G8: chain phase_persist enqueued accumulation + dedup across rounds
# ---------------------------------------------------------------------------


class _FakeManifest:
    pass


class _FakeOp:
    def __init__(self, i):
        self.id = f"op-{i}"


def test_phase_persist_dedupes_enqueued_across_rounds(monkeypatch):
    """phase_persist accumulates unique (ip,port) across rounds: a foothold
    already enqueued in a prior round is not re-added on the next."""
    cfg = ChainConfig(payload_id="xmrig", pool="p", wallet="w")
    orch = ChainOrchestrator(cfg)
    orch.state.footholds = [
        ("10.0.0.1", 22, "root", "pw"),
        ("10.0.0.2", 22, "root", "pw"),
    ]
    # Simulate a prior round already having enqueued 10.0.0.1.
    orch.state.enqueued = [("10.0.0.1", 22)]

    calls = {"ops": 0}

    def fake_build(pid, targets, variables, apply_evasion=None,
                   allow_unsafe_vars=False):
        return _FakeManifest()

    def fake_enqueue(c2, manifest):
        calls["ops"] += 1
        return _FakeOp(calls["ops"])

    monkeypatch.setattr("honeywatch.ops.build_manifest", fake_build)
    monkeypatch.setattr("honeywatch.ops.enqueue_operation", fake_enqueue)
    monkeypatch.setattr("honeywatch.c2.store.C2Store", lambda db_path: object())

    orch.phase_persist()
    # 10.0.0.1 already present -> not re-added; 10.0.0.2 appended.
    assert orch.state.enqueued == [("10.0.0.1", 22), ("10.0.0.2", 22)]

    # A second round with the same footholds must not duplicate.
    orch.phase_persist()
    assert orch.state.enqueued == [("10.0.0.1", 22), ("10.0.0.2", 22)]


# ---------------------------------------------------------------------------
# G9: integrity manifest drops non-hex garbage but keeps hex placeholders
# ---------------------------------------------------------------------------


def test_load_integrity_drops_non_hex_keeps_hex_placeholders(tmp_path):
    """load_integrity must reject non-hex garbage (a typo'd "TODO" entry that
    would masquerade as a pinned hash) while keeping real sha256s and short hex
    placeholders that tests/operators stage while pinning a release."""
    from honeywatch.payloads.integrity import load_integrity

    real = "a" * 64
    p = tmp_path / "integrity.toml"
    p.write_text(
        f'xmrig = "{real}"\n'
        'upx = "abc123"\n'          # short hex placeholder -> kept
        'metasploit = "TODO"\n'     # non-hex garbage -> dropped
        'stager = "see notes"\n'    # non-hex garbage -> dropped
        'empty = ""\n',             # empty -> dropped
        encoding="utf-8",
    )
    manifest = load_integrity(str(p))
    assert manifest == {"xmrig": real, "upx": "abc123"}
    assert "metasploit" not in manifest
    assert "stager" not in manifest
    assert "empty" not in manifest