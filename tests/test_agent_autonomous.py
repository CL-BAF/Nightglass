"""Tests for the autonomous self-driving agent loop.

The Ollama client is replaced with a scripted responder so the loop logic
(decide -> execute -> observe -> DONE/stall/max-cycles) is exercised
deterministically without a model or network. A real SQLite store backs the
fleet-status observation so get_status/list_credentials return live (empty)
state the way the loop sees it in production.
"""

from __future__ import annotations

import json
import types

from honeywatch.agent.ollama_agent import ChatAgent
from honeywatch.agent.setup import AgentConfig


def _make_agent(tmp_path):
    cfg = AgentConfig(ollama_api_key="k", ollama_base_url="http://localhost",
                      ollama_model="test-model")
    agent = ChatAgent(config=cfg, db_path=str(tmp_path / "hw.db"),
                      skip_vpn_check=True, autonomous=True)
    # Replace the Ollama client so no network is ever hit.
    return agent


def _scripted_client(responses):
    """A fake Ollama client whose .chat() pops scripted responses.

    Supports return_raw=True by returning a message dict with the text in
    the content field, matching the real OllamaClient.chat() contract.
    """
    queue = list(responses)
    calls = {"count": 0}

    def chat(messages, json_mode=False, *, return_raw=False):
        calls["count"] += 1
        if not queue:
            text = json.dumps({"thoughts": "", "speak": "done", "tools": [], "done": True})
        else:
            text = queue.pop(0)
        if return_raw:
            return {"role": "assistant", "content": text}
        return text

    return types.SimpleNamespace(chat=chat), calls


def _resp(thoughts="", speak="", tools=None, done=False):
    return json.dumps({"thoughts": thoughts, "speak": speak,
                       "tools": tools or [], "done": done})


def test_autonomous_loop_executes_tools_then_signals_done(tmp_path, monkeypatch):
    agent = _make_agent(tmp_path)
    client, calls = _scripted_client([
        _resp(thoughts="check the fleet", speak="getting status",
              tools=[{"name": "get_status", "arguments": {}}], done=False),
        _resp(thoughts="nothing left to do", speak="all done", done=True),
    ])
    agent.client = client

    summary = agent.run_autonomous(goal="test goal", max_cycles=10)
    assert summary["cycles"] == 2
    assert summary["tool_calls"] == 1          # the get_status call in cycle 1
    assert summary["done"] is True
    assert summary["stop_reason"].startswith("DONE")
    assert calls["count"] == 2                 # one ollama call per cycle


def test_autonomous_loop_caps_at_max_cycles(tmp_path, monkeypatch):
    agent = _make_agent(tmp_path)
    # Model never signals DONE and always emits a (safe) tool call.
    client, calls = _scripted_client([
        _resp(speak="scan again", tools=[{"name": "get_status", "arguments": {}}])
        for _ in range(50)
    ])
    agent.client = client

    summary = agent.run_autonomous(goal="test", max_cycles=3)
    assert summary["cycles"] == 3
    assert summary["done"] is False
    assert summary["stop_reason"] == "reached max_cycles=3"
    assert summary["tool_calls"] == 3


def test_autonomous_loop_stalls_on_no_tools_no_done(tmp_path, monkeypatch):
    agent = _make_agent(tmp_path)
    client, calls = _scripted_client([
        _resp(thoughts="stuck", speak="no move", tools=[], done=False),
    ])
    agent.client = client

    summary = agent.run_autonomous(goal="test", max_cycles=10)
    assert summary["cycles"] == 1
    assert summary["done"] is False
    assert "exhausted" in summary["stop_reason"]
    assert summary["tool_calls"] == 0


def test_autonomous_loop_done_with_final_tool_calls(tmp_path, monkeypatch):
    agent = _make_agent(tmp_path)
    client, calls = _scripted_client([
        _resp(thoughts="final check then done", speak="one last status",
              tools=[{"name": "get_status", "arguments": {}}], done=True),
    ])
    agent.client = client

    summary = agent.run_autonomous(goal="test", max_cycles=10)
    assert summary["cycles"] == 1
    assert summary["tool_calls"] == 1
    assert summary["done"] is True
    assert "DONE after executing 1 final tool call" in summary["stop_reason"]


def test_autonomous_loop_business_hours_gate_sleeps_without_ollama(tmp_path, monkeypatch):
    agent = _make_agent(tmp_path)
    client, calls = _scripted_client([_resp(done=True) for _ in range(20)])
    agent.client = client
    # Force "off-hours" so the loop must sleep every cycle, never call ollama.
    monkeypatch.setattr("honeywatch.agent.ollama_agent.within_business_hours",
                        lambda *a, **k: False)

    summary = agent.run_autonomous(goal="test", max_cycles=2,
                                   business_hours=True, cycle_delay=0.0)
    assert summary["cycles"] == 2
    assert calls["count"] == 0                 # ollama never consulted off-hours
    assert summary["stop_reason"] == "reached max_cycles=2"


def test_autonomous_loop_forever_until_done_with_max_cycles_zero(tmp_path, monkeypatch):
    """max_cycles=0 = run forever; must stop only when the model signals DONE."""
    agent = _make_agent(tmp_path)
    # Five productive cycles, then DONE on the sixth.
    scripted = [_resp(speak=f"cycle {i}", tools=[{"name": "get_status", "arguments": {}}])
                for i in range(5)]
    scripted.append(_resp(thoughts="goal met", speak="done", done=True))
    client, calls = _scripted_client(scripted)
    agent.client = client

    summary = agent.run_autonomous(goal="test", max_cycles=0)
    assert summary["cycles"] == 6
    assert summary["done"] is True
    assert summary["stop_reason"].startswith("DONE")
    assert calls["count"] == 6


def test_autonomous_loop_history_is_trimmed(tmp_path, monkeypatch):
    """A long run must not let the message list grow unbounded."""
    agent = _make_agent(tmp_path)
    client, calls = _scripted_client([
        _resp(speak=f"c{i}", tools=[{"name": "get_status", "arguments": {}}])
        for i in range(40)
    ] + [_resp(done=True)])
    agent.client = client

    agent.run_autonomous(goal="test", max_cycles=50)
    # system + goal seed + optional bridge + rolling tail (8).
    # The bridge message is inserted when trimming creates consecutive
    # same-role messages, so the maximum is 2 + 1 + 8 = 11.
    assert len(agent.messages) <= 2 + 1 + 8


def test_trim_history_preserves_alternation(tmp_path):
    """After trimming, the message list must maintain alternating
    user/assistant roles -- two consecutive user messages would cause
    an Ollama API 400 error."""
    agent = _make_agent(tmp_path)
    # Build a long message list manually to trigger trimming.
    agent.messages = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "goal"},
    ]
    # Add 20 user/assistant pairs to exceed the trim threshold.
    for i in range(20):
        agent.messages.append({"role": "user", "content": f"status {i}"})
        agent.messages.append({"role": "assistant", "content": f"reply {i}"})
    # Add one more user message at the end (fleet status).
    agent.messages.append({"role": "user", "content": "fleet status"})
    agent._trim_history()
    # Verify no two consecutive messages have the same role.
    for i in range(1, len(agent.messages)):
        assert agent.messages[i]["role"] != agent.messages[i - 1]["role"], (
            f"consecutive same-role messages at index {i - 1}/{i}: "
            f"{agent.messages[i - 1]['role']} -> {agent.messages[i]['role']}"
        )


def test_chat_agent_autonomous_uses_autonomous_prompt(tmp_path, monkeypatch):
    cfg = AgentConfig(ollama_api_key="k", ollama_model="m")
    agent = ChatAgent(config=cfg, db_path=str(tmp_path / "hw.db"),
                      skip_vpn_check=True, autonomous=True)
    assert "UNATTENDED" in agent.messages[0]["content"]
    assert "DONE" in agent.messages[0]["content"]

    convo = ChatAgent(config=cfg, db_path=str(tmp_path / "hw.db"),
                      skip_vpn_check=True, autonomous=False)
    assert "UNATTENDED" not in convo.messages[0]["content"]


def test_autonomous_loop_semi_structured_response(tmp_path, monkeypatch):
    """The agent should handle deepseek-v4-flash style semi-structured output."""
    agent = _make_agent(tmp_path)
    client, calls = _scripted_client([
        "THOUGHTS: scanning the network\n"
        "SPEAK: scanning 10.0.0.0/24\n"
        "TOOLS:\n"
        '- {"name": "scan", "arguments": {"targets": "10.0.0.0/24"}}\n'
        "DONE: false",
        _resp(done=True),
    ])
    agent.client = client

    summary = agent.run_autonomous(goal="test", max_cycles=10)
    assert summary["tool_calls"] == 1
    assert summary["cycles"] == 2