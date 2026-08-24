"""Tests for honeywatch.agent.ollama_agent parsing and chat loop."""

from __future__ import annotations

import json

import pytest

from honeywatch.agent.ollama_agent import ChatAgent, _extract_json
from honeywatch.agent.setup import AgentConfig


def test_extract_json_plain_object():
    assert _extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_fenced():
    text = '```json\n{"a": 1}\n```'
    assert _extract_json(text) == {"a": 1}


def test_extract_json_with_extra_text():
    text = 'Sure!\n```json\n{"a": 1}\n```\nDone.'
    assert _extract_json(text) == {"a": 1}


def test_build_system_prompt_no_error():
    from honeywatch.agent.ollama_agent import _build_system_prompt
    prompt = _build_system_prompt()
    assert "list_payloads" in prompt
    assert "THOUGHTS" in prompt


def test_chat_agent_builds_system_prompt():
    cfg = AgentConfig(ollama_api_key="k")
    agent = ChatAgent(config=cfg, skip_vpn_check=True)
    assert agent.messages[0]["role"] == "system"
    assert "list_payloads" in agent.messages[0]["content"]


def test_chat_agent_tool_round_trip(monkeypatch, tmp_path):
    cfg = AgentConfig(ollama_api_key="k")
    agent = ChatAgent(config=cfg, db_path=str(tmp_path / "db"), skip_vpn_check=True)

    calls = []

    def fake_chat(messages, json_mode=False):
        calls.append(messages)
        if len(calls) == 1:
            return json.dumps(
                {
                    "thoughts": "get status",
                    "speak": "Let me check the database.",
                    "tools": [{"name": "get_status", "arguments": {}}],
                }
            )
        return json.dumps(
            {
                "thoughts": "done",
                "speak": "There are 0 hosts in the database.",
                "tools": [],
            }
        )

    monkeypatch.setattr(agent.client, "chat", fake_chat)
    response = agent.chat("how many hosts do we have")
    assert "0 hosts" in response
    assert len(calls) == 2
