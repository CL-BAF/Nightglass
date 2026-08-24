"""Tests for honeywatch.agent.ollama_agent parsing and chat loop."""

from __future__ import annotations

import json

import pytest

from honeywatch.agent.ollama_agent import ChatAgent, _extract_json, _parse_model_response
from honeywatch.agent.setup import AgentConfig


def test_extract_json_plain_object():
    assert _extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_fenced():
    text = '```json\n{"a": 1}\n```\n```'
    assert _extract_json(text) == {"a": 1}


def test_extract_json_with_extra_text():
    text = 'Sure!\n```json\n{"a": 1}\n```\nDone.'
    assert _extract_json(text) == {"a": 1}


# ── _parse_model_response tests ──


def test_parse_model_response_valid_json():
    text = json.dumps({
        "THOUGHTS": "check fleet",
        "SPEAK": "scanning",
        "TOOLS": [{"name": "scan", "arguments": {"targets": "10.0.0.0/24"}}],
        "DONE": False,
    })
    result = _parse_model_response(text)
    assert result is not None
    assert result["thoughts"] == "check fleet"
    assert result["speak"] == "scanning"
    assert len(result["tools"]) == 1
    assert result["done"] is False


def test_parse_model_response_semi_structured():
    """The format deepseek-v4-flash actually emits."""
    text = (
        "THOUGHTS: No hosts yet, so I need to start recon.\n"
        "SPEAK: Starting recon on 10.0.0.0/24.\n"
        "TOOLS:\n"
        '- {"name": "scan", "arguments": {"targets": "10.0.0.0/24"}}\n'
        '- {"name": "list_payloads", "arguments": {}}\n'
        "DONE: false"
    )
    result = _parse_model_response(text)
    assert result is not None
    assert "start recon" in result["thoughts"]
    assert "Starting recon" in result["speak"]
    assert len(result["tools"]) == 2
    assert result["tools"][0]["name"] == "scan"
    assert result["tools"][1]["name"] == "list_payloads"
    assert result["done"] is False


def test_parse_model_response_semi_structured_no_done():
    text = (
        "THOUGHTS: scanning\n"
        "SPEAK: ok\n"
        "TOOLS:\n"
        '- {"name": "scan", "arguments": {"targets": "10.0.0.0/24"}}'
    )
    result = _parse_model_response(text)
    assert result is not None
    assert result["thoughts"] == "scanning"
    assert result["speak"] == "ok"
    assert len(result["tools"]) == 1
    assert result["done"] is False  # defaults to False


def test_parse_model_response_semi_structured_inline_tools():
    """TOOLS as a JSON array on the same line."""
    text = (
        'THOUGHTS: check status\n'
        'SPEAK: checking\n'
        'TOOLS: [{"name": "get_status", "arguments": {}}]\n'
        'DONE: true'
    )
    result = _parse_model_response(text)
    assert result is not None
    assert len(result["tools"]) == 1
    assert result["tools"][0]["name"] == "get_status"
    # DONE is parsed as a string from semi-structured text;
    # _signal_done() handles the coercion.
    assert result["done"] in (True, "true", "True")


def test_parse_model_response_plain_text():
    """Model returns text that isn't JSON or semi-structured."""
    result = _parse_model_response("I don't know what to do.")
    assert result is None  # nothing parseable


def test_parse_model_response_empty():
    assert _parse_model_response("") is None
    assert _parse_model_response("   ") is None


def test_parse_model_response_single_tool_json():
    """Model outputs just a tool call, not wrapped in the expected schema."""
    text = json.dumps({"name": "scan", "arguments": {"targets": "10.0.0.0/24"}})
    result = _parse_model_response(text)
    assert result is not None
    assert len(result["tools"]) == 1
    assert result["tools"][0]["name"] == "scan"


def test_parse_model_response_lowercase_keys():
    """Model uses lowercase keys."""
    text = json.dumps({"thoughts": "hi", "speak": "ok", "tools": [], "done": True})
    result = _parse_model_response(text)
    assert result is not None
    assert result["thoughts"] == "hi"
    assert result["done"] is True


def test_parse_model_response_mixed_case_keys():
    """Model uses THOUGHTS (uppercase) but the parser normalizes."""
    text = json.dumps({"THOUGHTS": "hi", "SPEAK": "ok", "TOOLS": [{"name": "scan", "arguments": {"targets": "10.0.0.0/24"}}], "DONE": False})
    result = _parse_model_response(text)
    assert result is not None
    assert result["thoughts"] == "hi"
    assert len(result["tools"]) == 1


# ── System prompt and agent tests ──


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


def _make_fake_chat(responses):
    """Create a fake chat function that supports return_raw=True."""
    queue = list(responses)

    def chat(messages, json_mode=False, *, return_raw=False):
        if not queue:
            return {"role": "assistant", "content": ""} if return_raw else ""
        text = queue.pop(0)
        if return_raw:
            return {"role": "assistant", "content": text}
        return text

    return chat


def test_chat_agent_tool_round_trip(tmp_path):
    cfg = AgentConfig(ollama_api_key="k")
    agent = ChatAgent(config=cfg, db_path=str(tmp_path / "db"), skip_vpn_check=True)

    responses = [
        json.dumps({
            "thoughts": "get status",
            "speak": "Let me check the database.",
            "tools": [{"name": "get_status", "arguments": {}}],
        }),
        json.dumps({
            "thoughts": "done",
            "speak": "There are 0 hosts in the database.",
            "tools": [],
        }),
    ]

    agent.client.chat = _make_fake_chat(responses)
    response = agent.chat("how many hosts do we have")
    assert "0 hosts" in response