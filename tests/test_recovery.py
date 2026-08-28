"""Tests for the programmatic failure-recovery enforcer (Phase 11)."""

from __future__ import annotations

import pytest

from honeywatch.agent.recovery import (
    MAX_RETRIES,
    RecoveryEnforcer,
    _arg_signature,
    _bump_timeout,
    _coerce_arg,
    _error_text,
    _normalize_args,
    _UNCOERCIBLE,
)
from honeywatch.agent.setup import AgentConfig
from honeywatch.agent.tools import ToolContext


@pytest.fixture
def ctx(tmp_path):
    cfg = AgentConfig(ollama_api_key="k")
    return ToolContext(
        db_path=str(tmp_path / "r.db"), agent_config=cfg, skip_vpn_check=True
    )


@pytest.fixture
def enforcer(ctx):
    return RecoveryEnforcer(ctx)


def _script(monkeypatch, returns):
    """Monkeypatch execute_tool in the recovery module to replay `returns`.

    Returns are consumed in order; once only one remains it is repeated for all
    further calls, so a single-element script (e.g. one persistent transport
    error) stays in effect for every retry the enforcer makes.
    """
    queue = list(returns)

    def fake(name, args, ctx):
        if len(queue) > 1:
            return queue.pop(0)
        return queue[0] if queue else {"error": "script exhausted"}

    monkeypatch.setattr("honeywatch.agent.recovery.execute_tool", fake)
    return fake


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


class TestNormalizeArgs:
    def test_dict_passes_through(self):
        assert _normalize_args({"a": 1}) == {"a": 1}

    def test_string_json(self):
        assert _normalize_args('{"a": 2}') == {"a": 2}

    def test_string_garbage(self):
        assert _normalize_args("nope") == {}

    def test_none_and_other(self):
        assert _normalize_args(None) == {}
        assert _normalize_args(42) == {}
        assert _normalize_args([1, 2]) == {}


class TestArgSignature:
    def test_order_independent(self):
        assert _arg_signature({"a": 1, "b": 2}) == _arg_signature({"b": 2, "a": 1})

    def test_stable(self):
        assert _arg_signature({"x": "y"}) == _arg_signature({"x": "y"})


class TestErrorText:
    def test_extracts_string(self):
        assert _error_text({"error": "boom"}) == "boom"

    def test_extracts_nonstring(self):
        assert _error_text({"error": 42}) == "42"

    def test_none_on_success(self):
        assert _error_text({"ok": True}) is None
        assert _error_text(None) is None


class TestBumpTimeout:
    def test_doubles_int(self):
        out = _bump_timeout({"timeout": 30, "host": "x"})
        assert out["timeout"] == 60
        assert out["host"] == "x"

    def test_doubles_float(self):
        out = _bump_timeout({"timeout": 1.5})
        assert out["timeout"] == 3.0

    def test_absent_unchanged(self):
        args = {"host": "x"}
        assert _bump_timeout(args) is args

    def test_non_numeric_unchanged(self):
        args = {"timeout": "soon"}
        assert _bump_timeout(args) is args


class TestCoerceArg:
    def test_none_passthrough(self):
        assert _coerce_arg(None, "integer") is None

    def test_integer(self):
        assert _coerce_arg(5, "integer") == 5
        assert _coerce_arg("30", "integer") == 30
        assert _coerce_arg(3.0, "integer") == 3
        # bool is not an integer here
        assert _coerce_arg(True, "integer") is _UNCOERCIBLE
        assert _coerce_arg("abc", "integer") is _UNCOERCIBLE
        assert _coerce_arg(3.7, "integer") is _UNCOERCIBLE

    def test_number(self):
        assert _coerce_arg(5, "number") == 5
        assert _coerce_arg("1.5", "number") == 1.5
        assert _coerce_arg(True, "number") is _UNCOERCIBLE
        assert _coerce_arg("x", "number") is _UNCOERCIBLE

    def test_boolean(self):
        assert _coerce_arg(True, "boolean") is True
        assert _coerce_arg("true", "boolean") is True
        assert _coerce_arg("yes", "boolean") is True
        assert _coerce_arg("1", "boolean") is True
        assert _coerce_arg("false", "boolean") is False
        assert _coerce_arg("no", "boolean") is False
        assert _coerce_arg("maybe", "boolean") is _UNCOERCIBLE

    def test_string(self):
        assert _coerce_arg("x", "string") == "x"
        assert _coerce_arg(5, "string") == "5"

    def test_unknown_type_passthrough(self):
        assert _coerce_arg([1, 2], "array") == [1, 2]
        assert _coerce_arg(5, None) == 5


# --------------------------------------------------------------------------- #
# Enforcer behavior
# --------------------------------------------------------------------------- #


class TestExecuteWithRecovery:
    def test_success_no_injection(self, enforcer, monkeypatch):
        _script(monkeypatch, [{"ok": True}])
        records = enforcer.execute_with_recovery(
            [{"name": "scan", "arguments": {"targets": "10.0.0.0/24"}}]
        )
        assert len(records) == 1
        assert records[0]["result"] == {"ok": True}
        assert "recovery" not in records[0]
        assert enforcer.injected_calls == []

    def test_transport_error_retries_then_succeeds(self, enforcer, monkeypatch):
        _script(monkeypatch, [{"error": "connection reset by peer"}, {"ok": True}])
        records = enforcer.execute_with_recovery(
            [{"name": "probe_host", "arguments": {"host": "10.0.0.1"}}]
        )
        assert len(records) == 2
        assert "error" in records[0]["result"]
        assert records[1]["result"] == {"ok": True}
        assert records[1]["recovery"].startswith("auto-retry:retry_same:transport_error")
        assert len(enforcer.injected_calls) == 1

    def test_transport_error_caps_at_max_retries(self, enforcer, monkeypatch):
        # Always fails with a transient transport error.
        _script(monkeypatch, [{"error": "connection reset by peer"}])
        records = enforcer.execute_with_recovery(
            [{"name": "probe_host", "arguments": {"host": "10.0.0.1"}}]
        )
        # 1 original + MAX_RETRIES auto-retries, then the budget is exhausted.
        assert len(records) == 1 + MAX_RETRIES
        assert all("error" in r["result"] for r in records)
        assert len(enforcer.injected_calls) == MAX_RETRIES
        # Every record after the first is a recovery.
        for r in records[1:]:
            assert r["recovery"].startswith("auto-retry:retry_same")

    def test_non_retryable_not_retried(self, enforcer, monkeypatch):
        # TARGET_UNREACHABLE -> SWITCH_CAPABILITY (not a programmatic retry).
        _script(monkeypatch, [{"error": "connection refused"}])
        records = enforcer.execute_with_recovery(
            [{"name": "probe_host", "arguments": {"host": "10.0.0.9"}}]
        )
        assert len(records) == 1
        assert enforcer.injected_calls == []

    def test_scope_blocked_not_retried(self, enforcer, monkeypatch):
        _script(monkeypatch, [{"error": "VPN gate blocked the run"}])
        records = enforcer.execute_with_recovery(
            [{"name": "scan", "arguments": {"targets": "10.0.0.0/24"}}]
        )
        assert len(records) == 1
        assert enforcer.injected_calls == []

    def test_callbacks_fire_for_original_and_recovery(self, enforcer, monkeypatch):
        _script(monkeypatch, [{"error": "connection reset by peer"}, {"ok": True}])
        running, results = [], []

        def on_run(name):
            running.append(name)

        def on_res(name, result):
            results.append((name, result))

        enforcer.execute_with_recovery(
            [{"name": "probe_host", "arguments": {"host": "10.0.0.1"}}],
            on_running=on_run,
            on_result=on_res,
        )
        assert running == ["probe_host", "probe_host"]
        assert len(results) == 2
        assert "error" in results[0][1]
        assert results[1][1] == {"ok": True}


# --------------------------------------------------------------------------- #
# SCHEMA_ERROR arg-stripping (uses the real tool schemas)
# --------------------------------------------------------------------------- #


class TestSchemaStrip:
    def test_missing_required_not_stripped(self, enforcer, monkeypatch):
        # scan requires "targets"; the model omitted it. Stripping can't create
        # a required arg, so no auto-retry -- left to the model.
        _script(monkeypatch, [{"error": "missing required argument: targets"}])
        records = enforcer.execute_with_recovery(
            [{"name": "scan", "arguments": {"limit": 5}}]
        )
        assert len(records) == 1
        assert enforcer.injected_calls == []

    def test_unknown_arg_stripped_then_succeeds(self, enforcer, monkeypatch):
        _script(monkeypatch, [{"error": "invalid argument bogus"}, {"ok": True}])
        records = enforcer.execute_with_recovery(
            [{"name": "scan", "arguments": {"targets": "10.0.0.0/24", "bogus": "x"}}]
        )
        assert len(records) == 2
        assert records[1]["recovery"] == "auto-retry:schema_strip"
        # The retry args should have the unknown arg removed.
        assert "bogus" not in records[1]["arguments"]
        assert records[1]["arguments"]["targets"] == "10.0.0.0/24"
        assert len(enforcer.injected_calls) == 1

    def test_type_coercion_then_succeeds(self, enforcer, monkeypatch):
        # scan.rate is integer; the model passed a string. Coerce -> retry.
        _script(monkeypatch, [{"error": "invalid type for parameter rate"}, {"ok": True}])
        records = enforcer.execute_with_recovery(
            [{"name": "scan", "arguments": {"targets": "10.0.0.0/24", "rate": "100"}}]
        )
        assert len(records) == 2
        assert records[1]["recovery"] == "auto-retry:schema_strip"
        assert records[1]["arguments"]["rate"] == 100
        assert isinstance(records[1]["arguments"]["rate"], int)

    def test_already_clean_no_retry(self, enforcer, monkeypatch):
        # Args already match the schema; a schema error here isn't strip-fixable.
        _script(monkeypatch, [{"error": "invalid argument something"}])
        records = enforcer.execute_with_recovery(
            [{"name": "scan", "arguments": {"targets": "10.0.0.0/24"}}]
        )
        assert len(records) == 1
        assert enforcer.injected_calls == []

    def test_uncoercible_required_arg_no_retry(self, enforcer, monkeypatch):
        # targets is a required string; passing a dict is uncoercible and
        # required -> can't strip -> no retry.
        _script(monkeypatch, [{"error": "invalid type for parameter targets"}])
        records = enforcer.execute_with_recovery(
            [{"name": "scan", "arguments": {"targets": {"nested": "obj"}}}]
        )
        assert len(records) == 1
        assert enforcer.injected_calls == []


# --------------------------------------------------------------------------- #
# reset()
# --------------------------------------------------------------------------- #


class TestReset:
    def test_reset_restores_budget(self, enforcer, monkeypatch):
        # Exhaust the retry budget on a persistent transport error.
        _script(monkeypatch, [{"error": "connection reset by peer"}])
        enforcer.execute_with_recovery(
            [{"name": "probe_host", "arguments": {"host": "10.0.0.1"}}]
        )
        assert len(enforcer.injected_calls) == MAX_RETRIES
        # After reset, the same call can be retried again.
        enforcer.reset()
        assert enforcer.injected_calls == []
        _script(monkeypatch, [{"error": "connection reset by peer"}, {"ok": True}])
        records = enforcer.execute_with_recovery(
            [{"name": "probe_host", "arguments": {"host": "10.0.0.1"}}]
        )
        assert len(records) == 2
        assert records[1]["result"] == {"ok": True}


# --------------------------------------------------------------------------- #
# Missing tool name
# --------------------------------------------------------------------------- #


def test_missing_tool_name_recorded(enforcer, monkeypatch):
    _script(monkeypatch, [])
    records = enforcer.execute_with_recovery([{"arguments": {"x": 1}}])
    assert len(records) == 1
    assert records[0]["tool"] == "?"
    assert "error" in records[0]["result"]
    assert enforcer.injected_calls == []


# --------------------------------------------------------------------------- #
# Integration: the enforcer fires through the real ChatAgent loop
# --------------------------------------------------------------------------- #


def test_agent_autonomous_loop_auto_recovers_transient_error(tmp_path, monkeypatch):
    """A transient transport error during an autonomous run is auto-recovered.

    The model emits a probe_host call; the (scripted) execute_tool first fails
    with a transport error then succeeds. The enforcer injects the retry in the
    same cycle, the run completes, and the recovery is observable on
    agent.recovery.injected_calls.
    """
    import json
    import types

    from honeywatch.agent.ollama_agent import ChatAgent

    # Script execute_tool: first call errors (transient), retry succeeds.
    calls = {"n": 0}

    def fake_execute(name, args, ctx):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"error": "connection reset by peer"}
        return {"ok": True, "recovered": True}

    monkeypatch.setattr("honeywatch.agent.recovery.execute_tool", fake_execute)

    cfg = AgentConfig(ollama_api_key="k", ollama_base_url="http://localhost",
                      ollama_model="test-model")
    agent = ChatAgent(config=cfg, db_path=str(tmp_path / "i.db"),
                      skip_vpn_check=True, autonomous=True)

    def chat(messages, json_mode=False, *, return_raw=False):
        # Cycle 1: emit a probe_host call. Cycle 2: signal DONE.
        if not getattr(chat, "_cycled", False):
            chat._cycled = True
            text = json.dumps({
                "thoughts": "probe", "speak": "probing",
                "tools": [{"name": "probe_host", "arguments": {"host": "10.0.0.1"}}],
                "done": False,
            })
        else:
            text = json.dumps({"thoughts": "done", "speak": "done", "tools": [], "done": True})
        return {"role": "assistant", "content": text} if return_raw else text

    agent.client = types.SimpleNamespace(chat=chat)

    summary = agent.run_autonomous(goal="probe a host", max_cycles=10)
    assert summary["done"] is True
    # The enforcer injected exactly one recovery (the transient retry).
    assert len(agent.recovery.injected_calls) == 1
    assert agent.recovery.injected_calls[0]["name"] == "probe_host"
    assert calls["n"] == 2  # original failure + one auto-retry