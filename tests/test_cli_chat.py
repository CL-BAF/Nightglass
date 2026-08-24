"""Tests for honeywatch.cli_chat — ANSI formatting and TerminalUI helpers."""

from __future__ import annotations

import os
import pytest

from honeywatch.cli_chat import (
    format_status_line,
    format_help,
    format_tool_result,
    panel,
    table,
    bold,
    dim,
    red,
    green,
    _supports_color,
    check_setup,
)


# ---------------------------------------------------------------------------
# ANSI formatting
# ---------------------------------------------------------------------------


class TestAnsiFormatting:
    """Basic ANSI helpers should wrap text and respect NO_COLOR."""

    def test_bold_wraps(self):
        result = bold("hello")
        assert "hello" in result

    def test_dim_wraps(self):
        result = dim("muted")
        assert "muted" in result

    def test_red_wraps(self):
        result = red("error")
        assert "error" in result

    def test_green_wraps(self):
        result = green("ok")
        assert "ok" in result

    def test_no_color_env(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert not _supports_color()

    def test_dumb_term(self, monkeypatch):
        monkeypatch.setenv("TERM", "dumb")
        monkeypatch.delenv("NO_COLOR", raising=False)
        assert not _supports_color()


# ---------------------------------------------------------------------------
# Panel / table
# ---------------------------------------------------------------------------


class TestPanelAndTable:
    def test_panel_contains_title_and_body(self):
        result = panel("test-title", "line one\nline two")
        assert "test-title" in result
        assert "line one" in result

    def test_table_renders_rows(self):
        headers = ["name", "value"]
        rows = [["a", "1"], ["b", "2"]]
        result = table(headers, rows)
        assert "name" in result
        assert "value" in result
        assert "a" in result


# ---------------------------------------------------------------------------
# Tool output formatters
# ---------------------------------------------------------------------------


class TestFormatToolResult:
    def test_error_result(self):
        result = format_tool_result("scan", {"error": "VPN not connected"})
        assert "VPN not connected" in result

    def test_scan_result(self):
        data = {
            "scanned": 5,
            "summary": {"real": 3, "honeypot": 2},
            "top": [
                {"ip": "10.0.0.1", "port": 22, "label": "real", "confidence": 0.12},
            ],
        }
        result = format_tool_result("scan", data)
        assert "5 hosts scored" in result

    def test_deploy_result(self):
        data = {
            "operation_id": "hw-abc123",
            "payload_id": "xmrig",
            "targets": 10,
            "status": "running",
        }
        result = format_tool_result("deploy", data)
        assert "hw-abc123" in result

    def test_list_payloads_result(self):
        data = {
            "payloads": [
                {"id": "xmrig", "category": "miner", "name": "XMRig"},
                {"id": "upx", "category": "evasion", "name": "UPX"},
            ]
        }
        result = format_tool_result("list_payloads", data)
        assert "xmrig" in result

    def test_get_status_result(self):
        data = {
            "status": {"total": 42, "by_label": {"real": 30, "honeypot": 12}, "by_flag": {}}
        }
        result = format_tool_result("get_status", data)
        assert "42 hosts" in result

    def test_set_wallet_result(self):
        data = {"ok": True, "wallet": "WALLET", "pool": "stratum+tcp://pool:3333", "worker": "hw"}
        result = format_tool_result("set_wallet", data)
        assert "wallet updated" in result

    def test_unknown_tool_uses_generic(self):
        data = {"key": "val", "number": 42}
        result = format_tool_result("unknown_tool", data)
        assert "key" in result


# ---------------------------------------------------------------------------
# Status line
# ---------------------------------------------------------------------------


class TestFormatStatusLine:
    def test_full_status(self):
        result = format_status_line(
            model="llama3.1:8b",
            wallet="4abc...xyz",
            pool="stratum+tcp://pool:3333",
            total_hosts=100,
            db_path="honeywatch.db",
        )
        assert "llama3.1:8b" in result
        assert "100" in result

    def test_empty_status(self):
        result = format_status_line()
        assert "not configured" in result


# ---------------------------------------------------------------------------
# Slash help
# ---------------------------------------------------------------------------


class TestSlashHelp:
    def test_format_help_has_commands(self):
        result = format_help()
        assert "/help" in result
        assert "/status" in result
        assert "/quit" in result


# ---------------------------------------------------------------------------
# Setup check
# ---------------------------------------------------------------------------


class TestCheckSetup:
    def test_unconfigured_db(self, tmp_path):
        db = str(tmp_path / "test.db")
        is_configured, cfg = check_setup(db)
        assert not is_configured  # No API key set yet

    def test_configured_db(self, tmp_path):
        from honeywatch.agent.setup import SetupStore

        db = str(tmp_path / "test.db")
        store = SetupStore(db)
        store.set("ollama_api_key", "sk-test-key-123")
        is_configured, cfg = check_setup(db)
        assert is_configured
        assert cfg.ollama_api_key == "sk-test-key-123"