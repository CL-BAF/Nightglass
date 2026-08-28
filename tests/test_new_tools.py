"""Tests for the 7 new agent tools (exec_command, port_scan, web_probe,
credential_for, test_credential, botnet_status, metasploit)."""

from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from honeywatch.agent.tools import ToolContext, execute_tool, TOOL_REGISTRY


@pytest.fixture
def ctx(tmp_path):
    return ToolContext(
        db_path=str(tmp_path / "test.db"),
        skip_vpn_check=True,
    )


# --------------------------------------------------------------------------- #
# Tool registration
# --------------------------------------------------------------------------- #


class TestToolRegistration:
    def test_all_7_new_tools_registered(self):
        new_tools = {"exec_command", "port_scan", "web_probe",
                     "credential_for", "test_credential", "botnet_status",
                     "metasploit"}
        assert new_tools.issubset(set(TOOL_REGISTRY.keys()))

    def test_total_tool_count(self):
        assert len(TOOL_REGISTRY) == 33

    def test_each_new_tool_has_spec_and_func(self):
        for name in ("exec_command", "port_scan", "web_probe",
                     "credential_for", "test_credential", "botnet_status",
                     "metasploit"):
            entry = TOOL_REGISTRY[name]
            assert "func" in entry
            assert "spec" in entry
            assert entry["spec"]["name"] == name


# --------------------------------------------------------------------------- #
# exec_command
# --------------------------------------------------------------------------- #


class TestExecCommand:
    def test_missing_host(self, ctx):
        result = execute_tool("exec_command", {"command": "id"}, ctx)
        assert "error" in result

    def test_missing_command(self, ctx):
        result = execute_tool("exec_command", {"host": "10.0.0.1"}, ctx)
        assert "error" in result

    def test_no_credential(self, ctx):
        result = execute_tool("exec_command",
                              {"host": "10.0.0.1", "command": "id"}, ctx)
        assert "error" in result
        assert "no credential" in result["error"]

    def test_runs_command_with_mock(self, ctx):
        with patch("honeywatch.chain._ssh_exec",
                   return_value=(0, "uid=0(root) gid=0(root)\n", None)):
            result = execute_tool("exec_command",
                                  {"host": "10.0.0.1", "command": "id",
                                   "user": "root", "password": "pw"}, ctx)
        assert result["returncode"] == 0
        assert "uid=0" in result["stdout"]

    def test_key_based_auth(self, ctx):
        with patch("honeywatch.chain._ssh_exec",
                   return_value=(0, "uid=0(root)\n", None)):
            result = execute_tool("exec_command",
                                  {"host": "10.0.0.1", "command": "id",
                                   "user": "root", "password": "key:/tmp/id_rsa"}, ctx)
        assert result["returncode"] == 0


# --------------------------------------------------------------------------- #
# port_scan
# --------------------------------------------------------------------------- #


class TestPortScan:
    def test_missing_targets(self, ctx):
        result = execute_tool("port_scan", {}, ctx)
        assert "error" in result

    def test_basic_scan_mocked(self, ctx):
        # Mock asyncio.open_connection to simulate open ports.
        import asyncio

        async def fake_open_connection(ip, port):
            if port in (22, 80):
                writer = MagicMock()
                writer.close = MagicMock()
                writer.wait_closed = MagicMock(return_value=asyncio.sleep(0))
                return MagicMock(), writer
            raise ConnectionRefusedError(f"port {port} closed")

        with patch("asyncio.open_connection", fake_open_connection):
            result = execute_tool("port_scan",
                                  {"targets": "127.0.0.1",
                                   "ports": "22,80,443",
                                   "timeout": 1}, ctx)
        assert result["ports_scanned"] == 3
        assert "127.0.0.1" in result["open_ports"]
        assert 22 in result["open_ports"]["127.0.0.1"]
        assert 80 in result["open_ports"]["127.0.0.1"]
        assert 443 not in result["open_ports"]["127.0.0.1"]


# --------------------------------------------------------------------------- #
# web_probe
# --------------------------------------------------------------------------- #


class TestWebProbe:
    def test_missing_url(self, ctx):
        result = execute_tool("web_probe", {}, ctx)
        assert "error" in result

    def test_adds_http_prefix(self, ctx):
        # Mock urllib to avoid real network.
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.read = MagicMock(return_value=b"<html>OK</html>")
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = execute_tool("web_probe", {"url": "10.0.0.1", "paths": ""}, ctx)
        assert result["url"] == "http://10.0.0.1"
        assert len(result["findings"]) >= 1

    def test_custom_paths(self, ctx):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.read = MagicMock(return_value=b"OK")
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = execute_tool("web_probe",
                                  {"url": "http://10.0.0.1",
                                   "paths": "/admin,/api"}, ctx)
        assert result["paths_checked"] == 3  # / + /admin + /api

    def test_connection_error_handled(self, ctx):
        import urllib.error
        with patch("urllib.request.urlopen",
                   side_effect=urllib.error.URLError("refused")):
            result = execute_tool("web_probe",
                                  {"url": "http://10.0.0.1:9999"}, ctx)
        # Should not crash — records the error in findings.
        assert "findings" in result
        assert len(result["findings"]) >= 1


# --------------------------------------------------------------------------- #
# credential_for
# --------------------------------------------------------------------------- #


class TestCredentialFor:
    def test_missing_host(self, ctx):
        result = execute_tool("credential_for", {}, ctx)
        assert "error" in result

    def test_no_creds_returns_empty(self, ctx):
        result = execute_tool("credential_for", {"host": "10.0.0.99"}, ctx)
        assert result["count"] == 0

    def test_returns_creds_for_host(self, ctx):
        # Store a credential.
        ctx.store.upsert_credential("10.0.0.5", 22, "root", "pass123",
                                    source="test", attempts=1)
        result = execute_tool("credential_for", {"host": "10.0.0.5"}, ctx)
        assert result["count"] == 1
        assert result["credentials"][0]["user"] == "root"
        assert result["credentials"][0]["password"] == "pass123"

    def test_filters_by_port(self, ctx):
        ctx.store.upsert_credential("10.0.0.5", 22, "root", "pass22",
                                    source="test", attempts=1)
        ctx.store.upsert_credential("10.0.0.5", 2222, "admin", "pass2222",
                                    source="test", attempts=1)
        result = execute_tool("credential_for",
                              {"host": "10.0.0.5", "port": 22}, ctx)
        assert result["count"] == 1
        assert result["credentials"][0]["user"] == "root"


# --------------------------------------------------------------------------- #
# test_credential
# --------------------------------------------------------------------------- #


class TestTestCredential:
    def test_missing_host(self, ctx):
        result = execute_tool("test_credential", {}, ctx)
        assert "error" in result

    def test_no_credential(self, ctx):
        result = execute_tool("test_credential", {"host": "10.0.0.99"}, ctx)
        assert "error" in result
        assert "no credential" in result["error"]

    def test_valid_credential_mocked(self, ctx):
        ctx.store.upsert_credential("10.0.0.5", 22, "root", "pass",
                                    source="test", attempts=1)
        with patch("honeywatch.chain._ssh_exec",
                   return_value=(0, "uid=0(root) gid=0(root)\n", None)):
            result = execute_tool("test_credential", {"host": "10.0.0.5"}, ctx)
        assert result["valid"] is True
        assert "uid=0" in result["output"]

    def test_invalid_credential_mocked(self, ctx):
        ctx.store.upsert_credential("10.0.0.5", 22, "root", "wrong",
                                    source="test", attempts=1)
        with patch("honeywatch.chain._ssh_exec",
                   return_value=(5, "", "Permission denied")):
            result = execute_tool("test_credential", {"host": "10.0.0.5"}, ctx)
        assert result["valid"] is False

    def test_explicit_credential_overrides_stored(self, ctx):
        ctx.store.upsert_credential("10.0.0.5", 22, "root", "stored",
                                    source="test", attempts=1)
        with patch("honeywatch.chain._ssh_exec",
                   return_value=(0, "uid=0(root)\n", None)) as mock_ssh:
            result = execute_tool("test_credential",
                                  {"host": "10.0.0.5", "user": "admin",
                                   "password": "explicit"}, ctx)
        assert result["valid"] is True
        # Check the mock was called with the explicit creds.
        call_args = mock_ssh.call_args
        assert call_args[0][2] == "admin"  # user
        assert call_args[0][3] == "explicit"  # password


# --------------------------------------------------------------------------- #
# botnet_status
# --------------------------------------------------------------------------- #


class TestBotnetStatus:
    def test_returns_status_dict(self, ctx):
        result = execute_tool("botnet_status", {}, ctx)
        assert "hosts_discovered" in result
        assert "credentials_recovered" in result
        assert "footholds" in result
        assert "enqueued_deploys" in result
        assert "pivoted_subnets" in result

    def test_empty_store_returns_zeros(self, ctx):
        result = execute_tool("botnet_status", {}, ctx)
        assert result["hosts_discovered"] == 0
        assert result["footholds"] == 0

    def test_with_stored_data(self, ctx):
        ctx.store.upsert_credential("10.0.0.5", 22, "root", "pass",
                                    source="test", attempts=1)
        result = execute_tool("botnet_status", {}, ctx)
        assert result["credentials_recovered"] >= 1


# --------------------------------------------------------------------------- #
# metasploit
# --------------------------------------------------------------------------- #


class TestMetasploit:
    def test_missing_host(self, ctx):
        result = execute_tool("metasploit", {}, ctx)
        assert "error" in result

    def test_no_credential(self, ctx):
        result = execute_tool("metasploit", {"host": "10.0.0.99"}, ctx)
        assert "error" in result
        assert "no credential" in result["error"]

    def test_msfconsole_not_found(self, ctx):
        ctx.store.upsert_credential("10.0.0.5", 22, "root", "pass",
                                    source="test", attempts=1)
        with patch("shutil.which", return_value=None):
            result = execute_tool("metasploit", {"host": "10.0.0.5"}, ctx)
        assert "error" in result
        assert "msfconsole not found" in result["error"]

    def test_runs_msfconsole_mocked(self, ctx):
        ctx.store.upsert_credential("10.0.0.5", 22, "root", "pass",
                                    source="test", attempts=1)
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "[*] 10.0.0.5:22 SSH version: OpenSSH 9.0"
        mock_proc.stderr = ""

        with patch("shutil.which", return_value="/usr/bin/msfconsole"), \
             patch("subprocess.run", return_value=mock_proc):
            result = execute_tool("metasploit",
                                  {"host": "10.0.0.5",
                                   "module": "auxiliary/scanner/ssh/ssh_version"}, ctx)
        assert result["returncode"] == 0
        assert "SSH version" in result["stdout"]

    def test_custom_options(self, ctx):
        ctx.store.upsert_credential("10.0.0.5", 22, "root", "pass",
                                    source="test", attempts=1)
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "OK"
        mock_proc.stderr = ""

        captured_rc = []
        def fake_run(argv, **kw):
            # Read the resource script to verify options were set.
            with open(argv[3], "r") as f:
                captured_rc.append(f.read())
            return mock_proc

        with patch("shutil.which", return_value="/usr/bin/msfconsole"), \
             patch("subprocess.run", side_effect=fake_run):
            result = execute_tool("metasploit",
                                  {"host": "10.0.0.5",
                                   "options": '{"VERBOSE":"true","THREADS":"10"}'}, ctx)
        assert result["returncode"] == 0
        assert len(captured_rc) == 1
        assert "set VERBOSE true" in captured_rc[0]
        assert "set THREADS 10" in captured_rc[0]

    def test_timeout_handled(self, ctx):
        ctx.store.upsert_credential("10.0.0.5", 22, "root", "pass",
                                    source="test", attempts=1)
        import subprocess
        with patch("shutil.which", return_value="/usr/bin/msfconsole"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("msfconsole", 60)):
            result = execute_tool("metasploit",
                                  {"host": "10.0.0.5", "timeout": 5}, ctx)
        assert "error" in result
        assert "timed out" in result["error"]