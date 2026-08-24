"""Tests for the honeywatch CLI (argparse construction and entry points)."""

from __future__ import annotations

import pytest

from honeywatch import cli


def test_build_parser_help_exits_zero():
    parser = cli.build_parser()
    with pytest.raises(SystemExit) as excinfo:
        parser.parse_args(["--help"])
    assert excinfo.value.code in (0, None)


def test_cli_main_help_returns_zero():
    assert cli.main(["--help"]) == 0


def test_cli_main_config_returns_zero(capsys):
    rc = cli.main(["config"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "[scanners.masscan]" in out
    assert "[ai]" in out
    assert "llama3.1:8b" in out


def test_cli_main_unknown_command_returns_error_code():
    assert cli.main(["not-a-command"]) == 2


def test_cli_build_parser_has_subcommands():
    parser = cli.build_parser()
    sub_actions = parser._subparsers._group_actions[0].choices
    assert {"scan", "probe", "report", "config", "c2", "worker", "deploy"} <= set(
        sub_actions
    )


def test_cli_main_deploy_dry_run_with_target_file(tmp_path, capsys):
    targets = tmp_path / "targets.txt"
    targets.write_text("10.0.0.1\n10.0.0.2:2222\n", encoding="utf-8")
    rc = cli.main(
        [
            "deploy",
            "stratum",
            "--target-file",
            str(targets),
            "--var",
            "upstream_pool=pool.example.com:3333",
            "--dry-run",
            "--skip-vpn-check",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "stratum" in out
    assert "stratum_proxy.py" in out
    assert "targets: 2" in out


def test_cli_main_c2_help_returns_zero():
    assert cli.main(["c2", "--help"]) == 0


def test_cli_main_worker_help_returns_zero():
    assert cli.main(["worker", "--help"]) == 0


def test_cli_main_deploy_help_returns_zero():
    assert cli.main(["deploy", "--help"]) == 0


def test_cli_main_setup_help_returns_zero():
    assert cli.main(["setup", "--help"]) == 0


def test_cli_main_chat_help_returns_zero():
    assert cli.main(["chat", "--help"]) == 0


def test_cli_main_setup_non_interactive(tmp_path, capsys):
    db = tmp_path / "setup.db"
    rc = cli.main(
        [
            "setup",
            "--db",
            str(db),
            "--ollama-api-key",
            "test-key",
            "--wallet",
            "test-wallet",
            "--pool",
            "stratum+tcp://p:3333",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "setup saved" in out


def test_cli_parse_host_helper():
    assert cli.parse_host("192.0.2.1") == ("192.0.2.1", 22)
    assert cli.parse_host("192.0.2.1:2222") == ("192.0.2.1", 2222)
    assert cli.parse_host("[2001:db8::1]:2200") == ("2001:db8::1", 2200)


def test_cli_parse_ports_helper():
    assert cli.parse_ports("22") == [22]
    assert cli.parse_ports("22,80,443") == [22, 80, 443]
    assert cli.parse_ports("2200-2202") == [2200, 2201, 2202]
    assert cli.parse_ports("22,2200-2202") == [22, 2200, 2201, 2202]
    # De-duplicated.
    assert cli.parse_ports("22,22") == [22]
