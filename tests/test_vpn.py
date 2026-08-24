"""Tests for the Mullvad VPN gate (honeywatch.vpn) and CLI enforcement."""

from __future__ import annotations

from honeywatch import cli, vpn
from honeywatch.config import load_config


def test_egress_parses_mullvad_exit_ip_true(monkeypatch):
    monkeypatch.setattr(vpn, "_fetch", lambda url, timeout: '{"mullvad_exit_ip": true}')
    assert vpn.egress_is_mullvad() is True


def test_egress_false_when_exit_ip_not_mullvad(monkeypatch):
    monkeypatch.setattr(vpn, "_fetch", lambda url, timeout: '{"mullvad_exit_ip": false}')
    assert vpn.egress_is_mullvad() is False


def test_egress_falls_back_to_connected_text(monkeypatch):
    def fake(url, timeout):
        if "json" in url:
            return "not json at all"
        return "You are connected to Mullvad."
    monkeypatch.setattr(vpn, "_fetch", fake)
    assert vpn.egress_is_mullvad() is True


def test_egress_false_on_not_connected_text(monkeypatch):
    def fake(url, timeout):
        if "json" in url:
            return "garbage"
        return "You are not connected to Mullvad"
    monkeypatch.setattr(vpn, "_fetch", fake)
    assert vpn.egress_is_mullvad() is False


def test_egress_false_when_fetch_fails(monkeypatch):
    monkeypatch.setattr(vpn, "_fetch", lambda url, timeout: None)
    assert vpn.egress_is_mullvad() is False


def test_require_mullvad_refuses_when_disconnected(monkeypatch, capsys):
    monkeypatch.setattr(vpn, "egress_is_mullvad", lambda timeout=8.0: False)
    monkeypatch.setattr(vpn, "interface_is_mull", lambda: False)
    assert vpn.require_mullvad() is False
    assert "REFUSED" in capsys.readouterr().err


def test_require_mullvad_passes_on_egress_confirm(monkeypatch, capsys):
    monkeypatch.setattr(vpn, "egress_is_mullvad", lambda timeout=8.0: True)
    assert vpn.require_mullvad() is True
    assert "OK" in capsys.readouterr().err


def test_require_mullvad_passes_on_local_interface(monkeypatch, capsys):
    monkeypatch.setattr(vpn, "egress_is_mullvad", lambda timeout=8.0: False)
    monkeypatch.setattr(vpn, "interface_is_mull", lambda: True)
    assert vpn.require_mullvad() is True


def test_require_mullvad_quiet_prints_nothing(monkeypatch, capsys):
    monkeypatch.setattr(vpn, "egress_is_mullvad", lambda timeout=8.0: False)
    monkeypatch.setattr(vpn, "interface_is_mull", lambda: False)
    assert vpn.require_mullvad(quiet=True) is False
    assert capsys.readouterr().err == ""


def test_env_opt_out_skips_gate(monkeypatch, capsys):
    monkeypatch.setenv("HONEYWATCH_SKIP_VPN", "1")
    monkeypatch.setattr(vpn, "egress_is_mullvad", lambda timeout=8.0: False)
    monkeypatch.setattr(vpn, "interface_is_mull", lambda: False)
    assert vpn.require_mullvad() is True
    assert "skipped" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# CLI enforcement
# ---------------------------------------------------------------------------


def test_cli_probe_refuses_without_mullvad(monkeypatch, capsys):
    monkeypatch.delenv("HONEYWATCH_SKIP_VPN", raising=False)
    monkeypatch.setattr(
        vpn, "mullvad_connected", lambda timeout=8.0: (False, "no mullvad")
    )
    rc = cli.main(["probe", "192.0.2.1"])
    assert rc == 2
    assert "REFUSED" in capsys.readouterr().err


def test_cli_scan_refuses_without_mullvad(monkeypatch, capsys):
    monkeypatch.delenv("HONEYWATCH_SKIP_VPN", raising=False)
    monkeypatch.setattr(
        vpn, "mullvad_connected", lambda timeout=8.0: (False, "no mullvad")
    )
    rc = cli.main(["scan", "192.0.2.0/24", "--tool", "masscan"])
    assert rc == 2
    assert "REFUSED" in capsys.readouterr().err


def test_enforce_vpn_skips_when_flag_passed():
    cfg = load_config()
    assert cli._enforce_vpn(cfg, skip_vpn_check=True) is True


def test_enforce_vpn_refused_by_default(monkeypatch):
    cfg = load_config()
    monkeypatch.setattr(vpn, "require_mullvad", lambda timeout=8.0: False)
    assert cli._enforce_vpn(cfg, skip_vpn_check=False) is False


def test_enforce_vpn_disabled_by_config(monkeypatch):
    cfg = load_config()
    cfg.vpn.required = False
    monkeypatch.setattr(vpn, "require_mullvad", lambda timeout=8.0: False)
    assert cli._enforce_vpn(cfg, skip_vpn_check=False) is True
