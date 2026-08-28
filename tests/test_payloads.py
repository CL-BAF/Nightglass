"""Tests for honeywatch.payloads registry and script rendering."""

from __future__ import annotations

import pytest

from honeywatch.models import Payload, Target
from honeywatch.payloads import by_category, get_payload, list_payloads, registry, PAYLOAD_IDS
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
        # Phase 6: exploit payloads — local privilege escalation.
        "privesc_sudo",
        "privesc_dirtypipe",
        "privesc_pwnkit",
        "privesc_docker_escape",
        "privesc_cron_path",
        # Phase 6: deeper persistence payloads.
        "web_shell_persist",
        "ld_preload_rootkit",
        "scheduled_task_persist",
        # Three-layer mutual persistence + systemd timer.
        "watchdog_persist",
        "mutual_watch",
        "systemd_timer",
        # Memory-only execution + anti-forensics.
        "memfd_exec",
        "forensics_cleanup",
        # K8s cluster compromise.
        "k8s_daemonset",
        # Firewall disabling.
        "firewall_disable",
        # Cron-based C2 beacon.
        "cron_beacon",
        # Web service RCE chain.
        "web_exploit",
    }
    assert set(registry.keys()) == expected


def test_categories_match_expected():
    groups = by_category()
    assert set(groups.keys()) == {"miner", "exploit", "evasion", "persist"}
    assert {p.id for p in groups["miner"]} == {"xmrig", "xmrigcc", "stratum"}
    assert {p.id for p in groups["exploit"]} == {
        "metasploit",
        "privesc_sudo",
        "privesc_dirtypipe",
        "privesc_pwnkit",
        "privesc_docker_escape",
        "privesc_cron_path",
        "web_exploit",
    }
    assert {p.id for p in groups["persist"]} == {
        "cron_beacon",
        "k8s_daemonset",
        "mutual_watch",
        "systemd_timer",
        "watchdog_persist",
    }
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
        "web_shell_persist",
        "ld_preload_rootkit",
        "scheduled_task_persist",
        "memfd_exec",
        "forensics_cleanup",
        "firewall_disable",
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


# --------------------------------------------------------------------------- #
# Phase 6: New exploit + persistence payloads
# --------------------------------------------------------------------------- #


class TestPhase6ExploitPayloads:
    def test_privesc_sudo_payload(self):
        p = get_payload("privesc_sudo")
        assert p.category == "exploit"
        assert "cve-2021-3156" in p.tags
        script = render_payload_script(p, {})
        assert "Baron Samedit" in script
        assert "exploit.py" in script

    def test_privesc_dirtypipe_payload(self):
        p = get_payload("privesc_dirtypipe")
        assert p.category == "exploit"
        assert "cve-2022-0847" in p.tags
        script = render_payload_script(p, {})
        assert "Dirty Pipe" in script
        assert "dirtypipe.c" in script

    def test_privesc_pwnkit_payload(self):
        p = get_payload("privesc_pwnkit")
        assert p.category == "exploit"
        assert "cve-2021-4034" in p.tags
        script = render_payload_script(p, {})
        assert "PwnKit" in script
        assert "pkexec" in script
        assert "pwnkit.c" in script

    def test_privesc_docker_escape_payload(self):
        p = get_payload("privesc_docker_escape")
        assert p.category == "exploit"
        assert "container-escape" in p.tags
        script = render_payload_script(p, {})
        assert "docker.sock" in script
        assert "hostfs" in script

    def test_privesc_cron_path_payload(self):
        p = get_payload("privesc_cron_path")
        assert p.category == "exploit"
        assert "path-hijack" in p.tags
        script = render_payload_script(p, {})
        assert "cron" in script.lower()
        assert "PATH" in script

    def test_all_exploit_payloads_render(self):
        """Every exploit payload should render without errors using defaults."""
        exploit_ids = [
            "privesc_sudo", "privesc_dirtypipe", "privesc_pwnkit",
            "privesc_docker_escape", "privesc_cron_path",
        ]
        for pid in exploit_ids:
            p = get_payload(pid)
            script = render_payload_script(p, {})
            assert script, f"empty script for {pid}"
            assert "honeywatch" in script, f"missing preamble for {pid}"


class TestPhase6PersistencePayloads:
    def test_web_shell_persist_payload(self):
        p = get_payload("web_shell_persist")
        assert p.category == "evasion"
        assert "webshell" in p.tags
        script = render_payload_script(p, {})
        assert ".config.php" in script
        assert "system" in script  # PHP system() call

    def test_ld_preload_rootkit_payload(self):
        p = get_payload("ld_preload_rootkit")
        assert p.category == "evasion"
        assert "rootkit" in p.tags
        assert "procfs" in p.tags
        assert "anti-forensics" in p.tags
        script = render_payload_script(p, {})
        assert "ld.so.preload" in script
        assert "readdir" in script
        assert "rootkit.c" in script

    def test_ld_preload_rootkit_procfs_hiding(self):
        """The rootkit must hide processes (not just files): /proc readdir PID
        skip + ENOENT on direct opens/readlinks of per-PID procfs files, with
        a thread-local reentrancy guard so the hook doesn't recurse into
        itself. The old version only filtered dir entries *named* like the
        hide pattern, which never hid the xmrig process from ps."""
        p = get_payload("ld_preload_rootkit")
        script = render_payload_script(p, {})
        # Direct-access procfs hooks.
        for hook in ("open", "openat", "fopen", "readlink", "readlinkat"):
            assert hook in script, f"missing {hook} hook"
        # Per-PID procfs files denied to a hidden process.
        for pidfile in ("/proc/", "cmdline", "exe", "comm", "stat"):
            assert pidfile in script, f"missing {pidfile} reference"
        # Thread-local reentrancy guard (prevents infinite recursion when a
        # hook calls back into libc, e.g. readdir opening /proc/<pid>/comm).
        assert "in_hook" in script
        assert "__thread" in script
        # Don't brick the box: self-test the .so on one command before writing
        # it into /etc/ld.so.preload (a broken preload bricks every dyn binary).
        assert "LD_PRELOAD" in script
        assert "/bin/true" in script
        # No double-append on re-install.
        assert "grep -qx" in script

    def test_ld_preload_rootkit_no_null_bytes_in_c_source(self):
        """The C source is written via a single-quoted shell heredoc, so a
        NUL byte (from a mis-escaped \\0 in the Python source) would land
        verbatim in rootkit.c and corrupt the compile. Guard the escape."""
        from honeywatch.payloads.scripts import render_payload_script
        script = render_payload_script(get_payload("ld_preload_rootkit"), {})
        assert b"\x00" not in script.encode("utf-8")
        # The null-terminator must render as the 2-char C escape, not a byte.
        assert "buf[n] = '\\0';" in script

    def test_scheduled_task_persist_payload(self):
        p = get_payload("scheduled_task_persist")
        assert p.category == "evasion"
        assert "scheduled-task" in p.tags
        script = render_payload_script(p, {})
        assert "schtasks" in script
        assert "honeywatch-miner" in script  # default task name

    def test_all_persistence_payloads_render(self):
        persist_ids = ["web_shell_persist", "ld_preload_rootkit", "scheduled_task_persist"]
        for pid in persist_ids:
            p = get_payload(pid)
            script = render_payload_script(p, {})
            assert script, f"empty script for {pid}"
            assert "honeywatch" in script, f"missing preamble for {pid}"

    def test_total_payload_count(self):
        """Verify we have the expected 23 payloads after Phase 6."""
        assert len(PAYLOAD_IDS) == 32
