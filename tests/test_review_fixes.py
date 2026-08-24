"""Tests pinning the codebase-review fixes so they can't quietly regress.

  R-C1  evasion audit trail is recorded in the operation manifest
  R-C2  unsafe shell-metacharacters in payload variables are refused by default
  R-C2b ...and allowed when the operator opts in
  R-H1  `--db=` / `--out-dir=` (equals form) override config, not silently drop
  R-H2  an operation with no targets deserialises to [], not [""]
  R-H2b worker categories with no entries are [], not [""]
  R-H3  list_workers(active_within_s=...) actually filters stale workers
  R-M1  worker polling backoff grows on controller errors
  R-M2  worker dry_run returns the actual script for review
  R-M3  c2_tasks has the claim/op indexes
"""

from __future__ import annotations

import asyncio
import json

import pytest

from honeywatch.c2.store import C2Store
from honeywatch.c2.worker import Worker, WorkerError
from honeywatch.models import Target
from honeywatch.ops import build_manifest, enqueue_operation


# ---------------------------------------------------------------------------
# R-C1: evasion audit trail
# ---------------------------------------------------------------------------

def test_build_manifest_records_evasion_ids():
    manifest = build_manifest(
        "stratum",
        [Target(ip="10.0.0.1", port=22)],
        {"upstream_pool": "pool.example.com:3333"},
        apply_evasion=["upx", "symbol_strip"],
    )
    assert manifest.evasion == ["upx", "symbol_strip"]


def test_enqueue_operation_persists_evasion_in_manifest(tmp_path):
    c2 = C2Store(str(tmp_path / "c.db"))
    manifest = build_manifest(
        "stratum",
        [Target(ip="10.0.0.1", port=22)],
        {"upstream_pool": "pool.example.com:3333"},
        apply_evasion=["upx", "anti_vm"],
    )
    op = enqueue_operation(c2, manifest)
    fetched = c2.get_operation(op.id)
    assert fetched.manifest.get("evasion") == ["upx", "anti_vm"]
    assert fetched.manifest.get("per_host_scripts") == manifest.per_host_scripts


# ---------------------------------------------------------------------------
# R-C2: unsafe variable guard
# ---------------------------------------------------------------------------

def test_build_manifest_refuses_shell_injection_in_wallet():
    with pytest.raises(ValueError, match="unsafe variable values"):
        build_manifest(
            "xmrig",
            [Target(ip="10.0.0.1", port=22)],
            {"pool": "stratum+tcp://p:3333", "wallet": "$(rm -rf ~)"},
        )


def test_build_manifest_refuses_backtick_and_newline():
    with pytest.raises(ValueError):
        build_manifest(
            "stratum",
            [Target(ip="10.0.0.1", port=22)],
            {"upstream_pool": "p:3333\nmalicious"},
        )


def test_build_manifest_allows_unsafe_when_opted_in():
    manifest = build_manifest(
        "xmrig",
        [Target(ip="10.0.0.1", port=22)],
        {"pool": "stratum+tcp://p:3333", "wallet": "$(echo hi)"},
        allow_unsafe_vars=True,
    )
    assert "10.0.0.1" in manifest.per_host_scripts


def test_build_manifest_allows_safe_values():
    manifest = build_manifest(
        "stratum",
        [Target(ip="10.0.0.1", port=22)],
        {"upstream_pool": "stratum+tcp://pool.example.com:3333"},
    )
    assert "pool.example.com:3333" in manifest.per_host_scripts["10.0.0.1"]


def test_resource_script_is_exempt_from_sanitizer():
    # resource_script is intentionally free-form (a metasploit rc file).
    manifest = build_manifest(
        "metasploit",
        [Target(ip="10.0.0.1", port=22)],
        {"resource_script": "use auxiliary/scanner/ssh/ssh_version\nrun\n"},
    )
    assert "10.0.0.1" in manifest.per_host_scripts


# ---------------------------------------------------------------------------
# R-H1: `--db=` / `--out-dir=` equals-form override
# ---------------------------------------------------------------------------

def test_cli_scan_db_equals_form_overrides_config(tmp_path, capsys, monkeypatch):
    import honeywatch.cli as cli
    from honeywatch.models import HostHit

    captured: dict = {}

    async def fake_to_thread(fn, *a, **k):
        return []  # no hits -> no probes

    monkeypatch.setattr("honeywatch.pipeline.asyncio.to_thread", fake_to_thread)

    cfg_db = tmp_path / "cfg.db"
    args = cli.build_parser().parse_args(
        ["scan", "192.0.2.0/24", f"--db={cfg_db}", "--skip-vpn-check", "--no-ai"]
    )
    # The equals form must populate args.db (argparse handles that) and the
    # handler must use it rather than fall back to the config default.
    assert args.db == str(cfg_db)
    argv = ["scan", "192.0.2.0/24", f"--db={cfg_db}", "--skip-vpn-check", "--no-ai"]
    rc = cli._cmd_scan(args, argv)
    assert rc == 0
    # The chosen db file should now exist (Store created it on init).
    assert cfg_db.exists()


def test_cli_report_db_equals_form_resolves(tmp_path, capsys):
    import honeywatch.cli as cli
    from honeywatch.store import Store
    from honeywatch.models import Score, Signals

    db = tmp_path / "rep.db"
    Store(str(db)).upsert_scores([
        Score(ip="1.2.3.4", port=22, signals=Signals(heuristic_score=0.5),
              final_label="uncertain", final_confidence=0.5)
    ])
    out = tmp_path / "out.json"
    args = cli.build_parser().parse_args(
        ["report", f"--db={db}", "--format", "json", "--out", str(out)]
    )
    assert args.db == str(db)
    rc = cli._cmd_report(args, ["report", f"--db={db}", "--format", "json", "--out", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data[0]["ip"] == "1.2.3.4"


# ---------------------------------------------------------------------------
# R-H2: empty target list / categories deserialise cleanly
# ---------------------------------------------------------------------------

def test_operation_with_no_targets_round_trips_empty(tmp_path):
    c2 = C2Store(str(tmp_path / "c.db"))
    op = c2.create_operation("xmrig", [], {})
    fetched = c2.get_operation(op.id)
    assert fetched.target_ips == []


def test_worker_categories_empty_round_trip(tmp_path):
    c2 = C2Store(str(tmp_path / "c.db"))
    c2.register_worker("w1", [])
    workers = c2.list_workers()
    assert workers[0]["categories"] == []


# ---------------------------------------------------------------------------
# R-H3: list_workers liveness filter
# ---------------------------------------------------------------------------

def test_list_workers_filters_stale(tmp_path):
    from datetime import datetime, timedelta, timezone
    c2 = C2Store(str(tmp_path / "c.db"))
    c2.register_worker("fresh", ["miner"])
    # Inject a stale worker row directly.
    stale = (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat()
    conn = c2._connect()
    with conn:
        conn.execute(
            "INSERT INTO c2_workers (id, categories, connected_at, last_seen) VALUES (?,?,?,?)",
            ("stale", "miner", stale, stale),
        )
    c2._close(conn)

    all_workers = c2.list_workers()
    assert {w["id"] for w in all_workers} == {"fresh", "stale"}

    active = c2.list_workers(active_within_s=60)
    assert [w["id"] for w in active] == ["fresh"]


# ---------------------------------------------------------------------------
# R-M1: worker polling backoff grows on controller outage
# ---------------------------------------------------------------------------

def test_worker_polling_backoff_grows_on_controller_error(monkeypatch):
    worker = Worker("http://127.0.0.1:1", poll_interval=0.01)
    sleeps: list[float] = []

    async def fake_sleep(d):
        sleeps.append(d)

    async def fake_claim():
        raise WorkerError("controller down")

    async def fake_to_thread(fn, *a, **k):
        return fake_claim()

    monkeypatch.setattr(worker, "claim_task", lambda: None)
    monkeypatch.setattr("honeywatch.c2.worker.asyncio.to_thread", fake_to_thread)
    monkeypatch.setattr("honeywatch.c2.worker.asyncio.sleep", fake_sleep)

    async def run_a_bit():
        task = asyncio.ensure_future(worker._run_polling())
        await asyncio.sleep(0.05)
        worker.stop()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            # Expected: we just called task.cancel() while it was mid-sleep.
            # Any *other* exception (e.g. a real crash inside _run_polling) must
            # propagate rather than be swallowed here.
            pass

    asyncio.run(run_a_bit())
    # Backoff sleeps should grow over the outage (later sleeps >= earlier).
    assert sleeps, "expected at least one backoff sleep"
    assert sleeps[-1] >= sleeps[0]


# ---------------------------------------------------------------------------
# R-M2: worker dry_run returns the script
# ---------------------------------------------------------------------------

def test_worker_dry_run_returns_script():
    from honeywatch.models import WorkerTask
    worker = Worker("http://127.0.0.1:1", exec_mode="dry_run")
    task = WorkerTask(id="t", operation_id="o", payload_id="xmrig", category="miner",
                      script="echo hello", target=Target(ip="10.0.0.1", port=22))
    result = worker.execute_task(task)
    assert result["mode"] == "dry_run"
    assert result["script"] == "echo hello"
    assert result["script_length"] == len("echo hello")


# ---------------------------------------------------------------------------
# R-M3: c2_tasks indexes exist
# ---------------------------------------------------------------------------

def test_c2_tasks_indexes_exist(tmp_path):
    import sqlite3
    db = str(tmp_path / "c.db")
    C2Store(db)
    conn = sqlite3.connect(db)
    names = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index'"
    ).fetchall()}
    conn.close()
    assert "idx_c2_tasks_claim" in names
    assert "idx_c2_tasks_op" in names
    assert "idx_c2_ops_status" in names