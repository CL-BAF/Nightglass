"""Tests for the SQLite store and the JSON/CSV/Markdown report writers."""

from __future__ import annotations

import csv
import json

from honeywatch.models import AiVerdict, Score, Signals
from honeywatch.report import write_csv, write_json, write_md
from honeywatch.store import Store


def _score(ip: str, label: str = "uncertain", confidence: float = 0.5):
    return Score(
        ip=ip,
        port=22,
        fingerprint=None,
        signals=Signals(flags=[], heuristic_score=confidence),
        ai=AiVerdict(classification=label, confidence=confidence, reasons=["r"], model="m"),
        final_confidence=confidence,
        final_label=label,
    )


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

def test_store_upsert_query_stats(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    store.upsert_scores(
        [
            _score("192.0.2.1", label="uncertain", confidence=0.35),
            _score("192.0.2.2", label="real", confidence=0.1),
            _score("192.0.2.3", label="honeypot", confidence=0.9),
        ]
    )

    rows = store.query(limit=10)
    assert len(rows) == 3
    ips = {r["ip"] for r in rows}
    assert ips == {"192.0.2.1", "192.0.2.2", "192.0.2.3"}
    assert all("ip" in r and "label" in r and "confidence" in r for r in rows)

    # Ordered by confidence descending.
    assert rows[0]["ip"] == "192.0.2.3"

    honeypots = store.query(limit=10, label="honeypot")
    assert [r["ip"] for r in honeypots] == ["192.0.2.3"]

    high = store.query(limit=10, min_confidence=0.8)
    assert [r["ip"] for r in high] == ["192.0.2.3"]

    stats = store.stats()
    assert stats["total"] == 3
    assert stats["by_label"]["honeypot"] == 1
    assert stats["by_label"]["uncertain"] == 1
    assert stats["by_label"]["real"] == 1


def test_store_upsert_replaces_existing(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    store.upsert_scores([_score("192.0.2.1", label="real", confidence=0.1)])
    store.upsert_scores([_score("192.0.2.1", label="honeypot", confidence=0.95)])
    assert store.stats()["total"] == 1
    rows = store.query(limit=10)
    assert rows[0]["label"] == "honeypot"
    assert rows[0]["confidence"] == 0.95


def test_store_query_limit(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    store.upsert_scores([_score(f"192.0.2.{i}") for i in range(1, 6)])
    rows = store.query(limit=2)
    assert len(rows) == 2


def test_store_stats_by_flag(tmp_path, openssh_fp):
    store = Store(str(tmp_path / "test.db"))
    s1 = _score("192.0.2.1")
    s1.signals.flags = ["crypto.legacy_cipher", "hostkey.weak"]
    store.upsert_scores([s1])
    stats = store.stats()
    assert stats["by_flag"]["crypto.legacy_cipher"] == 1
    assert stats["by_flag"]["hostkey.weak"] == 1


# ---------------------------------------------------------------------------
# v0.2: SQL-side label-set filtering + flag filtering (host_flags table)
# ---------------------------------------------------------------------------

def test_store_query_labels_set_filter(tmp_path):
    """labels=... filters in SQL via idx_hosts_label instead of the old
    100k-row Python filter."""
    store = Store(str(tmp_path / "test.db"))
    store.upsert_scores([
        _score("192.0.2.1", label="real", confidence=0.1),
        _score("192.0.2.2", label="likely_real", confidence=0.3),
        _score("192.0.2.3", label="honeypot", confidence=0.9),
    ])
    rows = store.query(limit=10, labels={"real", "likely_real"})
    ips = {r["ip"] for r in rows}
    assert ips == {"192.0.2.1", "192.0.2.2"}


def test_store_query_scores_flag_filters(tmp_path):
    """require_flags / exclude_flags filter through the normalized host_flags
    table — indexed EXISTS lookups, no Python string splitting."""
    store = Store(str(tmp_path / "test.db"))
    s1 = _score("192.0.2.1", label="real", confidence=0.1)
    s1.signals.flags = ["crypto.legacy_cipher"]
    s2 = _score("192.0.2.2", label="real", confidence=0.2)
    s2.signals.flags = ["banner.immediate"]
    store.upsert_scores([s1, s2])

    with_flag = store.query_scores(limit=10, require_flags={"crypto.legacy_cipher"})
    assert [s.ip for s in with_flag] == ["192.0.2.1"]

    without_flag = store.query_scores(limit=10, exclude_flags={"crypto.legacy_cipher"})
    assert [s.ip for s in without_flag] == ["192.0.2.2"]


# ---------------------------------------------------------------------------
# v0.2: chain run state persistence (durable resume)
# ---------------------------------------------------------------------------


def test_chain_state_round_trip(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    state = {
        "round": 2,
        "pivoted_subnets": ["10.0.0.0/24", "10.0.1.0/24"],
        "looted_footholds": [("10.0.0.5", 22)],
        "enqueued": [("10.0.0.5", 22)],
        "recovered_ssh_keys": ["/tmp/key1"],
        "cloud_creds": [{"ip": "10.0.0.5", "port": 22, "creds": ["AWS_SECRET"]}],
        "loot": [{"ip": "10.0.0.5", "summary": "x"}],
    }
    store.save_chain_state("run-1", state)
    loaded = store.load_chain_state("run-1")
    assert loaded is not None
    assert loaded["round"] == 2
    assert loaded["pivoted_subnets"] == ["10.0.0.0/24", "10.0.1.0/24"]
    assert loaded["looted_footholds"] == [("10.0.0.5", 22)]
    assert loaded["enqueued"] == [("10.0.0.5", 22)]
    assert loaded["recovered_ssh_keys"] == ["/tmp/key1"]
    assert loaded["cloud_creds"][0]["creds"] == ["AWS_SECRET"]


def test_chain_state_unknown_run_returns_none(tmp_path):
    store = Store(str(tmp_path / "test.db"))
    assert store.load_chain_state("never-ran") is None


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------

def test_write_json(tmp_path, openssh_fp):
    score = Score(
        ip="203.0.113.9",
        port=22,
        fingerprint=openssh_fp,
        signals=Signals(flags=["crypto.legacy_cipher"], heuristic_score=0.9),
        ai=AiVerdict(classification="honeypot", confidence=0.9, reasons=["x"], model="m"),
        final_confidence=0.9,
        final_label="honeypot",
    )
    path = tmp_path / "report.json"
    write_json(str(path), [score])
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data[0]["ip"] == "203.0.113.9"
    assert data[0]["fingerprint"]["software"] == "OpenSSH"
    assert data[0]["signals"]["flags"] == ["crypto.legacy_cipher"]


def test_write_csv(tmp_path, openssh_fp):
    score = Score(
        "203.0.113.10",
        22,
        fingerprint=openssh_fp,
        signals=Signals(flags=["crypto.legacy_cipher"]),
        final_confidence=0.9,
        final_label="honeypot",
    )
    path = tmp_path / "report.csv"
    write_csv(str(path), [score])
    rows = list(csv.reader(path.read_text(encoding="utf-8").splitlines()))
    assert rows[0] == [
        "ip",
        "port",
        "final_label",
        "final_confidence",
        "heuristic",
        "ai_classification",
        "ai_confidence",
        "banner",
        "software",
        "version",
        "flags",
    ]
    assert rows[1][0] == "203.0.113.10"
    assert rows[1][3] == "0.9"


def test_write_md(tmp_path, openssh_fp):
    score = Score(
        "203.0.113.11",
        22,
        fingerprint=openssh_fp,
        signals=Signals(flags=["crypto.legacy_cipher"]),
        ai=AiVerdict(classification="honeypot", confidence=0.9, reasons=["x"], model="m"),
        final_confidence=0.9,
        final_label="honeypot",
    )
    path = tmp_path / "report.md"
    text = write_md(str(path), [score])
    assert "203.0.113.11" in text
    assert "crypto.legacy_cipher" in text
    assert "Honeywatch Report" in text
    assert path.read_text(encoding="utf-8") == text
