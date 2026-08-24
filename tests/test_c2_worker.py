"""Tests for honeywatch.c2.worker task execution."""

from __future__ import annotations

import os

import pytest

from honeywatch.c2.store import C2Store
from honeywatch.c2.worker import Worker
from honeywatch.models import Target, WorkerTask


@pytest.fixture
def worker(tmp_path):
    db = tmp_path / "c2.db"
    store = C2Store(str(db))
    return Worker("http://127.0.0.1:1", worker_id="test-worker", categories=["miner"]), store


def test_dry_run_execution(worker):
    w, store = worker
    w.exec_mode = "dry_run"
    task = WorkerTask(
        id="t1",
        operation_id="op1",
        payload_id="xmrig",
        category="miner",
        target=Target(ip="10.0.0.1", port=22),
        script="echo hello",
    )
    result = w.execute_task(task)
    assert result["mode"] == "dry_run"
    assert result["script_length"] == 10
    assert "[dry run" in result["stdout"]


import os


def test_local_simulate_execution(worker):
    if os.name == "nt":
        pytest.skip("local_simulate requires a POSIX shell")
    w, _store = worker
    w.exec_mode = "local_simulate"
    task = WorkerTask(
        id="t2",
        operation_id="op1",
        payload_id="xmrig",
        category="miner",
        target=Target(ip="10.0.0.1", port=22),
        script="echo honeywatch-worker-test",
    )
    result = w.execute_task(task)
    assert result["mode"] == "local_simulate"
    assert result["returncode"] == 0
    assert "honeywatch-worker-test" in result["stdout"]


def test_ssh_mode_requires_target(worker):
    w, store = worker
    w.exec_mode = "ssh"
    task = WorkerTask(
        id="t3",
        operation_id="op1",
        payload_id="xmrig",
        category="miner",
        target=None,
        script="echo",
    )
    result = w.execute_task(task)
    assert result["mode"] == "ssh"
    assert "error" in result
