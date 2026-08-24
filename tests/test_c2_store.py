"""Tests for honeywatch.c2.store persistence."""

from __future__ import annotations

import pytest

from honeywatch.c2.store import C2Store
from honeywatch.models import Target, WorkerTask


@pytest.fixture
def store(tmp_path):
    db = tmp_path / "c2.db"
    return C2Store(str(db))


def test_create_operation(store):
    op = store.create_operation("xmrig", ["10.0.0.1", "10.0.0.2"], {"pool": "p"})
    assert op.id.startswith("op-")
    assert op.payload_id == "xmrig"
    assert op.target_ips == ["10.0.0.1", "10.0.0.2"]
    assert op.status == "pending"


def test_get_operation(store):
    op = store.create_operation("xmrig", ["10.0.0.1"])
    fetched = store.get_operation(op.id)
    assert fetched is not None
    assert fetched.id == op.id


def test_update_operation_status(store):
    op = store.create_operation("xmrig", ["10.0.0.1"])
    store.update_operation_status(op.id, "running", {"worker": "w1"})
    fetched = store.get_operation(op.id)
    assert fetched.status == "running"
    assert len(fetched.result_log) == 1


def test_task_lifecycle(store):
    op = store.create_operation("xmrig", ["10.0.0.1"])
    task = WorkerTask(
        id="",
        operation_id=op.id,
        payload_id="xmrig",
        category="miner",
        target=Target(ip="10.0.0.1", port=22),
        script="echo installed",
        variables={"pool": "p"},
    )
    store.create_task(task)
    assert task.id.startswith("task-")

    claimed = store.claim_next_task("worker-1", ["miner"])
    assert claimed is not None
    assert claimed.status == "running"
    assert claimed.worker_id == "worker-1"

    store.complete_task(claimed.id, "worker-1", True, {"rc": 0})
    tasks = store.list_tasks(operation_id=op.id, status="completed")
    assert len(tasks) == 1
    assert tasks[0].result == {"rc": 0}


def test_claim_respects_categories(store):
    op = store.create_operation("xmrig", ["10.0.0.1"])
    task = WorkerTask(
        id="",
        operation_id=op.id,
        payload_id="xmrig",
        category="miner",
        target=Target(ip="10.0.0.1", port=22),
        script="echo",
    )
    store.create_task(task)
    assert store.claim_next_task("w", ["exploit"]) is None
    assert store.claim_next_task("w", ["miner"]) is not None


def test_worker_registration_and_heartbeat(store):
    store.register_worker("w1", ["miner", "exploit"])
    store.heartbeat_worker("w1")
    workers = store.list_workers()
    assert len(workers) == 1
    assert workers[0]["id"] == "w1"
    assert workers[0]["categories"] == ["miner", "exploit"]
