"""Tests for honeywatch.c2.controller HTTP/WebSocket API."""

from __future__ import annotations

import asyncio
import sys

import pytest

from honeywatch.c2.store import C2Store

try:
    from honeywatch.c2.controller import Controller, HAS_AIOHTTP
except Exception:
    HAS_AIOHTTP = False
    Controller = None  # type: ignore[misc,assignment]


pytestmark = pytest.mark.skipif(not HAS_AIOHTTP, reason="aiohttp not installed")


@pytest.fixture
def controller(tmp_path):
    if not HAS_AIOHTTP:
        pytest.skip("aiohttp not installed")
    db = tmp_path / "c2.db"
    store = C2Store(str(db))
    return Controller(store, host="127.0.0.1", port=0)


@pytest.mark.asyncio
async def test_health_endpoint(controller):
    from aiohttp.test_utils import TestServer, TestClient

    server = TestServer(controller.app)
    client = TestClient(server)
    await client.start_server()
    try:
        resp = await client.get("/api/health")
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "ok"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_dashboard_served(controller):
    from aiohttp.test_utils import TestServer, TestClient

    server = TestServer(controller.app)
    client = TestClient(server)
    await client.start_server()
    try:
        resp = await client.get("/")
        assert resp.status == 200
        text = await resp.text()
        assert "honeywatch C2 dashboard" in text
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_create_operation(controller):
    from aiohttp.test_utils import TestServer, TestClient

    server = TestServer(controller.app)
    client = TestClient(server)
    await client.start_server()
    try:
        resp = await client.post(
            "/api/operations",
            json={"payload_id": "xmrig", "target_ips": ["10.0.0.1"], "manifest": {}},
        )
        assert resp.status == 201
        data = await resp.json()
        assert data["payload_id"] == "xmrig"
        assert "10.0.0.1" in data["target_ips"]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_claim_and_complete_task(controller):
    from aiohttp.test_utils import TestServer, TestClient

    server = TestServer(controller.app)
    client = TestClient(server)
    await client.start_server()
    try:
        await client.post(
            "/api/operations",
            json={
                "payload_id": "xmrig",
                "target_ips": ["10.0.0.1"],
                "manifest": {"scripts": {"10.0.0.1": "echo ok"}},
            },
        )

        # Directly inject a task since create_operation does not auto-create tasks.
        from honeywatch.models import Target, WorkerTask

        task = WorkerTask(
            id="",
            operation_id=controller.store.list_operations()[0].id,
            payload_id="xmrig",
            category="miner",
            target=Target(ip="10.0.0.1", port=22),
            script="echo ok",
        )
        controller.store.create_task(task)

        resp = await client.post(
            "/api/tasks/claim",
            json={"worker_id": "w1", "categories": ["miner"]},
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["task"]["payload_id"] == "xmrig"
        task_id = data["task"]["id"]

        resp = await client.post(
            f"/api/tasks/{task_id}/result",
            json={"worker_id": "w1", "success": True, "result": {"rc": 0}},
        )
        assert resp.status == 200
    finally:
        await client.close()
