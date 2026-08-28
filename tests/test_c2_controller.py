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


class _FakeTransport:
    """Minimal stand-in for an aiohttp request transport for peercert tests."""

    def __init__(self, peercert):
        self._peercert = peercert

    def get_extra_info(self, name, default=None):
        if name == "peercert":
            return self._peercert
        return default


class _FakeRequest:
    def __init__(self, peercert):
        self.transport = _FakeTransport(peercert)


def test_client_cert_serial_parses_hex_string(controller):
    """The asyncio SSL transport exposes serialNumber as a hex string, not int.

    Python's ``getpeercert()`` returns e.g. ``{'serialNumber': '2ED0594A...'}``;
    the controller must parse that to an int so revocation set membership works.
    """
    # 0x2ED0594AC6E47BE6 == 338882... ; use a small explicit value.
    assert controller._client_cert_serial(_FakeRequest({"serialNumber": "0A0B0C"})) == 0x0A0B0C
    # uppercase / long hex survives
    assert controller._client_cert_serial(
        _FakeRequest({"serialNumber": "2ED0594AC6E47BE6"})
    ) == int("2ED0594AC6E47BE6", 16)


def test_client_cert_serial_handles_missing_and_garbage(controller):
    assert controller._client_cert_serial(_FakeRequest(None)) is None
    assert controller._client_cert_serial(_FakeRequest({})) is None
    # garbage that isn't hex -> None (never raises)
    assert controller._client_cert_serial(_FakeRequest({"serialNumber": "nothex"})) is None
    # already-int passes through (defensive)
    assert controller._client_cert_serial(_FakeRequest({"serialNumber": 42})) == 42


def test_revocation_set_operations(controller):
    controller.revoke_serial(0x0A0B0C)
    assert controller.is_revoked(0x0A0B0C)
    assert not controller.is_revoked(0x0A0B0D)
    # revoking again is idempotent
    controller.revoke_serial(0x0A0B0C)
    assert controller.is_revoked(0x0A0B0C)
