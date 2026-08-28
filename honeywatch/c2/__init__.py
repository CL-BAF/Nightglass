"""C2 / web infrastructure for honeywatch.

Provides a controller server (HTTP + WebSocket dashboard), worker client,
and SQLite-backed task queue. The controller is intended to sit behind
``nginx`` with TLS termination or with its own SSL context.
"""

from __future__ import annotations

from honeywatch.c2.beacon import BeaconProfile
from honeywatch.c2.controller import Controller
from honeywatch.c2.store import C2Store
from honeywatch.c2.tls import (
    build_client_ssl_context,
    build_mtls_server_ssl_context,
    build_ssl_context,
    ensure_self_signed_pair,
)
from honeywatch.c2.worker import Worker, WorkerError

__all__ = [
    "BeaconProfile",
    "Controller",
    "C2Store",
    "Worker",
    "WorkerError",
    "build_client_ssl_context",
    "build_mtls_server_ssl_context",
    "build_ssl_context",
    "ensure_self_signed_pair",
]
