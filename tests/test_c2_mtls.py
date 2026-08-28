"""End-to-end mutual-TLS integration tests for the C2 worker/controller plane.

These spin up a real aiohttp controller with an mTLS server SSL context (an
internal CA signs both the controller's server cert and the workers' client
certs) and connect over HTTPS with stdlib ``urllib`` using a CA-pinned client
context -- exercising the full stack including the controller's app-layer
client-cert serial extraction (``request.transport.get_extra_info("peercert")``)
and revocation gate.

Skipped when ``openssl`` or ``aiohttp`` are unavailable so the suite still runs
in minimal CI. This is the verification that mTLS is actually wired end-to-end:
a CA-pinned worker with a valid client cert is accepted, a revoked serial is
rejected with 403, and a connection with no client cert fails the TLS handshake.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import urllib.error
import urllib.request

import pytest

from honeywatch.c2.ca import ca_pin_from_cert, cert_serial, generate_ca, sign_server_cert, sign_worker_cert
from honeywatch.c2.store import C2Store
from honeywatch.c2.tls import build_client_ssl_context, build_mtls_server_ssl_context

try:
    from honeywatch.c2.controller import Controller, HAS_AIOHTTP
except Exception:  # pragma: no cover
    HAS_AIOHTTP = False
    Controller = None  # type: ignore[misc,assignment]


_HAS_OPENSSL = shutil.which("openssl") is not None
pytestmark = [
    pytest.mark.skipif(not _HAS_OPENSSL, reason="openssl not on PATH"),
    pytest.mark.skipif(not HAS_AIOHTTP, reason="aiohttp not installed"),
]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def mtls_env(tmp_path):
    """Provision a CA + CA-signed server cert + two worker client certs."""
    ca_cert = str(tmp_path / "ca.crt")
    ca_key = str(tmp_path / "ca.key")
    generate_ca(ca_cert, ca_key, days=10)

    srv_cert = str(tmp_path / "server.crt")
    srv_key = str(tmp_path / "server.key")
    sign_server_cert(ca_cert, ca_key, srv_cert, srv_key, hostname="127.0.0.1", days=10)

    w1_cert = str(tmp_path / "worker-good.crt")
    w1_key = str(tmp_path / "worker-good.key")
    sign_worker_cert(ca_cert, ca_key, w1_cert, w1_key, worker_id="worker-good", days=10)

    w2_cert = str(tmp_path / "worker-bad.crt")
    w2_key = str(tmp_path / "worker-bad.key")
    sign_worker_cert(ca_cert, ca_key, w2_cert, w2_key, worker_id="worker-bad", days=10)

    return {
        "ca_cert": ca_cert,
        "ca_key": ca_key,
        "srv_cert": srv_cert,
        "srv_key": srv_key,
        "good_cert": w1_cert,
        "good_key": w1_key,
        "good_serial": cert_serial(w1_cert),
        "bad_cert": w2_cert,
        "bad_key": w2_key,
        "bad_serial": cert_serial(w2_cert),
        "ca_pin": ca_pin_from_cert(ca_cert),
    }


@pytest.fixture
def mtls_controller(mtls_env, tmp_path):
    """Start a real controller with an mTLS server context on a free port.

    The server runs on a dedicated event loop in a daemon thread so the main
    thread can drive blocking ``urllib`` clients against it. This mirrors how
    the controller runs in production (a live loop serving TLS) and lets the
    test assert transport-level handshake behaviour, not just app responses.
    """
    if not HAS_AIOHTTP:
        pytest.skip("aiohttp not installed")
    from aiohttp import web

    port = _free_port()
    store = C2Store(str(tmp_path / "c2.db"))
    ssl_ctx = build_mtls_server_ssl_context(
        mtls_env["srv_cert"], mtls_env["srv_key"], mtls_env["ca_cert"]
    )
    controller = Controller(
        store,
        host="127.0.0.1",
        port=port,
        ssl_context=ssl_ctx,
        api_token=None,
        ca_path=mtls_env["ca_cert"],
        revoked_serials=None,
    )

    loop = asyncio.new_event_loop()
    runner = web.AppRunner(controller.app)
    ready = threading.Event()
    server_error: list = []

    def _serve() -> None:
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(runner.setup())
            site = web.TCPSite(runner, "127.0.0.1", port, ssl_context=ssl_ctx)
            loop.run_until_complete(site.start())
            ready.set()
            loop.run_forever()
        except Exception as exc:  # pragma: no cover - surfaced via server_error
            server_error.append(exc)
            ready.set()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    assert ready.wait(10.0), "controller server failed to start"
    if server_error:
        raise server_error[0]
    base_url = f"https://127.0.0.1:{port}"
    try:
        yield controller, base_url
    finally:
        # Stop the serving loop, then cleanup the runner on a fresh loop.
        loop.call_soon_threadsafe(loop.stop)
        t.join(5.0)
        cleanup_loop = asyncio.new_event_loop()
        try:
            cleanup_loop.run_until_complete(runner.cleanup())
        finally:
            cleanup_loop.close()
            loop.close()


def _https_get(url: str, ctx: ssl.SSLContext | None) -> tuple[int, str]:
    """GET ``url`` with an SSL context; return (status, body). Raises on TLS error."""
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def test_valid_worker_accepted(mtls_controller, mtls_env):
    """A CA-pinned worker presenting a valid (non-revoked) client cert is let in."""
    controller, base_url = mtls_controller
    ctx = build_client_ssl_context(
        mtls_env["ca_cert"],
        worker_cert=mtls_env["good_cert"],
        worker_key=mtls_env["good_key"],
        ca_pin=mtls_env["ca_pin"],
    )
    assert ctx is not None
    status, body = _https_get(f"{base_url}/api/health", ctx)
    assert status == 200, f"valid worker rejected: {status} {body!r}"
    assert json.loads(body)["status"] == "ok"


def test_ca_pin_mismatch_rejected(mtls_env):
    """A wrong ca_pin is rejected before the CA file is trusted (anti-substitution)."""
    from honeywatch.c2.ca import CAError

    with pytest.raises(CAError):
        build_client_ssl_context(
            mtls_env["ca_cert"],
            worker_cert=mtls_env["good_cert"],
            worker_key=mtls_env["good_key"],
            ca_pin="sha256:" + "0" * 64,
        )


def test_revoked_worker_rejected(mtls_controller, mtls_env):
    """A worker whose client-cert serial has been revoked gets 403."""
    controller, base_url = mtls_controller
    # Revoke the *good* worker's serial and confirm it is now denied (proves the
    # server actually read the presented cert's serial, not just that a cert was
    # presented -- otherwise every non-revoked cert would look identical).
    controller.revoke_serial(mtls_env["good_serial"])
    assert controller.is_revoked(mtls_env["good_serial"])
    ctx = build_client_ssl_context(
        mtls_env["ca_cert"],
        worker_cert=mtls_env["good_cert"],
        worker_key=mtls_env["good_key"],
        ca_pin=mtls_env["ca_pin"],
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _https_get(f"{base_url}/api/health", ctx)
    assert exc_info.value.code == 403


def test_missing_client_cert_rejected_at_handshake(mtls_controller, mtls_env):
    """A connection that presents no client cert fails the TLS handshake.

    The server's CERT_REQUIRED (from build_mtls_server_ssl_context) rejects it
    before the request ever reaches the app -- so this is a transport-level
    failure (ssl.SSLError / URLError), not an HTTP 403.
    """
    _controller, base_url = mtls_controller
    # CA-pinned context that verifies the server but presents NO client cert.
    ctx = build_client_ssl_context(mtls_env["ca_cert"], ca_pin=mtls_env["ca_pin"])
    assert ctx is not None
    with pytest.raises((ssl.SSLError, urllib.error.URLError, ConnectionError, OSError)):
        _https_get(f"{base_url}/api/health", ctx)


def test_untrusted_client_cert_rejected(mtls_controller, tmp_path, mtls_env):
    """A client cert signed by a *different* CA fails the handshake.

    The server trusts only the internal CA, so a foreign-CA cert (even a valid
    one) cannot complete the mTLS handshake -- chain-level pinning.
    """
    _controller, base_url = mtls_controller
    rogue_ca_cert = str(tmp_path / "rogue-ca.crt")
    rogue_ca_key = str(tmp_path / "rogue-ca.key")
    generate_ca(rogue_ca_cert, rogue_ca_key, days=10)
    rogue_w_cert = str(tmp_path / "rogue-worker.crt")
    rogue_w_key = str(tmp_path / "rogue-worker.key")
    sign_worker_cert(rogue_ca_cert, rogue_ca_key, rogue_w_cert, rogue_w_key,
                     worker_id="rogue", days=10)
    # Worker trusts the *real* CA (so it'd accept the server) but presents a
    # rogue-CA-signed client cert -> server rejects the client chain.
    ctx = build_client_ssl_context(
        mtls_env["ca_cert"],
        worker_cert=rogue_w_cert,
        worker_key=rogue_w_key,
        ca_pin=mtls_env["ca_pin"],
    )
    with pytest.raises((ssl.SSLError, urllib.error.URLError, ConnectionError, OSError)):
        _https_get(f"{base_url}/api/health", ctx)