"""C2 controller / dashboard server for honeywatch.

Serves:
- a WebSocket-enabled HTML dashboard at ``/``
- REST endpoints for operations and tasks under ``/api/``
- a WebSocket endpoint at ``/ws`` for live dashboard + worker comms

Requires the optional ``aiohttp`` package (``pip install honeywatch[c2]``).
"""

from __future__ import annotations

import asyncio
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
    ):
        if not HAS_AIOHTTP:
            raise RuntimeError(
                "C2 controller requires aiohttp. Install: pip install honeywatch[c2]"
            )
        self.store = store
        self.host = host
        self.port = port
        self.ssl = ssl_context
        # When set, every API + WebSocket request must carry this bearer token
        # (``Authorization: Bearer <token>`` or ``?token=...``). ``None`` = open,
        # matching the historical lab-only behaviour and the test harness.
        self.api_token = api_token
        self.app = web.Application(middlewares=[self._build_auth_middleware()])
        self._clients: list["web.WebSocketResponse"] = []
        self._setup_routes()

    # ------------------------------------------------------------------ #
    # Auth middleware
    # ------------------------------------------------------------------ #
    def _build_auth_middleware(self):
        """Return a new-style aiohttp middleware enforcing the bearer token.

        When ``api_token`` is unset the middleware is a passthrough (preserving
        the historical lab-only behaviour and the test harness).
        """
        token = self.api_token

        @web.middleware
        async def _auth(request: "web.Request", handler):
            if token and not self._authorized(request):
                return web.json_response({"error": "unauthorized"}, status=401)
            return await handler(request)

        return _auth

    def _authorized(self, request: "web.Request") -> bool:
        """True when the request carries the configured bearer token.

        Accepts either an ``Authorization: Bearer <token>`` header or a
        ``?token=<token>`` query parameter (handy for WebSocket handshakes,
        which can't set headers everywhere).
        """
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            if auth[len("Bearer "):].strip() == self.api_token:
                return True
        if request.query.get("token") == self.api_token:
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
        self.app.router.add_get("/api/health", self._api_health)

    # ------------------------------------------------------------------ #
    # HTTP handlers
    # ------------------------------------------------------------------ #
    async def _dashboard(self, request: "web.Request") -> "web.Response":
        return web.Response(text=_DASHBOARD_HTML, content_type="text/html")

    async def _api_health(self, request: "web.Request") -> "web.Response":
        return _json_response({"status": "ok", "time": _now()})

    async def _api_workers(self, request: "web.Request") -> "web.Response":
        workers = await asyncio.to_thread(self.store.list_workers)
        return _json_response({"workers": workers})

    async def _api_operations(self, request: "web.Request") -> "web.Response":
        status = request.query.get("status")
        limit = int(request.query.get("limit", "100"))
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
        limit = int(request.query.get("limit", "500"))
        tasks = await asyncio.to_thread(
            self.store.list_tasks, operation_id, status, worker_id, limit
        )
        return _json_response({"tasks": [_task_dict(t) for t in tasks]})

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
        return _json_response({"task": _task_dict(task)})

    async def _api_task_result(self, request: "web.Request") -> "web.Response":
        task_id = request.match_info["task_id"]
        try:
            data = await request.json()
        except Exception:
            return _json_response({"error": "invalid JSON"}, status=400)
        worker_id = data.get("worker_id", "")
        success = bool(data.get("success"))
        result = data.get("result", {})
        await asyncio.to_thread(
            self.store.complete_task, task_id, worker_id, success, result
        )
        await self._broadcast(
            {
                "type": "task_completed",
                "id": task_id,
                "success": success,
                "worker_id": worker_id,
            }
        )
        return _json_response({"ok": True})

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
            while True:
                await asyncio.sleep(3600)
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


def _task_dict(task: WorkerTask) -> dict[str, Any]:
    return {
        "id": task.id,
        "operation_id": task.operation_id,
        "payload_id": task.payload_id,
        "category": task.category,
        "target": _target_to_dict(task.target),
        "script": task.script,
        "variables": task.variables,
        "status": task.status,
        "worker_id": task.worker_id,
        "result": task.result,
    }


def _target_to_dict(target: Target | None) -> dict[str, Any] | None:
    if target is None:
        return None
    return {
        "ip": target.ip,
        "port": target.port,
        "label": target.label,
        "confidence": target.confidence,
        "profile_key": target.profile_key,
        "allowed_categories": target.allowed_categories,
        "ssh_user": target.ssh_user,
        "ssh_key": target.ssh_key,
        "ssh_pass": target.ssh_pass,
    }


