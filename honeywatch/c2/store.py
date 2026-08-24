"""SQLite-backed store for the honeywatch C2 controller.

Tracks operations, worker tasks, and worker heartbeats. The controller and
worker plane are the only writers; the dashboard reads the same tables.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

from honeywatch.models import Operation, Target, WorkerTask

_SCHEMA = """
CREATE TABLE IF NOT EXISTS c2_operations (
    id TEXT PRIMARY KEY,
    payload_id TEXT NOT NULL,
    target_ips TEXT NOT NULL,
    status TEXT NOT NULL,
    manifest TEXT,
    result_log TEXT,
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS c2_tasks (
    id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL,
    payload_id TEXT NOT NULL,
    category TEXT NOT NULL,
    target_json TEXT,
    script TEXT,
    variables_json TEXT,
    status TEXT NOT NULL,
    worker_id TEXT,
    result_json TEXT,
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS c2_workers (
    id TEXT PRIMARY KEY,
    categories TEXT,
    connected_at TEXT,
    last_seen TEXT
);

CREATE INDEX IF NOT EXISTS idx_c2_tasks_claim ON c2_tasks(status, created_at);
CREATE INDEX IF NOT EXISTS idx_c2_tasks_op ON c2_tasks(operation_id);
CREATE INDEX IF NOT EXISTS idx_c2_ops_status ON c2_operations(status, created_at);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str = "hw") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _encode(obj: Any) -> str:
    return json.dumps(obj, default=str)


def _decode(text: str | None) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


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
        # Cracked credential, carried so password exec-mode works end-to-end.
        # The authoritative store remains the credentials table in the main
        # Store; this field is transient transport, not a credential vault.
        "ssh_pass": target.ssh_pass,
    }


def _target_from_dict(data: dict[str, Any] | None) -> Target | None:
    if not data:
        return None
    return Target(
        ip=data.get("ip", ""),
        port=int(data.get("port", 22)),
        label=data.get("label", ""),
        confidence=float(data.get("confidence", 0.0)),
        profile_key=data.get("profile_key", ""),
        allowed_categories=list(data.get("allowed_categories", [])),
        ssh_user=data.get("ssh_user"),
        ssh_key=data.get("ssh_key"),
        ssh_pass=data.get("ssh_pass"),
    )


class C2Store:
    """SQLite persistence for C2 operations, tasks, and worker registrations."""

    def __init__(self, db_path: str = "honeywatch.db"):
        self.db_path = db_path
        conn = self._connect()
        self._close(conn)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(_SCHEMA)
        conn.commit()
        return conn

    def _close(self, conn: sqlite3.Connection) -> None:
        conn.close()

    # ------------------------------------------------------------------ #
    # Operations
    # ------------------------------------------------------------------ #
    def create_operation(
        self,
        payload_id: str,
        target_ips: list[str],
        manifest: dict[str, Any] | None = None,
        operation_id: str | None = None,
    ) -> Operation:
        op = Operation(
            id=operation_id or _new_id("op"),
            payload_id=payload_id,
            target_ips=list(target_ips),
            status="pending",
            manifest=dict(manifest) if manifest else {},
            result_log=[],
            created_at=_now(),
            updated_at=_now(),
        )
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO c2_operations (id, payload_id, target_ips, status,
                        manifest, result_log, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        op.id,
                        op.payload_id,
                        ",".join(op.target_ips),
                        op.status,
                        _encode(op.manifest),
                        _encode(op.result_log),
                        op.created_at,
                        op.updated_at,
                    ),
                )
        finally:
            self._close(conn)
        return op

    def get_operation(self, operation_id: str) -> Operation | None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM c2_operations WHERE id = ?", (operation_id,)
            ).fetchone()
        finally:
            self._close(conn)
        if row is None:
            return None
        return self._operation_from_row(row)

    def update_operation_status(
        self, operation_id: str, status: str, result: dict[str, Any] | None = None
    ) -> None:
        conn = self._connect()
        try:
            # BEGIN IMMEDIATE acquires the write lock before the SELECT so the
            # read-modify-write of result_log is atomic: two concurrent callers
            # can't both read the old log and have one append silently overwrite
            # the other.
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT result_log FROM c2_operations WHERE id = ?",
                    (operation_id,),
                ).fetchone()
                log = _decode(row["result_log"]) if row else []
                log = list(log) if isinstance(log, list) else []
                if result:
                    log.append({"at": _now(), **result})
                conn.execute(
                    """
                    UPDATE c2_operations
                    SET status = ?, result_log = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (status, _encode(log), _now(), operation_id),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
        finally:
            self._close(conn)

    def list_operations(self, status: str | None = None, limit: int = 100) -> list[Operation]:
        conn = self._connect()
        try:
            sql = "SELECT * FROM c2_operations"
            params: list[Any] = []
            if status is not None:
                sql += " WHERE status = ?"
                params.append(status)
            sql += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(sql, params).fetchall()
        finally:
            self._close(conn)
        return [self._operation_from_row(r) for r in rows]

    def _operation_from_row(self, row: sqlite3.Row) -> Operation:
        raw_ips = row["target_ips"] or ""
        target_ips = [ip for ip in raw_ips.split(",") if ip]
        return Operation(
            id=row["id"],
            payload_id=row["payload_id"],
            target_ips=target_ips,
            status=row["status"],
            manifest=_decode(row["manifest"]) or {},
            result_log=_decode(row["result_log"]) or [],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # ------------------------------------------------------------------ #
    # Tasks
    # ------------------------------------------------------------------ #
    def create_task(self, task: WorkerTask) -> WorkerTask:
        if not task.id:
            task.id = _new_id("task")
        task.status = task.status or "pending"
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO c2_tasks (id, operation_id, payload_id, category,
                        target_json, script, variables_json, status, worker_id,
                        result_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        task.id,
                        task.operation_id,
                        task.payload_id,
                        task.category,
                        _encode(_target_to_dict(task.target)),
                        task.script,
                        _encode(task.variables),
                        task.status,
                        task.worker_id,
                        _encode(task.result),
                        _now(),
                        _now(),
                    ),
                )
        finally:
            self._close(conn)
        return task

    def claim_next_task(
        self, worker_id: str, categories: list[str] | None = None
    ) -> WorkerTask | None:
        """Atomically claim the oldest pending task matching ``categories``."""
        conn = self._connect()
        try:
            with conn:
                sql = "SELECT * FROM c2_tasks WHERE status = 'pending'"
                params: list[Any] = []
                if categories:
                    placeholders = ",".join("?" for _ in categories)
                    sql += f" AND category IN ({placeholders})"
                    params.extend(categories)
                sql += " ORDER BY created_at ASC LIMIT 1"
                row = conn.execute(sql, params).fetchone()
                if row is None:
                    return None
                task = self._task_from_row(row)
                cur = conn.execute(
                    """
                    UPDATE c2_tasks
                    SET status = 'running', worker_id = ?, updated_at = ?
                    WHERE id = ? AND status = 'pending'
                    """,
                    (worker_id, _now(), task.id),
                )
                # cursor.rowcount reflects only THIS update; conn.total_changes
                # is cumulative across the connection and would stay > 0 from
                # any earlier write, masking a no-op claim.
                if cur.rowcount == 0:
                    return None
                task.status = "running"
                task.worker_id = worker_id
                return task
        finally:
            self._close(conn)

    def complete_task(
        self,
        task_id: str,
        worker_id: str,
        success: bool,
        result: dict[str, Any] | None = None,
    ) -> bool:
        """Mark a claimed task completed/failed.

        Returns True only when a row was actually updated -- i.e. the task
        exists, is owned by ``worker_id``, and was still ``running``. Returns
        False (no-op) when the worker doesn't own the task, the task is
        missing, or it was already completed, so callers can avoid broadcasting
        a spurious "task_completed" event for a transition that didn't happen.
        """
        conn = self._connect()
        try:
            with conn:
                cur = conn.execute(
                    """
                    UPDATE c2_tasks
                    SET status = ?, result_json = ?, updated_at = ?
                    WHERE id = ? AND worker_id = ? AND status = 'running'
                    """,
                    (
                        "completed" if success else "failed",
                        _encode(result),
                        _now(),
                        task_id,
                        worker_id,
                    ),
                )
                return cur.rowcount > 0
        finally:
            self._close(conn)

    def list_tasks(
        self,
        operation_id: str | None = None,
        status: str | None = None,
        worker_id: str | None = None,
        limit: int = 500,
    ) -> list[WorkerTask]:
        conn = self._connect()
        try:
            sql = "SELECT * FROM c2_tasks WHERE 1=1"
            params: list[Any] = []
            if operation_id is not None:
                sql += " AND operation_id = ?"
                params.append(operation_id)
            if status is not None:
                sql += " AND status = ?"
                params.append(status)
            if worker_id is not None:
                sql += " AND worker_id = ?"
                params.append(worker_id)
            sql += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(sql, params).fetchall()
        finally:
            self._close(conn)
        return [self._task_from_row(r) for r in rows]

    def _task_from_row(self, row: sqlite3.Row) -> WorkerTask:
        return WorkerTask(
            id=row["id"],
            operation_id=row["operation_id"],
            payload_id=row["payload_id"],
            category=row["category"],
            target=_target_from_dict(_decode(row["target_json"])),
            script=row["script"] or "",
            variables=_decode(row["variables_json"]) or {},
            status=row["status"],
            worker_id=row["worker_id"],
            result=_decode(row["result_json"]),
        )

    # ------------------------------------------------------------------ #
    # Workers
    # ------------------------------------------------------------------ #
    def register_worker(self, worker_id: str, categories: list[str]) -> None:
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO c2_workers (id, categories, connected_at, last_seen)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        categories = excluded.categories,
                        last_seen = excluded.last_seen
                    """,
                    (worker_id, ",".join(categories), _now(), _now()),
                )
        finally:
            self._close(conn)

    def heartbeat_worker(self, worker_id: str) -> None:
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    "UPDATE c2_workers SET last_seen = ? WHERE id = ?",
                    (_now(), worker_id),
                )
        finally:
            self._close(conn)

    def list_workers(self, active_within_s: int | None = None) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            sql = "SELECT * FROM c2_workers"
            params: list[Any] = []
            rows = conn.execute(sql, params).fetchall()
        finally:
            self._close(conn)
        workers = []
        for r in rows:
            last_seen = r["last_seen"] or ""
            # Drop workers older than the liveness window when one is set.
            # ISO-8601 UTC timestamps compare lexically, which is enough to
            # decide "seen recently enough".
            if active_within_s is not None:
                from datetime import datetime, timedelta, timezone
                try:
                    seen = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                    cutoff = datetime.now(timezone.utc) - timedelta(seconds=active_within_s)
                    if seen.tzinfo is None:
                        seen = seen.replace(tzinfo=timezone.utc)
                    if seen < cutoff:
                        continue
                except ValueError:
                    continue
            workers.append(
                {
                    "id": r["id"],
                    "categories": [c for c in (r["categories"] or "").split(",") if c],
                    "connected_at": r["connected_at"],
                    "last_seen": r["last_seen"],
                }
            )
        return workers
