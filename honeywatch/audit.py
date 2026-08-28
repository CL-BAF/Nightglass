"""Tamper-evident audit chain for honeywatch.

Every tool call, deploy, crack, and grab gets a SHA256-chained record in an
append-only SQLite table.  Each row's ``this_hash`` is sha256 of the canonical
JSON of the row *excluding* ``this_hash``; row N+1's ``prev_hash`` is row N's
``this_hash``.  Verification re-walks the chain and recomputes hashes; any
tampering (modified row, deleted row, inserted row) breaks the chain.

This is the evidence store the hypothesis ledger references.  When the outcome
judge confirms a hypothesis, the audit chain proves *what actually ran* on the
target to produce that evidence — so an operator can prove what was deployed,
what was cracked, and what was grabbed.

Credential redaction is layered: secret-named arguments (password, key, token)
are masked before hashing, and inline credential shapes (URL ``user:pass@``,
``--password <v>``, ``Authorization: Bearer <t>``) are scrubbed from string
values.  The hash is computed on the redacted form so the chain is verifiable
without exposing secrets.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, asdict, field
from typing import Any


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Argument names whose values are always fully masked before hashing/logging.
_SECRET_ARG_NAMES = frozenset({
    "password", "pass", "passwd", "ssh_pass", "ssh_key", "key", "secret",
    "token", "api_key", "apikey", "auth", "private_key", "ntlm_hash",
    "hash", "credential", "passphrase", "pwd",
})

# Regex patterns for inline credential shapes in string values.  Each matches
# a credential-bearing substring and replaces the secret portion with ***.
_MASK_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"(user:pass@|://[^\s:]+:)[^\s@]+(@)"),          # URL user:pass@
    re.compile(r"(-u\s+\S+:\S+?)(\s)"),                          # -u user:pass
    re.compile(r"(--password\s+)\S+"),                          # --password <v>
    re.compile(r"(-hashes\s+)\S+"),                             # -hashes <NT>
    re.compile(r"(SMBPass=)\S+"),                               # SMBPass=v
    re.compile(r"(Authorization:\s*Bearer\s+)\S+"),              # Bearer <t>
    re.compile(r"""(auth=\(['"])[^'"]+(['"],\s*['"])[^'"]+(['"]\))"""),  # auth=("u","p")
)

_GENESIS_HASH = "0" * 64  # prev_hash for the first row in a chain


# --------------------------------------------------------------------------- #
# Dataclass
# --------------------------------------------------------------------------- #


@dataclass
class AuditRecord:
    """One entry in the tamper-evident audit chain.

    ``this_hash`` = sha256 of canonical JSON of this record *excluding*
    ``this_hash``.  ``prev_hash`` = the previous record's ``this_hash`` (or
    ``_GENESIS_HASH`` for the first row).  The chain is append-only; rows are
    never updated or deleted in normal operation.
    """

    run_id: str
    session_id: str
    cycle: int
    target_ip: str
    tool: str
    action: str
    arguments_json: str = ""
    result_json: str = ""
    code_sha256: str = ""
    exit_code: int | None = None
    prev_hash: str = _GENESIS_HASH
    this_hash: str = ""
    timestamp: str = ""
    seq: int | None = None  # AUTOINCREMENT primary key (None until inserted)

    def to_chain_dict(self) -> dict[str, Any]:
        """Dict excluding ``this_hash`` and ``seq`` — the input to the hash function.

        ``seq`` is the AUTOINCREMENT primary key assigned by SQLite at INSERT
        time, so it is unknown when the hash is computed.  Excluding it keeps
        the hash reproducible for verification.
        """
        d = asdict(self)
        d.pop("this_hash", None)
        d.pop("seq", None)
        return d

    def canonical_json(self) -> str:
        """Canonical JSON for hashing — sorted keys, no this_hash."""
        d = self.to_chain_dict()
        return json.dumps(d, sort_keys=True, default=str, ensure_ascii=True)

    def compute_hash(self) -> str:
        """SHA256 of the canonical JSON (excluding this_hash)."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #


def _mask_secret_value(value: Any) -> Any:
    """Mask inline credential shapes in a string value.

    Each pattern in :data:`_MASK_RES` has 1-3 capture groups:
    - 1 group:  ``group(1)***``  (e.g. ``--password <v>`` → ``--password ***``)
    - 2 groups: ``group(1)***group(2)``  (e.g. ``-u user:pass `` → ``-u ***:pass ``)
    - 3 groups: ``group(1)***group(2)***group(3)``  (e.g. ``auth=("u","p")`` → ``auth=("***","***")``)
    """
    if not isinstance(value, str):
        return value
    masked = value
    for pat in _MASK_RES:
        def _replace(m):
            n = m.lastindex or 1
            if n >= 3:
                return m.group(1) + "***" + m.group(2) + "***" + m.group(3)
            elif n >= 2:
                return m.group(1) + "***" + m.group(2)
            else:
                return m.group(1) + "***"
        masked = pat.sub(_replace, masked)
    return masked


def _redact_args(args: Any) -> dict[str, Any]:
    """Redact secret-named arguments + inline credential shapes in string values.

    A copy is returned; the input is not mutated.  The redaction is defensive
    — over-redaction is harmless (the hash is on the redacted form), but
    under-redaction is the only failure that matters.
    """
    if not args:
        return {}
    if not isinstance(args, dict):
        return {"value": str(args)}
    out: dict[str, Any] = {}
    for key, value in args.items():
        if key.lower() in _SECRET_ARG_NAMES:
            out[key] = "***"
        elif isinstance(value, str):
            out[key] = _mask_secret_value(value)
        elif isinstance(value, dict):
            out[key] = _redact_args(value)
        elif isinstance(value, list):
            out[key] = [
                _mask_secret_value(v) if isinstance(v, str)
                else (_redact_args(v) if isinstance(v, dict) else v)
                for v in value
            ]
        else:
            out[key] = value
    return out


def _redact_result(result: Any) -> dict[str, Any]:
    """Redact secrets from a tool result before hashing/logging.

    A tool result is expected to be a dict, but a misbehaving tool may return
    a string, None, or a list.  Non-dict results are wrapped in a ``{"value": ...}``
    dict so the audit record captures what was returned without crashing the
    redaction layer.
    """
    if not result:
        return {}
    if not isinstance(result, dict):
        return {"value": str(result) if not isinstance(result, (str, int, float, bool, list, type(None))) else result}
    out: dict[str, Any] = {}
    for key, value in result.items():
        if key.lower() in _SECRET_ARG_NAMES:
            out[key] = "***"
        elif isinstance(value, str):
            out[key] = _mask_secret_value(value)
        elif isinstance(value, dict):
            out[key] = _redact_result(value)
        elif isinstance(value, list):
            out[key] = [
                _mask_secret_value(v) if isinstance(v, str)
                else (_redact_result(v) if isinstance(v, dict) else v)
                for v in value
            ]
        else:
            out[key] = value
    return out


# --------------------------------------------------------------------------- #
# AuditStore — SQLite-backed append-only chain
# --------------------------------------------------------------------------- #


class AuditStore:
    """Persisted tamper-evident audit chain backed by SQLite.

    The chain is append-only: records are INSERTed, never UPDATEd or DELETEd
    in normal operation.  A process-wide lock serialises ``record()`` calls so
    concurrent ``execute_tool`` invocations form a strict deterministic chain
    (row N+1's prev_hash is row N's this_hash, regardless of thread interleaving).
    """

    # Process-wide: last hash seen for a given db_path, so the chain continues
    # across AuditStore instances in the same process (chain.py builds fresh
    # stores per phase, but they must continue the same chain).
    _LAST_HASH: dict[str, str] = {}
    _LOCK = threading.Lock()

    def __init__(self, db_path: str = "honeywatch.db"):
        self.db_path = db_path
        self._ensure_schema()
        # Seed the last hash from the existing chain tail so a new AuditStore
        # continues the chain rather than starting a new genesis.
        if self.db_path not in AuditStore._LAST_HASH:
            AuditStore._LAST_HASH[self.db_path] = self._load_last_hash()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        """Create the audit_chain table + indexes if they don't exist yet.

        Safe to call repeatedly (CREATE ... IF NOT EXISTS).  This lets the
        AuditStore work standalone without requiring the main Store to have
        been instantiated first.
        """
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit_chain (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    session_id TEXT,
                    cycle INTEGER,
                    timestamp TEXT,
                    target_ip TEXT,
                    tool TEXT,
                    action TEXT,
                    arguments_json TEXT,
                    result_json TEXT,
                    code_sha256 TEXT,
                    exit_code INTEGER,
                    prev_hash TEXT,
                    this_hash TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_run "
                "ON audit_chain(run_id, cycle)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_target "
                "ON audit_chain(target_ip)"
            )
            conn.commit()
        finally:
            conn.close()

    def _load_last_hash(self) -> str:
        """Read the this_hash of the last row so the chain continues across runs."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT this_hash FROM audit_chain ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            return row["this_hash"] if row else _GENESIS_HASH
        except sqlite3.OperationalError:
            # Table doesn't exist yet (store schema not applied).  Start fresh.
            return _GENESIS_HASH
        finally:
            conn.close()

    def _now_iso(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def record(
        self,
        run_id: str,
        session_id: str,
        cycle: int,
        target_ip: str,
        tool: str,
        action: str,
        arguments: dict[str, Any] | None = None,
        result: dict[str, Any] | None = None,
        code_sha256: str = "",
        exit_code: int | None = None,
    ) -> AuditRecord:
        """Append one record to the chain and return it (with this_hash set).

        Thread-safe: the process-wide lock ensures the prev_hash → this_hash
        chain is deterministic under concurrent ``record()`` calls.
        """
        redacted_args = _redact_args(arguments)
        redacted_result = _redact_result(result)

        with AuditStore._LOCK:
            prev_hash = AuditStore._LAST_HASH.get(self.db_path, _GENESIS_HASH)
            rec = AuditRecord(
                run_id=run_id,
                session_id=session_id,
                cycle=cycle,
                target_ip=target_ip,
                tool=tool,
                action=action,
                arguments_json=json.dumps(redacted_args, default=str, ensure_ascii=False),
                result_json=json.dumps(redacted_result, default=str, ensure_ascii=False),
                code_sha256=code_sha256,
                exit_code=exit_code,
                prev_hash=prev_hash,
                timestamp=self._now_iso(),
            )
            rec.this_hash = rec.compute_hash()

            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO audit_chain
                       (run_id, session_id, cycle, timestamp, target_ip, tool,
                        action, arguments_json, result_json, code_sha256,
                        exit_code, prev_hash, this_hash)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (rec.run_id, rec.session_id, rec.cycle, rec.timestamp,
                     rec.target_ip, rec.tool, rec.action,
                     rec.arguments_json, rec.result_json, rec.code_sha256,
                     rec.exit_code, rec.prev_hash, rec.this_hash),
                )
                conn.commit()
            finally:
                conn.close()

            AuditStore._LAST_HASH[self.db_path] = rec.this_hash
        return rec

    def verify_chain(self, run_id: str | None = None) -> tuple[bool, str]:
        """Re-walk the chain and verify every hash link.

        Returns ``(True, "chain ok (N records)")`` when the chain is intact, or
        ``(False, "<reason>")`` when tampering is detected.  When ``run_id`` is
        given, only that run's records are verified (the prev_hash of the first
        row in a filtered run is expected to be the genesis or the previous
        run's last hash — we relax that check for filtered runs).
        """
        conn = self._connect()
        try:
            if run_id:
                rows = conn.execute(
                    "SELECT * FROM audit_chain WHERE run_id = ? ORDER BY seq",
                    (run_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_chain ORDER BY seq"
                ).fetchall()
        finally:
            conn.close()

        if not rows:
            return True, "no audit records"

        prev = _GENESIS_HASH
        verified = 0
        for i, row in enumerate(rows):
            # Reconstruct the record (excluding this_hash and seq) and recompute.
            rec = AuditRecord(
                run_id=row["run_id"],
                session_id=row["session_id"],
                cycle=row["cycle"],
                target_ip=row["target_ip"] or "",
                tool=row["tool"] or "",
                action=row["action"] or "",
                arguments_json=row["arguments_json"] or "",
                result_json=row["result_json"] or "",
                code_sha256=row["code_sha256"] or "",
                exit_code=row["exit_code"],
                prev_hash=row["prev_hash"] or _GENESIS_HASH,
                timestamp=row["timestamp"] or "",
            )
            expected_hash = rec.compute_hash()
            stored_hash = row["this_hash"]

            if stored_hash != expected_hash:
                return False, (
                    f"record {row['seq']}: hash mismatch (entry tampered with; "
                    f"expected {expected_hash[:12]!r}, got {stored_hash[:12]!r})"
                )

            # For unfiltered chains, verify the prev_hash link.
            if run_id is None and row["prev_hash"] != prev:
                return False, (
                    f"record {row['seq']}: prev_hash mismatch (chain broken; "
                    f"expected {prev[:12]!r}, got {row['prev_hash'][:12]!r})"
                )

            prev = stored_hash
            verified += 1

        return True, f"chain ok ({verified} records)"

    def recent(
        self,
        target_ip: str | None = None,
        run_id: str | None = None,
        limit: int = 25,
    ) -> list[dict[str, Any]]:
        """Read recent audit records as plain dicts (for the get_evidence tool)."""
        conn = self._connect()
        try:
            clauses = []
            params: list = []
            if target_ip:
                clauses.append("target_ip = ?")
                params.append(target_ip)
            if run_id:
                clauses.append("run_id = ?")
                params.append(run_id)
            where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
            sql = f"SELECT * FROM audit_chain{where} ORDER BY seq DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def summary(self, run_id: str | None = None) -> dict[str, Any]:
        """Compact chain summary for the dashboard / fleet-status block."""
        conn = self._connect()
        try:
            if run_id:
                row = conn.execute(
                    "SELECT COUNT(*) as n FROM audit_chain WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) as n FROM audit_chain").fetchone()
            total = row["n"]
        finally:
            conn.close()
        valid, reason = self.verify_chain(run_id)
        return {"records": total, "chain_valid": valid, "reason": reason}


# --------------------------------------------------------------------------- #
# Convenience: compute sha256 of a deploy script (for code_sha256 field)
# --------------------------------------------------------------------------- #


def script_sha256(script: str) -> str:
    """SHA256 of a deploy script, for the audit record's code_sha256 field."""
    return hashlib.sha256(script.encode("utf-8")).hexdigest()