"""SQLite-backed persistence for honeywatch scan results.

The store is tuned for *planet-scale* scans: WAL journaling + relaxed
synchronous writes keep bulk ``upsert_scores`` fast, real indexes turn the
reporting queries (``ORDER BY final_confidence`` / ``WHERE final_label = ?``)
from full table scans into index lookups, and a persistent ``known_keys``
table accumulates host-key fingerprints that previous runs already decided
were honeypots — so detection gets sharper every scan instead of resetting.

Each public method opens its own connection (so the store can be used across
threads / coroutines without sharing a connection object). The schema and
connection pragmas are applied once per instance.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone

from honeywatch.ai.scorer import profile_key
from honeywatch.models import AiVerdict, Fingerprint, Score, Signals

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    profile_key TEXT,
    banner TEXT,
    software TEXT,
    version TEXT,
    flags TEXT,
    heuristic REAL,
    ai_classification TEXT,
    ai_confidence REAL,
    final_confidence REAL,
    final_label TEXT,
    json TEXT,
    scanned_at TEXT,
    PRIMARY KEY (ip, port)
)
"""

# Indexes that turn the common reporting / targeting queries from O(n) table
# scans into O(log n) index range lookups. Critical once the table holds
# millions of rows from a 0.0.0.0/0 sweep.
_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_hosts_label ON hosts(final_label)",
    "CREATE INDEX IF NOT EXISTS idx_hosts_conf ON hosts(final_label, final_confidence DESC)",
    "CREATE INDEX IF NOT EXISTS idx_hosts_final_conf ON hosts(final_confidence DESC)",
    "CREATE INDEX IF NOT EXISTS idx_hosts_profile ON hosts(profile_key)",
    "CREATE INDEX IF NOT EXISTS idx_hosts_banner ON hosts(banner)",
    "CREATE INDEX IF NOT EXISTS idx_hosts_software ON hosts(software)",
]

# Persistent catalogue of host-key SHA-256 fingerprints that previous runs
# classified as honeypots. Feeding this back into ``features.analyze`` as the
# ``known_hashes`` set means a honeypot farm seen once is recognised forever.
_KNOWN_KEYS_SCHEMA = """
CREATE TABLE IF NOT EXISTS known_keys (
    host_key_sha256 TEXT PRIMARY KEY,
    learned_at TEXT,
    source TEXT
)
"""


def _record(score: Score) -> dict:
    """Plain-dict representation of a Score (safe for json.dumps)."""
    fp = asdict(score.fingerprint) if score.fingerprint else None
    sig = score.signals
    ai = asdict(score.ai) if score.ai else None
    return {
        "ip": score.ip,
        "port": score.port,
        "final_label": score.final_label,
        "final_confidence": score.final_confidence,
        "fingerprint": fp,
        "signals": {
            "anomalies": list(sig.anomalies) if sig else [],
            "flags": list(sig.flags) if sig else [],
            "heuristic_score": sig.heuristic_score if sig else 0.0,
            "evidence": dict(sig.evidence) if sig else {},
        },
        "ai": ai,
    }


class Store:
    """Persist Scores to a local SQLite database.

    Each public method opens its own connection (so the store can be used
    across threads / coroutines without sharing a connection object).
    """

    def __init__(self, db_path: str = "honeywatch.db"):
        self.db_path = db_path
        self._mem_conn: sqlite3.Connection | None = None
        self._initialized = False
        # Ensure the schema + pragmas exist up front.
        conn = self._connect()
        self._close(conn)

    def _connect(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            # :memory: databases are per-connection; keep one shared connection
            # so writes are visible to later reads.
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:")
                self._apply_schema(self._mem_conn)
            return self._mem_conn
        conn = sqlite3.connect(self.db_path)
        if not self._initialized:
            self._apply_schema(conn)
        return conn

    def _apply_schema(self, conn: sqlite3.Connection) -> None:
        """Create tables, indexes and set write-friendly pragmas exactly once."""
        # WAL + relaxed fsync keeps bulk inserts from blocking on every commit;
        # temp_store=MEMORY avoids temp-file churn during big sorts.
        if self.db_path != ":memory:":
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("PRAGMA temp_store=MEMORY")
            except sqlite3.OperationalError:
                pass  # read-only filesystem or restricted sqlite — fall back silently
        conn.executescript(_SCHEMA)
        conn.executescript(_KNOWN_KEYS_SCHEMA)
        for stmt in _INDEXES:
            conn.execute(stmt)
        conn.commit()
        self._initialized = True

    def _close(self, conn: sqlite3.Connection) -> None:
        if conn is not self._mem_conn:
            conn.close()

    # ------------------------------------------------------------------ #
    # Writes
    # ------------------------------------------------------------------ #
    def upsert_scores(self, scores: list[Score]) -> None:
        """Insert or replace a row for each Score."""
        if not scores:
            return
        conn = self._connect()
        try:
            with conn:
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO hosts (
                        ip, port, profile_key, banner, software, version, flags,
                        heuristic, ai_classification, ai_confidence,
                        final_confidence, final_label, json, scanned_at
                    ) VALUES (
                        :ip, :port, :profile_key, :banner, :software, :version, :flags,
                        :heuristic, :ai_classification, :ai_confidence,
                        :final_confidence, :final_label, :json, :scanned_at
                    )
                    """,
                    [self._to_row(score) for score in scores],
                )
        finally:
            self._close(conn)

    @staticmethod
    def _to_row(score: Score) -> dict:
        fp = score.fingerprint
        sig = score.signals
        ai = score.ai
        return {
            "ip": score.ip,
            "port": score.port,
            "profile_key": profile_key(fp) if fp else "",
            "banner": (fp.banner or "") if fp else "",
            "software": (fp.software or "") if fp else "",
            "version": (fp.software_version or "") if fp else "",
            "flags": ",".join(sig.flags) if sig else "",
            "heuristic": (sig.heuristic_score if sig else 0.0),
            "ai_classification": (ai.classification if ai else ""),
            "ai_confidence": (ai.confidence if ai else 0.0),
            "final_confidence": score.final_confidence,
            "final_label": score.final_label,
            "json": json.dumps(_record(score), default=str),
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------ #
    # Persistent honeypot-key learning
    # ------------------------------------------------------------------ #
    def add_known_keys(self, keys, source: str = "scan") -> int:
        """Record host-key SHA-256 hashes flagged as honeypots.

        Existing keys are ignored (INSERT OR IGNORE). Returns how many new
        rows were actually inserted.
        """
        keys = [k for k in keys if k]
        if not keys:
            return 0
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            with conn:
                before = conn.total_changes
                conn.executemany(
                    "INSERT OR IGNORE INTO known_keys (host_key_sha256, learned_at, source) "
                    "VALUES (?, ?, ?)",
                    [(k, now, source) for k in keys],
                )
                return conn.total_changes - before
        finally:
            self._close(conn)

    def known_key_set(self) -> set[str]:
        """Return every previously-learned honeypot host-key hash."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT host_key_sha256 FROM known_keys"
            ).fetchall()
        finally:
            self._close(conn)
        return {r[0] for r in rows if r[0]}

    def learn_from_scores(self, scores: list[Score]) -> int:
        """Persist host-key hashes for hosts scored as honeypots.

        A key only counts as evidence once it has been seen — learning the key
        of a one-off host is fine because the verdict itself already flagged it.
        """
        keys = {
            score.fingerprint.host_key_sha256
            for score in scores
            if score.fingerprint
            and score.fingerprint.host_key_sha256
            and score.final_label in ("honeypot", "likely_honeypot")
        }
        return self.add_known_keys(keys, source="auto")

    # ------------------------------------------------------------------ #
    # Resume support
    # ------------------------------------------------------------------ #
    def scored_hosts(self) -> set[tuple[str, int]]:
        """Return the set of (ip, port) pairs already scored.

        Used by ``Pipeline.scan(resume=True)`` to skip re-probing hosts a
        previous (interrupted) run already finished. Note: for very large
        stores prefer :meth:`filter_unscored`, which does the filtering in SQL
        via a temp-table join instead of loading the whole table into memory.
        """
        conn = self._connect()
        try:
            rows = conn.execute("SELECT ip, port FROM hosts").fetchall()
        finally:
            self._close(conn)
        return {(r[0], int(r[1])) for r in rows}

    def filter_unscored(self, hits) -> list:
        """Return the subset of ``hits`` not already present in the store.

        ``hits`` is an iterable of objects with ``.ip`` and ``.port`` attributes
        (e.g. :class:`honeywatch.models.HostHit`). Filtering happens in SQL via
        a temporary table + ``LEFT JOIN`` so a resume over millions of already-
        scored hosts does not load the whole ``hosts`` table into a Python set.
        Order of the input is preserved.
        """
        hits = list(hits)
        if not hits:
            return []
        conn = self._connect()
        try:
            conn.execute(
                "CREATE TEMP TABLE IF NOT EXISTS _resume_candidates (ip TEXT, port INTEGER)"
            )
            conn.execute("DELETE FROM _resume_candidates")
            conn.executemany(
                "INSERT INTO _resume_candidates (ip, port) VALUES (?, ?)",
                [(str(h.ip), int(h.port)) for h in hits],
            )
            new = conn.execute(
                "SELECT c.ip, c.port FROM _resume_candidates c "
                "LEFT JOIN hosts h ON h.ip = c.ip AND h.port = c.port "
                "WHERE h.ip IS NULL"
            ).fetchall()
            conn.execute("DELETE FROM _resume_candidates")
        finally:
            self._close(conn)
        scored = {(r[0], int(r[1])) for r in new}
        # Preserve input order, keep only the unscored ones.
        return [h for h in hits if (str(h.ip), int(h.port)) in scored]

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #
    def query(
        self,
        limit: int = 100,
        label: str | None = None,
        min_confidence: float = 0.0,
    ) -> list[dict]:
        """Return stored rows as dicts with ip, port, label, confidence, banner, flags."""
        conn = self._connect()
        try:
            sql = (
                "SELECT ip, port, final_label, final_confidence, banner, flags "
                "FROM hosts WHERE final_confidence >= ?"
            )
            params: list[object] = [min_confidence]
            if label is not None:
                sql += " AND final_label = ?"
                params.append(label)
            sql += " ORDER BY final_confidence DESC, ip ASC LIMIT ?"
            params.append(int(limit))
            rows = conn.execute(sql, params).fetchall()
        finally:
            self._close(conn)

        return [
            {
                "ip": r[0],
                "port": r[1],
                "label": r[2],
                "confidence": r[3],
                "banner": r[4] or "",
                "flags": r[5] or "",
            }
            for r in rows
        ]

    def query_scores(
        self,
        limit: int = 100,
        label: str | None = None,
        min_confidence: float = 0.0,
    ) -> list[Score]:
        """Return stored rows as hydrated ``Score`` objects for report writers."""
        conn = self._connect()
        try:
            sql = (
                "SELECT ip, port, final_label, final_confidence, json "
                "FROM hosts WHERE final_confidence >= ?"
            )
            params: list[object] = [min_confidence]
            if label is not None:
                sql += " AND final_label = ?"
                params.append(label)
            sql += " ORDER BY final_confidence DESC, ip ASC LIMIT ?"
            params.append(int(limit))
            rows = conn.execute(sql, params).fetchall()
        finally:
            self._close(conn)

        scores: list[Score] = []
        for r in rows:
            try:
                rec = json.loads(r[4] or "{}")
            except ValueError:
                continue
            try:
                fp = (
                    Fingerprint(**rec["fingerprint"])
                    if rec.get("fingerprint")
                    else None
                )
                ai = AiVerdict(**rec["ai"]) if rec.get("ai") else None
            except (TypeError, ValueError, KeyError):
                # A record written by another schema version or tool; skip the
                # row rather than failing the whole report.
                continue
            sigd = rec.get("signals") or {}
            sig = Signals(
                anomalies=list(sigd.get("anomalies", [])),
                flags=list(sigd.get("flags", [])),
                heuristic_score=float(sigd.get("heuristic_score", 0.0)),
                evidence=dict(sigd.get("evidence", {})),
            )
            scores.append(
                Score(
                    ip=r[0],
                    port=int(r[1]),
                    final_label=r[2],
                    final_confidence=float(r[3]),
                    fingerprint=fp,
                    signals=sig,
                    ai=ai,
                )
            )
        return scores

    def stats(self) -> dict:
        """Aggregate totals: total hosts, counts per label, counts per flag."""
        conn = self._connect()
        try:
            total = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
            by_label = dict(
                conn.execute(
                    "SELECT final_label, COUNT(*) FROM hosts GROUP BY final_label"
                ).fetchall()
            )
            flag_rows = conn.execute("SELECT flags FROM hosts").fetchall()
            known = conn.execute("SELECT COUNT(*) FROM known_keys").fetchone()[0]
        finally:
            self._close(conn)

        by_flag: dict[str, int] = {}
        for (flags,) in flag_rows:
            if not flags:
                continue
            for flag in flags.split(","):
                if flag:
                    by_flag[flag] = by_flag.get(flag, 0) + 1

        return {
            "total": total,
            "by_label": by_label,
            "by_flag": by_flag,
            "known_keys": known,
        }