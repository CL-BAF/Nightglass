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
import threading
from datetime import datetime, timezone

from honeywatch.ai.scorer import profile_key
from honeywatch.models import AiVerdict, Fingerprint, Score, Signals, score_record

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

# Cracked SSH credentials. Populated by the password cracker so later deploy
# runs can reuse them and so an operator's accumulated access survives across
# sessions. (ip, port, user) is unique so re-cracking the same box updates the
# discovered password rather than stacking duplicates.
_CREDENTIALS_SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    user TEXT NOT NULL,
    password TEXT,
    banner TEXT,
    attempts INTEGER DEFAULT 0,
    source TEXT,
    discovered_at TEXT,
    PRIMARY KEY (ip, port, user)
)
"""


class Store:
    """Persist Scores to a local SQLite database.

    Each public method opens its own connection (so the store can be used
    across threads / coroutines without sharing a connection object).
    """

    def __init__(self, db_path: str = "honeywatch.db"):
        self.db_path = db_path
        self._mem_conn: sqlite3.Connection | None = None
        # A :memory: database lives on a single shared connection (each
        # sqlite3.connect(":memory:") is an isolated empty database, so we must
        # reuse one). That shared connection is accessed from whatever thread
        # the caller is on, so it is opened with check_same_thread=False and
        # guarded by this lock to serialise concurrent use. File-backed stores
        # open a fresh connection per call instead, so they need no lock.
        self._mem_lock = threading.RLock()
        self._initialized = False
        # Ensure the schema + pragmas exist up front.
        conn = self._connect()
        self._close(conn)

    def _connect(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            # :memory: databases are per-connection; keep one shared connection
            # so writes are visible to later reads. The lock is released by the
            # matching _close() in the caller's finally block.
            self._mem_lock.acquire()
            try:
                if self._mem_conn is None:
                    self._mem_conn = sqlite3.connect(
                        ":memory:", check_same_thread=False
                    )
                    self._apply_schema(self._mem_conn)
            except BaseException:
                self._mem_lock.release()
                raise
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
        conn.executescript(_CREDENTIALS_SCHEMA)
        for stmt in _INDEXES:
            conn.execute(stmt)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_credentials_ip "
            "ON credentials(ip, port)"
        )
        conn.commit()
        self._initialized = True

    def _close(self, conn: sqlite3.Connection) -> None:
        if conn is self._mem_conn:
            # Shared :memory: connection: keep it alive, just release the lock
            # acquired in _connect() so other threads can proceed.
            self._mem_lock.release()
        else:
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
            "json": json.dumps(score_record(score), default=str),
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
            # Flags are stored as a comma-joined string in one column, so a
            # pure-SQL count isn't possible without a normalized table. Stream
            # the cursor row-by-row instead of fetchall()-ing every host's flags
            # into a Python list first — on a 0.0.0.0/0 sweep that avoids holding
            # millions of flag strings in memory at once.
            flag_cursor = conn.execute("SELECT flags FROM hosts")
            by_flag: dict[str, int] = {}
            for (flags,) in flag_cursor:
                if not flags:
                    continue
                for flag in flags.split(","):
                    if flag:
                        by_flag[flag] = by_flag.get(flag, 0) + 1
            known = conn.execute("SELECT COUNT(*) FROM known_keys").fetchone()[0]
        finally:
            self._close(conn)

        return {
            "total": total,
            "by_label": by_label,
            "by_flag": by_flag,
            "known_keys": known,
        }

    # ------------------------------------------------------------------ #
    # Cracked credentials
    # ------------------------------------------------------------------ #
    def upsert_credential(
        self,
        ip: str,
        port: int,
        user: str,
        password: str | None,
        banner: str | None = None,
        attempts: int = 0,
        source: str = "crack",
    ) -> None:
        """Insert or replace one cracked credential row.

        Re-cracking the same ``(ip, port, user)`` updates the discovered
        password in place instead of stacking duplicates.
        """
        now = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO credentials
                        (ip, port, user, password, banner, attempts, source, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (str(ip), int(port), user, password, banner, int(attempts), source, now),
                )
        finally:
            self._close(conn)

    def query_credentials(
        self,
        ip: str | None = None,
        port: int | None = None,
        user: str | None = None,
        limit: int = 1000,
    ) -> list[dict]:
        """Return cracked credential rows as dicts.

        Filters are optional and combine with AND. Rows are ordered by most
        recently discovered first so an operator re-running crack sees fresh
        wins at the top.
        """
        sql = (
            "SELECT ip, port, user, password, banner, attempts, source, discovered_at "
            "FROM credentials WHERE 1=1"
        )
        params: list[object] = []
        if ip is not None:
            sql += " AND ip = ?"
            params.append(str(ip))
        if port is not None:
            sql += " AND port = ?"
            params.append(int(port))
        if user is not None:
            sql += " AND user = ?"
            params.append(user)
        sql += " ORDER BY discovered_at DESC LIMIT ?"
        params.append(int(limit))
        conn = self._connect()
        try:
            rows = conn.execute(sql, params).fetchall()
        finally:
            self._close(conn)
        return [
            {
                "ip": r[0],
                "port": int(r[1]),
                "user": r[2],
                "password": r[3],
                "banner": r[4],
                "attempts": int(r[5] or 0),
                "source": r[6],
                "discovered_at": r[7],
            }
            for r in rows
        ]

    def credential_for(self, ip: str, port: int = 22) -> dict | None:
        """Return the most recently discovered working credential for a host.

        Used by ``deploy`` to auto-fill ``Target.ssh_pass`` / ``ssh_user``
        when the operator did not pin credentials.
        """
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT ip, port, user, password, banner, attempts, source, discovered_at "
                "FROM credentials WHERE ip = ? AND port = ? "
                "ORDER BY discovered_at DESC LIMIT 1",
                (str(ip), int(port)),
            ).fetchone()
        finally:
            self._close(conn)
        if not row:
            return None
        return {
            "ip": row[0],
            "port": int(row[1]),
            "user": row[2],
            "password": row[3],
            "banner": row[4],
            "attempts": int(row[5] or 0),
            "source": row[6],
            "discovered_at": row[7],
        }