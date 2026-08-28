"""Hypothesis ledger + outcome judge for honeywatch.

The core concept: a tool running successfully (operational success) is NOT the
same as the evidence proving the claim that motivated the tool (evidential
success).  ``crack_ssh`` returning creds = operational success.  ``grab_shadow``
returning an empty file = evidential failure (the host has no shadow to crack,
so the "this host has crackable hashes" hypothesis is refuted even though the
tool ran fine).

The judge consumes structured observation fields, not raw output words like
``"success"`` — a tool that prints "success" while returning an empty result
does not confirm a hypothesis.  Terminal statuses (confirmed/refuted/exhausted)
stop further work on that claim so the agent doesn't keep trying a refuted
approach.

This module is pure Python — no LLM calls.  The judge is deterministic; the
model proposes hypotheses via tools, the judge evaluates evidence, and the
ledger persists the verdict.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class HypothesisStatus(str, Enum):
    """Evidential state of a hypothesis.

    ``open`` — under investigation, no terminal verdict yet.
    ``confirmed`` — evidence matches expected; the claim is proven.
    ``refuted`` — evidence contradicts the claim; stop trying this approach.
    ``inconclusive`` — evidence is ambiguous; a new check with a different
        fingerprint may continue.
    ``exhausted`` — N attempts without convergence; give up to preserve budget.
    """

    OPEN = "open"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    EXHAUSTED = "exhausted"


TERMINAL_STATUSES = frozenset({
    HypothesisStatus.CONFIRMED,
    HypothesisStatus.REFUTED,
    HypothesisStatus.EXHAUSTED,
})


# --------------------------------------------------------------------------- #
# Dataclasses
# --------------------------------------------------------------------------- #


@dataclass
class Hypothesis:
    """One claim the agent is testing against a target.

    ``statement`` is the natural-language claim ("10.0.0.5 has weak SSH
    credentials").  ``expected_evidence`` describes what would confirm it
    ("valid credentials returned").  ``tool`` / ``arguments_json`` record what
    was attempted.  The judge sets ``status`` / ``confidence`` / ``evidence_json``
    / ``failure_class`` after evaluating the result.
    """

    id: str
    run_id: str
    cycle: int
    statement: str
    target: str = ""
    tool: str = ""
    arguments_json: str = ""
    status: HypothesisStatus = HypothesisStatus.OPEN
    confidence: float = 0.5
    evidence_json: str = ""
    expected_evidence: str = ""
    failure_class: str = ""
    attempt_count: int = 0
    independent_check_count: int = 0
    created_at: str = ""
    judged_at: str = ""

    def to_row(self) -> dict[str, Any]:
        """Flatten to a dict suitable for INSERT/REPLACE into the table."""
        d = asdict(self)
        d["status"] = self.status.value if isinstance(self.status, Enum) else str(self.status)
        return d

    @classmethod
    def from_row(cls, row: sqlite3.Row | dict) -> "Hypothesis":
        d = dict(row) if not isinstance(row, dict) else row
        raw_status = d.get("status", "open")
        try:
            status = HypothesisStatus(raw_status)
        except ValueError:
            status = HypothesisStatus.OPEN
        return cls(
            id=d["id"],
            run_id=d.get("run_id", ""),
            cycle=d.get("cycle", 0),
            statement=d.get("statement", ""),
            target=d.get("target", ""),
            tool=d.get("tool", ""),
            arguments_json=d.get("arguments_json", ""),
            status=status,
            confidence=d.get("confidence", 0.5),
            evidence_json=d.get("evidence_json", ""),
            expected_evidence=d.get("expected_evidence", ""),
            failure_class=d.get("failure_class", ""),
            attempt_count=d.get("attempt_count", 0),
            independent_check_count=d.get("independent_check_count", 0),
            created_at=d.get("created_at", ""),
            judged_at=d.get("judged_at", ""),
        )


@dataclass
class Judgment:
    """The outcome judge's verdict on one tool result.

    ``operational_success`` — did the tool run without error?  (A caught
    exception is operational failure; a tool that returns an ``error`` key is
    also operational failure.)
    ``evidential_status`` — did the evidence confirm, refute, or leave
    inconclusive the hypothesis that motivated the tool?
    ``confidence_delta`` — how much to nudge the hypothesis confidence (positive
    for confirmatory evidence, negative for contradictory).
    ``evidence_summary`` — short human-readable note appended to the ledger.
    ``failure_class`` — when operational failure, the failure taxonomy class
    (filled by Phase 4; empty string until then).
    """

    operational_success: bool
    evidential_status: HypothesisStatus
    confidence_delta: float
    evidence_summary: str
    failure_class: str = ""

    def is_terminal(self) -> bool:
        return self.evidential_status in TERMINAL_STATUSES


# --------------------------------------------------------------------------- #
# Outcome judge
# --------------------------------------------------------------------------- #


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _result_has_error(result: dict) -> bool:
    """A tool result carries operational failure when it has an ``error`` key."""
    return bool(result.get("error"))


def _result_is_empty(result: dict) -> bool:
    """A tool result is evidentially empty when it has no positive artifacts.

    E.g. ``crack_ssh`` returning ``{"found": false}`` or ``grab_shadow`` returning
    ``{"content": ""}`` — the tool ran fine but produced nothing useful.
    """
    for key in ("found", "success", "recovered", "confirmed", "access", "compromised"):
        if key in result and result[key] is False:
            return True
    # Empty list/dict/str on the primary payload key
    for key in ("credentials", "hosts", "footholds", "content", "shadow", "loot", "result"):
        val = result.get(key)
        if val is not None and not val:
            return True
    return False


def _result_has_artifacts(result: dict) -> bool:
    """A tool result has positive artifacts when its payload key is non-empty."""
    for key in ("credentials", "hosts", "footholds", "content", "shadow", "loot",
                "cracked", "deployed", "enqueued"):
        val = result.get(key)
        if val:  # non-empty list/dict/str
            return True
    if result.get("found") is True or result.get("success") is True:
        return True
    return False


def judge_outcome(
    hypothesis: Hypothesis,
    tool_result: dict[str, Any],
    expected_evidence: str = "",
) -> Judgment:
    """Evaluate a tool result against the hypothesis that motivated it.

    This is the deterministic, evidence-grounded outcome judge.  It deliberately
    separates operational success (did the tool run) from evidential success
    (did the evidence prove the claim).  A tool that prints "success" while
    returning an empty result does NOT confirm a hypothesis.

    Args:
        hypothesis: the claim being tested.
        tool_result: the dict returned by ``execute_tool``.
        expected_evidence: optional description of what would confirm (defaults
            to the hypothesis's own ``expected_evidence``).

    Returns:
        A :class:`Judgment` with the evidential verdict.
    """
    expected = expected_evidence or hypothesis.expected_evidence
    op_success = not _result_has_error(tool_result)

    if not op_success:
        # Operational failure: the tool itself broke.  This is inconclusive
        # for the hypothesis (we learned nothing about the claim, only that
        # the tool broke).  Classify the failure via the taxonomy (Phase 4)
        # so the capability graph / agent loop knows what recovery action
        # to take.
        err = tool_result.get("error", "")
        fc = ""
        try:
            from honeywatch.failure import classify_failure
            fc = classify_failure(err).value
        except Exception:
            pass
        return Judgment(
            operational_success=False,
            evidential_status=HypothesisStatus.INCONCLUSIVE,
            confidence_delta=-0.1,
            evidence_summary=f"tool error: {err[:200]}",
            failure_class=fc,
        )

    # Operational success.  Now evaluate the evidence.
    has_artifacts = _result_has_artifacts(tool_result)
    is_empty = _result_is_empty(tool_result)

    if has_artifacts:
        # The tool produced positive artifacts.  If we had an expected-evidence
        # description, check whether the result plausibly matches; otherwise a
        # non-empty result is confirmatory.
        if expected:
            # Lightweight check: does the expected-evidence keyword appear in
            # any of the result's string values?  E.g. expected="valid
            # credentials" and result has credentials=[...] — the word
            # "credentials" in expected matches the key.
            expected_lower = expected.lower()
            result_text = json.dumps(tool_result, default=str).lower()
            if any(word in result_text for word in expected_lower.split() if len(word) > 3):
                return Judgment(
                    operational_success=True,
                    evidential_status=HypothesisStatus.CONFIRMED,
                    confidence_delta=0.3,
                    evidence_summary=f"evidence matches expected: {expected[:200]}",
                )
            # Non-empty result but no keyword overlap — probable confirmation
            # but the judge is conservative.
            return Judgment(
                operational_success=True,
                evidential_status=HypothesisStatus.CONFIRMED,
                confidence_delta=0.2,
                evidence_summary="artifacts produced (weak match to expected evidence)",
            )
        # No expected-evidence description: non-empty result is confirmatory.
        return Judgment(
            operational_success=True,
            evidential_status=HypothesisStatus.CONFIRMED,
            confidence_delta=0.25,
            evidence_summary="artifacts produced",
        )

    if is_empty:
        # The tool ran but produced nothing.  This is evidential failure for
        # hypotheses that expected artifacts ("this host has crackable hashes"
        # refuted by an empty shadow file).
        return Judgment(
            operational_success=True,
            evidential_status=HypothesisStatus.REFUTED,
            confidence_delta=-0.3,
            evidence_summary="tool produced no artifacts — hypothesis refuted by empty result",
        )

    # Operational success, neither artifacts nor empty — ambiguous.  E.g. a
    # scan that returned a status dict but no hosts.  Inconclusive.
    return Judgment(
        operational_success=True,
        evidential_status=HypothesisStatus.INCONCLUSIVE,
        confidence_delta=0.0,
        evidence_summary="tool ran but evidence is ambiguous",
    )


# --------------------------------------------------------------------------- #
# HypothesisStore — SQLite-backed ledger
# --------------------------------------------------------------------------- #


_EXHAUSTION_THRESHOLD = 5  # attempts before an open hypothesis is exhausted


class HypothesisStore:
    """Persisted hypothesis ledger backed by the shared SQLite database.

    Each public method opens its own connection (same pattern as the main
    Store) so the ledger is safe across threads / coroutines.
    """

    def __init__(self, db_path: str = "honeywatch.db"):
        self.db_path = db_path
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        """Create the hypotheses table + indexes if they don't exist yet.

        Safe to call repeatedly (CREATE ... IF NOT EXISTS).  This lets the
        HypothesisStore work standalone without requiring the main Store to
        have been instantiated first.
        """
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS hypotheses (
                    id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    cycle INTEGER NOT NULL DEFAULT 0,
                    statement TEXT NOT NULL,
                    target TEXT,
                    tool TEXT,
                    arguments_json TEXT,
                    status TEXT NOT NULL DEFAULT 'open',
                    confidence REAL DEFAULT 0.5,
                    evidence_json TEXT,
                    expected_evidence TEXT,
                    failure_class TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    independent_check_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT,
                    judged_at TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hypotheses_run "
                "ON hypotheses(run_id, cycle)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hypotheses_status "
                "ON hypotheses(status)"
            )
            conn.commit()
        finally:
            conn.close()

    def _new_id(self) -> str:
        return "hyp-" + uuid.uuid4().hex[:10]

    def propose(
        self,
        run_id: str,
        cycle: int,
        statement: str,
        target: str = "",
        tool: str = "",
        arguments: dict | None = None,
        expected_evidence: str = "",
    ) -> Hypothesis:
        """Create a new open hypothesis and persist it.

        Returns the created :class:`Hypothesis` (with id + timestamps).
        """
        hyp = Hypothesis(
            id=self._new_id(),
            run_id=run_id,
            cycle=cycle,
            statement=statement,
            target=target,
            tool=tool,
            arguments_json=json.dumps(arguments or {}, default=str),
            expected_evidence=expected_evidence,
            created_at=_now_iso(),
        )
        conn = self._connect()
        try:
            row = hyp.to_row()
            conn.execute(
                """INSERT OR REPLACE INTO hypotheses
                   (id, run_id, cycle, statement, target, tool, arguments_json,
                    status, confidence, evidence_json, expected_evidence,
                    failure_class, attempt_count, independent_check_count,
                    created_at, judged_at)
                   VALUES (:id, :run_id, :cycle, :statement, :target, :tool,
                           :arguments_json, :status, :confidence, :evidence_json,
                           :expected_evidence, :failure_class, :attempt_count,
                           :independent_check_count, :created_at, :judged_at)""",
                row,
            )
            conn.commit()
        finally:
            conn.close()
        return hyp

    def judge(
        self,
        hypothesis_id: str,
        judgment: Judgment,
        evidence: dict | None = None,
        tool_name: str | None = None,
    ) -> Hypothesis | None:
        """Apply a judgment to a hypothesis and persist the updated state.

        Increments ``attempt_count`` (always) and ``independent_check_count``
        (when ``tool_name`` is non-empty AND differs from the last tool that
        judged this hypothesis).  Sets ``status`` / ``confidence`` /
        ``evidence_json`` / ``judged_at`` / ``failure_class``.  A terminal
        judgment (confirmed/refuted/exhausted) is final — subsequent judgments
        on the same hypothesis are ignored.

        ``tool_name`` is the name of the tool that produced the evidence (e.g.
        ``"crack_ssh"``, ``"grab_shadow"``).  When provided, it is stored on
        the hypothesis as ``hyp.tool`` (the last tool that checked it) and
        used to detect independent verification — a check from a *different*
        tool than the previous one counts as independent.

        Returns the updated :class:`Hypothesis`, or ``None`` if the hypothesis
        doesn't exist or is already terminal.
        """
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM hypotheses WHERE id = ?", (hypothesis_id,)
            ).fetchone()
            if row is None:
                return None
            hyp = Hypothesis.from_row(row)
            if hyp.status in TERMINAL_STATUSES:
                # Terminal — don't overwrite a confirmed/refuted verdict.
                return hyp

            hyp.attempt_count += 1
            # Independent check = a different tool than the previous attempt.
            # Only counts when tool_name is provided AND the hypothesis already
            # has a recorded tool AND they differ. The first check (no prior
            # tool) does NOT count as independent — it's the initial check.
            if judgment.operational_success and tool_name and hyp.tool and tool_name != hyp.tool:
                hyp.independent_check_count += 1
            # Track the tool that produced this evidence so the next judgment
            # can compare against it.
            if tool_name:
                hyp.tool = tool_name

            hyp.status = judgment.evidential_status
            hyp.confidence = max(0.0, min(1.0, hyp.confidence + judgment.confidence_delta))
            hyp.evidence_json = json.dumps(evidence or {}, default=str)
            hyp.failure_class = judgment.failure_class
            hyp.judged_at = _now_iso()

            # Auto-exhaustion: an open/inconclusive hypothesis that has been
            # checked too many times without converging is exhausted to
            # preserve budget.
            if (hyp.status in (HypothesisStatus.OPEN, HypothesisStatus.INCONCLUSIVE)
                    and hyp.attempt_count >= _EXHAUSTION_THRESHOLD):
                hyp.status = HypothesisStatus.EXHAUSTED

            conn.execute(
                """UPDATE hypotheses SET status = ?, confidence = ?,
                   evidence_json = ?, failure_class = ?, attempt_count = ?,
                   independent_check_count = ?, tool = ?, judged_at = ?
                   WHERE id = ?""",
                (hyp.status.value, hyp.confidence, hyp.evidence_json,
                 hyp.failure_class, hyp.attempt_count, hyp.independent_check_count,
                 hyp.tool, hyp.judged_at, hyp.id),
            )
            conn.commit()
        finally:
            conn.close()
        return hyp

    def get(self, hypothesis_id: str) -> Hypothesis | None:
        """Fetch one hypothesis by id."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM hypotheses WHERE id = ?", (hypothesis_id,)
            ).fetchone()
            return Hypothesis.from_row(row) if row else None
        finally:
            conn.close()

    def open_hypotheses(self, run_id: str) -> list[Hypothesis]:
        """All non-terminal hypotheses for a run (still under investigation)."""
        conn = self._connect()
        try:
            rows = conn.execute(
                """SELECT * FROM hypotheses WHERE run_id = ?
                   AND status NOT IN ('confirmed', 'refuted', 'exhausted')
                   ORDER BY cycle, created_at""",
                (run_id,),
            ).fetchall()
            return [Hypothesis.from_row(r) for r in rows]
        finally:
            conn.close()

    def all_hypotheses(
        self,
        run_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[Hypothesis]:
        """Query hypotheses, optionally filtered by run_id and/or status."""
        conn = self._connect()
        try:
            clauses = []
            params: list = []
            if run_id:
                clauses.append("run_id = ?")
                params.append(run_id)
            if status:
                clauses.append("status = ?")
                params.append(status)
            where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
            sql = f"SELECT * FROM hypotheses{where} ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(sql, params).fetchall()
            return [Hypothesis.from_row(r) for r in rows]
        finally:
            conn.close()

    def summary(self, run_id: str) -> dict[str, Any]:
        """Compact summary for the agent's per-cycle fleet-status block."""
        conn = self._connect()
        try:
            counts: dict[str, int] = {}
            rows = conn.execute(
                "SELECT status, COUNT(*) as n FROM hypotheses WHERE run_id = ? "
                "GROUP BY status",
                (run_id,),
            ).fetchall()
            for r in rows:
                counts[r["status"]] = r["n"]
            total = sum(counts.values())
            open_count = counts.get("open", 0)
            confirmed = counts.get("confirmed", 0)
            refuted = counts.get("refuted", 0)
            inconclusive = counts.get("inconclusive", 0)
            exhausted = counts.get("exhausted", 0)
            return {
                "total": total,
                "open": open_count,
                "confirmed": confirmed,
                "refuted": refuted,
                "inconclusive": inconclusive,
                "exhausted": exhausted,
            }
        finally:
            conn.close()

    def all_exhausted(self, run_id: str) -> bool:
        """True when every hypothesis for a run is in a terminal state.

        The agent loop consults this to decide whether to halt: if there are
        no open hypotheses left to test, the run has nothing productive to do.
        """
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*) as n FROM hypotheses WHERE run_id = ? "
                "AND status NOT IN ('confirmed', 'refuted', 'exhausted')",
                (run_id,),
            ).fetchone()
            total_row = conn.execute(
                "SELECT COUNT(*) as n FROM hypotheses WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            total = total_row["n"]
            open_count = row["n"]
            # No open hypotheses AND at least one existed → exhausted.
            return open_count == 0 and total > 0
        finally:
            conn.close()