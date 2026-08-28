"""Tests for the hypothesis ledger + outcome judge (Phase 1)."""

from __future__ import annotations

import pytest

from honeywatch.agent.hypothesis import (
    Hypothesis,
    HypothesisStatus,
    HypothesisStore,
    Judgment,
    judge_outcome,
    TERMINAL_STATUSES,
)


@pytest.fixture
def store(tmp_path):
    return HypothesisStore(str(tmp_path / "test.db"))


# --------------------------------------------------------------------------- #
# Outcome judge — the pure function
# --------------------------------------------------------------------------- #


class TestJudgeOutcome:
    def test_confirmed_when_artifacts_match_expected(self):
        hyp = Hypothesis(
            id="h1", run_id="r1", cycle=1,
            statement="host has weak SSH creds",
            expected_evidence="valid credentials returned",
        )
        result = {"credentials": [{"user": "root", "password": "summer"}]}
        j = judge_outcome(hyp, result)
        assert j.operational_success is True
        assert j.evidential_status == HypothesisStatus.CONFIRMED
        assert j.confidence_delta > 0

    def test_confirmed_when_artifacts_no_expected(self):
        hyp = Hypothesis(id="h1", run_id="r1", cycle=1, statement="scan finds hosts")
        result = {"hosts": ["10.0.0.1", "10.0.0.2"]}
        j = judge_outcome(hyp, result)
        assert j.evidential_status == HypothesisStatus.CONFIRMED

    def test_refuted_when_result_empty(self):
        hyp = Hypothesis(
            id="h1", run_id="r1", cycle=1,
            statement="host has shadow hashes",
            expected_evidence="shadow content",
        )
        result = {"content": ""}
        j = judge_outcome(hyp, result)
        assert j.operational_success is True
        assert j.evidential_status == HypothesisStatus.REFUTED
        assert j.confidence_delta < 0

    def test_refuted_when_found_is_false(self):
        hyp = Hypothesis(id="h1", run_id="r1", cycle=1, statement="crack succeeds")
        result = {"found": False}
        j = judge_outcome(hyp, result)
        assert j.evidential_status == HypothesisStatus.REFUTED

    def test_inconclusive_on_tool_error(self):
        hyp = Hypothesis(id="h1", run_id="r1", cycle=1, statement="scan")
        result = {"error": "connection timeout"}
        j = judge_outcome(hyp, result)
        assert j.operational_success is False
        assert j.evidential_status == HypothesisStatus.INCONCLUSIVE

    def test_inconclusive_on_ambiguous_result(self):
        hyp = Hypothesis(id="h1", run_id="r1", cycle=1, statement="check status")
        result = {"status": "ok"}  # no artifacts, not empty
        j = judge_outcome(hyp, result)
        assert j.operational_success is True
        assert j.evidential_status == HypothesisStatus.INCONCLUSIVE
        assert j.confidence_delta == 0.0

    def test_success_key_true_is_confirmed(self):
        hyp = Hypothesis(id="h1", run_id="r1", cycle=1, statement="deploy works")
        result = {"success": True, "deployed": "xmrig"}
        j = judge_outcome(hyp, result)
        assert j.evidential_status == HypothesisStatus.CONFIRMED


# --------------------------------------------------------------------------- #
# HypothesisStore — persistence
# --------------------------------------------------------------------------- #


class TestHypothesisStore:
    def test_propose_creates_open_hypothesis(self, store):
        hyp = store.propose(
            run_id="r1", cycle=1, statement="test claim",
            target="10.0.0.5", tool="crack_ssh",
        )
        assert hyp.id.startswith("hyp-")
        assert hyp.status == HypothesisStatus.OPEN
        assert hyp.cycle == 1
        assert hyp.created_at != ""

    def test_judge_confirmed_updates_status(self, store):
        hyp = store.propose(run_id="r1", cycle=1, statement="claim",
                            expected_evidence="credentials")
        j = Judgment(
            operational_success=True,
            evidential_status=HypothesisStatus.CONFIRMED,
            confidence_delta=0.3,
            evidence_summary="creds found",
        )
        updated = store.judge(hyp.id, j, evidence={"credentials": ["root"]})
        assert updated is not None
        assert updated.status == HypothesisStatus.CONFIRMED
        assert updated.confidence > 0.5

    def test_judge_refuted_updates_status(self, store):
        hyp = store.propose(run_id="r1", cycle=1, statement="claim")
        j = Judgment(
            operational_success=True,
            evidential_status=HypothesisStatus.REFUTED,
            confidence_delta=-0.3,
            evidence_summary="empty",
        )
        updated = store.judge(hyp.id, j)
        assert updated.status == HypothesisStatus.REFUTED

    def test_terminal_hypothesis_not_re_judged(self, store):
        hyp = store.propose(run_id="r1", cycle=1, statement="claim")
        j = Judgment(True, HypothesisStatus.CONFIRMED, 0.3, "ok")
        store.judge(hyp.id, j)
        # Second judgment should not change a terminal status.
        j2 = Judgment(True, HypothesisStatus.REFUTED, -0.5, "nope")
        updated = store.judge(hyp.id, j2)
        assert updated.status == HypothesisStatus.CONFIRMED  # stays confirmed

    def test_judge_nonexistent_returns_none(self, store):
        j = Judgment(True, HypothesisStatus.CONFIRMED, 0.3, "ok")
        assert store.judge("hyp-nonexistent", j) is None

    def test_get_returns_hypothesis(self, store):
        hyp = store.propose(run_id="r1", cycle=1, statement="claim")
        fetched = store.get(hyp.id)
        assert fetched is not None
        assert fetched.statement == "claim"

    def test_get_nonexistent_returns_none(self, store):
        assert store.get("hyp-nope") is None

    def test_open_hypotheses_filters_terminal(self, store):
        h1 = store.propose(run_id="r1", cycle=1, statement="a")
        h2 = store.propose(run_id="r1", cycle=2, statement="b")
        store.judge(h1.id, Judgment(True, HypothesisStatus.CONFIRMED, 0.3, "ok"))
        opens = store.open_hypotheses("r1")
        assert len(opens) == 1
        assert opens[0].id == h2.id

    def test_all_hypotheses_with_filters(self, store):
        h1 = store.propose(run_id="r1", cycle=1, statement="a")
        h2 = store.propose(run_id="r1", cycle=2, statement="b")
        h3 = store.propose(run_id="r2", cycle=1, statement="c")
        store.judge(h1.id, Judgment(True, HypothesisStatus.CONFIRMED, 0.3, "ok"))
        # All for r1
        all_r1 = store.all_hypotheses(run_id="r1")
        assert len(all_r1) == 2
        # Only confirmed for r1
        confirmed = store.all_hypotheses(run_id="r1", status="confirmed")
        assert len(confirmed) == 1
        assert confirmed[0].id == h1.id

    def test_summary_counts(self, store):
        h1 = store.propose(run_id="r1", cycle=1, statement="a")
        h2 = store.propose(run_id="r1", cycle=2, statement="b")
        h3 = store.propose(run_id="r1", cycle=3, statement="c")
        store.judge(h1.id, Judgment(True, HypothesisStatus.CONFIRMED, 0.3, "ok"))
        store.judge(h2.id, Judgment(True, HypothesisStatus.REFUTED, -0.3, "no"))
        s = store.summary("r1")
        assert s["total"] == 3
        assert s["confirmed"] == 1
        assert s["refuted"] == 1
        assert s["open"] == 1

    def test_all_exhausted_false_when_open_exists(self, store):
        h1 = store.propose(run_id="r1", cycle=1, statement="a")
        h2 = store.propose(run_id="r1", cycle=2, statement="b")
        store.judge(h1.id, Judgment(True, HypothesisStatus.CONFIRMED, 0.3, "ok"))
        # h2 is still open
        assert store.all_exhausted("r1") is False

    def test_all_exhausted_true_when_all_terminal(self, store):
        h1 = store.propose(run_id="r1", cycle=1, statement="a")
        store.judge(h1.id, Judgment(True, HypothesisStatus.CONFIRMED, 0.3, "ok"))
        assert store.all_exhausted("r1") is True

    def test_all_exhausted_false_when_no_hypotheses(self, store):
        # No hypotheses at all -> not "exhausted" (nothing was tested)
        assert store.all_exhausted("r1") is False

    def test_auto_exhaustion_after_threshold(self, store):
        hyp = store.propose(run_id="r1", cycle=1, statement="hard claim")
        # Judge it as inconclusive 5 times to trigger exhaustion.
        for _ in range(5):
            j = Judgment(True, HypothesisStatus.INCONCLUSIVE, 0.0, "ambiguous")
            store.judge(hyp.id, j)
        updated = store.get(hyp.id)
        assert updated.status == HypothesisStatus.EXHAUSTED
        assert updated.attempt_count == 5

    def test_attempt_count_increments(self, store):
        hyp = store.propose(run_id="r1", cycle=1, statement="claim")
        store.judge(hyp.id, Judgment(True, HypothesisStatus.INCONCLUSIVE, 0.0, "a"))
        store.judge(hyp.id, Judgment(True, HypothesisStatus.INCONCLUSIVE, 0.0, "b"))
        updated = store.get(hyp.id)
        assert updated.attempt_count == 2

    def test_confidence_clamped_to_0_1(self, store):
        hyp = store.propose(run_id="r1", cycle=1, statement="claim")
        # Large positive delta should clamp at 1.0
        store.judge(hyp.id, Judgment(True, HypothesisStatus.CONFIRMED, 0.9, "big"))
        updated = store.get(hyp.id)
        assert updated.confidence <= 1.0

    def test_from_row_handles_bad_status(self):
        """A corrupted status string falls back to OPEN."""
        hyp = Hypothesis.from_row({
            "id": "h1", "run_id": "r1", "cycle": 1, "statement": "s",
            "status": "bogus_status",
        })
        assert hyp.status == HypothesisStatus.OPEN

    def test_independent_check_count_tracks_different_tools(self, store):
        """Regression: independent_check_count must increment only when a
        *different* tool than the previous one produces evidence. The old
        code compared hyp.tool (a tool name) against judgment.evidence_summary
        (a human string) — always unequal — so it incremented unconditionally,
        making it a duplicate of attempt_count."""
        hyp = store.propose(run_id="r1", cycle=1, statement="host has creds")
        # First check with crack_ssh — no prior tool, so NOT independent.
        store.judge(hyp.id,
                    Judgment(True, HypothesisStatus.INCONCLUSIVE, 0.0, "a"),
                    tool_name="crack_ssh")
        updated = store.get(hyp.id)
        assert updated.independent_check_count == 0
        assert updated.tool == "crack_ssh"
        assert updated.attempt_count == 1

        # Second check with grab_shadow — different tool, IS independent.
        store.judge(hyp.id,
                    Judgment(True, HypothesisStatus.INCONCLUSIVE, 0.0, "b"),
                    tool_name="grab_shadow")
        updated = store.get(hyp.id)
        assert updated.independent_check_count == 1
        assert updated.tool == "grab_shadow"

        # Third check with crack_ssh again — different from grab_shadow, IS independent.
        store.judge(hyp.id,
                    Judgment(True, HypothesisStatus.INCONCLUSIVE, 0.0, "c"),
                    tool_name="crack_ssh")
        updated = store.get(hyp.id)
        assert updated.independent_check_count == 2
        assert updated.attempt_count == 3

    def test_independent_check_count_same_tool_not_independent(self, store):
        """Repeated checks with the same tool must NOT increment
        independent_check_count."""
        hyp = store.propose(run_id="r1", cycle=1, statement="claim")
        for _ in range(3):
            store.judge(hyp.id,
                        Judgment(True, HypothesisStatus.INCONCLUSIVE, 0.0, "x"),
                        tool_name="crack_ssh")
        updated = store.get(hyp.id)
        assert updated.attempt_count == 3
        assert updated.independent_check_count == 0

    def test_independent_check_count_no_tool_name_not_independent(self, store):
        """Judgments without tool_name must NOT increment independent_check_count."""
        hyp = store.propose(run_id="r1", cycle=1, statement="claim")
        store.judge(hyp.id, Judgment(True, HypothesisStatus.INCONCLUSIVE, 0.0, "x"))
        store.judge(hyp.id, Judgment(True, HypothesisStatus.INCONCLUSIVE, 0.0, "y"))
        updated = store.get(hyp.id)
        assert updated.independent_check_count == 0


# --------------------------------------------------------------------------- #
# Terminal statuses
# --------------------------------------------------------------------------- #


class TestTerminalStatuses:
    def test_confirmed_is_terminal(self):
        assert HypothesisStatus.CONFIRMED in TERMINAL_STATUSES

    def test_refuted_is_terminal(self):
        assert HypothesisStatus.REFUTED in TERMINAL_STATUSES

    def test_exhausted_is_terminal(self):
        assert HypothesisStatus.EXHAUSTED in TERMINAL_STATUSES

    def test_open_is_not_terminal(self):
        assert HypothesisStatus.OPEN not in TERMINAL_STATUSES

    def test_inconclusive_is_not_terminal(self):
        assert HypothesisStatus.INCONCLUSIVE not in TERMINAL_STATUSES