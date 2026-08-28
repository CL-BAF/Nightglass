"""Tests for the capability graph DAG (Phase 3)."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from honeywatch.capability import (
    Capability,
    CapabilityPhase,
    CapabilityGraph,
    ChainContext,
    build_default_graph,
    ARTIFACT_KINDS,
)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def graph():
    return build_default_graph()


@pytest.fixture
def empty_state():
    """A ChainState with no artifacts — nothing has been done yet."""
    state = MagicMock()
    state.hosts = []
    state.sprayable = []
    state.credentials = []
    state.footholds = []
    state.loot = []
    state.cloud_creds = []
    state.recovered_ssh_keys = []
    state.enqueued = []
    state.pivoted_subnets = []
    return state


@pytest.fixture
def ctx(empty_state):
    config = MagicMock()
    config.shadow_stash = "/tmp/shadow_stash"
    return ChainContext(state=empty_state, config=config)


def make_ctx(**artifact_overrides):
    """Build a ChainContext with specific artifacts present."""
    state = MagicMock()
    state.hosts = artifact_overrides.get("hosts", [])
    state.sprayable = artifact_overrides.get("sprayable", [])
    state.credentials = artifact_overrides.get("credentials", [])
    state.footholds = artifact_overrides.get("footholds", [])
    state.loot = artifact_overrides.get("loot", [])
    state.cloud_creds = artifact_overrides.get("cloud_creds", [])
    state.recovered_ssh_keys = artifact_overrides.get("ssh_keys", [])
    state.enqueued = artifact_overrides.get("deployed", [])
    state.pivoted_subnets = artifact_overrides.get("pivoted_subnets", [])
    config = MagicMock()
    config.shadow_stash = "/tmp/shadow_stash"
    return ChainContext(state=state, config=config)


# --------------------------------------------------------------------------- #
# Capability dataclass
# --------------------------------------------------------------------------- #


class TestCapability:
    def test_requires_and_produces_defaults_empty(self):
        cap = Capability(id="x", name="X", phase_hint=CapabilityPhase.RECON)
        assert cap.requires == []
        assert cap.produces == []

    def test_applicability_returns_zero_when_missing_prereqs(self, ctx):
        cap = Capability(
            id="spray", name="Spray", phase_hint=CapabilityPhase.SPRAY,
            requires=["sprayable"], produces=["credentials"],
        )
        # No sprayable hosts in ctx
        assert cap.applicability(ctx) == 0.0

    def test_applicability_returns_positive_when_prereqs_met(self):
        ctx = make_ctx(sprayable=[("10.0.0.1", 22)])
        cap = Capability(
            id="spray", name="Spray", phase_hint=CapabilityPhase.SPRAY,
            requires=["sprayable"], produces=["credentials"],
        )
        assert cap.applicability(ctx) > 0

    def test_applicability_returns_zero_when_already_done(self):
        ctx = make_ctx(
            sprayable=[("10.0.0.1", 22)],
            credentials=[{"user": "root", "password": "x"}],
        )
        cap = Capability(
            id="spray", name="Spray", phase_hint=CapabilityPhase.SPRAY,
            requires=["sprayable"], produces=["credentials"],
        )
        # All produced artifacts already present → 0
        assert cap.applicability(ctx) == 0.0


# --------------------------------------------------------------------------- #
# CapabilityGraph — graph queries
# --------------------------------------------------------------------------- #


class TestCapabilityGraph:
    def test_default_graph_has_8_capabilities(self, graph):
        assert len(graph.capabilities) == 8
        ids = {c.id for c in graph.capabilities}
        assert ids == {"recon", "enumerate", "spray", "foothold",
                       "escalate", "loot", "persist", "pivot"}

    def test_get_by_id(self, graph):
        cap = graph.get("recon")
        assert cap is not None
        assert cap.name == "Network Reconnaissance"

    def test_get_nonexistent_returns_none(self, graph):
        assert graph.get("nonexistent") is None

    def test_find_producers(self, graph):
        # Find what produces "credentials"
        producers = graph.find_producers("credentials")
        ids = {c.id for c in producers}
        assert "spray" in ids
        # escalate also produces cracked_creds, not credentials directly
        # but credentials is on state.credentials after escalate
        # So spray is the direct producer

    def test_find_producers_no_match(self, graph):
        producers = graph.find_producers("nonexistent_kind")
        assert producers == []

    def test_missing_prerequisites_empty_context(self, graph, ctx):
        cap = graph.get("spray")
        missing = graph.missing_prerequisites(cap, ctx)
        assert "sprayable" in missing

    def test_missing_prerequisites_all_present(self, graph):
        ctx = make_ctx(sprayable=[("10.0.0.1", 22)])
        cap = graph.get("spray")
        assert graph.missing_prerequisites(cap, ctx) == []

    def test_next_capabilities_empty_context(self, graph, ctx):
        """With no artifacts, only recon (which requires nothing) is ready."""
        ready = graph.next_capabilities(ctx)
        assert len(ready) == 1
        assert ready[0].id == "recon"

    def test_next_capabilities_after_recon(self, graph):
        ctx = make_ctx(hosts=[("10.0.0.1", 22)])
        ready = graph.next_capabilities(ctx)
        ids = {c.id for c in ready}
        assert "enumerate" in ids
        # recon is done (hosts already present)
        assert "recon" not in ids

    def test_next_capabilities_after_foothold(self, graph):
        """With a foothold, multiple capabilities become ready."""
        ctx = make_ctx(
            hosts=[("10.0.0.1", 22)],
            sprayable=[("10.0.0.1", 22)],
            credentials=[{"user": "root", "password": "x"}],
            footholds=[("10.0.0.1", 22, "root", "x")],
        )
        ready = graph.next_capabilities(ctx)
        ids = {c.id for c in ready}
        # With foothold, escalate (needs shadow too — not ready), loot, persist are candidates.
        # loot and persist require only foothold. escalate requires shadow too.
        assert "loot" in ids
        assert "persist" in ids
        # escalate needs shadow too — not ready
        # (unless shadow stash has a file, which it doesn't in make_ctx)
        assert "escalate" not in ids

    def test_next_capabilities_ranked_by_phase_order(self, graph, ctx):
        """Recon (phase 0) runs before everything else."""
        ready = graph.next_capabilities(ctx)
        assert ready[0].phase_hint == CapabilityPhase.RECON

    def test_has_ready_capabilities_empty(self, graph, ctx):
        assert graph.has_ready_capabilities(ctx) is True  # recon is ready

    def test_has_ready_capabilities_all_done(self, graph):
        ctx = make_ctx(
            hosts=[("10.0.0.1", 22)],
            sprayable=[("10.0.0.1", 22)],
            credentials=[{"user": "root", "password": "x"}],
            footholds=[("10.0.0.1", 22, "root", "x")],
            loot=[{"foo": "bar"}],
            cloud_creds=[{"token": "x"}],
            ssh_keys=["key1"],
            deployed=[("10.0.0.1", 22)],
            pivoted_subnets=["10.0.1.0/24"],
        )
        # Everything produced — but escalate needs shadow (no shadow file
        # in /tmp/shadow_stash), and pivot needs loot which is present.
        # Some capabilities may still be ready if their produces aren't
        # ALL present. Let's check the graph knows it's mostly done.
        ready = graph.next_capabilities(ctx)
        # With all artifacts present, most capabilities return 0 applicability.
        # The graph should report no ready capabilities (or very few).
        # Recon/enumerate/spray/foothold/loot/persist/pivot all done.
        # Escalate is blocked (no shadow file). So nothing is ready.
        assert len(ready) == 0 or all(c.id == "escalate" for c in ready)

    def test_all_blocked_or_done_when_no_ready(self, graph):
        ctx = make_ctx(
            hosts=[("10.0.0.1", 22)],
            sprayable=[("10.0.0.1", 22)],
            credentials=[{"user": "root", "password": "x"}],
            footholds=[("10.0.0.1", 22, "root", "x")],
            loot=[{"foo": "bar"}],
            cloud_creds=[{"token": "x"}],
            ssh_keys=["key1"],
            deployed=[("10.0.0.1", 22)],
            pivoted_subnets=["10.0.1.0/24"],
        )
        # All produced except escalate (blocked by shadow).
        # The graph should report all_blocked_or_done = True.
        assert graph.all_blocked_or_done(ctx) is True

    def test_all_blocked_or_done_false_when_ready(self, graph, ctx):
        # recon is ready in empty ctx
        assert graph.all_blocked_or_done(ctx) is False

    def test_blocked_capabilities_reports_missing(self, graph, ctx):
        blocked = graph.blocked_capabilities(ctx)
        # With empty state, everything except recon is blocked.
        blocked_ids = {cap.id for cap, _ in blocked}
        assert "enumerate" in blocked_ids
        assert "spray" in blocked_ids
        # recon is NOT blocked (no requires)
        assert "recon" not in blocked_ids

    def test_graph_summary(self, graph, ctx):
        summary = graph.graph_summary(ctx)
        assert "CAPABILITY GRAPH" in summary
        assert "ready" in summary
        assert "blocked" in summary


# --------------------------------------------------------------------------- #
# ChainContext — artifact availability
# --------------------------------------------------------------------------- #


class TestChainContext:
    def test_has_artifact_hosts(self):
        ctx = make_ctx(hosts=[("10.0.0.1", 22)])
        assert ctx.has_artifact("hosts") is True
        ctx2 = make_ctx(hosts=[])
        assert ctx2.has_artifact("hosts") is False

    def test_has_artifact_foothold(self):
        ctx = make_ctx(footholds=[("10.0.0.1", 22, "root", "x")])
        assert ctx.has_artifact("foothold") is True
        ctx2 = make_ctx(footholds=[])
        assert ctx2.has_artifact("foothold") is False

    def test_has_artifact_credentials(self):
        ctx = make_ctx(credentials=[{"user": "root"}])
        assert ctx.has_artifact("credentials") is True
        ctx2 = make_ctx(credentials=[])
        assert ctx2.has_artifact("credentials") is False

    def test_has_artifact_unknown_kind_fails_open(self):
        ctx = make_ctx()
        assert ctx.has_artifact("unknown_kind") is True

    def test_has_artifact_cracked_creds_checks_source(self):
        ctx = make_ctx(credentials=[
            {"user": "root", "source": "chain-hashcrack"},
        ])
        assert ctx.has_artifact("cracked_creds") is True
        ctx2 = make_ctx(credentials=[
            {"user": "root", "source": "spray"},
        ])
        assert ctx2.has_artifact("cracked_creds") is False

    def test_is_hypothesis_refuted_no_store(self):
        ctx = make_ctx()
        assert ctx.is_hypothesis_refuted("spray") is False

    def test_is_hypothesis_refuted_with_store(self, tmp_path):
        from honeywatch.agent.hypothesis import HypothesisStore, Hypothesis, HypothesisStatus, Judgment
        store = HypothesisStore(str(tmp_path / "test.db"))
        # Create a refuted hypothesis mentioning "spray"
        hyp = store.propose(run_id="r1", cycle=1, statement="spray will find creds",
                            tool="spray")
        store.judge(hyp.id, Judgment(
            operational_success=True,
            evidential_status=HypothesisStatus.REFUTED,
            confidence_delta=-0.3,
            evidence_summary="empty",
        ))
        ctx = make_ctx()
        ctx.hypothesis_store = store
        ctx.run_id = "r1"
        assert ctx.is_hypothesis_refuted("spray") is True
        assert ctx.is_hypothesis_refuted("recon") is False


# --------------------------------------------------------------------------- #
# Growth loop — pivot feeds back to hosts
# --------------------------------------------------------------------------- #


class TestGrowthLoop:
    def test_pivot_produces_pivoted_subnets(self, graph):
        cap = graph.get("pivot")
        assert "pivoted_subnets" in cap.produces

    def test_pivot_requires_foothold_and_loot(self, graph):
        cap = graph.get("pivot")
        assert "foothold" in cap.requires
        assert "loot" in cap.requires

    def test_recon_produces_hosts(self, graph):
        cap = graph.get("recon")
        assert "hosts" in cap.produces
        assert cap.requires == []

    def test_full_chain_progression(self, graph):
        """Walk the graph step by step: recon → enumerate → spray → ..."""
        # Start: only recon ready
        ctx = make_ctx()
        ready = graph.next_capabilities(ctx)
        assert ready[0].id == "recon"

        # After recon: enumerate ready
        ctx = make_ctx(hosts=[("10.0.0.1", 22)])
        ready = graph.next_capabilities(ctx)
        assert ready[0].id == "enumerate"

        # After enumerate: spray ready
        ctx = make_ctx(hosts=[("10.0.0.1", 22)],
                       sprayable=[("10.0.0.1", 22)])
        ready = graph.next_capabilities(ctx)
        assert ready[0].id == "spray"

        # After spray: foothold ready
        ctx = make_ctx(hosts=[("10.0.0.1", 22)],
                       sprayable=[("10.0.0.1", 22)],
                       credentials=[{"user": "root", "password": "x"}])
        ready = graph.next_capabilities(ctx)
        assert ready[0].id == "foothold"

        # After foothold: loot + persist ready (escalate blocked by shadow)
        ctx = make_ctx(hosts=[("10.0.0.1", 22)],
                       sprayable=[("10.0.0.1", 22)],
                       credentials=[{"user": "root", "password": "x"}],
                       footholds=[("10.0.0.1", 22, "root", "x")])
        ready = graph.next_capabilities(ctx)
        ids = {c.id for c in ready}
        assert "loot" in ids
        assert "persist" in ids
        assert "escalate" not in ids  # needs shadow too

        # After loot: pivot ready (needs foothold + loot)
        ctx = make_ctx(hosts=[("10.0.0.1", 22)],
                       sprayable=[("10.0.0.1", 22)],
                       credentials=[{"user": "root", "password": "x"}],
                       footholds=[("10.0.0.1", 22, "root", "x")],
                       loot=[{"foo": "bar"}])
        ready = graph.next_capabilities(ctx)
        ids = {c.id for c in ready}
        assert "pivot" in ids


# --------------------------------------------------------------------------- #
# ARTIFACT_KINDS constant
# --------------------------------------------------------------------------- #


class TestArtifactKinds:
    def test_all_expected_kinds_present(self):
        expected = {
            "hosts", "sprayable", "credentials", "foothold", "shadow",
            "cracked_creds", "loot", "cloud_creds", "ssh_keys",
            "deployed", "pivoted_subnets",
        }
        assert set(ARTIFACT_KINDS) == expected