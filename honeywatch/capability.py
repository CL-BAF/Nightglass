"""Capability graph DAG for honeywatch.

Replaces the fixed 7-phase pipeline in chain.py with a real directed acyclic
graph.  Each phase becomes a *capability node* that declares what it requires
(artifact kinds it needs as input) and what it produces (artifact kinds it
creates as output).  The graph walker queries the graph for the next
highest-value capability given the current chain state + hypothesis ledger,
instead of running phases in a hardcoded order.

The key advantage over a fixed pipeline: the graph can skip phases (no
sprayable hosts → skip spray), re-run phases (new hosts from pivot →
re-enumerate), and insert recovery capabilities (foothold fails with
PREREQUISITE_MISSING → schedule a producer of ``credentials``).  The 7 phases
become a default ordering, not a hard constraint.

Artifact kinds (the currency of the graph):
    hosts              — discovered SSH hosts (from recon)
    sprayable          — hosts offering password auth (from enumerate)
    credentials         — recovered SSH creds (from spray/escalate)
    foothold           — verified SSH access (from foothold)
    shadow             — /etc/shadow file (from foothold/grab)
    cracked_creds       — offline-cracked creds (from escalate)
    loot               — exfil'd intel + creds (from loot)
    cloud_creds        — IMDS-recovered creds (from loot)
    ssh_keys           — recovered SSH private keys (from loot)
    deployed           — deployed payload (from persist)
    pivoted_subnets    — adjacent subnets (from pivot → feeds back to hosts)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from honeywatch.chain import ChainState, ChainConfig
    from honeywatch.agent.hypothesis import HypothesisStore


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class CapabilityPhase(str, Enum):
    """The phase hint a capability belongs to (advisory, not a hard gate)."""

    RECON = "recon"
    ENUMERATE = "enumerate"
    SPRAY = "spray"
    FOOTHOLD = "foothold"
    ESCALATE = "escalate"
    LOOT = "loot"
    PERSIST = "persist"
    PIVOT = "pivot"


# All artifact kinds the graph knows about.
ARTIFACT_KINDS = (
    "hosts",
    "sprayable",
    "credentials",
    "foothold",
    "shadow",
    "cracked_creds",
    "loot",
    "cloud_creds",
    "ssh_keys",
    "deployed",
    "pivoted_subnets",
    "arp_neighbors",
    "installed_packages",
    "vulnerable_packages",
)


# --------------------------------------------------------------------------- #
# Capability dataclass
# --------------------------------------------------------------------------- #


@dataclass
class Capability:
    """One node in the capability graph.

    ``requires`` lists artifact kinds that must be present in the chain state
    for this capability to be *ready* (applicability > 0).  ``produces`` lists
    artifact kinds this capability creates when it runs successfully.

    ``phase_hint`` is advisory — the graph walker uses it for display and
    default ordering, but the graph is not constrained to phase order.

    ``cost`` is a planning hint (low/medium/high) — higher-cost capabilities
    run later among ready peers when EV is similar.

    ``tool_name`` is the agent tool to call when this capability is delegated
    to the agent (for the autonomous loop).  When driven by the chain
    orchestrator, ``execute`` is called directly.
    """

    id: str
    name: str
    phase_hint: CapabilityPhase
    requires: list[str] = field(default_factory=list)
    produces: list[str] = field(default_factory=list)
    cost: str = "medium"  # low | medium | high
    tool_name: str = ""

    def applicability(self, ctx: "ChainContext") -> float:
        """Return 0-100 — how applicable this capability is right now.

        0 means "not applicable at all" (hard gate — the graph won't schedule
        it).  Higher = more valuable to run next.

        The default implementation checks:
        - All required artifacts are present (else 0).
        - The primary (first) produced artifact is already present and the
          capability has run before (else it might still be valuable to get
          secondary artifacts like shadow from foothold).
        """
        # Hard gate: all required artifacts must be present.
        for req in self.requires:
            if not ctx.has_artifact(req):
                return 0.0
        # Already done: the primary produced artifact is present.
        # The primary artifact is the first in the produces list — it's the
        # "main point" of the capability. Secondary artifacts (e.g. shadow
        # from foothold) may or may not be present, but if the primary is
        # there, the capability has done its main job.
        if self.produces and ctx.has_artifact(self.produces[0]):
            return 0.0
        # Base applicability: we're ready and not done.
        return 50.0

    def execute(self, ctx: "ChainContext") -> dict[str, Any]:
        """Execute this capability.  Overridden by concrete capabilities.

        The default implementation is a no-op (returns ``{}``).  Concrete
        capabilities delegate to the corresponding chain phase method.
        """
        return {}


# --------------------------------------------------------------------------- #
# Chain context — the live state the graph reasons against
# --------------------------------------------------------------------------- #


@dataclass
class ChainContext:
    """Live chain state the graph walker reasons against.

    Wraps :class:`honeywatch.chain.ChainState` with artifact-availability
    predicates and a reference to the hypothesis ledger so the graph can
    block capabilities whose hypothesis is refuted.
    """

    state: "ChainState"
    config: "ChainConfig"
    orchestrator: Any = None  # ChainOrchestrator — for calling phase methods
    hypothesis_store: "HypothesisStore | None" = None
    run_id: str = ""

    def has_artifact(self, kind: str) -> bool:
        """True when the chain state has a non-empty instance of ``kind``."""
        s = self.state
        if kind == "hosts":
            return bool(s.hosts)
        if kind == "sprayable":
            return bool(s.sprayable)
        if kind == "credentials":
            return bool(s.credentials)
        if kind == "foothold":
            return bool(s.footholds)
        if kind == "shadow":
            # A shadow file exists in the stash for at least one foothold.
            import os
            for ip, port, _, _ in s.footholds:
                safe_ip = ip.replace("/", "_").replace("\\", "_").replace("..", "_")
                stash = os.path.join(self.config.shadow_stash, safe_ip, "shadow")
                if os.path.isfile(stash):
                    return True
            return False
        if kind == "cracked_creds":
            # Escalate adds to s.credentials, so cracked_creds == any cred
            # with source containing "hashcrack" or "chain-hashcrack".
            return any("hashcrack" in (c.get("source", "") or "")
                       for c in s.credentials)
        if kind == "loot":
            return bool(s.loot)
        if kind == "cloud_creds":
            return bool(s.cloud_creds)
        if kind == "ssh_keys":
            return bool(s.recovered_ssh_keys)
        if kind == "deployed":
            return bool(s.enqueued)
        if kind == "pivoted_subnets":
            return bool(s.pivoted_subnets)
        # Unknown kind — fail open (don't block capabilities on typo).
        return True

    def is_hypothesis_refuted(self, capability_id: str) -> bool:
        """True when the hypothesis ledger has a refuted hypothesis for this
        capability.  The graph blocks refuted capabilities so the agent
        doesn't keep trying an approach the evidence disproved.
        """
        if self.hypothesis_store is None or not self.run_id:
            return False
        try:
            hyps = self.hypothesis_store.all_hypotheses(
                run_id=self.run_id, status="refuted", limit=100,
            )
            return any(capability_id in (h.tool or "") or
                       capability_id in (h.statement or "")
                       for h in hyps)
        except Exception:
            return False


# --------------------------------------------------------------------------- #
# CapabilityGraph
# --------------------------------------------------------------------------- #


_COST_WEIGHTS = {"low": 1.0, "medium": 0.5, "high": 0.25}
_PHASE_ORDER = {
    CapabilityPhase.RECON: 0,
    CapabilityPhase.ENUMERATE: 1,
    CapabilityPhase.SPRAY: 2,
    CapabilityPhase.FOOTHOLD: 3,
    CapabilityPhase.ESCALATE: 4,
    CapabilityPhase.LOOT: 5,
    CapabilityPhase.PERSIST: 6,
    CapabilityPhase.PIVOT: 7,
}


class CapabilityGraph:
    """The capability graph: a collection of capability nodes + graph queries.

    The graph is built once (from the chain config) and walked per round.
    The walker queries ``next_capabilities`` for the highest-EV capabilities
    given the current chain context, then dispatches them in priority order.
    """

    def __init__(self, capabilities: list[Capability] | None = None):
        self.capabilities: list[Capability] = capabilities or []
        self._by_id: dict[str, Capability] = {c.id: c for c in self.capabilities}

    def add(self, cap: Capability) -> None:
        self.capabilities.append(cap)
        self._by_id[cap.id] = cap

    def get(self, cap_id: str) -> Capability | None:
        return self._by_id.get(cap_id)

    def find_producers(self, artifact_kind: str) -> list[Capability]:
        """Return all capabilities whose ``produces`` includes ``artifact_kind``."""
        kind = artifact_kind.lower()
        return [c for c in self.capabilities
                if kind in {p.lower() for p in c.produces}]

    def missing_prerequisites(self, cap: Capability, ctx: ChainContext) -> list[str]:
        """Return the artifact kinds ``cap`` requires that aren't in ``ctx``."""
        return [req for req in cap.requires if not ctx.has_artifact(req)]

    def next_capabilities(self, ctx: ChainContext) -> list[Capability]:
        """Return capabilities ready to run, ranked by EV.

        A capability is *ready* when:
        - All its required artifacts are present (applicability > 0).
        - It's not already done (all produced artifacts present).
        - No hypothesis refutes it.

        Ranking (highest first):
        - Applicability score (from the capability's ``applicability()``).
        - Phase order (earlier phases first among equal applicability).
        - Cost (lower cost first among equal phase).
        """
        ready: list[tuple[float, int, float, Capability]] = []
        for cap in self.capabilities:
            # Skip refuted capabilities.
            if ctx.is_hypothesis_refuted(cap.id):
                continue
            score = cap.applicability(ctx)
            if score <= 0:
                continue
            phase_rank = _PHASE_ORDER.get(cap.phase_hint, 99)
            cost_weight = _COST_WEIGHTS.get(cap.cost, 0.5)
            # EV = applicability * cost_weight, with phase as tiebreaker.
            ev = score * cost_weight
            ready.append((ev, phase_rank, score, cap))

        # Sort: highest EV first, then earliest phase, then highest raw score.
        ready.sort(key=lambda t: (-t[0], t[1], -t[2]))
        return [cap for _, _, _, cap in ready]

    def blocked_capabilities(self, ctx: ChainContext) -> list[tuple[Capability, list[str]]]:
        """Return capabilities that are blocked (missing prerequisites).

        Each entry is ``(capability, [missing_artifact_kinds])``.  A capability
        is blocked when it has missing prereqs AND is not refuted.
        """
        blocked = []
        for cap in self.capabilities:
            if ctx.is_hypothesis_refuted(cap.id):
                continue
            missing = self.missing_prerequisites(cap, ctx)
            if missing:
                blocked.append((cap, missing))
        return blocked

    def has_ready_capabilities(self, ctx: ChainContext) -> bool:
        """True when at least one capability is ready to run."""
        return len(self.next_capabilities(ctx)) > 0

    def all_blocked_or_done(self, ctx: ChainContext) -> bool:
        """True when no capability is ready and at least one is blocked.

        This is the graph's halt signal: either every capability is done
        (all produced artifacts present) or the remaining ones are blocked
        by missing prerequisites or refuted hypotheses.
        """
        if self.has_ready_capabilities(ctx):
            return False
        # Not ready — is anything blocked (vs. all done)?
        return len(self.blocked_capabilities(ctx)) > 0

    def graph_summary(self, ctx: ChainContext, max_caps: int = 10) -> str:
        """Compact one-line-per-capability summary for the model / dashboard."""
        ready = self.next_capabilities(ctx)
        blocked = self.blocked_capabilities(ctx)
        lines = [f"CAPABILITY GRAPH: {len(self.capabilities)} capabilities "
                 f"({len(ready)} ready, {len(blocked)} blocked)"]
        for cap in ready[:max_caps]:
            missing = self.missing_prerequisites(cap, ctx)
            if missing:
                lines.append(f"  [blocked] {cap.id} (missing: {', '.join(missing)})")
            else:
                lines.append(f"  [ready]   {cap.id} -> produces: {', '.join(cap.produces)}")
        for cap, missing in blocked[:max_caps]:
            lines.append(f"  [blocked] {cap.id} (missing: {', '.join(missing)})")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Default capability set — maps the 8 chain phases to graph nodes
# --------------------------------------------------------------------------- #


def build_default_graph() -> CapabilityGraph:
    """Build the capability graph from the default 8 chain phases.

    Each phase becomes a capability node with its requires/produces contract.
    The graph walker uses these to decide the execution order dynamically
    instead of the hardcoded sequence in ``chain.py:_run_async``.
    """
    caps = [
        Capability(
            id="recon",
            name="Network Reconnaissance",
            phase_hint=CapabilityPhase.RECON,
            requires=[],
            produces=["hosts"],
            cost="high",
            tool_name="scan",
        ),
        Capability(
            id="enumerate",
            name="Auth-Method Enumeration",
            phase_hint=CapabilityPhase.ENUMERATE,
            requires=["hosts"],
            produces=["sprayable"],
            cost="medium",
            tool_name="probe_host",
        ),
        Capability(
            id="spray",
            name="Password Spray",
            phase_hint=CapabilityPhase.SPRAY,
            requires=["sprayable"],
            produces=["credentials"],
            cost="medium",
            tool_name="crack_ssh",
        ),
        Capability(
            id="foothold",
            name="Foothold Verification",
            phase_hint=CapabilityPhase.FOOTHOLD,
            requires=["credentials"],
            produces=["foothold", "shadow"],
            cost="medium",
        ),
        Capability(
            id="escalate",
            name="Offline Hash Cracking",
            phase_hint=CapabilityPhase.ESCALATE,
            requires=["foothold", "shadow"],
            produces=["cracked_creds"],
            cost="high",
            tool_name="hashcrack",
        ),
        Capability(
            id="loot",
            name="Credential + Intel Exfiltration",
            phase_hint=CapabilityPhase.LOOT,
            requires=["foothold"],
            produces=["loot", "cloud_creds", "ssh_keys"],
            cost="medium",
            tool_name="grab_loot",
        ),
        Capability(
            id="persist",
            name="Payload Deployment",
            phase_hint=CapabilityPhase.PERSIST,
            requires=["foothold"],
            produces=["deployed"],
            cost="high",
            tool_name="deploy",
        ),
        Capability(
            id="pivot",
            name="Subnet Discovery + Growth",
            phase_hint=CapabilityPhase.PIVOT,
            requires=["foothold", "loot"],
            produces=["pivoted_subnets"],
            cost="medium",
        ),
    ]
    return CapabilityGraph(caps)