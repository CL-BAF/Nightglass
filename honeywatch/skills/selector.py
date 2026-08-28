"""Skill selector for honeywatch's advisory skill brain (Phase 5).

Two-tier selection:
1. **Deterministic** (tag/keyword weighted scoring) — always available, no
   external dependencies. Field weights: name=12, tags=10, description=5,
   classification=4, body=1.
2. **Semantic** (embedding cosine similarity) — optional, requires Ollama
   running locally with ``nomic-embed-text``. Falls back to deterministic-only
   when Ollama is unreachable or the model is missing.

Selection is advisory-only — skills never grant execution authority or change
scope/permission/audit rules. They inject tradecraft guidance into the agent's
system prompt so the model makes better-informed decisions.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from honeywatch.skills.registry import (
    LoadedSkill,
    SkillRegistry,
    _tokenize,
    _SEARCH_STOPWORDS,
)

log = logging.getLogger(__name__)

__all__ = ["select_skills", "SkillSelector"]


# Phase-to-tag mapping: which tags are relevant for each chain phase.
PHASE_TAGS: dict[str, frozenset[str]] = {
    "recon": frozenset({"reconnaissance", "nmap", "network-security", "osint", "scanning"}),
    "enumerate": frozenset({"enumeration", "ssh", "auth-methods", "service-discovery"}),
    "spray": frozenset({"credential-access", "password-spray", "brute-force", "ssh"}),
    "foothold": frozenset({"foothold", "initial-access", "ssh", "credential-validation"}),
    "privesc": frozenset({"privilege-escalation", "privesc", "kernel-exploit", "sudo", "docker"}),
    "escalate": frozenset({"hash-cracking", "hashcat", "john", "credential-recovery", "shadow"}),
    "loot": frozenset({"credential-theft", "exfiltration", "cloud-metadata", "docker", "ssh-keys"}),
    "persist": frozenset({"persistence", "systemd", "cron", "miner", "webshell", "rootkit",
                          "beacon", "k8s", "daemonset", "watchdog", "timer", "self-healing"}),
    "verify": frozenset({"verification", "health-check", "deploy-verify", "process-check"}),
    "pivot": frozenset({"lateral-movement", "network-discovery", "pivot", "subnet"}),
}

# Attack-only terms: skills with these in their name/tags are filtered out in
# non-attack mode (recon-only / read-only).
_ATTACK_ONLY_TERMS = frozenset({
    "exploit", "bypass", "post-exploit", "red-team", "privesc",
    "persistence", "rootkit", "webshell", "backdoor",
})


# CVE regex — auto-detect CVE patterns in the query.
_CVE_RE = re.compile(r"\bcve-\d{4}-\d+\b", re.IGNORECASE)


class SkillSelector:
    """Selects skills for a given context (phase, query, mode).

    Two tiers:
    1. Deterministic (tag/keyword) — always runs.
    2. Semantic (embedding) — runs when an embedder is available; gracefully
       falls back to deterministic-only when not.

    Selection is advisory-only. Skills are injected into the system prompt as
    untrusted guidance; they never grant execution authority.
    """

    def __init__(
        self,
        registry: SkillRegistry,
        embedder: Any | None = None,
        max_active: int = 6,
        min_contextual: int = 3,
        attack_mode: bool = True,
    ):
        self.registry = registry
        self.embedder = embedder
        self.max_active = max_active
        self.min_contextual = min_contextual
        self.attack_mode = attack_mode
        self._semantic_warned = False

    def select(
        self,
        query: str = "",
        phase: str = "",
        cves: list[str] | None = None,
        active_names: list[str] | None = None,
    ) -> list[LoadedSkill]:
        """Select the most relevant skills for the current context.

        Args:
            query: natural-language context (e.g. "scanning for SSH hosts").
            phase: chain phase hint (recon, spray, privesc, etc.).
            cves: list of CVE IDs discovered mid-run (triggers CVE-tagged skills).
            active_names: currently active skill names (sticky — retained across
                re-selections).

        Returns:
            A list of :class:`LoadedSkill` objects, ranked by relevance, capped
            at ``max_active``.
        """
        # Build the search query from query + phase tags + CVEs.
        search_parts: list[str] = [query] if query else []
        if phase and phase in PHASE_TAGS:
            search_parts.extend(PHASE_TAGS[phase])
        if cves:
            for cve in cves:
                search_parts.append("cve vulnerability-scanning exploit-research")

        # CVE auto-detection from the query.
        cve_matches = _CVE_RE.findall(query)
        if cve_matches:
            search_parts.append("cve vulnerability-scanning exploit-research")

        search_query = " ".join(search_parts)

        # Tier 1: deterministic.
        deterministic = self.registry.search_scored(search_query, max_results=self.max_active * 2)

        # Tier 2: semantic (optional).
        semantic_results: list[tuple[LoadedSkill, float]] = []
        if self.embedder is not None:
            try:
                semantic_results = self._semantic_rank(search_query)
            except Exception as exc:
                if not self._semantic_warned:
                    log.warning("skills: semantic selection failed: %s", exc)
                    self._semantic_warned = True

        # Merge: deterministic score + semantic similarity (when available).
        merged: dict[str, tuple[LoadedSkill, float]] = {}
        for skill, det_score in deterministic:
            merged[skill.name] = (skill, float(det_score))
        for skill, sim in semantic_results:
            if skill.name in merged:
                s, det = merged[skill.name]
                merged[skill.name] = (s, det + int(sim * 20))
            else:
                merged[skill.name] = (skill, int(sim * 20))

        # Filter attack-only skills in non-attack mode.
        if not self.attack_mode:
            merged = {
                name: (s, score) for name, (s, score) in merged.items()
                if not self._is_attack_only(s)
            }

        # Sticky defaults: retain active skills across re-selections.
        if active_names:
            for name in active_names:
                if name in self.registry._skills and name not in merged:
                    skill = self.registry._skills[name]
                    if self.attack_mode or not self._is_attack_only(skill):
                        merged[name] = (skill, 12)  # default weight

        # Sort by score descending, cap at max_active.
        ranked = sorted(merged.values(), key=lambda t: -t[1])
        return [s for s, _ in ranked[:self.max_active]]

    def _semantic_rank(self, query: str) -> list[tuple[LoadedSkill, float]]:
        """Rank skills by embedding cosine similarity to the query."""
        if not query or not self.embedder:
            return []

        query_vec = self.embedder.embed_text(query)
        if query_vec is None:
            return []

        results: list[tuple[LoadedSkill, float]] = []
        for skill in self.registry.list_skills():
            # Embed name + description (cheap, cached by the embedder).
            skill_text = f"{skill.name} {skill.description} {skill.metadata.domain} {skill.metadata.subdomain}"
            skill_vec = self.embedder.embed_text(skill_text)
            if skill_vec is None:
                continue
            sim = _cosine(query_vec, skill_vec)
            if sim >= 0.35:  # min_similarity threshold
                results.append((skill, sim))

        results.sort(key=lambda t: -t[1])
        return results[:self.max_active]

    @staticmethod
    def _is_attack_only(skill: LoadedSkill) -> bool:
        """True when a skill's name/tags contain attack-only terms."""
        name_lower = skill.name.lower()
        tag_lower = {t.lower() for t in skill.tags}
        return bool(_ATTACK_ONLY_TERMS & tag_lower) or any(
            term in name_lower for term in _ATTACK_ONLY_TERMS
        )


def _cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity, clamped to [0, 1]."""
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = sum(x * x for x in a) ** 0.5
    mag_b = sum(y * y for y in b) ** 0.5
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return max(0.0, min(1.0, dot / (mag_a * mag_b)))


def select_skills(
    registry: SkillRegistry,
    query: str = "",
    phase: str = "",
    cves: list[str] | None = None,
    attack_mode: bool = True,
    max_active: int = 6,
) -> list[LoadedSkill]:
    """Convenience function: build a selector and select in one call."""
    selector = SkillSelector(
        registry,
        max_active=max_active,
        attack_mode=attack_mode,
    )
    return selector.select(query=query, phase=phase, cves=cves)