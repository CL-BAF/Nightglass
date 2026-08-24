"""Target selection for red-team operations.

Selects hosts from the honeywatch SQLite store based on their honeypot label,
confidence, flags, and allowed payload categories. The selections are meant to
be run against machines the operator owns or is authorized to test.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from honeywatch.models import Score, Target
from honeywatch.store import Store


@dataclass
class TargetFilter:
    """Criteria for picking scan results as red-team targets."""

    labels: set[str] | None = None
    min_confidence: float = 0.0
    max_confidence: float = 1.0
    require_flags: set[str] | None = None
    exclude_flags: set[str] | None = None
    allowed_categories: list[str] | None = None
    limit: int | None = None

    def match(self, score: Score) -> bool:
        """Return True when ``score`` satisfies this filter."""
        if self.labels is not None and score.final_label not in self.labels:
            return False
        if not (self.min_confidence <= score.final_confidence <= self.max_confidence):
            return False
        flags = set(score.signals.flags) if score.signals else set()
        if self.require_flags and not self.require_flags.issubset(flags):
            return False
        if self.exclude_flags and self.exclude_flags & flags:
            return False
        return True


def _score_to_target(score: Score, allowed_categories: list[str] | None = None) -> Target:
    """Hydrate a Target from a scored host."""
    return Target(
        ip=score.ip,
        port=score.port,
        label=score.final_label,
        confidence=score.final_confidence,
        profile_key="",
        allowed_categories=list(allowed_categories) if allowed_categories else [],
    )


def select_targets(
    store: Store,
    filter_: TargetFilter,
    ssh_user: str | None = None,
    ssh_key: str | None = None,
) -> list[Target]:
    """Query the store and return matching targets."""
    rows = store.query_scores(
        limit=filter_.limit or 1000,
        label=None,  # we filter labels ourselves so we can use confidence bounds
        min_confidence=filter_.min_confidence,
    )
    targets: list[Target] = []
    for score in rows:
        if filter_.match(score):
            target = _score_to_target(score, filter_.allowed_categories)
            target.ssh_user = ssh_user
            target.ssh_key = ssh_key
            targets.append(target)
        if filter_.limit is not None and len(targets) >= filter_.limit:
            break
    return targets
