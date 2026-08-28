"""Upper Confidence Bound (UCB1) bandit for SSH banner-based target selection.

Tracks per-banner (attempts, successes) to prioritise target SSH software
versions that historically yield more footholds. New banners receive an
exploration bonus so they are tried at least once.

UCB1 formula::

    score = success_rate + sqrt(2 * ln(total_attempts) / arm_attempts)

A banner with 0 attempts is initialised with (1, 0) so the exploration term
dominates and it is selected early. After the first real attempt the arm
converges toward its true success rate.

The bandit state is persisted to the ``learning_outcomes`` table in the
honeywatch store so learning survives across runs.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

__all__ = ["UCB1Bandit"]


class UCB1Bandit:
    """UCB1 bandit per SSH banner version.

    Parameters
    ----------
    arms : dict[str, tuple[int, int]]
        Initial arm state: ``banner -> (attempts, successes)``. Loaded from
        the store on startup; empty dict for a fresh bandit.
    """

    def __init__(self, arms: dict[str, tuple[int, int]] | None = None):
        self.arms: dict[str, tuple[int, int]] = dict(arms) if arms else {}
        self._total_attempts: int = sum(a for a, _ in self.arms.values())

    def _ensure_arm(self, banner: str) -> None:
        if banner not in self.arms:
            self.arms[banner] = (1, 0)
            self._total_attempts += 1

    def select(self, candidates: list[str]) -> str:
        """Return the candidate banner with the highest UCB1 score.

        Ties are broken by the candidate with *fewest* attempts (explore
        under-sampled arms first). Raises ``ValueError`` on an empty list.
        """
        if not candidates:
            raise ValueError("no candidates")
        for b in candidates:
            self._ensure_arm(b)
        scores = self.scores()
        scored = [(scores[b], self.arms[b][0], b) for b in candidates]
        scored.sort(key=lambda t: (-t[0], t[1]))
        return scored[0][2]

    def update(self, banner: str, success: bool) -> None:
        """Record the outcome of an attempt against *banner*."""
        self._ensure_arm(banner)
        attempts, successes = self.arms[banner]
        attempts += 1
        successes += 1 if success else 0
        self.arms[banner] = (attempts, successes)
        self._total_attempts += 1

    def scores(self) -> dict[str, float]:
        """Current UCB1 score for every known arm."""
        out: dict[str, float] = {}
        total = max(self._total_attempts, 1)
        for banner, (attempts, successes) in self.arms.items():
            rate = successes / max(attempts, 1)
            exploration = math.sqrt(2.0 * math.log(total) / max(attempts, 1))
            out[banner] = rate + exploration
        return out

    def to_rows(self) -> list[dict]:
        """Serialize arm state for store persistence."""
        now = datetime.now(timezone.utc).isoformat()
        return [
            {"banner": b, "attempts": a, "successes": s, "updated_at": now}
            for b, (a, s) in self.arms.items()
        ]