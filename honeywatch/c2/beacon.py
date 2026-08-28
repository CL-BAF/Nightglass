"""Adaptive jittered beacon cadence for the C2 worker.

A fixed-interval poll -- every 5.0s on the dot -- is a network signature: a
SOC watching flow or IDS data sees a metronomic beacon to one host, which is
how a lot of immature implants get caught. Real malware beacons with jitter
(Cobalt Strike's ``jitter`` percentage, Empire's ``delay`` + ``jitter``,
Sliver's beacon jitter). This module gives the worker that behaviour: a
randomized wait centered on ``base`` with a +/- ``jitter_fraction * base``
spread, plus exponential backoff up to ``max_backoff`` on repeated idle/error
cycles so a controller outage is not hammered.

Pass a seeded ``random.Random`` for deterministic beacons (tests).
"""

from __future__ import annotations

import random

__all__ = ["BeaconProfile", "human_like_interval"]


class BeaconProfile:
    """Jittered, exponentially-backing-off beacon schedule.

    The profile tracks a current *backoff level* (starts at ``base``). Each
    call to :meth:`next_beacon` returns a randomized wait drawn from
    ``[level - spread, level + spread]`` where ``spread = level *
    jitter_fraction`` (floored at 0). :meth:`on_idle` and :meth:`on_error`
    return such a jittered wait at the *current* level and then grow the
    level (so the first idle/error sleeps ~base, the next ~base*factor, ...),
    capped at ``max_backoff``. :meth:`on_success` resets the level to ``base``.

    This mirrors the worker's pre-existing backoff semantics (sleep the
    current level, then grow it) but adds jitter so the cadence is no longer a
    clean metronome, and centralizes the policy in one tested object instead
    of three ad-hoc copies in the polling and WebSocket loops.
    """

    def __init__(
        self,
        base: float = 5.0,
        jitter_fraction: float = 0.2,
        max_backoff: float = 60.0,
        backoff_factor: float = 1.5,
        error_backoff_factor: float = 2.0,
        rng: "random.Random | None" = None,
    ):
        if base <= 0:
            raise ValueError("base must be > 0")
        if not 0.0 <= jitter_fraction <= 1.0:
            raise ValueError("jitter_fraction must be in [0.0, 1.0]")
        if max_backoff < base:
            raise ValueError("max_backoff must be >= base")
        if backoff_factor < 1.0:
            raise ValueError("backoff_factor must be >= 1.0")
        if error_backoff_factor < 1.0:
            raise ValueError("error_backoff_factor must be >= 1.0")
        self.base = base
        self.jitter_fraction = jitter_fraction
        self.max_backoff = max_backoff
        self.backoff_factor = backoff_factor
        self.error_backoff_factor = error_backoff_factor
        # Seeded for deterministic test beacons; unseeded (system entropy) in
        # production so two workers don't beacon in lockstep.
        self._rng = rng if rng is not None else random.Random()
        self._current = base

    @property
    def current(self) -> float:
        """The current backoff level (before the next growth)."""
        return self._current

    def next_beacon(self) -> float:
        """A jittered wait drawn from the current level. Does not advance the
        level -- call this for a one-shot wait, or use :meth:`on_idle` /
        :meth:`on_error` for the backing-off loops."""
        spread = self._current * self.jitter_fraction
        low = max(0.0, self._current - spread)
        high = self._current + spread
        if high <= 0.0:
            return 0.0
        return self._rng.uniform(low, high)

    def on_idle(self) -> float:
        """Return the jittered wait to sleep after an idle cycle (no task),
        then grow the level by ``backoff_factor`` toward ``max_backoff``."""
        wait = self.next_beacon()
        self._current = min(self._current * self.backoff_factor, self.max_backoff)
        return wait

    def on_error(self) -> float:
        """Return the jittered wait to sleep after a controller error, then
        grow the level by ``error_backoff_factor`` (steeper than idle) toward
        ``max_backoff``."""
        wait = self.next_beacon()
        self._current = min(self._current * self.error_backoff_factor, self.max_backoff)
        return wait

    def on_success(self) -> None:
        """Reset the backoff level to ``base`` after successful work/contact."""
        self._current = self.base

    def reset(self) -> None:
        """Explicitly reset to the base level (e.g. on (re)connect)."""
        self._current = self.base


def human_like_interval(base: float, hour: int | None = None) -> float:
    """Produce a beacon interval that mimics human web browsing patterns.

    Business hours (8-18): shorter intervals, higher variance (active use).
    Evening (19-23): medium intervals (background tabs, occasional use).
    Night (0-7): long intervals (device asleep, no user traffic).

    The returned value is *additional* wait time beyond the base. Callers
    should add this to their normal beacon interval for ML detection evasion.
    A SOC analysing netflow with a Gaussian mixture model sees what looks
    like user browsing, not a periodic implant.

    Parameters
    ----------
    base : float
        Minimum interval (seconds). The result is never less than this.
    hour : int or None
        Hour of day (0-23). If None, uses the current local hour.
    """
    import datetime
    import math

    if hour is None:
        hour = datetime.datetime.now().hour

    rng = random.Random()
    if 8 <= hour <= 18:
        return max(base, rng.gauss(15.0, 8.0))
    elif 19 <= hour <= 23:
        return max(base * 2, rng.gauss(45.0, 15.0))
    else:
        return max(base * 4, rng.gauss(300.0, 60.0))