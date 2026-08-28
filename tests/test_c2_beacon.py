"""Tests for the adaptive jittered beacon profile and its Worker integration.

The fixed-interval poll (every 5s on the dot) was a network signature -- a
metronomic beacon to one host. BeaconProfile replaces it with a jittered,
exponentially-backing-off cadence. These tests pin the policy and make the
backoff sequence deterministic via a seeded random.Random (the roadmap's R-M1
"backoff test doesn't flake" requirement).
"""

from __future__ import annotations

import asyncio
import random

import pytest

from honeywatch.c2.beacon import BeaconProfile
from honeywatch.c2.worker import Worker
from honeywatch.models import Target, WorkerTask


# ---------------------------------------------------------------------------
# Construction + validation
# ---------------------------------------------------------------------------

def test_defaults():
    b = BeaconProfile()
    assert b.base == 5.0
    assert b.jitter_fraction == 0.2
    assert b.max_backoff == 60.0
    assert b.current == 5.0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"base": 0},
        {"base": -1},
        {"jitter_fraction": -0.1},
        {"jitter_fraction": 1.1},
        {"max_backoff": 4.0, "base": 5.0},
        {"backoff_factor": 0.9},
        {"error_backoff_factor": 0.9},
    ],
)
def test_invalid_construction_raises(kwargs):
    with pytest.raises(ValueError):
        BeaconProfile(**kwargs)


def test_max_backoff_equal_to_base_allowed():
    # max_backoff == base is the degenerate "never back off" case; allowed.
    b = BeaconProfile(base=5.0, max_backoff=5.0)
    assert b.max_backoff == b.base


# ---------------------------------------------------------------------------
# Jitter spread
# ---------------------------------------------------------------------------

def test_next_beacon_within_jitter_spread():
    rng = random.Random(1234)
    b = BeaconProfile(base=10.0, jitter_fraction=0.3, rng=rng)
    spread = 10.0 * 0.3  # +/- 3.0 -> [7.0, 13.0]
    for _ in range(200):
        w = b.next_beacon()
        assert 7.0 <= w <= 13.0
    # next_beacon does not advance the level.
    assert b.current == 10.0


def test_zero_jitter_is_exact_level():
    b = BeaconProfile(base=7.0, jitter_fraction=0.0)
    for _ in range(10):
        assert b.next_beacon() == 7.0


def test_jitter_never_negative():
    # A tiny base with large jitter must still floor at 0, never negative.
    b = BeaconProfile(base=0.5, jitter_fraction=1.0, rng=random.Random(99))
    for _ in range(100):
        assert b.next_beacon() >= 0.0


# ---------------------------------------------------------------------------
# Backoff growth + cap (deterministic via seed)
# ---------------------------------------------------------------------------

def test_on_idle_grows_then_caps_at_max_backoff():
    b = BeaconProfile(base=4.0, jitter_fraction=0.0, max_backoff=20.0)
    # jitter 0 -> wait == current level exactly, then advance.
    waits = [b.on_idle() for _ in range(10)]
    # 4, 6, 9, 13.5, 20(cap), 20, 20, 20, 20, 20
    assert waits[0] == 4.0
    assert waits[1] == pytest.approx(6.0)
    assert waits[2] == pytest.approx(9.0)
    assert waits[3] == pytest.approx(13.5)
    assert waits[4] == pytest.approx(20.0)
    for w in waits[4:]:
        assert w == 20.0  # capped
    assert b.current == 20.0


def test_on_error_grows_steeper_than_idle():
    idle = BeaconProfile(base=4.0, jitter_fraction=0.0, max_backoff=1000.0)
    err = BeaconProfile(base=4.0, jitter_fraction=0.0, max_backoff=1000.0)
    idle.on_idle()
    err.on_error()
    # idle: 4 -> current 6; error: 4 -> current 8 (factor 2 > 1.5)
    assert idle.current == pytest.approx(6.0)
    assert err.current == pytest.approx(8.0)


def test_on_success_and_reset_drop_to_base():
    b = BeaconProfile(base=4.0, jitter_fraction=0.0, max_backoff=100.0)
    b.on_idle()
    b.on_idle()
    assert b.current > 4.0
    b.on_success()
    assert b.current == 4.0
    b.on_error()
    assert b.current > 4.0
    b.reset()
    assert b.current == 4.0


def test_on_idle_returns_pre_advance_wait():
    # on_idle returns the jittered wait at the CURRENT level, THEN advances.
    # So the first idle sleeps ~base, not ~base*factor.
    b = BeaconProfile(base=5.0, jitter_fraction=0.0, max_backoff=1000.0)
    w = b.on_idle()
    assert w == 5.0  # slept the base level
    assert b.current == pytest.approx(7.5)  # then advanced


# ---------------------------------------------------------------------------
# Seeded determinism (the R-M1 "doesn't flake" guarantee)
# ---------------------------------------------------------------------------

def test_seeded_beacon_sequence_is_deterministic():
    def seq():
        b = BeaconProfile(base=5.0, jitter_fraction=0.4, max_backoff=60.0, rng=random.Random(42))
        return [b.on_idle() for _ in range(8)]

    assert seq() == seq()


def test_seeded_on_error_sequence_is_deterministic():
    def seq():
        b = BeaconProfile(base=5.0, jitter_fraction=0.3, max_backoff=60.0, rng=random.Random(7))
        return [b.on_error() for _ in range(6)]

    assert seq() == seq()


def test_different_seeds_usually_differ():
    a = BeaconProfile(base=5.0, jitter_fraction=0.4, rng=random.Random(1))
    b = BeaconProfile(base=5.0, jitter_fraction=0.4, rng=random.Random(2))
    seq_a = [a.on_idle() for _ in range(8)]
    seq_b = [b.on_idle() for _ in range(8)]
    assert seq_a != seq_b


# ---------------------------------------------------------------------------
# Worker integration
# ---------------------------------------------------------------------------

def test_worker_builds_beacon_from_kwargs():
    w = Worker("http://127.0.0.1:1", poll_interval=3.0, jitter_fraction=0.25, max_backoff=45.0)
    assert isinstance(w.beacon, BeaconProfile)
    assert w.beacon.base == 3.0
    assert w.beacon.jitter_fraction == 0.25
    assert w.beacon.max_backoff == 45.0
    # poll_interval kept as a back-compat alias for the base cadence.
    assert w.poll_interval == 3.0


def test_worker_accepts_prebuilt_seeded_beacon():
    seeded = BeaconProfile(base=2.0, jitter_fraction=0.5, rng=random.Random(123))
    w = Worker("http://127.0.0.1:1", beacon=seeded)
    assert w.beacon is seeded
    assert w.poll_interval == 2.0


def test_worker_polling_loop_uses_beacon_on_idle(monkeypatch):
    """The polling loop must sleep the beacon's on_idle() waits when no task is
    claimed, not a fixed interval. With a seeded beacon the captured sleep
    sequence matches an independent BeaconProfile with the same seed -- the
    R-M1 deterministic-backoff guarantee."""
    w = Worker(
        "http://127.0.0.1:1",
        categories=["miner"],
        beacon=BeaconProfile(base=5.0, jitter_fraction=0.4, max_backoff=60.0, rng=random.Random(42)),
    )
    # claim_task always idle -> drives the on_idle() path.
    monkeypatch.setattr(w, "claim_task", lambda: None)

    sleeps: list[float] = []
    real_sleep = asyncio.sleep

    async def fake_sleep(seconds):
        sleeps.append(seconds)
        # Stop after capturing a few idle waits.
        if len(sleeps) >= 5:
            w.stop()
        # Don't actually wait; just yield once.
        await real_sleep(0)

    monkeypatch.setattr("honeywatch.c2.worker.asyncio.sleep", fake_sleep)

    asyncio.run(w.run())

    # Rebuild the expected sequence from a fresh seeded profile.
    expected = BeaconProfile(base=5.0, jitter_fraction=0.4, max_backoff=60.0, rng=random.Random(42))
    expected_waits = [expected.on_idle() for _ in range(5)]
    assert sleeps == pytest.approx(expected_waits, rel=1e-9)


def test_worker_polling_loop_resets_beacon_on_success(monkeypatch):
    """A claimed task resets the beacon, so after work the next idle sleeps the
    base level again (not a grown backoff)."""
    w = Worker(
        "http://127.0.0.1:1",
        categories=["miner"],
        beacon=BeaconProfile(base=5.0, jitter_fraction=0.0, max_backoff=1000.0),
    )

    # First claim returns a task (success path), subsequent claims are idle.
    calls = {"n": 0}

    def fake_claim():
        calls["n"] += 1
        if calls["n"] == 1:
            return WorkerTask(
                id="t1",
                operation_id="op1",
                payload_id="xmrig",
                category="miner",
                target=Target(ip="10.0.0.1", port=22),
                script="echo hi",
            )
        return None

    monkeypatch.setattr(w, "claim_task", fake_claim)
    # dry_run execute + report must not hit the network.
    monkeypatch.setattr(w, "report_result", lambda *a, **k: None)

    sleeps: list[float] = []
    real_sleep = asyncio.sleep

    async def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) >= 3:
            w.stop()
        await real_sleep(0)

    monkeypatch.setattr("honeywatch.c2.worker.asyncio.sleep", fake_sleep)

    asyncio.run(w.run())

    # task executed (no sleep) -> beacon reset to 5. Then two idles: 5.0, 7.5.
    assert sleeps[0] == pytest.approx(5.0)
    assert sleeps[1] == pytest.approx(7.5)


def test_worker_polling_loop_backs_off_on_controller_error(monkeypatch):
    """A WorkerError (controller unreachable) drives on_error() -- steeper
    backoff than idle."""
    w = Worker(
        "http://127.0.0.1:1",
        categories=["miner"],
        beacon=BeaconProfile(base=5.0, jitter_fraction=0.0, max_backoff=1000.0),
    )

    from honeywatch.c2.worker import WorkerError

    def boom():
        raise WorkerError("controller down")

    monkeypatch.setattr(w, "claim_task", boom)

    sleeps: list[float] = []
    real_sleep = asyncio.sleep

    async def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) >= 3:
            w.stop()
        await real_sleep(0)

    monkeypatch.setattr("honeywatch.c2.worker.asyncio.sleep", fake_sleep)

    asyncio.run(w.run())

    # on_error factor 2: 5.0, 10.0, 20.0
    assert sleeps[0] == pytest.approx(5.0)
    assert sleeps[1] == pytest.approx(10.0)
    assert sleeps[2] == pytest.approx(20.0)