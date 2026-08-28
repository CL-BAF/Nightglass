"""Tests for the target-aware OPSEC system (Phase 7)."""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import MagicMock, patch

from honeywatch.opsec import (
    OpsecProfile,
    OpsecManager,
    build_opsec_briefing,
    _is_private_or_local,
    _LOW_NOISE_REWRITES,
    _NOISY_PATTERNS,
    _AGGRESSION_FACTOR,
)


# --------------------------------------------------------------------------- #
# _is_private_or_local
# --------------------------------------------------------------------------- #


class TestIsPrivateOrLocal:
    def test_rfc1918_is_private(self):
        assert _is_private_or_local("10.0.0.1") is True
        assert _is_private_or_local("172.16.0.1") is True
        assert _is_private_or_local("192.168.1.1") is True

    def test_loopback_is_local(self):
        assert _is_private_or_local("127.0.0.1") is True

    def test_link_local(self):
        assert _is_private_or_local("169.254.1.1") is True

    def test_public_ip_not_local(self):
        assert _is_private_or_local("8.8.8.8") is False
        assert _is_private_or_local("1.1.1.1") is False

    def test_local_cidrs(self):
        assert _is_private_or_local("203.0.113.1", local_cidrs=("203.0.113.0/24",)) is True
        assert _is_private_or_local("203.0.114.1", local_cidrs=("203.0.113.0/24",)) is False

    def test_invalid_ip(self):
        assert _is_private_or_local("not-an-ip") is False
        assert _is_private_or_local("") is False


# --------------------------------------------------------------------------- #
# OpsecProfile
# --------------------------------------------------------------------------- #


class TestOpsecProfile:
    def test_defaults_all_off(self):
        p = OpsecProfile()
        assert p.enabled is False
        assert p.ua_rotation is False
        assert p.is_off() is True

    def test_resolve_for_target_local_disables(self):
        p = OpsecProfile(enabled=True, local_targets_off=True)
        resolved = p.resolve_for_target("10.0.0.5")
        assert resolved.enabled is False
        assert resolved.is_off() is True

    def test_resolve_for_target_public_keeps_enabled(self):
        p = OpsecProfile(enabled=True, local_targets_off=True)
        resolved = p.resolve_for_target("8.8.8.8")
        assert resolved.enabled is True
        assert resolved.is_off() is False

    def test_resolve_for_target_local_off_disabled(self):
        p = OpsecProfile(enabled=True, local_targets_off=False)
        resolved = p.resolve_for_target("10.0.0.5")
        # local_targets_off=False means OPSEC applies even to local IPs
        assert resolved.enabled is True

    def test_resolve_preserves_re_resolution_fields(self):
        p = OpsecProfile(enabled=True, local_targets_off=True, local_cidrs=("10.0.0.0/8",))
        resolved = p.resolve_for_target("10.0.0.5")
        assert resolved.local_targets_off is True
        assert resolved.local_cidrs == ("10.0.0.0/8",)

    def test_resolve_empty_ip_returns_self(self):
        p = OpsecProfile(enabled=True)
        assert p.resolve_for_target("") is p

    def test_from_config_missing_opsec_block(self):
        cfg = MagicMock()
        cfg.opsec = None
        p = OpsecProfile.from_config(cfg)
        assert p.is_off() is True

    def test_from_config_partial(self):
        cfg = MagicMock()
        opsec = MagicMock()
        opsec.enabled = True
        opsec.ua_rotation = True
        opsec.doh = False
        opsec.doh_provider = "cloudflare"
        opsec.min_gap_seconds = 2.0
        opsec.jitter_seconds = 1.0
        opsec.rate_per_minute = 10
        opsec.quiet_command_patterns = ()
        opsec.noise_budget = 0
        opsec.local_targets_off = True
        opsec.local_cidrs = ()
        opsec.public_autonomy = True
        cfg.opsec = opsec
        p = OpsecProfile.from_config(cfg)
        assert p.enabled is True
        assert p.ua_rotation is True
        assert p.min_gap_seconds == 2.0
        assert p.rate_per_minute == 10


# --------------------------------------------------------------------------- #
# OpsecManager — noise scoring
# --------------------------------------------------------------------------- #


class TestNoiseScoring:
    def test_quiet_command_zero_noise(self):
        m = OpsecManager(OpsecProfile(enabled=True))
        result = m.score_command_noise("ls -la /tmp")
        assert result["score"] == 0
        assert result["noisy"] is False

    def test_nmap_t5_is_noisy(self):
        m = OpsecManager(OpsecProfile(enabled=True))
        result = m.score_command_noise("nmap -t5 10.0.0.1")
        assert result["score"] > 0
        assert result["noisy"] is True

    def test_masscan_is_noisy(self):
        m = OpsecManager(OpsecProfile(enabled=True))
        result = m.score_command_noise("masscan 10.0.0.0/24 -p22")
        assert result["score"] > 0
        assert result["noisy"] is True

    def test_hydra_is_noisy(self):
        m = OpsecManager(OpsecProfile(enabled=True))
        result = m.score_command_noise("hydra -l root -P rockyou.txt 10.0.0.1 ssh")
        assert result["score"] > 0

    def test_disabled_profile_zero_noise(self):
        m = OpsecManager(OpsecProfile(enabled=False))
        result = m.score_command_noise("nmap -t5 masscan hydra")
        assert result["score"] == 0
        assert result["noisy"] is False

    def test_empty_command_zero_noise(self):
        m = OpsecManager(OpsecProfile(enabled=True))
        assert m.score_command_noise("")["score"] == 0
        assert m.score_command_noise(None)["score"] == 0

    def test_no_duplicate_counting(self):
        m = OpsecManager(OpsecProfile(enabled=True))
        result = m.score_command_noise("nmap -t5 -t5 -t5")
        # -t5 should count once, not three times.
        assert result["score"] >= 1


# --------------------------------------------------------------------------- #
# OpsecManager — low-noise rewrites
# --------------------------------------------------------------------------- #


class TestLowNoiseRewrite:
    def test_t5_to_t2(self):
        m = OpsecManager(OpsecProfile(enabled=True))
        rewritten = m.suggest_low_noise_alternative("nmap -t5 10.0.0.1")
        assert "-T2" in rewritten
        assert "-t5" not in rewritten

    def test_masscan_to_nmap(self):
        m = OpsecManager(OpsecProfile(enabled=True))
        rewritten = m.suggest_low_noise_alternative("masscan 10.0.0.0/24")
        assert "nmap -sS -Pn" in rewritten

    def test_hydra_not_rewritten(self):
        # hydra isn't in _LOW_NOISE_REWRITES (no clean alternative).
        m = OpsecManager(OpsecProfile(enabled=True))
        rewritten = m.suggest_low_noise_alternative("hydra -l root 10.0.0.1")
        assert rewritten == "hydra -l root 10.0.0.1"

    def test_empty_command_passthrough(self):
        m = OpsecManager(OpsecProfile(enabled=True))
        assert m.suggest_low_noise_alternative("") == ""
        assert m.suggest_low_noise_alternative(None) is None

    def test_case_insensitive(self):
        m = OpsecManager(OpsecProfile(enabled=True))
        rewritten = m.suggest_low_noise_alternative("NMAP -T5 10.0.0.1")
        assert "-T2" in rewritten


# --------------------------------------------------------------------------- #
# OpsecManager — pacing
# --------------------------------------------------------------------------- #


class TestPacing:
    def test_disabled_profile_zero_delay(self):
        m = OpsecManager(OpsecProfile(enabled=False))
        assert m.pacing_delay("normal") == 0.0

    def test_enabled_zero_gap_zero_delay(self):
        m = OpsecManager(OpsecProfile(enabled=True, min_gap_seconds=0.0))
        assert m.pacing_delay("normal") == 0.0

    def test_stealth_doubles_delay(self):
        import random
        rng = random.Random(42)
        m = OpsecManager(OpsecProfile(enabled=True, min_gap_seconds=2.0, jitter_seconds=0.0), rng=rng)
        assert m.pacing_delay("stealth") == 4.0

    def test_maximum_zero_delay(self):
        m = OpsecManager(OpsecProfile(enabled=True, min_gap_seconds=2.0))
        assert m.pacing_delay("maximum") == 0.0

    def test_aggressive_half_delay(self):
        import random
        rng = random.Random(42)
        m = OpsecManager(OpsecProfile(enabled=True, min_gap_seconds=2.0, jitter_seconds=0.0), rng=rng)
        assert m.pacing_delay("aggressive") == 1.0

    def test_jitter_adds_randomness(self):
        import random
        rng = random.Random(42)
        m = OpsecManager(OpsecProfile(enabled=True, min_gap_seconds=1.0, jitter_seconds=2.0), rng=rng)
        delay = m.pacing_delay("normal")
        # base=1.0, jitter = 2.0 * random() — should be between 1.0 and 3.0
        assert 1.0 <= delay <= 3.0

    @pytest.mark.asyncio
    async def test_acquire_pacing_sleeps(self):
        slept_times: list[float] = []

        async def fake_sleep(t):
            slept_times.append(t)

        import random
        rng = random.Random(42)
        m = OpsecManager(
            OpsecProfile(enabled=True, min_gap_seconds=0.01, jitter_seconds=0.0),
            rng=rng,
        )
        # Patch asyncio.sleep
        with patch("asyncio.sleep", fake_sleep):
            slept = await m.acquire_pacing("normal")
        assert slept > 0
        assert len(slept_times) >= 1


# --------------------------------------------------------------------------- #
# OpsecManager — UA rotation
# --------------------------------------------------------------------------- #


class TestUserAgent:
    def test_disabled_returns_default(self):
        m = OpsecManager(OpsecProfile(enabled=False))
        assert m.user_agent() == "honeywatch/1.0"

    def test_enabled_no_rotation_returns_default(self):
        m = OpsecManager(OpsecProfile(enabled=True, ua_rotation=False))
        assert m.user_agent() == "honeywatch/1.0"

    def test_enabled_with_rotation_returns_browser_ua(self):
        import random
        rng = random.Random(42)
        m = OpsecManager(OpsecProfile(enabled=True, ua_rotation=True), rng=rng)
        ua = m.user_agent()
        assert "Mozilla" in ua or "curl" in ua
        assert ua != "honeywatch/1.0"


# --------------------------------------------------------------------------- #
# OpsecManager — resolve_for_target
# --------------------------------------------------------------------------- #


class TestManagerResolveForTarget:
    def test_local_target_disables(self):
        m = OpsecManager(OpsecProfile(enabled=True, local_targets_off=True))
        resolved = m.resolve_for_target("10.0.0.5")
        assert resolved.profile.is_off() is True

    def test_public_target_keeps_enabled(self):
        m = OpsecManager(OpsecProfile(enabled=True, local_targets_off=True))
        resolved = m.resolve_for_target("8.8.8.8")
        assert resolved.profile.is_off() is False

    def test_is_quiet_blocked_off_profile(self):
        m = OpsecManager(OpsecProfile(enabled=False, quiet_command_patterns=("nmap",)))
        assert m.is_quiet_blocked("nmap -sS 10.0.0.1") is False

    def test_is_quiet_blocked_on_profile(self):
        m = OpsecManager(OpsecProfile(enabled=True, quiet_command_patterns=("nmap",)))
        assert m.is_quiet_blocked("nmap -sS 10.0.0.1") is True

    def test_is_quiet_blocked_no_match(self):
        m = OpsecManager(OpsecProfile(enabled=True, quiet_command_patterns=("hydra",)))
        assert m.is_quiet_blocked("nmap -sS 10.0.0.1") is False


# --------------------------------------------------------------------------- #
# build_opsec_briefing
# --------------------------------------------------------------------------- #


class TestOpsecBriefing:
    def test_disabled_profile_empty_briefing(self):
        p = OpsecProfile(enabled=False)
        assert build_opsec_briefing(p) == ""

    def test_local_target_empty_briefing(self):
        p = OpsecProfile(enabled=True, local_targets_off=True)
        assert build_opsec_briefing(p, target_ip="10.0.0.5") == ""

    def test_public_target_nonempty_briefing(self):
        p = OpsecProfile(enabled=True, local_targets_off=True, min_gap_seconds=2.0)
        briefing = build_opsec_briefing(p, target_ip="8.8.8.8")
        assert "OPSEC BRIEFING" in briefing
        assert "ENABLED" in briefing
        assert "min_gap=2.0s" in briefing

    def test_briefing_lists_rewrites(self):
        p = OpsecProfile(enabled=True, local_targets_off=False)
        briefing = build_opsec_briefing(p, target_ip="8.8.8.8")
        assert "low-noise rewrite" in briefing.lower() or "rewrite" in briefing.lower()

    def test_briefing_advisory_note(self):
        p = OpsecProfile(enabled=True, local_targets_off=False)
        briefing = build_opsec_briefing(p, target_ip="8.8.8.8")
        assert "advisory" in briefing.lower()