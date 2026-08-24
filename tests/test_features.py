"""Tests for the rule-based heuristic scorer (fingerprint.features.analyze)."""

from __future__ import annotations

import copy

from honeywatch.fingerprint.features import analyze


def test_realistic_openssh_low_score(openssh_fp):
    signals = analyze(openssh_fp)
    assert signals.heuristic_score < 0.2
    assert not any(f.startswith("crypto.legacy_") for f in signals.flags)
    assert not signals.flags


def test_cowrie_like_high_score(cowrie_fp):
    signals = analyze(cowrie_fp)
    assert signals.heuristic_score > 0.6
    assert "crypto.legacy_cipher" in signals.flags
    assert "crypto.legacy_mac" in signals.flags
    assert "hostkey.weak" in signals.flags


def test_none_fingerprint_base_score():
    signals = analyze(None)
    assert signals.heuristic_score == 0.35
    assert signals.flags == ["fp.unreachable"]


def test_none_with_known_hashes_ignored():
    signals = analyze(None, known_hashes={"deadbeef"})
    assert signals.heuristic_score == 0.35


def test_host_key_farm_flag(openssh_fp):
    fp = openssh_fp
    fp.host_key_sha256 = "f" * 64
    signals = analyze(fp, known_hashes={"f" * 64})
    assert "farm.hostkey_reuse" in signals.flags
    assert signals.heuristic_score == 0.20


def test_host_key_farm_requires_known_hash(openssh_fp):
    fp = openssh_fp
    fp.host_key_sha256 = "f" * 64
    signals = analyze(fp, known_hashes={"a" * 64})
    assert "farm.hostkey_reuse" not in signals.flags


def test_evidence_is_string_valued(openssh_fp):
    signals = analyze(openssh_fp)
    assert all(isinstance(v, str) for v in signals.evidence.values())
    assert signals.evidence["banner"] == openssh_fp.banner
    assert signals.evidence["software"] == "OpenSSH"
