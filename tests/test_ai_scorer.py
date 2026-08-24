"""Tests for the AI scoring glue (profile keys, verdict parsing, AiScorer)."""

from __future__ import annotations

import asyncio
import copy
import json

from honeywatch.ai.ollama import OllamaClient
from honeywatch.ai.scorer import AiScorer, profile_key, verdict_from_text
from honeywatch.fingerprint.features import analyze


# ---------------------------------------------------------------------------
# verdict_from_text
# ---------------------------------------------------------------------------

def test_verdict_from_text_valid_json():
    text = '{"classification": "honeypot", "confidence": 0.9, "reasons": ["legacy cipher"]}'
    verdict = verdict_from_text(text)
    assert verdict.classification == "honeypot"
    assert verdict.confidence == 0.9
    assert verdict.reasons == ["legacy cipher"]
    assert verdict.raw == text


def test_verdict_from_text_extracts_json_from_wrapped_text():
    text = (
        "Here is the analysis: "
        '{"classification": "likely_honeypot", "confidence": 0.7, "reasons": ["x"]}'
        " -- hope that helps"
    )
    verdict = verdict_from_text(text)
    assert verdict.classification == "likely_honeypot"
    assert verdict.confidence == 0.7


def test_verdict_from_text_garbage_falls_back():
    text = "definitely not json {"
    verdict = verdict_from_text(text)
    assert verdict.classification == "uncertain"
    assert verdict.confidence == 0.0
    assert "parse_failed" in verdict.reasons
    assert verdict.raw == text


def test_verdict_from_text_empty():
    verdict = verdict_from_text("")
    assert verdict.classification == "uncertain"
    assert verdict.reasons == ["parse_failed"]
    assert verdict.raw == ""


def test_verdict_from_text_invalid_classification_clamped_confidence():
    verdict = verdict_from_text('{"classification": "banana", "confidence": 1.5}')
    assert verdict.classification == "uncertain"
    assert verdict.confidence == 1.0


def test_verdict_from_text_reasons_string_coerced():
    text = '{"classification": "real", "confidence": 0.1, "reasons": "fast"}'
    verdict = verdict_from_text(text)
    assert verdict.reasons == ["fast"]


# ---------------------------------------------------------------------------
# profile_key
# ---------------------------------------------------------------------------

def test_profile_key_stable_across_list_reorder(openssh_fp):
    fp1 = openssh_fp
    fp2 = copy.deepcopy(fp1)
    fp2.kex_algorithms = list(reversed(fp1.kex_algorithms))
    fp2.enc_c2s = list(reversed(fp1.enc_c2s))
    fp2.mac_s2c = list(reversed(fp1.mac_s2c))
    assert profile_key(fp1) == profile_key(fp2)


def test_profile_key_differs_across_hosts(openssh_fp):
    fp2 = copy.deepcopy(openssh_fp)
    fp2.banner = "SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu0.6"
    assert profile_key(openssh_fp) != profile_key(fp2)


def test_profile_key_none_stable():
    assert profile_key(None) == profile_key(None)
    assert len(profile_key(None)) == 64


def test_profile_key_is_hexdigest(openssh_fp):
    key = profile_key(openssh_fp)
    assert len(key) == 64
    int(key, 16)  # raises if not hex


# ---------------------------------------------------------------------------
# AiScorer
# ---------------------------------------------------------------------------

def _scorer(model="test-model") -> OllamaClient:
    return OllamaClient(
        base_url="http://127.0.0.1:1",
        api_key=None,
        model=model,
        timeout=5,
    )


def test_scorer_batch(monkeypatch, openssh_fp):
    from honeywatch.fingerprint.features import analyze

    fp = openssh_fp
    signals = analyze(fp)
    key = profile_key(fp)
    canned = json.dumps(
        {key: {"classification": "honeypot", "confidence": 0.85, "reasons": ["legacy"]}}
    )
    monkeypatch.setattr(
        OllamaClient, "chat", lambda self, messages, json_mode=False: canned
    )
    monkeypatch.setattr(OllamaClient, "is_reachable", lambda self: True)

    scorer = AiScorer(_scorer(), batch=True)
    verdicts = asyncio.run(scorer.score({key: (fp, signals)}))
    assert verdicts[key].classification == "honeypot"
    assert verdicts[key].confidence == 0.85
    assert verdicts[key].model == "test-model"
    assert verdicts[key].raw == canned


def test_scorer_individual(monkeypatch, openssh_fp):
    from honeywatch.fingerprint.features import analyze

    fp = openssh_fp
    signals = analyze(fp)
    key = profile_key(fp)
    canned = (
        '{"classification": "likely_honeypot", "confidence": 0.7, '
        '"reasons": ["banner mismatch"]}'
    )
    monkeypatch.setattr(
        OllamaClient, "chat", lambda self, messages, json_mode=False: canned
    )
    monkeypatch.setattr(OllamaClient, "is_reachable", lambda self: True)

    scorer = AiScorer(_scorer(), batch=False)
    verdicts = asyncio.run(scorer.score({key: (fp, signals)}))
    assert verdicts[key].classification == "likely_honeypot"
    assert verdicts[key].confidence == 0.7
    assert verdicts[key].model == "test-model"


def test_scorer_unreachable_returns_empty(monkeypatch, openssh_fp):
    from honeywatch.fingerprint.features import analyze

    fp = openssh_fp
    signals = analyze(fp)
    key = profile_key(fp)
    monkeypatch.setattr(OllamaClient, "is_reachable", lambda self: False)
    scorer = AiScorer(_scorer(), batch=True)
    verdicts = asyncio.run(scorer.score({key: (fp, signals)}))
    assert verdicts == {}


def test_scorer_empty_profiles(monkeypatch):
    scorer = AiScorer(_scorer(), batch=True)
    assert asyncio.run(scorer.score({})) == {}
