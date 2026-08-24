"""Scoring glue: fingerprint -> profile key -> LLM verdict -> AiVerdict."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from typing import Any

from ..models import AiVerdict, Fingerprint, Signals
from .ollama import AiError, OllamaClient
from .prompts import SYSTEM_PROMPT, user_prompt_for

__all__ = [
    "AiScorer",
    "CLASSIFICATIONS",
    "profile_key",
    "summarize",
    "verdict_from_text",
]

CLASSIFICATIONS = {"real", "likely_real", "uncertain", "likely_honeypot", "honeypot"}

_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)

_ALGO_FIELDS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "enc_c2s",
    "enc_s2c",
    "mac_c2s",
    "mac_s2c",
    "comp_c2s",
    "comp_s2c",
)


# ------------------------------------------------------------------ profiling
def profile_key(fp: Fingerprint | None) -> str:
    """Stable sha256 hexdigest identifying an identical fingerprint cluster."""
    if fp is None:
        payload: Any = None
    else:
        payload = {
            "software": fp.software,
            "software_version": fp.software_version,
            "banner": fp.banner,
            "host_key_type": fp.host_key_type,
            "host_key_sha256": fp.host_key_sha256,
        }
        for field in _ALGO_FIELDS:
            payload[field] = sorted(getattr(fp, field) or [])
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def summarize(fp: Fingerprint | None, signals: Signals | None = None) -> dict[str, Any]:
    """Compact evidence dict handed to the prompt (see ``user_prompt_for``)."""
    summary: dict[str, Any] = {}
    if fp is not None:
        summary["banner"] = fp.banner
        summary["software"] = fp.software
        summary["software_version"] = fp.software_version
        summary["protocol"] = fp.protocol
        for field in _ALGO_FIELDS:
            summary[field] = list(getattr(fp, field) or [])
        summary["host_key_type"] = fp.host_key_type
        summary["host_key_sha256"] = fp.host_key_sha256
        summary["connect_ms"] = fp.connect_ms
        summary["banner_ms"] = fp.banner_ms
        summary["time_to_banner_ms"] = fp.time_to_banner_ms
        summary["error"] = fp.error
        extra = getattr(fp, "evidence", None) or {}
        if extra:
            summary["auth_probe"] = {k: str(v) for k, v in extra.items()}

    if signals is not None:
        summary["flags"] = list(signals.flags)
        summary["anomalies"] = list(signals.anomalies)
        summary["heuristic_score"] = signals.heuristic_score
    else:
        summary["flags"] = []
        summary["anomalies"] = []
        summary["heuristic_score"] = 0.0
    return summary


# ------------------------------------------------------------------ parsing
def _coerce_verdict(obj: Any) -> AiVerdict:
    """Coerce a parsed JSON object into an AiVerdict (raw left empty)."""
    if not isinstance(obj, dict):
        raise ValueError("verdict is not an object")

    classification = obj.get("classification", "uncertain")
    if not isinstance(classification, str) or classification not in CLASSIFICATIONS:
        classification = "uncertain"

    try:
        confidence = float(obj.get("confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    reasons = obj.get("reasons", [])
    if isinstance(reasons, str):
        reasons = [reasons]
    elif not isinstance(reasons, list):
        reasons = []
    reasons = [str(r) for r in reasons]

    return AiVerdict(
        classification=classification,
        confidence=confidence,
        reasons=reasons,
        raw="",
    )


def _first_json_object(text: str) -> str:
    """Return the first balanced {...} block in ``text`` (string-aware)."""
    start = text.find("{")
    if start == -1:
        raise ValueError("no JSON object in model output")
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise ValueError("unbalanced JSON block in model output")


def _extract_json(text: str) -> dict[str, Any]:
    # Prefer a fenced ```json ...``` block when present.
    fenced = _FENCE_RE.search(text)
    candidate = fenced.group(1).strip() if fenced else _first_json_object(text)
    obj = json.loads(candidate)
    if not isinstance(obj, dict):
        raise ValueError("top-level JSON is not an object")
    return obj


def verdict_from_text(text: str) -> AiVerdict:
    """Parse the first {...} block of model text into an AiVerdict."""
    if not text:
        return AiVerdict(
            classification="uncertain",
            confidence=0.0,
            reasons=["parse_failed"],
            raw="",
        )
    try:
        obj = _extract_json(text)
        verdict = _coerce_verdict(obj)
        verdict.raw = text
        return verdict
    except Exception:
        return AiVerdict(
            classification="uncertain",
            confidence=0.0,
            reasons=["parse_failed"],
            raw=text,
        )


def _parse_batch_response(text: str) -> dict[str, AiVerdict]:
    """Split a batch JSON object keyed by profile key into per-key verdicts."""
    try:
        obj = _extract_json(text)
    except Exception:
        return {}
    results: dict[str, AiVerdict] = {}
    for key, value in obj.items():
        if not isinstance(key, str):
            continue
        try:
            results[key] = _coerce_verdict(value)
        except ValueError:
            continue
    return results


# Max profiles per batch chat call. Bounding the prompt keeps it inside the
# model context window on planet-scale scans with thousands of distinct
# profiles; each chunk is its own independent request. Overridable via
# ``AiScorer(batch_size=...)`` / config ``ai.batch_size``.
_BATCH_SIZE = 100

# Backoff schedule: ``retry_base_delay * 2**attempt`` seconds between retries.
_MAX_RETRIES = 3


def _with_retry(
    func,
    *args,
    retries: int = _MAX_RETRIES,
    base_delay: float = 1.0,
    **kwargs,
):
    """Call ``func`` with retries on :class:`AiError` (exponential backoff)."""
    last = None
    for attempt in range(max(1, retries)):
        try:
            return func(*args, **kwargs)
        except AiError as exc:
            last = exc
            if attempt + 1 >= retries:
                break
            # Non-blocking sleep would require an event loop; this helper is
            # always run inside asyncio.to_thread, so a short sleep is fine and
            # keeps callers simple.
            import time as _time
            _time.sleep(base_delay * (2 ** attempt))
    raise last if last is not None else AiError("retry exhausted")


# ------------------------------------------------------------------ scorer
class AiScorer:
    """Turn a dict of {profile_key: (Fingerprint, Signals)} into AiVerdicts.

    In batch mode the profiles are classified in chunks of at most
    ``_BATCH_SIZE``; each chunk is one chat call and the model returns a JSON
    object keyed by profile key. Chunks run concurrently, and any profile that
    does not come back cleanly is retried with its own dedicated call.
    """

    def __init__(self, client: OllamaClient, batch: bool = True, batch_size: int | None = None,
                 retries: int = _MAX_RETRIES, retry_base_delay: float = 1.0) -> None:
        self.client = client
        self.batch = batch
        self.batch_size = int(batch_size) if batch_size and batch_size > 0 else _BATCH_SIZE
        self.retries = max(1, int(retries))
        self.retry_base_delay = max(0.0, float(retry_base_delay))

    async def score(
        self,
        profiles: dict[str, tuple[Fingerprint, Signals]],
    ) -> dict[str, AiVerdict]:
        if not profiles:
            return {}
        if self.client is None:
            return {}

        reachable = await asyncio.to_thread(self.client.is_reachable)
        if not reachable:
            return {}

        results: dict[str, AiVerdict] = {}
        if self.batch:
            results = await self._score_batch(profiles)

        missing = {k: v for k, v in profiles.items() if k not in results}
        if missing:
            results.update(await self._score_individual(missing))
        return results

    async def _score_batch(
        self,
        profiles: dict[str, tuple[Fingerprint, Signals]],
    ) -> dict[str, AiVerdict]:
        """Score every profile via chunked, concurrent batch chat calls."""
        items = list(profiles.items())
        chunks = [items[i : i + self.batch_size] for i in range(0, len(items), self.batch_size)]
        if not chunks:
            return {}
        chunk_results = await asyncio.gather(
            *(self._score_chunk(c) for c in chunks), return_exceptions=True
        )
        results: dict[str, AiVerdict] = {}
        for chunk in chunk_results:
            # return_exceptions=True: a non-AiError exception in one chunk
            # (e.g. a parse bug) shouldn't abort every other in-flight chunk.
            if isinstance(chunk, BaseException):
                continue
            if chunk:
                results.update(chunk)
        return results

    async def _score_chunk(
        self,
        chunk: list[tuple[str, tuple[Fingerprint, Signals]]],
    ) -> dict[str, AiVerdict]:
        """Classify a single <=``_BATCH_SIZE`` chunk of profiles."""
        chunk_profiles = dict(chunk)
        sections = []
        for key, (fp, signals) in chunk:
            sections.append(f"[profile {key}]\n{user_prompt_for(summarize(fp, signals))}")
        user_message = (
            "\n\n".join(sections)
            + "\n\nReturn ONE JSON object whose keys are the profile keys listed "
            'above and whose values are {"classification": one of "real" | '
            '"likely_real" | "uncertain" | "likely_honeypot" | "honeypot", '
            '"confidence": float 0.0-1.0, "reasons": [string]}. '
            "Include a key for EVERY profile listed above."
        )
        try:
            text = await asyncio.to_thread(
                _with_retry,
                self.client.chat,
                [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_message},
                ],
                json_mode=True,
                retries=self.retries,
                base_delay=self.retry_base_delay,
            )
        except AiError:
            return {}

        results = {
            k: v for k, v in _parse_batch_response(text).items() if k in chunk_profiles
        }
        for verdict in results.values():
            verdict.model = self.client.model
            verdict.raw = text
        return results

    async def _score_individual(
        self,
        profiles: dict[str, tuple[Fingerprint, Signals]],
    ) -> dict[str, AiVerdict]:
        async def _one(key: str, fp: Fingerprint, signals: Signals):
            summary = summarize(fp, signals)
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt_for(summary)},
            ]
            try:
                text = await asyncio.to_thread(
                    _with_retry,
                    self.client.chat,
                    messages,
                    json_mode=True,
                    retries=self.retries,
                    base_delay=self.retry_base_delay,
                )
            except AiError:
                return None
            verdict = verdict_from_text(text)
            verdict.model = self.client.model
            return key, verdict

        # Score profiles concurrently instead of serially: a failed/slow profile
        # no longer forces N sequential round-trips on the rest.
        outcomes = await asyncio.gather(
            *(_one(k, fp, sig) for k, (fp, sig) in profiles.items()),
            return_exceptions=True,
        )
        results: dict[str, AiVerdict] = {}
        for outcome in outcomes:
            if isinstance(outcome, BaseException) or outcome is None:
                continue
            key, verdict = outcome
            results[key] = verdict
        return results
