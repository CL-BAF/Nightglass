"""Prompt templates for the honeypot classification LLM calls."""

from __future__ import annotations

from typing import Any

__all__ = ["SYSTEM_PROMPT", "OUTPUT_JSON", "user_prompt_for"]

SYSTEM_PROMPT = (
    "You are a senior network security analyst who detects SSH honeypots "
    "(emulated SSH servers that are not real OpenSSH/Dropbear). Given the "
    "fingerprint of one SSH server, classify how likely it is a honeypot. "
    "Consider: coherence between the advertised software/version and the "
    "actually offered algorithms; presence of legacy/obsolete algorithms "
    "(3des-cbc, arcfour, hmac-md5) that modern real servers disabled; missing "
    "chacha20-poly1305 or curve25519 on a claimed-modern OpenSSH; weak or "
    "mismatched host keys; a server whose banner differs from real software "
    "behavior; instant responses; identical fingerprints across hosts (farms). "
    "Respond with a JSON object ONLY."
)

OUTPUT_JSON = (
    '{"classification": "real" | "likely_real" | "uncertain" | '
    '"likely_honeypot" | "honeypot", "confidence": 0.0, '
    '"reasons": ["short reason"]}'
)


def user_prompt_for(summary: dict[str, Any]) -> str:
    """Render a compact fingerprint summary into a single-turn user prompt."""
    lines: list[str] = []
    for key, value in summary.items():
        if isinstance(value, (list, tuple)):
            rendered = ", ".join(str(v) for v in value) if value else "(none)"
        elif value is None:
            rendered = "(none)"
        else:
            rendered = str(value)
        lines.append(f"{key}: {rendered}")

    lines.append("")
    lines.append(
        'Return JSON: {"classification": one of "real" | "likely_real" | '
        '"uncertain" | "likely_honeypot" | "honeypot", "confidence": float '
        '0.0-1.0, "reasons": [string]} '
    )
    return "\n".join(lines)
