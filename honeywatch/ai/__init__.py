"""AI-assisted honeypot classification for honeywatch.

This package wraps an Ollama-compatible chat-completions endpoint (stdlib
``urllib.request`` only) and turns per-host fingerprints into structured
``AiVerdict`` objects via a security-analyst system prompt.
"""

from __future__ import annotations

from .ollama import AiError, OllamaClient
from .prompts import OUTPUT_JSON, SYSTEM_PROMPT, user_prompt_for
from .scorer import AiScorer, profile_key, summarize, verdict_from_text

__all__ = [
    "AiError",
    "AiScorer",
    "OllamaClient",
    "OUTPUT_JSON",
    "SYSTEM_PROMPT",
    "profile_key",
    "summarize",
    "user_prompt_for",
    "verdict_from_text",
]
