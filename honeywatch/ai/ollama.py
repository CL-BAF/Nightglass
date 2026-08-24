"""Thin stdlib-only client for an Ollama (OpenAI-compatible) chat API.

No third-party dependencies: uses ``urllib.request``. Used by the AI scorer to
classify SSH fingerprints as honeypot-likely.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

__all__ = ["AiError", "OllamaClient"]

log = logging.getLogger(__name__)

_DEFAULT_BASE = "https://ollama.com/v1"
_DEFAULT_MODEL = "llama3.1:8b"

_UNREACHABLE_MSG = (
    "Ollama Cloud not reachable at {base} — check OLLAMA_API_KEY (create one at "
    "https://ollama.com/settings/keys)"
)

# Cap response bodies so a misbehaving endpoint can't make us buffer an
# unbounded stream into memory before json.loads. 16 MiB is far above any
# legitimate chat/model-list payload.
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024


def _read_capped(resp: Any, max_bytes: int = _MAX_RESPONSE_BYTES) -> str:
    """Read an HTTP response body up to ``max_bytes``, then stop.

    Raises ``AiError`` if the body exceeds the cap so a runaway endpoint
    doesn't force an unbounded ``resp.read()`` into memory.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = resp.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise AiError(
                f"Ollama response exceeded {max_bytes} bytes; aborting read"
            )
        chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


class AiError(Exception):
    """Raised when the AI backend cannot be reached or returns garbage."""


class OllamaClient:
    """Minimal Ollama Cloud chat-completions client (stdlib only).

    Cloud models only — there is no localhost fallback. Resolution order for
    ``base_url``: explicit arg -> ``HONEYWATCH_AI_BASE`` env var ->
    ``https://ollama.com/v1``. An ``OLLAMA_API_KEY`` is required to
    authenticate.
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout: float = 120,
        temperature: float = 0.0,
    ) -> None:
        self.api_key = api_key or os.environ.get("OLLAMA_API_KEY") or ""

        if base_url:
            self.base_url = base_url.rstrip("/")
        else:
            env_base = os.environ.get("HONEYWATCH_AI_BASE")
            self.base_url = env_base.rstrip("/") if env_base else _DEFAULT_BASE

        self.model = model or os.environ.get("HONEYWATCH_MODEL") or _DEFAULT_MODEL
        self.timeout = timeout
        self.temperature = temperature

    # ------------------------------------------------------------------ auth
    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    # ------------------------------------------------------------------ chat
    def chat(
        self,
        messages: list[dict[str, Any]],
        json_mode: bool = False,
        temperature: float | None = None,
        *,
        return_raw: bool = False,
    ) -> str | dict[str, Any]:
        """POST ``/chat/completions`` and return the assistant text (stripped).

        When *return_raw* is True, returns the full message dict from the first
        choice (including ``reasoning_content``, ``thinking``, etc.) instead of
        just the content string.  This lets callers inspect alternate fields
        that reasoning models may populate instead of ``content``.
        """
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature if temperature is None else temperature,
            "stream": False,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}

        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=payload,
            headers=self._headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(_read_capped(resp))
        except urllib.error.HTTPError as err:
            snippet = err.read().decode("utf-8", errors="replace")[:500]
            raise AiError(f"Ollama HTTP {err.code}: {snippet}") from err
        except OSError as err:
            raise AiError(_UNREACHABLE_MSG.format(base=self.base_url)) from err
        except ValueError as err:
            raise AiError(f"Ollama returned non-JSON response: {err}") from err

        try:
            message = data["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as err:
            raise AiError(
                f"Unexpected Ollama response shape: {str(data)[:500]}"
            ) from err

        if return_raw:
            return message

        # Reasoning models (e.g. glm, deepseek-r1) may put their output in
        # ``reasoning_content`` or ``thinking`` instead of (or in addition to)
        # ``content``.  Fall back through these fields so the agent loop
        # actually receives the model's response instead of a silent empty
        # string that causes an immediate "exhausted" exit.
        raw_content = message.get("content")

        # OpenAI-compatible APIs may return content as a list of content
        # blocks: [{"type": "text", "text": "..."}].  Extract the text.
        if isinstance(raw_content, list):
            parts = []
            for block in raw_content:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))
            content = "\n".join(parts) if parts else ""
        elif raw_content is None:
            content = ""
        else:
            content = str(raw_content)

        if not content.strip():
            # Try alternate fields where reasoning models stash their output.
            for alt_key in ("reasoning_content", "thinking"):
                alt = message.get(alt_key)
                if alt and isinstance(alt, str) and alt.strip():
                    log.debug(
                        "message.content empty; falling back to %s (%d chars)",
                        alt_key, len(alt),
                    )
                    content = alt
                    break

        if not content.strip():
            log.warning(
                "Ollama response message had no usable text content: %s",
                str(message)[:300],
            )

        return str(content).strip()

    # ------------------------------------------------------------ discovery
    # --------------------------------------------------------- diagnostics
    def raw_chat(
        self,
        messages: list[dict[str, Any]],
        json_mode: bool = False,
        temperature: float | None = None,
    ) -> dict[str, Any]:
        """POST ``/chat/completions`` and return the **full** parsed response.

        Unlike :meth:`chat` which extracts and returns only the content string,
        this method returns the entire JSON response dict so you can inspect
        ``reasoning_content``, ``thinking``, usage stats, and any other fields
        the model might include.  Useful for debugging why a model returns an
        empty ``content`` field.
        """
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature if temperature is None else temperature,
            "stream": False,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}

        payload = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=payload,
            headers=self._headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(_read_capped(resp))
        except urllib.error.HTTPError as err:
            snippet = err.read().decode("utf-8", errors="replace")[:500]
            raise AiError(f"Ollama HTTP {err.code}: {snippet}") from err
        except OSError as err:
            raise AiError(_UNREACHABLE_MSG.format(base=self.base_url)) from err
        except ValueError as err:
            raise AiError(f"Ollama returned non-JSON response: {err}") from err

    def is_reachable(self) -> bool:
        """True when GET ``/models`` returns any 2xx status.

        Sends the ``Authorization`` header when an API key is set so this also
        works against authenticated endpoints (Ollama Cloud rejects an
        unauthenticated ``/models`` with 401, which would otherwise make the
        scorer silently skip AI on every run).
        """
        try:
            req = urllib.request.Request(
                f"{self.base_url}/models", headers=self._headers(), method="GET"
            )
            with urllib.request.urlopen(req, timeout=min(self.timeout, 10.0)) as resp:
                return 200 <= resp.status < 300
        except OSError:
            return False

    def models(self) -> list[str]:
        """List model ids advertised by the endpoint (GET ``/models``, "data").

        Returns ``[]`` for any failure (HTTP error, network error, bad JSON),
        matching :meth:`is_reachable`'s "False for both" liveness contract so
        callers don't have to handle two different failure shapes.
        """
        try:
            req = urllib.request.Request(
                f"{self.base_url}/models", headers=self._headers(), method="GET"
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(_read_capped(resp))
        except (urllib.error.HTTPError, OSError, ValueError, AiError):
            return []

        if not isinstance(data, dict):
            return []
        return [
            m["id"]
            for m in data.get("data", [])
            if isinstance(m, dict) and isinstance(m.get("id"), str)
        ]
