# API — AI

`honeywatch/ai/` — re-exports at `ai/__init__.py:24`.

## Re-exports

```python
from honeywatch.ai import OllamaClient, AiError, SYSTEM_PROMPT, OUTPUT_JSON, user_prompt_for, AiScorer, profile_key, summarize, verdict_from_text
__all__ = ["OllamaClient","AiError","SYSTEM_PROMPT","OUTPUT_JSON","user_prompt_for","AiScorer","profile_key","summarize","verdict_from_text"]
```

## `ollama.py`

`honeywatch/ai/ollama.py:138`.

```python
from honeywatch.ai import OllamaClient, AiError

client = OllamaClient(base_url="https://ollama.com/v1", api_key="...", model="llama3.1:8b", timeout=120, temperature=0.0)
client.chat(messages, json_mode=False, temperature=None) -> str
client.is_reachable() -> bool   # GET /v1/models 2xx
client.models() -> list[str]    # GET /v1/models data[].id
class AiError(Exception)
```

Stdlib `urllib.request`, `AiError` on `HTTPError`, `OSError→unreachable` message.

## `prompts.py`

`honeywatch/ai/prompts.py:47`.

- `SYSTEM_PROMPT: str` — senior analyst, legacy ciphers, JSON only
- `OUTPUT_JSON: str` — `{"classification":..., "confidence":0.0, "reasons":[...]}`
- `user_prompt_for(summary: dict) -> str` — renders `key: value` lines + JSON instruction

## `scorer.py`

`honeywatch/ai/scorer.py:354`.

| Symbol | Detail |
|---|---|
| `CLASSIFICATIONS` | `{real,likely_real,uncertain,likely_honeypot,honeypot}` |
| `_ALGO_FIELDS` | 8-tuple of algo field names |
| `_BATCH_SIZE` | `100` |
| `_MAX_RETRIES` | `3` |
| `_FENCE_RE` | fence regex |
| `profile_key(fp)` | `sha256(canonical JSON)` |
| `summarize(fp, signals)` | `-> dict` compact prompt input |
| `_coerce_verdict(obj)` | `-> AiVerdict` normalize + clamp |
| `_first_json_object(text)` | balanced brace, string-aware |
| `_extract_json(text)` | fence-aware |
| `verdict_from_text(text)` | `-> AiVerdict` fallback `uncertain 0.0` |
| `_parse_batch_response(text)` | `-> dict[str,AiVerdict]` |
| `_with_retry(func, *args, retries, base_delay)` | `base*2**attempt` backoff |
| `class AiScorer(client, batch, batch_size, retries, retry_base_delay)` | `async score(profiles) -> dict[str,AiVerdict]`, `_score_batch`, `_score_chunk`, `_score_individual` |

See [AI Integration](../ai-integration.md) for batching and JSON contract.
