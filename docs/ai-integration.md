# AI Integration

honeywatch uses Ollama's **OpenAI-compatible** `/v1/chat/completions` endpoint against **Ollama Cloud only** (`https://ollama.com/v1`). There is no local-server fallback. Source: `honeywatch/ai/`.

## Setup

```bash
export OLLAMA_API_KEY=ollama_...          # create at https://ollama.com/settings/keys
export HONEYWATCH_MODEL=gpt-oss:20b       # optional; default llama3.1:8b
export HONEYWATCH_AI_BASE=https://ollama.com/v1   # optional; default is this
```

Config (`config.toml` `[ai]`):

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | run the LLM verdict stage |
| `model` | `llama3.1:8b` | model tag on Ollama Cloud |
| `base_url` | `https://ollama.com/v1` | OpenAI-compatible endpoint |
| `api_key_env` | `OLLAMA_API_KEY` | env var holding the key (REQUIRED) |
| `batch_profiles` | `true` | one prompt per identical profile |
| `batch_size` | `100` | max profiles per call |
| `temperature` | `0.0` | deterministic when 0.0 |
| `timeout_s` | `120` | LLM request timeout |
| `retries` | `3` | retries with exponential backoff |
| `retry_base_delay` | `1.0` | base delay; `backoff = base*2**attempt` |

With no key or when `is_reachable()` fails, the pipeline keeps heuristics and emits `uncertain` at `0.0` — a bad LLM output never produces a false high-confidence result.

Verify:

```bash
curl https://ollama.com/v1/models -H "Authorization: Bearer $OLLAMA_API_KEY"
```

## Ollama Client (`ai/ollama.py`)

`honeywatch/ai/ollama.py:138` `OllamaClient`.

```python
from honeywatch.ai import OllamaClient

client = OllamaClient(
    base_url="https://ollama.com/v1",  # or HONEYWATCH_AI_BASE env
    api_key="ollama_...",               # or OLLAMA_API_KEY env
    model="llama3.1:8b",                # or HONEYWATCH_MODEL env
    timeout=120,
    temperature=0.0,
)
```

- `_headers() -> dict` — `Content-Type: application/json` + `Authorization: Bearer <key>` when key is set.
- `chat(messages: list[dict], json_mode=False, temperature=None) -> str` — POST `/v1/chat/completions`, handles `HTTPError→AiError`, `OSError→unreachable`, parses `data["choices"][0]["message"]["content"]`.
- `is_reachable() -> bool` — GET `/v1/models` returns 2xx.
- `models() -> list[str]` — GET `/v1/models` → `data[].id`.
- `class AiError(Exception)`.

All HTTP is `urllib.request` (stdlib, no `requests`).

## Prompts (`ai/prompts.py`)

`honeywatch/ai/prompts.py:47`.

- `SYSTEM_PROMPT` — instructs the model as a senior analyst to detect emulated SSH, calls out legacy ciphers, missing `chacha20-poly1305` / `curve25519-sha256`, demands JSON only.
- `OUTPUT_JSON` — template `{"classification": "...", "confidence": 0.0, "reasons": [...]}`.
- `user_prompt_for(summary: dict) -> str` — renders `key: value` lines from `summarize()` plus `Return JSON ...` instruction.

## Scorer (`ai/scorer.py`)

`honeywatch/ai/scorer.py:354`.

### Profile Key

```python
from honeywatch.ai import profile_key

key = profile_key(fp)  # sha256(canonical JSON of sorted algo lists)
```

Stable SHA-256 of canonical JSON containing banner, software, version, and 8 `_ALGO_FIELDS` (kex, host-key, ciphers, MACs, compression). Two hosts with the same profile share a key and thus a verdict — this is what makes planet-scale AI feasible.

### Summarize

```python
from honeywatch.ai import summarize

summary = summarize(fp, signals)
# {"banner": "...", "protocol": "2.0", "software": "OpenSSH", "version": "9.3p1",
#  "kex_algorithms": [...], "flags": [...], "anomalies": [...], "heuristic_score": 0.65, ...}
```

Compact dict fed to `user_prompt_for`.

### Verdict Parsing

- `_coerce_verdict(obj) -> AiVerdict` — normalizes `classification`/`confidence`/`reasons` (clamps confidence to `0.0–1.0`, lowercases label, defaults to `uncertain`).
- `_first_json_object(text) -> str` — balanced-brace extraction, string-aware, fence-aware.
- `_extract_json(text) -> dict` — handles ```json fences.
- `verdict_from_text(text) -> AiVerdict` — strict parse; malformed → `uncertain` at `0.0`, `raw=text`, `reasons=["parse_failed"]`.
- `_parse_batch_response(text) -> dict[str, AiVerdict]` — expects `{profile_key: verdict, ...}` JSON.

### `AiScorer`

```python
from honeywatch.ai import AiScorer

scorer = AiScorer(client, batch=True, batch_size=100, retries=3, retry_base_delay=1.0)
verdicts: dict[str, AiVerdict] = await scorer.score({profile_key: (fp, signals), ...})
```

- `async score(profiles: dict[str, tuple[Fingerprint,Signals]]) -> dict[str,AiVerdict]` — checks `is_reachable()` first; if batch mode, calls `_score_batch`, else `_score_individual`.
- `async _score_batch` — chunks profiles by `batch_size`, concurrent via `asyncio.gather`, delegates to `_score_chunk`.
- `async _score_chunk(chunk)` — builds one prompt with `[profile key]\nuser_prompt` sections, single `chat(json_mode=True)` per chunk, maps verdicts back by key via `_parse_batch_response`.
- `async _score_individual` — one `chat` per host (for lab experiments).
- `_with_retry(func, *args, retries, base_delay)` — retries with `base_delay*2**attempt` on transient `AiError`/`OSError`.

Constants: `_BATCH_SIZE=100`, `_MAX_RETRIES=3`, `_FENCE_RE`, `CLASSIFICATIONS={real,likely_real,uncertain,likely_honeypot,honeypot}`, `_ALGO_FIELDS` (8 tuple).

## Pipeline Fusion

`Pipeline.analyze_and_score` (`pipeline.py:352`):

```python
final_confidence = ai.confidence*0.6 + heuristic*0.4  # when AI enabled+reachable
final_confidence = heuristic                          # otherwise
final_label = _classify(final_confidence)  # <0.2 real ... >=0.8 honeypot
```

Batch-aware caching: the verdict for profile X is shared by all its members, so a 50k-host cluster gets a single auditable decision.

## JSON Contract

Every prompt asks for exactly:

```json
{
  "classification": "real" | "likely_real" | "uncertain" | "likely_honeypot" | "honeypot",
  "confidence": 0.0,
  "reasons": ["...", "..."]
}
```

`confidence` is `0.0–1.0`. `reasons` are short, specific, human-readable justifications grounded in the signals provided. Malformed responses → `uncertain` `0.0`.

## Why Per-Profile Batching Makes Planet-Scale Feasible

A fingerprint has ~10 algorithm lists, a software string, a version, a host key hash. But real servers cluster: OpenSSH 9.x on Ubuntu, dropbear on routers, the same honeypot image on thousands of IPs. Two hosts with the **same profile** are the same *thing* to the classifier, so it's correct and vastly cheaper to ask about the profile, not the host:

- **1 LLM call per unique profile, not per host.** A honeypot farm of 10,000 identical hosts costs one call.
- **LLM cost scales with distinct software identities** (small), not address-space size (huge).
- **Labeling is stable** and auditable per profile.
- With `batch_profiles=false` you get one call per host (for experiments).

## Troubleshooting

- **Heuristic-only scores** — check `OLLAMA_API_KEY` is set and `curl https://ollama.com/v1/models -H "Authorization: Bearer $OLLAMA_API_KEY"` succeeds. If `is_reachable()` is false, honeywatch prints a warning and continues with heuristics.
- **Timeout** — raise `ai.timeout_s` (default 120) for large batches or slow models.
- **Context window** — lower `ai.batch_size` (default 100) if prompts are truncated.
