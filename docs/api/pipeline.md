# API — Pipeline

`honeywatch/pipeline.py:352` — end-to-end orchestration.

## `class Pipeline(config, store=None, ai_client=None)`

```python
from honeywatch.pipeline import Pipeline
from honeywatch.config import load_config
from honeywatch.store import Store

cfg = load_config()
pipeline = Pipeline(cfg, store=Store("honeywatch.db"))
# ai_client auto-built from cfg.ai if enabled
```

| Param | Type | Meaning |
|---|---|---|
| `config` | `Config` | from `load_config()` |
| `store` | `Store|None` | persistence; creates from `storage.db` if omitted |
| `ai_client` | `OllamaClient|None` | LLM client; builds from `ai.*` when `None` and `ai.enabled` |

## `async probe_hosts(hosts, port=22, only_ssh=None, on_result=None) -> list[Fingerprint]`

Groups `list[HostHit]` by port, calls `probe_many` with `concurrency`/`timeout_s`/`level`/`auth_probe`, filters via `is_ssh` when `only_ssh` (default `scan.only_ssh`). `on_result(fp)` per completion.

## `async analyze_and_score(fingerprints) -> list[Score]`

Computes `Counter(host_key_sha256)` ≥2 ∪ `store.known_key_set()` → `known_hashes`, `analyze(fp, known_hashes)` → `Signals`, batches by `profile_key` → `AiScorer` (batch_size/retries), fusion `ai*0.6+heuristic*0.4`, `_classify` mapping, `store.learn_from_scores`.

## `async scan(targets, tool, ports, rate, max_hosts, skip_vpn_check, resume, progress) -> list[Score]`

Validates `masscan`/`zmap`, resolves `bin_path`/`timeout_s`/`exclude`, `masscan.run`/`zmap.run` via `to_thread`, slices `max_hosts`, filters `resume` via `scored_hosts()`, progress via `_make_progress_reporter`, `probe_hosts+analyze_and_score`, `upsert_scores`.

Private: `_require_vpn(skip)` raises `VpnError`, `_make_progress_reporter(every=1000)`, `_classify(confidence)`.

See [Pipeline](../pipeline.md) for full examples and fusion table.
