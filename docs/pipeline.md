# Pipeline

Orchestrates the full flow: **scanner → probe → heuristic + AI scoring → store**. Defined in `honeywatch/pipeline.py:352`.

## Class `Pipeline`

```python
from honeywatch.pipeline import Pipeline
from honeywatch.config import load_config
from honeywatch.store import Store

cfg = load_config()
store = Store("honeywatch.db")
pipeline = Pipeline(cfg, store=store)  # ai_client auto-built from cfg.ai if enabled
```

### Constructor

```python
Pipeline(config, store=None, ai_client=None)
```

- `config`: `Config` from `load_config()`.
- `store`: `Store` instance; creates one from `storage.db` if omitted.
- `ai_client`: `OllamaClient` instance; when `None` and `ai.enabled` is true, builds one from `ai.base_url` / `api_key_env` / `model` / `timeout_s` / `temperature`.

### `async probe_hosts(hosts, port=22, only_ssh=None, on_result=None) -> list[Fingerprint]`

Groups `list[HostHit]` by port, delegates to `fingerprint.probe.probe_many` with:

- `concurrency = probe.concurrency`
- `timeout = probe.timeout_s`
- `level = probe.level`
- `auth_probe = probe.auth_probe`

Filters with `is_ssh(fp)` when `only_ssh` is true (default from `scan.only_ssh`). `on_result` is called per fingerprint as it completes (used for `--progress` heartbeat). See `fingerprint/probe.py:343` for the underlying asyncio.

```python
from honeywatch.models import HostHit
hits = [HostHit(ip="1.2.3.4"), HostHit(ip="5.6.7.8")]
fps = await pipeline.probe_hosts(hits)
```

### `async analyze_and_score(fingerprints) -> list[Score]`

For each `Fingerprint`:

1. **Farm detection.** `Counter(host_key_sha256)` where count ≥ 2 plus `store.known_key_set()` → `known_hashes` set.
2. **Heuristic.** `analyze(fp, known_hashes)` → `Signals` (`fingerprint/features.py:209`).
3. **Profile batching.** `profile_key(fp)` (`ai/scorer.py:354`) groups identical fingerprints; `AiScorer` scores one verdict per unique profile (batched by `batch_size`, retries with exponential backoff).
4. **Fusion.** `final_confidence = ai.confidence*0.6 + heuristic*0.4` when AI is enabled and reachable; else pure heuristic. `final_label = _classify(final_confidence)`:

| Confidence | Label |
|---|---|
| `<0.2` | `real` |
| `<0.4` | `likely_real` |
| `<0.6` | `uncertain` |
| `<0.8` | `likely_honeypot` |
| `>=0.8` | `honeypot` |

5. **Learn.** `store.learn_from_scores(scores)` persists honeypot + `likely_honeypot` host keys to `known_keys` for future farm detection.

```python
scores = await pipeline.analyze_and_score(fps)
for s in scores:
    print(s.ip, s.final_label, s.final_confidence, s.signals.flags)
```

### `async scan(targets, tool="masscan", ports=[22], rate=1000, max_hosts=None, skip_vpn_check=False, resume=False, progress=False) -> list[Score]`

High-level entry used by `honeywatch scan` (`cli.py:723`).

- Validates `tool` is `masscan` or `zmap`.
- Resolves `bin_path`, `timeout_s`, `exclude` from `scanners.<tool>` config.
- Calls `masscan.run` / `zmap.run` via `asyncio.to_thread` (blocking `subprocess`).
- Applies `max_hosts` slice.
- When `resume=True`, filters `store.scored_hosts()` so interrupted scans skip done hosts.
- Optional `progress` reporter via `_make_progress_reporter(every=1000)` — prints heartbeat to stderr.
- Calls `probe_hosts` + `analyze_and_score`, persists scores, returns them.

VPN gate: `_require_vpn(skip)` raises `VpnError` (`vpn.py:169`) if `vpn.required` and `require_mullvad` fails and `skip` is false.

```python
scores = await pipeline.scan(
    targets=["192.0.2.0/24"],
    tool="masscan",
    ports=[22],
    rate=1000,
    max_hosts=5000,
    resume=True,
    progress=True,
)
```

## Progress Reporter

`_make_progress_reporter(every=1000)` (`pipeline.py:352`) returns a callback that prints `probed N hosts (M ssh)` every N fingerprints — wired as `on_result` to `probe_many` when `--progress` is set.

## Error Handling

- Scanner `ScannerError` propagates to the caller; `cli.py:785` catches it per `--interval` iteration so a transient failure doesn't kill the loop.
- Per-host probe errors are stored in `Fingerprint.error` and still produce a `Score` with heuristic fallback.
- LLM `is_reachable()` failure keeps heuristic-only scoring and emits `uncertain` AI verdicts at `0.0`.

## Configuration Keys Used

- `scanners.masscan.*`, `scanners.zmap.*` — scanner binaries, rate, timeout, excludes
- `probe.*` — concurrency, timeout, level, auth_probe, progress
- `ai.*` — enabled, model, base_url, batch_profiles, batch_size, temperature, timeout_s, retries, retry_base_delay
- `scan.only_ssh` — SSH filtering
- `vpn.*` — gate enforcement
- `storage.db` — store path when not injected
