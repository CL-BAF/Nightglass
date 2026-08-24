# Storage

`honeywatch/store.py:383` — SQLite persistence for scan results. Planet-scale tuning: `WAL` + `synchronous=NORMAL` + `temp_store=MEMORY`, 5 indexes, persistent `known_keys` table for honeypot-key learning.

## Schema

### `hosts` table

One row per scored host, `PRIMARY KEY (ip, port)`:

| Column | Type | Meaning |
|---|---|---|
| `ip` | TEXT | host IP |
| `port` | INTEGER | port (default 22) |
| `profile_key` | TEXT | `sha256(canonical JSON)` from `ai/scorer.py:354` |
| `banner` | TEXT | raw banner string |
| `software` | TEXT | parsed software (e.g. `OpenSSH`) |
| `version` | TEXT | parsed version (e.g. `9.3p1`) |
| `flags` | TEXT | CSV of `Signals.flags` |
| `heuristic` | REAL | `Signals.heuristic_score` |
| `ai_classification` | TEXT | `AiVerdict.classification` |
| `ai_confidence` | REAL | `AiVerdict.confidence` |
| `final_confidence` | REAL | fused score |
| `final_label` | TEXT | `real`/`likely_real`/`uncertain`/`likely_honeypot`/`honeypot` |
| `json` | TEXT | full `Score` as JSON (hydrated by `query_scores`) |
| `scanned_at` | TEXT | ISO timestamp |

### Indexes (`_INDEXES`)

- `final_label`
- `final_confidence`
- `profile_key`
- `banner`
- `software`

Plus the implicit `PRIMARY KEY` index on `(ip,port)`. Queries use indexes, not full scans (tested in `tests/test_upgrades.py`).

### `known_keys` table

- `host_key_sha256 TEXT PRIMARY KEY`
- `learned_at TEXT`
- `source TEXT` (e.g. `"scan"`)

Persisted via `learn_from_scores` for farm detection.

## Class `Store`

```python
from honeywatch.store import Store
store = Store("honeywatch.db")  # default
store = Store(":memory:")       # shared single connection for tests
```

### Connection

- `_connect() -> sqlite3.Connection` — applies `PRAGMA journal_mode=WAL`, `synchronous=NORMAL`, `temp_store=MEMORY` (skipped for `:memory:` which uses a shared connection).
- `_apply_schema(conn)` — `CREATE TABLE IF NOT EXISTS` + `CREATE INDEX IF NOT EXISTS` (idempotent, applied once).
- `_close(conn)` — special handling for `:memory:`.

### Writes

```python
from honeywatch.models import Score

store.upsert_scores(scores: list[Score])  # INSERT OR REPLACE per row via _to_row()
store.add_known_keys(keys: set[str], source="scan") -> int  # INSERT OR IGNORE count
store.learn_from_scores(scores) -> int  # persists honeypot + likely_honeypot host keys
```

- `_to_row(score) -> dict` — maps `Score` fields to row columns.
- `learn_from_scores` filters `s.final_label in ("honeypot","likely_honeypot")` and `s.fingerprint.host_key_sha256` before inserting.

### Resume

```python
scored: set[tuple[str,int]] = store.scored_hosts()  # {(ip,port), ...}
# used by Pipeline.scan(resume=True) to skip already-scored hosts
```

### Reads

```python
# Lightweight dict rows (no Score hydration)
rows: list[dict] = store.query(limit=100, label="honeypot", min_confidence=0.9)
# → [{"ip": "...", "port": 22, "label": "honeypot", "confidence": 0.91, "banner": "...", "flags": [...]}, ...]

# Full Score objects (hydrated via json column, skips incompatible rows)
scores: list[Score] = store.query_scores(limit=100, label="honeypot", min_confidence=0.9)

# Aggregates
stats: dict = store.stats()
# → {"total": 1234, "by_label": {"real": 900, "honeypot": 100, ...}, "by_flag": {"legacy_cipher": 42, ...}, "known_keys": 7}
```

- `query(limit=100, label=None, min_confidence=0.0)` — parameterized `WHERE final_label=? AND final_confidence>=? ORDER BY final_confidence DESC LIMIT ?`.
- `query_scores` — same filter, then `json.loads(row["json"])` → `Score` (with dataclass hydration, skipped on `KeyError`/`TypeError` for schema evolution).
- `stats()` — `COUNT(*)`, `GROUP BY final_label`, `GROUP BY flags` (split CSV), `COUNT(*) FROM known_keys`.

Helper `_record(score) -> dict` builds the API dict for `query`.

### `known_key_set()`

```python
keys: set[str] = store.known_key_set()  # {"SHA256:...", ...}
```

Used as `known_hashes` input to `analyze()` (farm detection).

## Database Defaults

- File: `honeywatch.db` (`storage.db` in config).
- Reports dir: `reports/` (`storage.reports_dir`).
- In-memory for tests: `Store(":memory:")` shares a single connection so WAL pragmas don't apply.

## Performance Notes

- **WAL** allows concurrent readers during writes (scans + reports).
- Indexes prevent full table scans on `query(limit, label, min_confidence)` — see `tests/test_upgrades.py: test_store_query_uses_indexes_not_full_scan`.
- `upsert_scores` is called once per scan iteration, not per host, to batch writes.

## See Also

- [Pipeline](pipeline.md) — how scores are produced and persisted
- [Reports](reports.md) — rendering `query_scores` to JSON/CSV/MD
- [Fingerprinting](fingerprinting.md) — `Fingerprint` fields stored as JSON
