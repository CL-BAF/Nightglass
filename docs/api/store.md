# API — Store

`honeywatch/store.py:383`.

## `class Store(db_path="honeywatch.db")`

WAL + `synchronous=NORMAL` + `temp_store=MEMORY`, 5 indexes, `known_keys` table.

| Method | Signature | Meaning |
|---|---|---|
| `__init__` | `(db_path)` | `:memory:` uses shared single connection |
| `_connect` | `() -> Connection` | applies pragmas |
| `_apply_schema` | `(conn)` | `CREATE TABLE IF NOT EXISTS` + indexes (idempotent) |
| `_close` | `(conn)` | special `:memory:` handling |
| `upsert_scores` | `(scores: list[Score])` | `INSERT OR REPLACE` via `_to_row` |
| `_to_row` | `(score) -> dict` | maps Score → row |
| `add_known_keys` | `(keys: set[str], source="scan") -> int` | `INSERT OR IGNORE` count |
| `known_key_set` | `() -> set[str]` | for farm detection |
| `learn_from_scores` | `(scores) -> int` | persists honeypot/likely_honeypot keys |
| `scored_hosts` | `() -> set[tuple[str,int]]` | for `resume` |
| `query` | `(limit=100, label=None, min_confidence=0.0) -> list[dict]` | lightweight rows |
| `query_scores` | `(limit, label, min_confidence) -> list[Score]` | hydrated via `json` column |
| `stats` | `() -> {total, by_label, by_flag, known_keys}` | aggregates |

Helpers: `score_record(score) -> dict` (shared with the report writers; see `honeywatch.models.score_record`).

See [Storage](../storage.md) for schema and examples.
