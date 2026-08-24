# Reports

`honeywatch/report.py:142` — three report writers operating on `list[Score]`. Every scan writes reports to `storage.reports_dir` (default `reports/`); you can re-render anytime via `honeywatch report`.

## Writers

```python
from honeywatch.report import write_json, write_csv, write_md
from honeywatch.store import Store

store = Store("honeywatch.db")
scores = store.query_scores(limit=200, label="honeypot", min_confidence=0.9)

write_json("reports/report.json", scores)  # json.dump indent=2
write_csv("reports/report.csv", scores)    # flat table
write_md("reports/report.md", scores)      # human-readable markdown, returns text
```

All writers take `(path: str, scores: list[Score])`. They create parent dirs as needed.

### `write_json(path, scores)`

Writes a JSON array of `_score_record(score)` dicts (`report.py:142`):

```json
[
  {
    "ip": "1.2.3.4",
    "port": 22,
    "final_label": "honeypot",
    "final_confidence": 0.88,
    "heuristic": 0.65,
    "ai_classification": "honeypot",
    "ai_confidence": 0.92,
    "banner": "SSH-2.0-OpenSSH_7.4",
    "software": "OpenSSH",
    "version": "7.4",
    "flags": ["legacy_cipher", "host_key_reuse"]
  }
]
```

### `write_csv(path, scores)`

Columns: `ip,port,final_label,final_confidence,heuristic,ai_classification,ai_confidence,banner,software,version,flags`

Flags are joined as `";".join(flags)`.

### `write_md(path, scores) -> str`

Markdown with:

- `Generated: <timestamp>` header
- `Hosts analyzed: N`
- `Counts by label` table (using `LABELS` order)
- `Top 20 by confidence` table (`ip:port | label | confidence | banner`)
- `Flag breakdown` table (`flag | count`, sorted descending)

Returns the rendered text (also written to `path`).

## CLI

```bash
honeywatch scan 192.0.2.0/24 --report-format json,csv,md --skip-vpn-check
# writes reports/scan-20260318-120000.{json,csv,md}

honeywatch report --format json --limit 200
honeywatch report --format csv --label honeypot --out ./honeypots.csv
honeywatch report --format md --min-confidence 0.9 --out reports/custom.md
# honeywatch report --out can be a file or a directory; when a directory, a timestamped file is created

honeywatch stats                      # aggregate counts from store
honeywatch stats --json
```

Handler `cli.py:691` `_cmd_report` respects `storage.reports_dir` and `--out` being a directory.

## Labels

```python
from honeywatch.report import LABELS
# ["real", "likely_real", "uncertain", "likely_honeypot", "honeypot"]
```

Order is used for the markdown `Counts by label` table.

## Internal

- `_score_record(score) -> dict` — flattens `Score` + `Fingerprint` + `Signals` + `AiVerdict` into a single dict for JSON/CSV.
- Writers handle empty `scores` gracefully (empty file / header-only).
- Defensive in `cli.py:712`: if a writer returns a string instead of writing the file, the CLI writes it for the user.

## See Also

- [Storage](storage.md) — `query_scores` and `stats()`
- [CLI Reference](cli.md) — `honeywatch report` flags
