# API — Report

`honeywatch/report.py:142`.

```python
from honeywatch.report import write_json, write_csv, write_md, LABELS

LABELS  # ["real","likely_real","uncertain","likely_honeypot","honeypot"]
```

| Function | Signature | Meaning |
|---|---|---|
| `write_json` | `(path: str, scores: list[Score])` | `json.dump` indent 2, `score_record` per score |
| `write_csv` | `(path: str, scores: list[Score])` | header `ip,port,final_label,final_confidence,heuristic,ai_classification,ai_confidence,banner,software,version,flags` |
| `write_md` | `(path: str, scores: list[Score]) -> str` | Generated timestamp, Hosts analyzed, Counts by label, Top 20, Flag breakdown; returns text |

`_md_cell(value)` escapes `\`, `|` and newlines so a hostile banner/flag string cannot inject Markdown table structure. `score_record(score) -> dict` (imported from `honeywatch.models`) is the shared Score serializer.

All writers create parent dirs as needed and handle empty `scores`. `cli.py:691` defensively writes `result` string if writer returns instead of writing file.

See [Reports](../reports.md).
