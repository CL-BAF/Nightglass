"""Report writers for honeywatch scan results (JSON, CSV, Markdown)."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone

from honeywatch.models import Score, score_record

LABELS = ["real", "likely_real", "uncertain", "likely_honeypot", "honeypot"]


def _md_cell(value: object) -> str:
    """Escape a value for safe use inside a Markdown table cell.

    A ``|`` would start a new column and a newline would break the row, so
    either would let a hostile banner / flag string inject arbitrary table
    structure (or smuggle a row past the top-hosts table). Backslash is escaped
    first so the replacements below are not themselves escaped.
    """
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def write_json(path: str, scores: list[Score]) -> None:
    """Write every Score as a list of JSON records."""
    records = [score_record(score) for score in scores]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, default=str)


def write_csv(path: str, scores: list[Score]) -> None:
    """Write a flat CSV table of the most useful Score fields."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "ip",
                "port",
                "final_label",
                "final_confidence",
                "heuristic",
                "ai_classification",
                "ai_confidence",
                "banner",
                "software",
                "version",
                "flags",
            ]
        )
        for score in scores:
            fp = score.fingerprint
            sig = score.signals
            ai = score.ai
            writer.writerow(
                [
                    score.ip,
                    score.port,
                    score.final_label,
                    score.final_confidence,
                    (sig.heuristic_score if sig else 0.0),
                    (ai.classification if ai else ""),
                    (ai.confidence if ai else 0.0),
                    ((fp.banner or "") if fp else ""),
                    ((fp.software or "") if fp else ""),
                    ((fp.software_version or "") if fp else ""),
                    (",".join(sig.flags) if sig else ""),
                ]
            )


def write_md(path: str, scores: list[Score]) -> str:
    """Write a Markdown report and return its text."""
    lines: list[str] = []
    lines.append("# Honeywatch Report")
    lines.append("")
    lines.append(f"- Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"- Hosts analyzed: {len(scores)}")
    lines.append("")

    # Counts by label.
    counts = Counter(score.final_label for score in scores)
    lines.append("## Counts by label")
    lines.append("")
    lines.append("| Label | Count |")
    lines.append("| --- | ---: |")
    for label in LABELS:
        lines.append(f"| {_md_cell(label)} | {counts.get(label, 0)} |")
    lines.append("")

    # Top 20 hosts by final confidence.
    top = sorted(
        scores, key=lambda s: s.final_confidence, reverse=True
    )[:20]
    lines.append("## Top hosts by confidence")
    lines.append("")
    if top:
        lines.append("| Rank | Host | Port | Label | Confidence |")
        lines.append("| --- | --- | ---: | --- | ---: |")
        for rank, score in enumerate(top, 1):
            lines.append(
                f"| {rank} | {_md_cell(score.ip)} | {score.port} | "
                f"{_md_cell(score.final_label)} | {score.final_confidence:.3f} |"
            )
    else:
        lines.append("_No hosts to report._")
    lines.append("")

    # Per-flag breakdown.
    flag_counts: Counter[str] = Counter()
    for score in scores:
        if score.signals:
            for flag in score.signals.flags:
                flag_counts[flag] += 1

    lines.append("## Flag breakdown")
    lines.append("")
    if flag_counts:
        lines.append("| Flag | Count |")
        lines.append("| --- | ---: |")
        for flag, count in flag_counts.most_common():
            lines.append(f"| {_md_cell(flag)} | {count} |")
    else:
        lines.append("_No flags observed._")
    lines.append("")

    # C2 operations section (when available).
    lines.append("## C2 Operations")
    lines.append("")
    try:
        from honeywatch.c2 import C2Store
        import os
        db_path = os.environ.get("HONEYWATCH_DB", "honeywatch.db")
        if os.path.isfile(db_path):
            store = C2Store(db_path)
            ops = store.list_operations()
            lines.append(f"- Operations: {len(ops)}")
            tasks = store.list_tasks()
            pending = sum(1 for t in tasks if t.status == "pending")
            running = sum(1 for t in tasks if t.status == "running")
            completed = sum(1 for t in tasks if t.status == "completed")
            failed = sum(1 for t in tasks if t.status == "failed")
            retried = sum(1 for t in tasks if getattr(t, "retry_count", 0) > 0)
            lines.append(f"- Tasks: {len(tasks)} total, {pending} pending, {running} running, {completed} completed, {failed} failed")
            if retried:
                lines.append(f"- Retried tasks: {retried}")
            workers = store.list_workers()
            if workers:
                lines.append(f"- Workers: {len(workers)}")
                for w in workers:
                    ip = w.get("egress_ip", "unknown") or "unknown"
                    lines.append(f"  - {w.get('id', 'unknown')} (IP: {ip}, last seen: {w.get('last_seen', 'unknown')})")
    except Exception:
        lines.append("_C2 data unavailable._")
    lines.append("")

    # Deploy verification section (when chain state exists).
    lines.append("## Deploy Verification")
    lines.append("")
    try:
        import json
        state_path = os.environ.get("HONEYWATCH_STATE", ".honeywatch/chain_state.json")
        if os.path.isfile(state_path):
            with open(state_path, "r", encoding="utf-8") as sf:
                state = json.load(sf)
            footholds = state.get("footholds", [])
            lines.append(f"- Footholds: {len(footholds)}")
            loot = state.get("loot", [])
            if loot:
                encrypted = sum(1 for l in loot if isinstance(l, dict) and l.get("encrypted"))
                lines.append(f"- Loot entries: {len(loot)}" + (f" ({encrypted} encrypted)" if encrypted else ""))
    except Exception:
        lines.append("_No chain state available._")
    lines.append("")

    text = "\n".join(lines)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return text
