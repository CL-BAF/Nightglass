"""Report writers for honeywatch scan results (JSON, CSV, Markdown)."""

from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone

from honeywatch.models import Score

LABELS = ["real", "likely_real", "uncertain", "likely_honeypot", "honeypot"]


def _score_record(score: Score) -> dict:
    """Plain-dict representation of a full Score (safe for json.dumps)."""
    fp = asdict(score.fingerprint) if score.fingerprint else None
    sig = score.signals
    ai = asdict(score.ai) if score.ai else None
    return {
        "ip": score.ip,
        "port": score.port,
        "final_confidence": score.final_confidence,
        "final_label": score.final_label,
        "fingerprint": fp,
        "signals": {
            "anomalies": list(sig.anomalies) if sig else [],
            "flags": list(sig.flags) if sig else [],
            "heuristic_score": sig.heuristic_score if sig else 0.0,
            "evidence": dict(sig.evidence) if sig else {},
        },
        "ai": ai,
    }


def write_json(path: str, scores: list[Score]) -> None:
    """Write every Score as a list of JSON records."""
    records = [_score_record(score) for score in scores]
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
        lines.append(f"| {label} | {counts.get(label, 0)} |")
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
                f"| {rank} | {score.ip} | {score.port} | "
                f"{score.final_label} | {score.final_confidence:.3f} |"
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
            lines.append(f"| {flag} | {count} |")
    else:
        lines.append("_No flags observed._")
    lines.append("")

    text = "\n".join(lines)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return text
