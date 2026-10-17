"""CSV and JSON report generation."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence, Union

from . import __version__
from .evaluation import EvaluationReport
from .models import ClassificationResult

CSV_COLUMNS = [
    "email_id", "source", "sender", "subject", "predicted_label", "true_label", "correct",
    "risk_score", "phishing_score", "spam_score", "matched_rules", "explanation", "elapsed_ms", "error",
]
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection: untrusted text starting with = + - @ gets a quote prefix."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def summarize(results: Sequence[ClassificationResult]) -> dict[str, Any]:
    counts = Counter(r.label for r in results)
    ok = [r for r in results if r.ok]
    return {
        "total": len(results),
        "by_label": dict(counts),
        "errors": sum(1 for r in results if not r.ok),
        "mean_risk_score": round(sum(r.risk_score for r in ok) / len(ok), 2) if ok else 0.0,
        "max_risk_score": max((r.risk_score for r in ok), default=0.0),
    }


def _row(r: ClassificationResult) -> dict[str, Any]:
    correct = "" if r.true_label is None or not r.ok else str(r.label == r.true_label).lower()
    return {
        "email_id": csv_safe(r.email_id),
        "source": csv_safe(r.source),
        "sender": csv_safe(r.sender),
        "subject": csv_safe(r.subject),
        "predicted_label": r.label,
        "true_label": r.true_label or "",
        "correct": correct,
        "risk_score": r.risk_score,
        "phishing_score": r.phishing_score,
        "spam_score": r.spam_score,
        "matched_rules": ";".join(m.rule_id for m in r.matches),
        "explanation": csv_safe(r.explanation.replace("\n", " | ")),
        "elapsed_ms": r.elapsed_ms,
        "error": csv_safe(r.error or ""),
    }


def write_csv_report(results: Iterable[ClassificationResult], path: Union[str, Path]) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for r in results:
            writer.writerow(_row(r))
    return p


def build_json_report(
    results: Sequence[ClassificationResult],
    *,
    metrics: Optional[EvaluationReport] = None,
    scan_stats: Optional[dict[str, Any]] = None,
    parse_errors: Optional[Sequence[str]] = None,
) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool_version": __version__,
        "summary": summarize(results),
        "scan_stats": scan_stats or {},
        "parse_errors": list(parse_errors or []),
        "metrics": metrics.to_dict() if metrics else None,
        "results": [r.to_dict() for r in results],
    }


def write_json_report(
    results: Sequence[ClassificationResult],
    path: Union[str, Path],
    *,
    metrics: Optional[EvaluationReport] = None,
    scan_stats: Optional[dict[str, Any]] = None,
    parse_errors: Optional[Sequence[str]] = None,
) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = build_json_report(results, metrics=metrics, scan_stats=scan_stats, parse_errors=parse_errors)
    with p.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return p


def generate_reports(
    results: Sequence[ClassificationResult],
    output_dir: Union[str, Path],
    *,
    formats: Sequence[str] = ("csv", "json"),
    basename: Optional[str] = None,
    metrics: Optional[EvaluationReport] = None,
    scan_stats: Optional[dict[str, Any]] = None,
    parse_errors: Optional[Sequence[str]] = None,
) -> list[Path]:
    """Write the requested report formats into ``output_dir`` and return the created paths."""
    unknown = set(formats) - {"csv", "json"}
    if unknown:
        raise ValueError(f"Unsupported report format(s): {sorted(unknown)}")
    name = basename or "scan_" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = Path(output_dir)
    paths: list[Path] = []
    if "csv" in formats:
        paths.append(write_csv_report(results, out / f"{name}.csv"))
    if "json" in formats:
        paths.append(write_json_report(results, out / f"{name}.json", metrics=metrics, scan_stats=scan_stats, parse_errors=parse_errors))
    return paths
