#!/usr/bin/env python3
"""Command-line interface for the Email Spam & Phishing Classifier.

Examples (run from the project root):

    python cli.py classify data/eml_samples/phishing_paypal_lookalike.eml
    python cli.py scan data/sample_emails.csv --output-dir reports
    python cli.py evaluate data/sample_emails.csv
    python cli.py benchmark data/sample_emails.csv --copies 20
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from src import __version__
from src.async_scanner import AsyncScanner, benchmark
from src.classifier import EmailClassifier
from src.config import ConfigError
from src.email_parser import EmailParseError, load_emails
from src.evaluation import evaluate_results
from src.models import ClassificationResult
from src.report_generator import generate_reports, summarize


def _positive_int(value: str) -> int:
    try:
        n = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from exc
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


def _int_list(value: str) -> list[int]:
    return [_positive_int(v) for v in value.split(",") if v.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="Classify emails as spam, phishing or legitimate with an explainable rule engine.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("input", help="a .eml file, a .csv dataset, or a directory of .eml files")
        p.add_argument("--config", help="path to a rules JSON file (default: config/rules.json)")

    p = sub.add_parser("classify", help="classify and explain emails one by one")
    common(p)
    p.add_argument("--json", action="store_true", help="print results as JSON instead of text")
    p.add_argument("--limit", type=_positive_int, help="only classify the first N emails")

    p = sub.add_parser("scan", help="batch-scan (async) and write CSV/JSON reports")
    common(p)
    p.add_argument("--output-dir", default="reports", help="where to write reports (default: reports)")
    p.add_argument("--formats", nargs="+", choices=["csv", "json"], default=["csv", "json"])
    p.add_argument("--concurrency", type=_positive_int, default=8, help="max parallel classifications (default 8)")
    p.add_argument("--no-report", action="store_true", help="do not write report files")

    p = sub.add_parser("evaluate", help="compute accuracy/precision/recall/F1 and the confusion matrix")
    common(p)
    p.add_argument("--concurrency", type=_positive_int, default=8)
    p.add_argument("--output-dir", help="optionally also write reports (with metrics) to this directory")
    p.add_argument("--show-errors", action="store_true", help="list misclassified emails")

    p = sub.add_parser("benchmark", help="measure real sequential vs asyncio throughput")
    common(p)
    p.add_argument("--copies", type=_positive_int, default=10, help="repeat the corpus N times (default 10)")
    p.add_argument("--concurrency", type=_int_list, default=[1, 4, 8, 16], help="comma-separated levels (default 1,4,8,16)")
    return parser


def _load(args: argparse.Namespace, classifier: EmailClassifier):
    emails, parse_errors = load_emails(args.input, max_body_chars=classifier.max_body_chars)
    for err in parse_errors:
        print(f"warning: {err}", file=sys.stderr)
    if not emails:
        raise EmailParseError("no usable emails found in input")
    return emails, parse_errors


def _short(text: str, width: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= width else text[: width - 1] + "…"


def _print_table(results: Sequence[ClassificationResult]) -> None:
    print(f"{'ID':<22}{'TRUE':<12}{'PREDICTED':<12}{'RISK':>6}  SUBJECT")
    for r in results:
        print(f"{_short(r.email_id, 20):<22}{(r.true_label or '-'):<12}{r.label:<12}{r.risk_score:>6.1f}  {_short(r.subject, 48)}")


def cmd_classify(args: argparse.Namespace) -> int:
    classifier = EmailClassifier(config_path=args.config)
    emails, _ = _load(args, classifier)
    if args.limit:
        emails = emails[: args.limit]
    results = [classifier.classify_safe(e) for e in emails]
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False))
        return 0
    for r in results:
        print("=" * 78)
        print(f"Email:   {r.email_id}")
        print(f"From:    {_short(r.sender, 70)}")
        print(f"Subject: {_short(r.subject, 70)}")
        if r.true_label:
            print(f"Ground truth: {r.true_label}")
        print(r.explanation)
    return 0


def _scan(args: argparse.Namespace, classifier: EmailClassifier):
    emails, parse_errors = _load(args, classifier)
    scanner = AsyncScanner(classifier, concurrency=args.concurrency)
    results, stats = scanner.scan_sync(emails)
    return results, stats, parse_errors


def cmd_scan(args: argparse.Namespace) -> int:
    classifier = EmailClassifier(config_path=args.config)
    results, stats, parse_errors = _scan(args, classifier)
    _print_table(results)
    summary = summarize(results)
    print(f"\nScanned {stats.total} emails in {stats.elapsed_seconds:.3f}s "
          f"({stats.throughput_per_sec:.1f}/s, concurrency {stats.concurrency}); "
          f"labels: {summary['by_label']}; errors: {summary['errors']}")
    metrics = evaluate_results(results)
    if metrics:
        print(f"Accuracy on labelled emails: {metrics.accuracy:.4f} ({metrics.total} evaluated)")
    if not args.no_report:
        paths = generate_reports(results, args.output_dir, formats=args.formats, metrics=metrics,
                                 scan_stats=stats.to_dict(), parse_errors=parse_errors)
        for path in paths:
            print(f"Report written: {path}")
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    classifier = EmailClassifier(config_path=args.config)
    results, stats, parse_errors = _scan(args, classifier)
    metrics = evaluate_results(results)
    if metrics is None:
        print("error: no emails with a ground-truth label (spam/phishing/legitimate) to evaluate.", file=sys.stderr)
        return 2
    print(metrics.format_text())
    if args.show_errors:
        print("\nMisclassified emails:")
        wrong = [r for r in results if r.true_label and r.label != r.true_label]
        for r in wrong or []:
            print(f"  {r.email_id}: true={r.true_label} predicted={r.label} "
                  f"(phishing={r.phishing_score}, spam={r.spam_score}) rules={[m.rule_id for m in r.matches]}")
        if not wrong:
            print("  none")
    print("\nNote: metrics from a small synthetic dataset are optimistic; see docs/evaluation_and_limitations.md.")
    if args.output_dir:
        for path in generate_reports(results, args.output_dir, metrics=metrics,
                                     scan_stats=stats.to_dict(), parse_errors=parse_errors):
            print(f"Report written: {path}")
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    classifier = EmailClassifier(config_path=args.config)
    emails, _ = _load(args, classifier)
    rows = benchmark(classifier, emails, copies=args.copies, concurrency_levels=args.concurrency)
    print(f"{'mode':<18}{'conc.':>6}{'emails':>8}{'seconds':>10}{'emails/s':>11}{'vs seq.':>9}")
    for r in rows:
        print(f"{r['mode']:<18}{r['concurrency']:>6}{r['emails']:>8}{r['seconds']:>10.3f}{r['emails_per_sec']:>11.1f}"
              f"{r['relative_to_sequential']:>8.2f}x")
    print("\nThese are measured wall-clock results on this machine. Classification is CPU-bound pure Python, "
          "so asyncio+threads gives bounded concurrency and a responsive loop, not necessarily a speed-up.")
    return 0


COMMANDS = {"classify": cmd_classify, "scan": cmd_scan, "evaluate": cmd_evaluate, "benchmark": cmd_benchmark}


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except (EmailParseError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
