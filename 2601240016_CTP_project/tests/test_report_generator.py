import csv
import json
import tempfile
import unittest
from pathlib import Path

from src.evaluation import compute_metrics
from src.models import ClassificationResult, RuleMatch
from src.report_generator import CSV_COLUMNS, csv_safe, generate_reports, summarize, write_csv_report, write_json_report


def sample_results():
    return [
        ClassificationResult("a", "src", "x@y.example", "Hello", "spam", 55.0, 10.0, 55.0,
                             matches=[RuleMatch("SP01", "Spam keywords", "spam", 24, "spam_keyword_count=3")],
                             explanation="line1\nline2", true_label="spam"),
        ClassificationResult("b", "src", "z@y.example", "=HYPERLINK(\"http://x\")", "legitimate", 0, 0, 0, true_label="phishing"),
        ClassificationResult("c", "src", "", "", "error", 0, 0, 0, error="ValueError: bad"),
    ]


class ReportTests(unittest.TestCase):
    def test_csv_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_csv_report(sample_results(), Path(tmp) / "r" / "out.csv")
            with path.open(newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
        self.assertEqual(list(rows[0].keys()), CSV_COLUMNS)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["predicted_label"], "spam")
        self.assertEqual(rows[0]["matched_rules"], "SP01")
        self.assertEqual(rows[0]["correct"], "true")
        self.assertEqual(rows[1]["correct"], "false")
        self.assertEqual(rows[2]["correct"], "")
        self.assertNotIn("\n", rows[0]["explanation"])
        self.assertEqual(rows[2]["error"], "ValueError: bad")

    def test_csv_formula_injection_neutralised(self):
        self.assertEqual(csv_safe("=1+1"), "'=1+1")
        self.assertEqual(csv_safe("@SUM(A1)"), "'@SUM(A1)")
        self.assertEqual(csv_safe("-2"), "'-2")
        self.assertEqual(csv_safe("normal"), "normal")
        self.assertEqual(csv_safe(5.0), 5.0)
        with tempfile.TemporaryDirectory() as tmp:
            path = write_csv_report(sample_results(), Path(tmp) / "o.csv")
            with path.open(newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
        self.assertTrue(rows[1]["subject"].startswith("'="))

    def test_json_structure(self):
        results = sample_results()
        metrics = compute_metrics(["spam", "phishing"], ["spam", "legitimate"])
        with tempfile.TemporaryDirectory() as tmp:
            path = write_json_report(results, Path(tmp) / "o.json", metrics=metrics,
                                     scan_stats={"total": 3}, parse_errors=["row 9 bad"])
            data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(set(data), {"generated_at", "tool_version", "summary", "scan_stats", "parse_errors", "metrics", "results"})
        self.assertEqual(data["summary"]["total"], 3)
        self.assertEqual(data["summary"]["errors"], 1)
        self.assertEqual(data["results"][0]["matches"][0]["rule_id"], "SP01")
        self.assertEqual(data["parse_errors"], ["row 9 bad"])
        self.assertAlmostEqual(data["metrics"]["accuracy"], 0.5)

    def test_json_without_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = json.loads(write_json_report(sample_results(), Path(tmp) / "o.json").read_text(encoding="utf-8"))
        self.assertIsNone(data["metrics"])

    def test_generate_reports_formats_and_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            both = generate_reports(sample_results(), tmp, basename="run1")
            self.assertEqual(sorted(p.name for p in both), ["run1.csv", "run1.json"])
            only_csv = generate_reports(sample_results(), tmp, formats=["csv"], basename="run2")
            self.assertEqual([p.name for p in only_csv], ["run2.csv"])
            with self.assertRaises(ValueError):
                generate_reports(sample_results(), tmp, formats=["xml"])

    def test_summarize(self):
        s = summarize(sample_results())
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["by_label"], {"spam": 1, "legitimate": 1, "error": 1})
        self.assertEqual(s["errors"], 1)

    def test_empty_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_csv_report([], Path(tmp) / "e.csv")
            self.assertEqual(len(path.read_text(encoding="utf-8").strip().splitlines()), 1)  # header only


if __name__ == "__main__":
    unittest.main()
