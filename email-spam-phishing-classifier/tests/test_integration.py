"""End-to-end tests: sample data -> parse -> classify (async) -> reports -> metrics -> CLI."""

import contextlib
import csv
import io
import json
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import EML_DIR, ROOT, SAMPLE_CSV
import cli
from src.async_scanner import AsyncScanner
from src.classifier import EmailClassifier
from src.email_parser import load_emails
from src.evaluation import evaluate_results
from src.models import LABELS
from src.report_generator import generate_reports


class SampleDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.emails, cls.errors = load_emails(SAMPLE_CSV)
        cls.clf = EmailClassifier()
        cls.results, cls.stats = AsyncScanner(cls.clf, concurrency=8).scan_sync(cls.emails)

    def test_dataset_parses_cleanly_and_covers_all_classes(self):
        self.assertEqual(self.errors, [])
        self.assertGreaterEqual(len(self.emails), 45)
        counts = {label: sum(1 for e in self.emails if e.true_label == label) for label in LABELS}
        self.assertTrue(all(c >= 10 for c in counts.values()), counts)
        ids = {e.email_id for e in self.emails}
        self.assertTrue(any(i.startswith("edge-") for i in ids))
        self.assertEqual(len(ids), len(self.emails), "ids must be unique")

    def test_async_scan_preserves_order_and_has_no_errors(self):
        self.assertEqual([r.email_id for r in self.results], [e.email_id for e in self.emails])
        self.assertEqual(self.stats.failed, 0)

    def test_metrics_are_reasonable_and_consistent(self):
        m = evaluate_results(self.results)
        self.assertEqual(m.total, len(self.emails))
        self.assertGreaterEqual(m.accuracy, 0.85)  # floor, not a target; dataset is synthetic
        self.assertEqual(sum(sum(row) for row in m.confusion_matrix), m.total)
        manual = sum(1 for r in self.results if r.label == r.true_label) / len(self.results)
        self.assertAlmostEqual(m.accuracy, manual)

    def test_clear_cases_classified_correctly(self):
        by_id = {r.email_id: r for r in self.results}
        for rid, expected in [("phish-01", "phishing"), ("phish-13", "phishing"), ("spam-01", "spam"),
                              ("spam-11", "spam"), ("legit-01", "legitimate"), ("legit-05", "legitimate")]:
            self.assertEqual(by_id[rid].label, expected, rid)

    def test_every_non_legit_verdict_is_explained(self):
        for r in self.results:
            if r.label in ("spam", "phishing"):
                self.assertTrue(r.matches, r.email_id)
                self.assertIn(r.matches[0].rule_id, r.explanation)

    def test_reports_from_real_scan(self):
        metrics = evaluate_results(self.results)
        with tempfile.TemporaryDirectory() as tmp:
            csv_path, json_path = generate_reports(self.results, tmp, basename="it", metrics=metrics,
                                                   scan_stats=self.stats.to_dict())
            with csv_path.open(newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            data = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(len(rows), len(self.results))
        self.assertEqual(len(data["results"]), len(self.results))
        self.assertAlmostEqual(data["metrics"]["accuracy"], metrics.accuracy)
        self.assertEqual(data["scan_stats"]["total"], len(self.results))


class EmlSamplesTests(unittest.TestCase):
    def test_eml_samples_classified_as_labelled(self):
        emails, errors = load_emails(EML_DIR)
        self.assertEqual(errors, [])
        results, _ = AsyncScanner(EmailClassifier(), 4).scan_sync(emails)
        for r in results:
            self.assertEqual(r.label, r.true_label, r.email_id)

    def test_exe_attachment_is_flagged_by_name_only(self):
        emails, _ = load_emails(EML_DIR / "phishing_invoice_exe.eml")
        r = EmailClassifier().classify(emails[0])
        ids = {m.rule_id for m in r.matches}
        self.assertTrue({"PH17", "PH18"} <= ids)


class NoNetworkTests(unittest.TestCase):
    def test_scanning_never_touches_the_network(self):
        def forbidden(*args, **kwargs):
            raise AssertionError("network access attempted")

        emails, _ = load_emails(SAMPLE_CSV)
        with mock.patch.object(socket.socket, "connect", forbidden), \
             mock.patch.object(socket, "getaddrinfo", forbidden), \
             mock.patch.object(socket, "gethostbyname", forbidden):
            results, stats = AsyncScanner(EmailClassifier(), 4).scan_sync(emails)
        self.assertEqual(stats.failed, 0)
        self.assertEqual(len(results), len(emails))


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_classify_eml(self):
        code, out, _ = run_cli("classify", str(EML_DIR / "spam_lottery.eml"))
        self.assertEqual(code, 0)
        self.assertIn("SPAM", out)
        self.assertIn("Matched rules", out)

    def test_classify_json_output_is_valid_json(self):
        code, out, _ = run_cli("classify", str(SAMPLE_CSV), "--json", "--limit", "3")
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(out)), 3)

    def test_scan_writes_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = run_cli("scan", str(SAMPLE_CSV), "--output-dir", tmp, "--concurrency", "4")
            files = sorted(p.suffix for p in Path(tmp).iterdir())
        self.assertEqual(code, 0)
        self.assertEqual(files, [".csv", ".json"])
        self.assertIn("Scanned", out)

    def test_scan_single_format_and_no_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_cli("scan", str(SAMPLE_CSV), "--output-dir", tmp, "--formats", "json")
            self.assertEqual([p.suffix for p in Path(tmp).iterdir()], [".json"])
        with tempfile.TemporaryDirectory() as tmp:
            run_cli("scan", str(SAMPLE_CSV), "--output-dir", tmp, "--no-report")
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_evaluate_prints_metrics(self):
        code, out, _ = run_cli("evaluate", str(SAMPLE_CSV), "--show-errors")
        self.assertEqual(code, 0)
        for needle in ("Accuracy", "precision", "recall", "f1-score", "Confusion matrix", "Misclassified"):
            self.assertIn(needle, out)

    def test_evaluate_without_labels_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "nolabels.csv"
            p.write_text("subject,body\nHi,hello there\n", encoding="utf-8")
            code, _, err = run_cli("evaluate", str(p))
        self.assertEqual(code, 2)
        self.assertIn("ground-truth", err)

    def test_benchmark(self):
        code, out, _ = run_cli("benchmark", str(SAMPLE_CSV), "--copies", "1", "--concurrency", "1,2")
        self.assertEqual(code, 0)
        self.assertIn("sequential loop", out)
        self.assertIn("asyncio scanner", out)

    def test_missing_input_returns_error_code(self):
        code, _, err = run_cli("scan", "/no/such/file.csv")
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_bad_config_returns_error_code(self):
        code, _, err = run_cli("scan", str(SAMPLE_CSV), "--config", "/no/such/rules.json", "--no-report")
        self.assertEqual(code, 2)
        self.assertIn("not found", err)

    def test_invalid_concurrency_rejected_by_argparse(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                cli.main(["scan", str(SAMPLE_CSV), "--concurrency", "0"])

    def test_real_subprocess_invocation(self):
        proc = subprocess.run([sys.executable, "cli.py", "evaluate", "data/sample_emails.csv"],
                              cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Accuracy", proc.stdout)


class DashboardImportTests(unittest.TestCase):
    def test_app_py_compiles_and_imports_exist(self):
        """app.py needs Streamlit to run, but its src imports must match the real module structure."""
        import ast

        tree = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
        import importlib

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("src"):
                module = importlib.import_module(node.module)
                for alias in node.names:
                    self.assertTrue(hasattr(module, alias.name), f"{node.module} has no {alias.name}")


if __name__ == "__main__":
    unittest.main()
