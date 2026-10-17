import asyncio
import random
import threading
import time
import unittest

from tests.helpers import email
from src.async_scanner import AsyncScanner, benchmark
from src.classifier import EmailClassifier
from src.models import ClassificationResult


class FakeClassifier:
    """Records concurrency; sleeps a random time so completion order differs from input order."""

    def __init__(self, fail_on=()):
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.fail_on = set(fail_on)

    def classify_safe(self, e):
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            time.sleep(random.uniform(0.001, 0.02))
            if e.email_id in self.fail_on:
                return ClassificationResult(e.email_id, e.source, "", "", "error", 0, 0, 0, error="boom")
            return ClassificationResult(e.email_id, e.source, "", e.subject, "legitimate", 0, 0, 0)
        finally:
            with self.lock:
                self.active -= 1


def emails(n):
    return [email(email_id=f"e{i}", subject=f"s{i}") for i in range(n)]


class AsyncScannerTests(unittest.IsolatedAsyncioTestCase):
    async def test_order_is_preserved(self):
        items = emails(40)
        results, stats = await AsyncScanner(FakeClassifier(), concurrency=8).scan(items)
        self.assertEqual([r.email_id for r in results], [e.email_id for e in items])
        self.assertEqual(stats.total, 40)
        self.assertEqual(stats.failed, 0)

    async def test_concurrency_is_bounded(self):
        fake = FakeClassifier()
        await AsyncScanner(fake, concurrency=3).scan(emails(30))
        self.assertLessEqual(fake.max_active, 3)
        self.assertGreaterEqual(fake.max_active, 2)  # and it really is concurrent

    async def test_concurrency_one_is_serial(self):
        fake = FakeClassifier()
        await AsyncScanner(fake, concurrency=1).scan(emails(10))
        self.assertEqual(fake.max_active, 1)

    async def test_failures_are_isolated(self):
        results, stats = await AsyncScanner(FakeClassifier(fail_on={"e2", "e5"}), 4).scan(emails(8))
        self.assertEqual(stats.failed, 2)
        self.assertEqual(stats.succeeded, 6)
        self.assertEqual([r.label for r in results].count("error"), 2)
        self.assertEqual(len(results), 8)

    async def test_empty_input(self):
        results, stats = await AsyncScanner(FakeClassifier(), 4).scan([])
        self.assertEqual(results, [])
        self.assertEqual(stats.total, 0)

    async def test_progress_callback(self):
        seen = []
        await AsyncScanner(FakeClassifier(), 4).scan(emails(10), progress=lambda d, t: seen.append((d, t)))
        self.assertEqual(len(seen), 10)
        self.assertEqual(seen[-1], (10, 10))
        self.assertEqual([d for d, _ in seen], list(range(1, 11)))

    async def test_scan_sync_inside_running_loop(self):
        results, _ = AsyncScanner(FakeClassifier(), 2).scan_sync(emails(5))
        self.assertEqual(len(results), 5)

    async def test_real_classifier_matches_sequential_results(self):
        clf = EmailClassifier()
        items = [email(email_id=f"x{i}", sender="a@b.example", subject="s", body=f"limited time click here {i} act now")
                 for i in range(15)]
        async_results, _ = await AsyncScanner(clf, 5).scan(items)
        sequential = [clf.classify_safe(e) for e in items]
        self.assertEqual([(r.email_id, r.label, r.risk_score) for r in async_results],
                         [(r.email_id, r.label, r.risk_score) for r in sequential])


class SyncApiTests(unittest.TestCase):
    def test_invalid_concurrency(self):
        for bad in (0, -1, 2.5, "3"):
            with self.assertRaises(ValueError):
                AsyncScanner(FakeClassifier(), bad)  # type: ignore[arg-type]

    def test_scan_sync_outside_loop(self):
        results, stats = AsyncScanner(FakeClassifier(), 4).scan_sync(emails(6))
        self.assertEqual(len(results), 6)
        self.assertGreater(stats.elapsed_seconds, 0)
        self.assertEqual(stats.concurrency, 4)

    def test_benchmark_reports_measured_numbers(self):
        rows = benchmark(FakeClassifier(), emails(10), copies=2, concurrency_levels=(1, 4))
        self.assertEqual([r["mode"] for r in rows], ["sequential loop", "asyncio scanner", "asyncio scanner"])
        self.assertTrue(all(r["emails"] == 20 and r["seconds"] > 0 for r in rows))

    def test_benchmark_empty(self):
        self.assertEqual(benchmark(FakeClassifier(), []), [])

    def test_threaded_io_like_work_does_speed_up(self):
        # Sleep releases the GIL, so with latency-bound work concurrency should clearly beat serial.
        items = emails(24)
        _, serial = AsyncScanner(FakeClassifier(), 1).scan_sync(items)
        _, parallel = AsyncScanner(FakeClassifier(), 8).scan_sync(items)
        self.assertLess(parallel.elapsed_seconds, serial.elapsed_seconds)


if __name__ == "__main__":
    unittest.main()
