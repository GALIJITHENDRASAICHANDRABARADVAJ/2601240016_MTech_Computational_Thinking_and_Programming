"""Bounded-concurrency batch scanning with ``asyncio``.

Design
------
* A fixed pool of ``concurrency`` worker coroutines pulls email indices from a queue, so at most
  ``concurrency`` classifications are in flight at any moment (bounded concurrency).
* Each classification runs via ``asyncio.to_thread`` so the event loop stays responsive (progress
  callbacks, UI). Results are written into a pre-sized list by index, so **output order always
  equals input order**, regardless of completion order.
* A failing email yields an error result; it never aborts the batch.

Honest performance note: classification is CPU-bound pure Python, so the GIL limits real
parallel speed-up. Use :func:`benchmark` to measure what you actually get on your machine.
"""

from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from typing import Any, Callable, Optional, Sequence

from .models import ERROR_LABEL, ClassificationResult, ParsedEmail

ProgressCallback = Callable[[int, int], None]


@dataclass
class ScanStats:
    total: int
    succeeded: int
    failed: int
    elapsed_seconds: float
    throughput_per_sec: float
    concurrency: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AsyncScanner:
    """Runs a classifier over many emails concurrently while preserving order."""

    def __init__(self, classifier: Any, concurrency: int = 8) -> None:
        if not isinstance(concurrency, int) or concurrency < 1:
            raise ValueError("concurrency must be an integer >= 1")
        self.classifier = classifier
        self.concurrency = concurrency

    async def scan(
        self,
        emails: Sequence[ParsedEmail],
        progress: Optional[ProgressCallback] = None,
    ) -> tuple[list[ClassificationResult], ScanStats]:
        total = len(emails)
        results: list[Optional[ClassificationResult]] = [None] * total
        started = time.perf_counter()
        if total:
            queue: asyncio.Queue[int] = asyncio.Queue()
            for index in range(total):
                queue.put_nowait(index)
            done = 0

            async def worker() -> None:
                nonlocal done
                while True:
                    try:
                        index = queue.get_nowait()
                    except asyncio.QueueEmpty:
                        return
                    results[index] = await asyncio.to_thread(self.classifier.classify_safe, emails[index])
                    done += 1
                    if progress is not None:
                        progress(done, total)

            await asyncio.gather(*(worker() for _ in range(min(self.concurrency, total))))
        elapsed = time.perf_counter() - started
        final = [r for r in results if r is not None]
        failed = sum(1 for r in final if r.label == ERROR_LABEL)
        stats = ScanStats(
            total=total,
            succeeded=total - failed,
            failed=failed,
            elapsed_seconds=round(elapsed, 4),
            throughput_per_sec=round(total / elapsed, 2) if elapsed > 0 else 0.0,
            concurrency=self.concurrency,
        )
        return final, stats

    def scan_sync(
        self,
        emails: Sequence[ParsedEmail],
        progress: Optional[ProgressCallback] = None,
    ) -> tuple[list[ClassificationResult], ScanStats]:
        """Blocking wrapper for CLIs and dashboards. Safe even if an event loop is already running."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.scan(emails, progress))
        with ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(lambda: asyncio.run(self.scan(emails, progress))).result()


def benchmark(
    classifier: Any,
    emails: Sequence[ParsedEmail],
    *,
    copies: int = 1,
    concurrency_levels: Sequence[int] = (1, 4, 8, 16),
) -> list[dict[str, Any]]:
    """Measure real throughput: a plain sequential loop versus the async scanner at several levels.

    ``copies`` repeats the corpus to get a measurable workload. Nothing here is estimated; every
    number is wall-clock time from ``time.perf_counter``.
    """
    corpus = list(emails) * max(1, copies)
    n = len(corpus)
    rows: list[dict[str, Any]] = []
    if n == 0:
        return rows
    t0 = time.perf_counter()
    for email in corpus:
        classifier.classify_safe(email)
    seq = max(time.perf_counter() - t0, 1e-9)
    rows.append(
        {"mode": "sequential loop", "concurrency": 1, "emails": n, "seconds": round(seq, 4),
         "emails_per_sec": round(n / seq, 1), "relative_to_sequential": 1.0}
    )
    for level in concurrency_levels:
        _, stats = AsyncScanner(classifier, level).scan_sync(corpus)
        secs = max(stats.elapsed_seconds, 1e-9)
        rows.append(
            {"mode": "asyncio scanner", "concurrency": level, "emails": n, "seconds": round(secs, 4),
             "emails_per_sec": round(n / secs, 1), "relative_to_sequential": round(seq / secs, 2)}
        )
    return rows
