# Architecture

```
 .eml / .csv / dir ──► email_parser ──► ParsedEmail
                                           │
                                  feature_extractor  (headers, auth, content, URLs, attachments)
                                           │  flat feature dict
                                    scoring_engine   (greedy, configurable rules from rules.json)
                                           │  phishing score, spam score, matched rules
                                      classifier     (thresholds -> label, explanation)
                                           │
              async_scanner (bounded asyncio workers, ordered results, error isolation)
                                           │
                    ┌──────────────────────┼───────────────────────┐
              report_generator        evaluation               cli.py / app.py
              (CSV + JSON)     (accuracy, P/R/F1, confusion)   (terminal / Streamlit)
```

| Module | Responsibility |
|---|---|
| `src/models.py` | Dataclasses: `ParsedEmail`, `Attachment`, `RuleMatch`, `ClassificationResult` |
| `src/config.py` | Load + validate `config/rules.json` (`ConfigError` on any problem) |
| `src/email_parser.py` | `.eml` (stdlib `email`), CSV (column aliases), directories; collects per-row errors |
| `src/feature_extractor.py` | Sender/Reply-To/Return-Path/Message-ID checks, SPF/DKIM/DMARC, keyword families, URL and HTML analysis, attachment-name analysis |
| `src/scoring_engine.py` | Greedy rule evaluation with early exit |
| `src/classifier.py` | `EmailClassifier`: features -> scores -> label -> explanation; `classify_safe` never raises |
| `src/async_scanner.py` | `AsyncScanner` (worker pool + `asyncio.to_thread`) and `benchmark()` |
| `src/report_generator.py` | CSV/JSON reports; CSV formula-injection protection |
| `src/evaluation.py` | Metrics implemented from scratch |

## Safety design
* No network code anywhere. URLs are parsed with `urllib.parse` only; no DNS lookups, no fetching.
* Attachments are judged by file name/MIME type/size; payloads are never saved, opened or executed.
* HTML is parsed (not rendered). The dashboard shows bodies as plain text and URLs as inert text.
* Report CSV cells beginning with `= + - @` are prefixed with `'` so opening a report in a spreadsheet cannot execute an attacker-controlled formula.
* Body size is capped (`limits.max_body_chars`), `.eml` files over 25 MB are rejected.

## Concurrency model
A fixed pool of `concurrency` worker coroutines drains an `asyncio.Queue` of indices; each classification
runs in `asyncio.to_thread`. Results are stored by index, so output order equals input order. Concurrency is
therefore bounded exactly. Because classification is CPU-bound Python, the GIL prevents real parallel
speed-up; run `python cli.py benchmark ...` to see actual numbers (on the author's test machine the async
scanner was roughly equal to or slower than a plain loop for this workload).
