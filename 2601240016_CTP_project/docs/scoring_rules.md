# Scoring rules

Rules live in `config/rules.json` (validated on load). Each rule has:

```json
{"id": "PH06", "name": "...", "category": "phishing|spam|both", "weight": 36, "per_hit": 12,
 "condition": {"feature": "credential_count", "op": "gte", "value": 1},
 "evidence": "credential_phrases", "description": "..."}
```

* `op`: `true` (truthy), `gte`, `eq`, `in`.
* `weight`: points added (negative = mitigating). With `per_hit`, contribution = `min(weight, per_hit * value)`, so `weight` is a cap.
* `category`: which score receives the points (`both` adds to each).
* `evidence`: a feature (dotted paths allowed, e.g. `url_flags.ip_host`) shown in the explanation.

## Greedy strategy
Rules are sorted by `|weight|` descending and evaluated in that order. Evaluation stops ("early exit") once either
score reaches `greedy.decisive_score` (default 90). Scores are clamped to 0-100. Trade-off: after an early exit,
smaller rules, including any mitigating negative ones, are not evaluated; this is flagged in the result.

## Decision
A category is a candidate if its score >= its threshold (`thresholds.phishing` = 50, `thresholds.spam` = 40).
Both candidates: higher score wins, exact tie -> phishing. None: legitimate. `risk_score = max(phishing, spam)`.

## Shipped rules (summary)
* **Phishing (PH01-PH23):** look-alike sender domain, brand in display name, Reply-To/Return-Path/Message-ID mismatch,
  credential requests (+ with link), threats, SPF/DKIM/DMARC failures, IP/`@`/punycode/brand-mismatch/many-subdomain/hyphen URLs,
  link text vs target mismatch, password form, executable/double-extension/HTML/macro/archive attachments, executive title from free mail.
* **Both (BO01-BO04, LG01):** urgency, URL shortener, abused TLD (URL or sender); LG01 subtracts 15 when >= 2 auth checks pass.
* **Spam (SP01-SP10):** spam vocabulary, financial lures, exclamation marks, capitals, money amounts, unsubscribe text, many links, empty subject, auth failures.

Keyword lists, brand list (keywords + legitimate domains), shortener/TLD/extension lists are all in the same file.

## Tuning
Edit weights/thresholds in `config/rules.json`, or pass `--config my_rules.json` to the CLI. The dashboard sidebar overrides the two thresholds live.
