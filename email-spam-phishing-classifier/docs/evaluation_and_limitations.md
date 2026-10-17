# Evaluation and limitations

## How metrics are computed
`src/evaluation.py` builds a confusion matrix (rows = true, columns = predicted) from labelled emails and derives
accuracy, per-class precision/recall/F1 (+ macro and support-weighted averages). Emails without a label, or that
failed to classify, are excluded and counted as `skipped`. Unit tests check the numbers against a hand-computed example.

## Results on the bundled dataset (`data/sample_emails.csv`, 51 emails)
Run `python cli.py evaluate data/sample_emails.csv --show-errors`. With the shipped configuration:

| | legitimate | spam | phishing |
|---|---|---|---|
| true legitimate (20) | 20 | 0 | 0 |
| true spam (15) | 1 | 14 | 0 |
| true phishing (16) | 2 | 0 | 14 |

Accuracy 0.9412. The three errors are deliberate hard cases left unfixed:
`spam-07` (advance-fee scam from a Yahoo address that passes auth, so mitigation cancels the lure score),
`edge-03` (CEO gift-card fraud: no links, no brand, only soft signals) and
`edge-08` (very short smishing-style text with one shortened link).

## Why these numbers must not be over-trusted
* **Synthetic and tiny.** 51 hand-written emails; each class is a handful of templates.
* **Authored alongside the rules.** The same author wrote the dataset and the rules, so the rules fit the data. Real-world accuracy will be lower, often much lower.
* **No held-out split / no tuning protocol.** Nothing was cross-validated; thresholds were chosen by hand.
* **Class balance is artificial**; real mail is overwhelmingly legitimate, so real precision for spam/phishing would be lower.
* Auth results (SPF/DKIM/DMARC) in the CSV are typed in by the author; in real .eml files they depend on the receiving server's headers.

## Known limitations of the approach
* Rule-based, no learning: novel wording, other languages (lexicons are English) and well-written targeted phishing (no links, no brand) are weak spots.
* Authenticated mail can still be malicious (compromised accounts, attacker-owned domains with valid SPF/DKIM); the mitigating rule LG01 can hide that.
* Brand look-alike detection uses a configured brand list and simple normalisation; short brand names require a whole-token match, so `appleid-verify.com` would be missed while `apple-id-verify.com` is caught.
* "Registered domain" uses a small built-in suffix list, not the full Public Suffix List.
* Attachments are judged only by name/type; content is never inspected. QR-code phishing, image-only mail and HTML smuggling are not detected.
* Legitimate marketing mail can look like spam (see `edge-02`, which passes only thanks to authentication results).
* Performance: classification is CPU-bound; asyncio gives bounded concurrency and responsiveness, not guaranteed speed-ups. Use `cli.py benchmark` for your own numbers.

For a serious evaluation use a public labelled corpus (e.g. SpamAssassin public corpus, Enron-Spam, Nazario phishing corpus), split into tune/test sets, and report results on the untouched test set.
