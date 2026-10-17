# Email Spam & Phishing Classifier Pipeline

An explainable, rule-based pipeline that classifies emails as **Spam**, **Phishing** or **Legitimate**.
It parses `.eml` files and CSV datasets, extracts header and content features, scores them with a
configurable *greedy* rule engine, processes batches with bounded `asyncio` concurrency, writes CSV/JSON
reports, reports accuracy/precision/recall/F1 + confusion matrix, and offers both a CLI and a local
Streamlit dashboard.

* Python 3.11+ (developed and tested on 3.12), free/open-source dependencies only, no paid APIs.
* The classifier core uses **only the standard library**. Streamlit + pandas are needed just for the dashboard.
* **Privacy/safety:** everything runs locally. No email content is ever sent anywhere, links are never
  opened or resolved, attachments are never executed (judged by file name only).

> All sample data is synthetic. Company, look-alike and URL domains are invented (IPs use the reserved
> 192.0.2.0/24 documentation range). Do not visit any URL found in the samples.

## Project layout

```
email-spam-phishing-classifier/
├── app.py                  Streamlit dashboard
├── cli.py                  Command-line interface (classify | scan | evaluate | benchmark)
├── requirements.txt
├── config/rules.json       Rules, weights, thresholds, lexicons, brand list (all configurable)
├── src/
│   ├── email_parser.py     .eml / CSV / directory parsing
│   ├── feature_extractor.py  header, auth, content, URL, attachment features
│   ├── scoring_engine.py   greedy rule-based scoring
│   ├── classifier.py       label + explanation
│   ├── async_scanner.py    bounded asyncio batch scanning + benchmark
│   ├── report_generator.py CSV / JSON reports
│   ├── evaluation.py       accuracy, P/R/F1, confusion matrix
│   ├── config.py, models.py
├── data/
│   ├── sample_emails.csv   51 labelled synthetic emails (incl. edge cases)
│   └── eml_samples/        6 synthetic .eml files (label inferred from file-name prefix)
├── scripts/generate_sample_data.py   regenerates data/
├── tests/                  unit + integration tests (129 tests)
├── docs/                   architecture, scoring rules, evaluation & limitations, demo guide
└── reports/                generated reports go here
```

## Installation (Kali Linux)

```bash
# 1. Extract
unzip email-spam-phishing-classifier.zip
cd email-spam-phishing-classifier

# 2. Check Python (3.11 or newer)
python3 --version

# 3. Create a virtual environment (required on recent Kali: system pip is "externally managed")
sudo apt update && sudo apt install -y python3-venv python3-pip   # only if venv is missing
python3 -m venv .venv
source .venv/bin/activate

# 4. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

The CLI and the tests work even without step 4 (`python3 -m unittest ...`); the dashboard needs Streamlit.

### VS Code
Open the folder (`code .`), choose **Python: Select Interpreter** -> `.venv/bin/python`. Run commands from the integrated terminal at the project root.

## Usage

All commands are run **from the project root**.

### Command line

```bash
# Explain one or more emails (a .eml file, a CSV, or a directory of .eml files)
python cli.py classify data/eml_samples/phishing_paypal_lookalike.eml
python cli.py classify data/sample_emails.csv --limit 5
python cli.py classify data/sample_emails.csv --json --limit 3

# Async batch scan + CSV/JSON reports (written to reports/)
python cli.py scan data/sample_emails.csv
python cli.py scan data/eml_samples --concurrency 4 --output-dir reports --formats csv json

# Metrics: accuracy, precision, recall, F1, confusion matrix (needs labelled input)
python cli.py evaluate data/sample_emails.csv --show-errors

# Measure real throughput: sequential loop vs asyncio at several concurrency levels
python cli.py benchmark data/sample_emails.csv --copies 20 --concurrency 1,4,8,16

# Use a custom rule file
python cli.py scan data/sample_emails.csv --config my_rules.json
```
Exit codes: `0` success, `2` input/config error (message on stderr), `130` interrupted.

### Dashboard

```bash
streamlit run app.py
```
Streamlit prints a local URL (normally http://localhost:8501). Tabs:
* **Single email** - upload an `.eml` or type/paste fields; see scores, matched rules and the explanation.
* **Batch scan** - upload CSV and/or `.eml` files (try `data/sample_emails.csv`), run the async scan, filter, inspect, view metrics + confusion matrix, download CSV/JSON, measure performance.
* **Rules & config** - table of all active rules. Threshold and concurrency sliders are in the sidebar.

### Input formats
* **.eml** - standard RFC 5322 messages. From, Reply-To, Return-Path, Message-ID, `Authentication-Results` / `Received-SPF` (SPF, DKIM, DMARC), text and HTML bodies and attachment *metadata* are used. If the file name starts with `spam`, `phishing`, `legitimate`/`legit`/`ham`, that becomes the ground-truth label for evaluation.
* **CSV** - needs a `subject` and/or `body` column. Optional: `id`, `label` (`spam|phishing|legitimate`, also `ham`), `sender` (or `from`), `reply_to`, `return_path`, `message_id`, `spf`, `dkim`, `dmarc`, `attachments` (names separated by `;`). Bodies containing HTML are parsed as HTML. Bad rows are reported as warnings and skipped.

### Configuration
Everything tunable is in `config/rules.json`: thresholds (`phishing`, `spam`), the greedy `decisive_score`, every rule's weight/category/condition, keyword lexicons, brand list, TLD/shortener/extension lists. The file is validated on load with clear error messages. See `docs/scoring_rules.md`.

## Testing

```bash
python -m unittest discover -s tests -v     # no extra packages needed
# or, with pytest installed (it is in requirements.txt):
python -m pytest -v
```
The suite covers the parser, feature extractor, scoring engine (greedy order, early exit, per-hit caps, config validation),
classifier, async scanner (ordering, bounded concurrency, error isolation), reports (incl. CSV formula injection),
evaluation metrics (hand-computed example), a no-network guard, CLI commands, and end-to-end runs on the sample data.
The Streamlit UI itself is not covered by automated tests (see Known limitations); the test suite only checks that `app.py`'s `src` imports are valid.

## How it works (short)

1. **Parse** into a `ParsedEmail`.
2. **Extract features**: sender/Reply-To/Return-Path/Message-ID domain mismatches, look-alike brand domains, display-name spoofing, SPF/DKIM/DMARC results, suspicious/urgency/credential/threat/financial phrases, URLs (IP hosts, `@`, punycode, shorteners, abused TLDs, brand-in-host, link text vs target), password forms, attachment names (executables, double extensions, macros, HTML).
3. **Score greedily**: rules sorted by absolute weight, evaluated in order, adding to a phishing score and/or a spam score; stops early at a decisive score.
4. **Decide**: category thresholds (phishing 50, spam 40 by default); higher score wins; ties go to phishing.
5. **Explain**: every result lists each matched rule, its points and the evidence.

Example output:
```
Classified as PHISHING (risk score 100.0/100; phishing=100.0, spam=0.0; thresholds: phishing>=50, spam>=40).
  - [PH01] Look-alike brand domain in sender: +35 to phishing (lookalike_brand_domain=PayPal [PayPal])
  - [PH02] Brand name in display name, wrong sender domain: +30 to phishing (...)
  - [PH06] Credential / sensitive-data request phrases: +24 to phishing (credential_count=2 [verify your account, confirm your password])
```

## Results on the bundled data (measured)
51 synthetic emails: accuracy **0.9412** (48/51). The three misses are deliberate hard cases. **These numbers are optimistic**: the data and rules
were written together and the set is tiny. Details and caveats: `docs/evaluation_and_limitations.md`.

Performance: classification is CPU-bound Python, so under the GIL the asyncio scanner is about as fast as, or slightly slower than, a plain loop
(measured on the build machine, 1,020 emails: ~1,800/s sequential vs ~1,100-1,800/s async depending on concurrency). The async design gives bounded
concurrency, ordered results, error isolation and a responsive UI rather than a speed-up. Run `python cli.py benchmark ...` for your own numbers.

## Troubleshooting

| Problem | Fix |
|---|---|
| `error: externally-managed-environment` when running pip | Use the virtual environment (`python3 -m venv .venv && source .venv/bin/activate`) |
| `ModuleNotFoundError: No module named 'streamlit'` | Activate the venv and run `pip install -r requirements.txt` |
| `ModuleNotFoundError: No module named 'src'` | Run commands from the project root (the folder containing `cli.py`) |
| `streamlit: command not found` | Activate the venv, or use `python -m streamlit run app.py` |
| Dashboard port busy | `streamlit run app.py --server.port 8502` |
| `error: Path does not exist` / `Unsupported input type` | Give a `.eml`, `.csv` or a directory of `.eml` files |
| `CSV needs a 'subject' and/or 'body' column` | Rename your columns (aliases: `text`, `content`, `message`, `title`, ...) |
| `error: no emails with a ground-truth label` | Add a `label` column (spam / phishing / legitimate) to evaluate |
| `ConfigError: ...` | The message names the invalid field in your rules file; compare with `config/rules.json` |
| Python older than 3.11 | The code uses modern type syntax; install Python 3.11+ (e.g. `sudo apt install python3.12`) |

## Known limitations
* Rule-based and English-only lexicons; targeted phishing with no links/brand/attachment can evade it.
* Metrics come from a small synthetic dataset and are optimistic; not a measure of real-world accuracy.
* Authentication results are only as trustworthy as the headers in the input; authenticated mail can still be malicious.
* Attachments and images are not content-inspected; QR-code phishing and HTML smuggling are not detected.
* Brand matching is list-based with simple look-alike normalisation; the public-suffix handling is approximate.
* The Streamlit dashboard was smoke-tested with a stubbed `streamlit` module in the build environment (no network, Streamlit not installable there); it has not been exercised in a real browser. If you hit a UI problem, please check your Streamlit version (>= 1.30).

## Documentation
`docs/architecture.md` - `docs/scoring_rules.md` - `docs/evaluation_and_limitations.md` - `docs/demo_guide.md`

## License
Academic project; add the license of your choice.
