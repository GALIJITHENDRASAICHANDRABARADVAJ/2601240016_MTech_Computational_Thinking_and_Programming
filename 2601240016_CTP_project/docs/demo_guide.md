# Demo guide (about 5 minutes)

1. **Show one explainable verdict (CLI)**
   `python cli.py classify data/eml_samples/phishing_paypal_lookalike.eml`
   Point out: look-alike domain `paypa1-secure.top`, display-name spoof, credential phrases, failed SPF/DMARC, and the greedy early-exit note.
2. **Compare with a legitimate mail**
   `python cli.py classify data/eml_samples/legitimate_meeting.eml` (score 0, auth-pass mitigation).
3. **Batch scan + reports**
   `python cli.py scan data/sample_emails.csv --output-dir reports` then open the CSV/JSON in `reports/`.
4. **Evaluation + honest failures**
   `python cli.py evaluate data/sample_emails.csv --show-errors`: discuss the three misses and why the data is optimistic.
5. **Measured performance**
   `python cli.py benchmark data/sample_emails.csv --copies 20`: explain why asyncio is not faster for CPU-bound work.
6. **Dashboard**
   `streamlit run app.py`. Single email tab: tweak the sender/body and watch the rules change. Batch tab: upload `data/sample_emails.csv`, run the scan, inspect an email, view the confusion matrix, download reports. Move the threshold sliders in the sidebar to show configurability.
7. **Configurability**
   Edit a weight in `config/rules.json` (e.g. `SP01.per_hit`), rerun step 3 and compare.
