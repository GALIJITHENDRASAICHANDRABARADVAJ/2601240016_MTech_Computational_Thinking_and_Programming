"""Streamlit dashboard for the Email Spam & Phishing Classifier.

Run locally:   streamlit run app.py

Safety: everything runs locally. Email bodies are shown as plain text (never rendered as HTML),
URLs are shown as inert text (never as clickable links), nothing is fetched and nothing leaves
this machine.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pandas as pd
import streamlit as st

from src.async_scanner import AsyncScanner, benchmark
from src.classifier import EmailClassifier
from src.config import load_config
from src.email_parser import (
    EmailParseError,
    attachments_from_names,
    make_email,
    parse_csv_bytes,
    parse_eml_bytes,
)
from src.evaluation import evaluate_results
from src.models import LABELS, ClassificationResult, ParsedEmail
from src.report_generator import build_json_report, summarize, write_csv_report

st.set_page_config(page_title="Email Spam & Phishing Classifier", page_icon="📧", layout="wide")

LABEL_ICON = {"legitimate": "🟢", "spam": "🟠", "phishing": "🔴", "error": "⚠️"}
AUTH_OPTIONS = ["missing", "pass", "fail", "softfail", "neutral", "none"]


@st.cache_resource(show_spinner=False)
def get_classifier(phishing_threshold: float, spam_threshold: float) -> EmailClassifier:
    """Build (and cache) a classifier for the chosen thresholds."""
    cfg: dict[str, Any] = copy.deepcopy(load_config())
    cfg["thresholds"] = {"phishing": phishing_threshold, "spam": spam_threshold}
    return EmailClassifier(config=cfg)


def results_to_frame(results: list[ClassificationResult]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "id": r.email_id,
                "predicted": f"{LABEL_ICON.get(r.label, '')} {r.label}",
                "true label": r.true_label or "",
                "risk": r.risk_score,
                "phishing": r.phishing_score,
                "spam": r.spam_score,
                "rules": ", ".join(m.rule_id for m in r.matches),
                "sender": r.sender,
                "subject": r.subject,
            }
            for r in results
        ]
    )


def csv_bytes(results: list[ClassificationResult]) -> bytes:
    """Render the CSV report in memory (same sanitised format as the CLI)."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        path = write_csv_report(results, Path(tmp) / "report.csv")
        return path.read_bytes()


def show_result(result: ClassificationResult) -> None:
    icon = LABEL_ICON.get(result.label, "")
    st.subheader(f"{icon} {result.label.upper()}  —  risk {result.risk_score:.1f}/100")
    c1, c2, c3 = st.columns(3)
    c1.metric("Phishing score", f"{result.phishing_score:.1f}")
    c2.metric("Spam score", f"{result.spam_score:.1f}")
    c3.metric("Rules matched", len(result.matches))
    if result.matches:
        st.dataframe(
            pd.DataFrame(
                [{"rule": m.rule_id, "name": m.name, "applies to": m.category, "points": m.weight, "evidence": m.detail}
                 for m in sorted(result.matches, key=lambda m: -abs(m.weight))]
            ),
            hide_index=True,
        )
    with st.expander("Full explanation"):
        st.code(result.explanation, language="text")
    if result.early_exit:
        st.caption("Greedy early exit: a decisive score was reached, so lower-weight rules were skipped.")


# ----------------------------------------------------------------------------- sidebar

st.sidebar.title("Settings")
_defaults = load_config()["thresholds"]
phish_t = st.sidebar.slider("Phishing threshold", 5, 100, int(_defaults["phishing"]), 5,
                            help="Minimum phishing score to label an email as phishing.")
spam_t = st.sidebar.slider("Spam threshold", 5, 100, int(_defaults["spam"]), 5,
                           help="Minimum spam score to label an email as spam.")
concurrency = st.sidebar.slider("Async concurrency", 1, 32, 8, 1, help="Maximum parallel classifications.")
st.sidebar.info("Runs 100% locally. No email content is sent anywhere, links are never opened and "
                "attachments are never executed.")
classifier = get_classifier(float(phish_t), float(spam_t))

st.title("📧 Email Spam & Phishing Classifier")
st.caption("Explainable, rule-based classification into Spam, Phishing or Legitimate.")

tab_single, tab_batch, tab_rules = st.tabs(["Single email", "Batch scan", "Rules & config"])

# ----------------------------------------------------------------------------- single email

with tab_single:
    st.markdown("Upload an `.eml` file **or** fill in the fields below.")
    uploaded = st.file_uploader("Email file (.eml)", type=["eml"], key="single_eml")
    email: ParsedEmail | None = None

    if uploaded is not None:
        try:
            email = parse_eml_bytes(uploaded.getvalue(), source=uploaded.name, email_id=uploaded.name,
                                    max_body_chars=classifier.max_body_chars)
        except EmailParseError as exc:
            st.error(f"Could not parse the file: {exc}")
    else:
        left, right = st.columns(2)
        sender = left.text_input("From", 'PayPal Security <service@paypa1-secure.top>')
        reply_to = right.text_input("Reply-To (optional)", "paypal.resolution@gmail.com")
        subject = st.text_input("Subject", "Action required: your account has been limited")
        body = st.text_area(
            "Body (plain text or HTML)", height=180,
            value="We noticed unusual activity. Verify your account and confirm your password within 24 hours: "
                  "http://paypa1-secure.top/login",
        )
        a1, a2, a3 = st.columns(3)
        spf = a1.selectbox("SPF", AUTH_OPTIONS, index=AUTH_OPTIONS.index("fail"))
        dkim = a2.selectbox("DKIM", AUTH_OPTIONS, index=0)
        dmarc = a3.selectbox("DMARC", AUTH_OPTIONS, index=AUTH_OPTIONS.index("fail"))
        attachments = st.text_input("Attachment file names (separated by ;)", "")
        if st.button("Classify", type="primary"):
            email = make_email(
                email_id="manual-entry", source="dashboard", sender=sender, reply_to=reply_to, subject=subject,
                body=body, auth={"spf": spf, "dkim": dkim, "dmarc": dmarc},
                attachments=attachments_from_names(attachments), max_body_chars=classifier.max_body_chars,
            )

    if email is not None:
        show_result(classifier.classify_safe(email))
        with st.expander("Email preview (plain text, links disabled)"):
            st.text(f"From: {email.from_raw}\nReply-To: {email.reply_to_addr}\nSubject: {email.subject}\n\n"
                    f"{(email.body_text or email.body_html)[:5000]}")

# ----------------------------------------------------------------------------- batch scan

with tab_batch:
    st.markdown(
        "Upload a **CSV** (columns: `subject`, `body`, optional `sender`, `reply_to`, `label`, `spf`, `dkim`, "
        "`dmarc`, `attachments`, `id`) and/or several **.eml** files. Try `data/sample_emails.csv`."
    )
    files = st.file_uploader("Files", type=["csv", "eml"], accept_multiple_files=True, key="batch_files")
    run_col, bench_col = st.columns([1, 1])
    run = run_col.button("Run async scan", type="primary", disabled=not files)
    run_bench = bench_col.button("Measure performance", disabled=not files)

    if run or run_bench:
        emails: list[ParsedEmail] = []
        problems: list[str] = []
        for f in files:
            data = f.getvalue()
            try:
                if f.name.lower().endswith(".csv"):
                    rows, errs = parse_csv_bytes(data, source=f.name, max_body_chars=classifier.max_body_chars)
                    emails.extend(rows)
                    problems.extend(errs)
                else:
                    emails.append(parse_eml_bytes(data, source=f.name, email_id=f.name.rsplit(".", 1)[0],
                                                  max_body_chars=classifier.max_body_chars))
            except EmailParseError as exc:
                problems.append(str(exc))
        for p in problems:
            st.warning(p)
        if not emails:
            st.error("No usable emails found in the uploaded files.")
        elif run:
            bar = st.progress(0.0, text="Scanning…")
            results, stats = AsyncScanner(classifier, concurrency).scan_sync(
                emails, progress=lambda done, total: bar.progress(done / total, text=f"Scanned {done}/{total}")
            )
            bar.empty()
            st.session_state["batch"] = {
                "results": results, "stats": stats.to_dict(), "problems": problems,
            }
        else:
            with st.spinner("Benchmarking…"):
                rows = benchmark(classifier, emails, copies=max(1, 300 // len(emails)),
                                 concurrency_levels=(1, 4, 8, 16))
            st.dataframe(pd.DataFrame(rows), hide_index=True)
            st.caption("Measured wall-clock results. Classification is CPU-bound, so asyncio mainly provides "
                       "bounded concurrency and responsiveness rather than guaranteed speed-ups.")

    batch = st.session_state.get("batch")
    if batch:
        results: list[ClassificationResult] = batch["results"]
        summary = summarize(results)
        m = st.columns(5)
        m[0].metric("Emails", summary["total"])
        for col, label in zip(m[1:4], LABELS):
            col.metric(label.capitalize(), summary["by_label"].get(label, 0))
        m[4].metric("Errors", summary["errors"])
        st.caption(f"Scan time {batch['stats']['elapsed_seconds']}s, {batch['stats']['throughput_per_sec']} emails/s, "
                   f"concurrency {batch['stats']['concurrency']}.")

        wanted = st.multiselect("Filter by predicted label", list(LABELS) + ["error"], default=list(LABELS) + ["error"])
        shown = [r for r in results if r.label in wanted]
        st.dataframe(results_to_frame(shown), hide_index=True)

        choice = st.selectbox("Inspect an email", [r.email_id for r in results])
        picked = next((r for r in results if r.email_id == choice), None)
        if picked:
            show_result(picked)

        metrics = evaluate_results(results)
        if metrics:
            st.subheader("Evaluation (against the uploaded labels)")
            k = st.columns(4)
            k[0].metric("Accuracy", f"{metrics.accuracy:.3f}")
            k[1].metric("Macro precision", f"{metrics.macro_avg['precision']:.3f}")
            k[2].metric("Macro recall", f"{metrics.macro_avg['recall']:.3f}")
            k[3].metric("Macro F1", f"{metrics.macro_avg['f1']:.3f}")
            st.dataframe(
                pd.DataFrame(
                    {label: {"precision": c.precision, "recall": c.recall, "f1": c.f1, "support": c.support}
                     for label, c in metrics.per_class.items()}
                ).T.round(3),
            )
            st.markdown("**Confusion matrix** (rows = true, columns = predicted)")
            st.dataframe(pd.DataFrame(metrics.confusion_matrix, index=metrics.labels, columns=metrics.labels))
            st.caption("Small synthetic datasets give optimistic numbers — see docs/evaluation_and_limitations.md.")
        else:
            metrics = None

        d1, d2 = st.columns(2)
        d1.download_button("Download CSV report", csv_bytes(results), "classification_report.csv", "text/csv")
        d2.download_button(
            "Download JSON report",
            json.dumps(build_json_report(results, metrics=metrics, scan_stats=batch["stats"],
                                         parse_errors=batch["problems"]), indent=2, ensure_ascii=False),
            "classification_report.json", "application/json",
        )

# ----------------------------------------------------------------------------- rules

with tab_rules:
    cfg = load_config()
    st.markdown("Rules are defined in `config/rules.json`. Positive weights add risk, negative weights mitigate it. "
                "The engine evaluates rules **greedily** (largest |weight| first) and stops early once a score "
                f"reaches {cfg['greedy']['decisive_score']}.")
    st.dataframe(
        pd.DataFrame(
            [{"id": r["id"], "name": r["name"], "applies to": r["category"], "weight (cap)": r["weight"],
              "per hit": r.get("per_hit", ""), "feature": r["condition"]["feature"],
              "description": r.get("description", "")} for r in cfg["rules"]]
        ),
        hide_index=True,
    )
