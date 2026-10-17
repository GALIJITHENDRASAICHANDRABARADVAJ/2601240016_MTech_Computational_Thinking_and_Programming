"""Explainable email classifier: parsed email -> features -> rule scores -> label + explanation."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional, Union

from .config import load_config, validate_config
from .feature_extractor import FeatureExtractor, scalar_features
from .models import ERROR_LABEL, ClassificationResult, ParsedEmail, RuleMatch
from .scoring_engine import ScoringEngine


def decide_label(phishing_score: float, spam_score: float, thresholds: dict[str, float]) -> str:
    """Pick the label from the two category scores.

    A category is a candidate when its score reaches its threshold. If both are candidates the one
    with the higher score wins; an exact tie goes to phishing (the more severe class). If neither
    is a candidate the email is legitimate.
    """
    candidates: list[tuple[str, float]] = []
    if phishing_score >= thresholds["phishing"]:
        candidates.append(("phishing", phishing_score))
    if spam_score >= thresholds["spam"]:
        candidates.append(("spam", spam_score))
    if not candidates:
        return "legitimate"
    return max(candidates, key=lambda c: (c[1], c[0] == "phishing"))[0]


def build_explanation(
    label: str,
    risk: float,
    phishing: float,
    spam: float,
    matches: list[RuleMatch],
    thresholds: dict[str, float],
    early_exit: bool,
) -> str:
    lines = [
        f"Classified as {label.upper()} (risk score {risk:.1f}/100; phishing={phishing:.1f}, spam={spam:.1f}; "
        f"thresholds: phishing>={thresholds['phishing']:g}, spam>={thresholds['spam']:g})."
    ]
    if label == "legitimate":
        lines.append("Neither category reached its threshold.")
    if matches:
        lines.append("Matched rules (largest impact first):")
        for m in sorted(matches, key=lambda m: -abs(m.weight)):
            target = {"both": "phishing+spam"}.get(m.category, m.category)
            lines.append(f"  - [{m.rule_id}] {m.name}: {m.weight:+g} to {target} ({m.detail})")
    else:
        lines.append("No risk rules matched.")
    if early_exit:
        lines.append("Note: a decisive score was reached, so lower-weight rules were not evaluated (greedy early exit).")
    return "\n".join(lines)


class EmailClassifier:
    """Classifies :class:`ParsedEmail` objects as legitimate, spam or phishing.

    The instance is stateless after construction and safe to share between threads.
    """

    def __init__(
        self,
        config: Optional[dict[str, Any]] = None,
        config_path: Optional[Union[str, Path]] = None,
    ) -> None:
        self.config = validate_config(config) if config is not None else load_config(config_path)
        self.extractor = FeatureExtractor(self.config)
        self.engine = ScoringEngine(self.config)
        self.thresholds = {k: float(v) for k, v in self.config["thresholds"].items()}

    @property
    def max_body_chars(self) -> int:
        return int(self.config.get("limits", {}).get("max_body_chars", 500_000))

    def classify(self, email: ParsedEmail) -> ClassificationResult:
        """Classify one email. May raise on unexpected input; see :meth:`classify_safe`."""
        started = time.perf_counter()
        features = self.extractor.extract(email)
        outcome = self.engine.score(features)
        label = decide_label(outcome.phishing_score, outcome.spam_score, self.thresholds)
        risk = round(max(outcome.phishing_score, outcome.spam_score), 1)
        return ClassificationResult(
            email_id=email.email_id,
            source=email.source,
            sender=email.from_raw or email.from_addr,
            subject=email.subject,
            label=label,
            risk_score=risk,
            phishing_score=outcome.phishing_score,
            spam_score=outcome.spam_score,
            matches=outcome.matches,
            explanation=build_explanation(
                label, risk, outcome.phishing_score, outcome.spam_score, outcome.matches, self.thresholds, outcome.early_exit
            ),
            true_label=email.true_label,
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
            early_exit=outcome.early_exit,
            rules_evaluated=outcome.rules_evaluated,
            features=scalar_features(features),
        )

    def classify_safe(self, email: ParsedEmail) -> ClassificationResult:
        """Like :meth:`classify`, but a failure becomes a result with ``error`` set instead of raising."""
        try:
            return self.classify(email)
        except Exception as exc:  # noqa: BLE001 - one bad email must not abort a batch
            return ClassificationResult(
                email_id=getattr(email, "email_id", "?"),
                source=getattr(email, "source", "?"),
                sender=getattr(email, "from_raw", ""),
                subject=getattr(email, "subject", ""),
                label=ERROR_LABEL,
                risk_score=0.0,
                phishing_score=0.0,
                spam_score=0.0,
                explanation=f"Classification failed: {type(exc).__name__}: {exc}",
                true_label=getattr(email, "true_label", None),
                error=f"{type(exc).__name__}: {exc}",
            )
