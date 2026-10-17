"""Shared dataclasses used across the pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

LABELS: tuple[str, ...] = ("legitimate", "spam", "phishing")
ERROR_LABEL = "error"


@dataclass
class Attachment:
    """Metadata about an attachment. The content is never stored or executed."""

    filename: str
    content_type: str = "application/octet-stream"
    size: int = 0


@dataclass
class ParsedEmail:
    """Normalised representation of an email, from either an .eml file or a CSV row."""

    email_id: str
    source: str
    from_raw: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to_addr: str = ""
    return_path_addr: str = ""
    message_id: str = ""
    subject: str = ""
    body_text: str = ""
    body_html: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    # SPF / DKIM / DMARC results: pass, fail, softfail, neutral, none, ... or "missing"
    auth: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    true_label: Optional[str] = None  # ground truth, when known


@dataclass
class RuleMatch:
    """A rule that fired for one email, with the evidence that triggered it."""

    rule_id: str
    name: str
    category: str  # phishing | spam | both
    weight: float  # contribution applied to each targeted category (may be negative)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ClassificationResult:
    """Outcome of classifying one email."""

    email_id: str
    source: str
    sender: str
    subject: str
    label: str
    risk_score: float
    phishing_score: float
    spam_score: float
    matches: list[RuleMatch] = field(default_factory=list)
    explanation: str = ""
    true_label: Optional[str] = None
    elapsed_ms: float = 0.0
    early_exit: bool = False
    rules_evaluated: int = 0
    features: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["matches"] = [m.to_dict() for m in self.matches]
        return d
