"""Shared helpers for the test-suite."""

from __future__ import annotations

import copy
import sys
from email.message import EmailMessage
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config import load_config  # noqa: E402
from src.email_parser import make_email  # noqa: E402

SAMPLE_CSV = ROOT / "data" / "sample_emails.csv"
EML_DIR = ROOT / "data" / "eml_samples"


def default_config() -> dict[str, Any]:
    return copy.deepcopy(load_config())


def email(**kwargs: Any):
    """Shortcut for make_email with sensible defaults."""
    kwargs.setdefault("email_id", "t1")
    kwargs.setdefault("source", "test")
    return make_email(**kwargs)


def build_eml(
    *,
    sender: str = "Alice <alice@example.org>",
    subject: str = "Hello",
    text: str = "Hi there",
    html: str | None = None,
    reply_to: str | None = None,
    extra_headers: dict[str, str] | None = None,
    attachment: tuple[str, bytes] | None = None,
) -> bytes:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = "bob@example.net"
    msg["Subject"] = subject
    if reply_to:
        msg["Reply-To"] = reply_to
    for key, value in (extra_headers or {}).items():
        msg[key] = value
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    if attachment:
        msg.add_attachment(attachment[1], maintype="application", subtype="octet-stream", filename=attachment[0])
    return msg.as_bytes()
