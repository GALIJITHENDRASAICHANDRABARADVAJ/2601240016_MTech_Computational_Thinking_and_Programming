"""Parsing of emails from ``.eml`` files, directories of ``.eml`` files and CSV datasets.

Security notes
--------------
* Attachments are only inspected for *metadata* (file name, MIME type, size). Their content is
  never written to disk, opened or executed.
* No network access happens here or anywhere else in the pipeline.
"""

from __future__ import annotations

import csv
import io
import mimetypes
import re
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Any, Optional, Union

from .models import LABELS, Attachment, ParsedEmail

DEFAULT_MAX_BODY_CHARS = 500_000
MAX_EML_BYTES = 25 * 1024 * 1024

csv.field_size_limit(10_000_000)


class EmailParseError(Exception):
    """Raised when an input cannot be parsed into an email."""


# --------------------------------------------------------------------------- labels

_LABEL_ALIASES = {
    "spam": "spam",
    "junk": "spam",
    "phishing": "phishing",
    "phish": "phishing",
    "legitimate": "legitimate",
    "legit": "legitimate",
    "ham": "legitimate",
    "benign": "legitimate",
    "safe": "legitimate",
    "not spam": "legitimate",
}


def normalize_label(value: Optional[str]) -> Optional[str]:
    """Map a free-form label to one of LABELS. Empty values give None; unknown values raise."""
    if value is None:
        return None
    cleaned = str(value).strip().lower().replace("_", " ").replace("-", " ")
    if not cleaned:
        return None
    if cleaned in _LABEL_ALIASES:
        return _LABEL_ALIASES[cleaned]
    raise EmailParseError(f"Unknown label {value!r}; expected one of {', '.join(LABELS)}")


def _infer_label_from_filename(stem: str) -> Optional[str]:
    """``phishing_paypal.eml`` -> phishing, ``legit-01.eml`` -> legitimate, otherwise None."""
    match = re.match(r"(?i)^(phishing|phish|spam|legitimate|legit|ham)(?![a-z])", stem)
    return normalize_label(match.group(1)) if match else None


# --------------------------------------------------------------------------- helpers

_KNOWN_AUTH = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy", "missing"}
_AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)")
_HTML_RE = re.compile(r"<\s*(?:html|body|a\s|form|input|div|p|table|br)\b", re.IGNORECASE)


def _normalize_auth(value: Optional[str]) -> str:
    v = (value or "").strip().lower()
    if not v:
        return "missing"
    return v if v in _KNOWN_AUTH else "unknown"


def _split_addr(value: Optional[str]) -> tuple[str, str]:
    """Return (display name, lower-cased address) from a header value."""
    name, addr = parseaddr(value or "")
    return name.strip(), addr.strip().lower()


def _looks_like_html(text: str) -> bool:
    return bool(_HTML_RE.search(text))


def make_email(
    *,
    email_id: str,
    source: str,
    sender: str = "",
    reply_to: str = "",
    return_path: str = "",
    subject: str = "",
    body: str = "",
    auth: Optional[dict[str, str]] = None,
    attachments: Optional[list[Attachment]] = None,
    headers: Optional[dict[str, str]] = None,
    message_id: str = "",
    true_label: Optional[str] = None,
    max_body_chars: int = DEFAULT_MAX_BODY_CHARS,
) -> ParsedEmail:
    """Build a ParsedEmail from plain fields (used by the CSV loader and the dashboard form)."""
    name, addr = _split_addr(sender)
    _, reply_addr = _split_addr(reply_to)
    _, rpath_addr = _split_addr(return_path)
    body = (body or "")[:max_body_chars]
    is_html = _looks_like_html(body)
    merged_auth = {"spf": "missing", "dkim": "missing", "dmarc": "missing"}
    for key, value in (auth or {}).items():
        if key in merged_auth:
            merged_auth[key] = _normalize_auth(value)
    return ParsedEmail(
        email_id=email_id,
        source=source,
        from_raw=sender or "",
        from_name=name,
        from_addr=addr,
        reply_to_addr=reply_addr,
        return_path_addr=rpath_addr,
        message_id=(message_id or "").strip(),
        subject=(subject or "").strip(),
        body_text="" if is_html else body,
        body_html=body if is_html else "",
        attachments=list(attachments or []),
        auth=merged_auth,
        headers=dict(headers or {}),
        true_label=normalize_label(true_label),
    )


# --------------------------------------------------------------------------- .eml

def _part_text(part: Message) -> str:
    try:
        content = part.get_content()  # type: ignore[attr-defined]
        return content if isinstance(content, str) else ""
    except Exception:  # unknown charset, broken encoding, ...
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else ""


def _extract_auth(msg: Message) -> dict[str, str]:
    auth = {"spf": "missing", "dkim": "missing", "dmarc": "missing"}
    try:
        for header in msg.get_all("authentication-results", []) or []:
            for match in _AUTH_RE.finditer(str(header)):
                mech, result = match.group(1).lower(), match.group(2)
                if auth[mech] == "missing":
                    auth[mech] = _normalize_auth(result)
        received_spf = str(msg.get("received-spf", "") or "").strip()
        if received_spf and auth["spf"] == "missing":
            auth["spf"] = _normalize_auth(received_spf.split()[0])
    except Exception:
        pass
    return auth


def _header(msg: Message, name: str) -> str:
    try:
        value = msg.get(name)
        return "" if value is None else str(value).strip()
    except Exception:
        return ""


def parse_eml_bytes(
    data: bytes,
    *,
    source: str = "<bytes>",
    email_id: Optional[str] = None,
    true_label: Optional[str] = None,
    max_body_chars: int = DEFAULT_MAX_BODY_CHARS,
) -> ParsedEmail:
    """Parse raw RFC 5322 message bytes into a ParsedEmail."""
    if not data or not data.strip():
        raise EmailParseError(f"{source}: empty message")
    if len(data) > MAX_EML_BYTES:
        raise EmailParseError(f"{source}: message larger than {MAX_EML_BYTES // (1024 * 1024)} MB")
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data)
    except Exception as exc:  # pragma: no cover - the stdlib parser is very tolerant
        raise EmailParseError(f"{source}: cannot parse message ({exc})") from exc
    if not msg.keys():
        raise EmailParseError(f"{source}: no email headers found")

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        try:
            filename = part.get_filename()
        except Exception:
            filename = None
        ctype = part.get_content_type()
        try:
            disposition = part.get_content_disposition()
        except Exception:
            disposition = None
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True)
            size = len(payload) if isinstance(payload, bytes) else 0
            attachments.append(Attachment(filename=str(filename or "(unnamed)"), content_type=ctype, size=size))
        elif ctype == "text/plain":
            text_parts.append(_part_text(part))
        elif ctype == "text/html":
            html_parts.append(_part_text(part))

    headers: dict[str, str] = {}
    try:
        for key in msg.keys():
            headers.setdefault(key.lower(), _header(msg, key)[:1000])
    except Exception:
        pass

    from_raw = _header(msg, "from")
    name, addr = _split_addr(from_raw)
    _, reply_addr = _split_addr(_header(msg, "reply-to"))
    _, rpath_addr = _split_addr(_header(msg, "return-path"))
    return ParsedEmail(
        email_id=email_id or source,
        source=source,
        from_raw=from_raw,
        from_name=name,
        from_addr=addr,
        reply_to_addr=reply_addr,
        return_path_addr=rpath_addr,
        message_id=_header(msg, "message-id"),
        subject=_header(msg, "subject"),
        body_text="\n".join(text_parts)[:max_body_chars],
        body_html="\n".join(html_parts)[:max_body_chars],
        attachments=attachments,
        auth=_extract_auth(msg),
        headers=headers,
        true_label=normalize_label(true_label),
    )


def parse_eml_file(path: Union[str, Path], *, max_body_chars: int = DEFAULT_MAX_BODY_CHARS) -> ParsedEmail:
    """Parse one ``.eml`` file. A label is inferred from the file-name prefix (e.g. ``spam_x.eml``)."""
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise EmailParseError(f"{p}: cannot read file ({exc})") from exc
    return parse_eml_bytes(
        data,
        source=str(p),
        email_id=p.stem,
        true_label=_infer_label_from_filename(p.stem),
        max_body_chars=max_body_chars,
    )


# --------------------------------------------------------------------------- CSV

_COLUMN_ALIASES: dict[str, tuple[str, ...]] = {
    "id": ("id", "email_id", "uid"),
    "label": ("label", "category", "class", "true_label"),
    "sender": ("sender", "from", "from_addr", "from_address"),
    "reply_to": ("reply_to", "replyto"),
    "return_path": ("return_path", "returnpath"),
    "message_id": ("message_id", "messageid"),
    "subject": ("subject", "title"),
    "body": ("body", "text", "content", "message", "email_text"),
    "spf": ("spf",),
    "dkim": ("dkim",),
    "dmarc": ("dmarc",),
    "attachments": ("attachments", "attachment", "attachment_names"),
}


def _canonical(name: str) -> str:
    return re.sub(r"[\s\-]+", "_", (name or "").strip().lower())


def _resolve_columns(fieldnames: list[str]) -> dict[str, str]:
    by_canonical = {_canonical(f): f for f in fieldnames if f}
    resolved: dict[str, str] = {}
    for canon, aliases in _COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in by_canonical:
                resolved[canon] = by_canonical[alias]
                break
    return resolved


def attachments_from_names(cell: str) -> list[Attachment]:
    result = []
    for name in re.split(r"[;|]", cell or ""):
        name = name.strip()
        if name:
            ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
            result.append(Attachment(filename=name, content_type=ctype, size=0))
    return result


def parse_csv_text(
    text: str,
    *,
    source: str = "<csv>",
    max_body_chars: int = DEFAULT_MAX_BODY_CHARS,
) -> tuple[list[ParsedEmail], list[str]]:
    """Parse CSV text into emails. Returns (emails, per-row error messages).

    Recognised columns (case-insensitive, aliases in parentheses): id, label (category), sender (from),
    reply_to, return_path, message_id, subject, body (text/content), spf, dkim, dmarc, attachments.
    At least a ``subject`` or ``body`` column is required.
    """
    stem = Path(source).stem if source and not source.startswith("<") else "csv"
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""))
        fieldnames = reader.fieldnames or []
    except csv.Error as exc:
        raise EmailParseError(f"{source}: invalid CSV ({exc})") from exc
    cols = _resolve_columns(list(fieldnames))
    if "subject" not in cols and "body" not in cols:
        raise EmailParseError(
            f"{source}: CSV needs a 'subject' and/or 'body' column (found: {', '.join(fieldnames) or 'none'})"
        )

    def cell(row: dict[str, Any], key: str) -> str:
        column = cols.get(key)
        value = row.get(column) if column else None
        return value if isinstance(value, str) else ""

    emails: list[ParsedEmail] = []
    errors: list[str] = []
    row_number = 1  # header is row 1
    try:
        for row in reader:
            row_number += 1
            try:
                subject, body, sender = cell(row, "subject"), cell(row, "body"), cell(row, "sender")
                if not (subject.strip() or body.strip() or sender.strip()):
                    raise EmailParseError("row is empty")
                emails.append(
                    make_email(
                        email_id=cell(row, "id").strip() or f"{stem}-row{row_number}",
                        source=f"{source}#row{row_number}",
                        sender=sender,
                        reply_to=cell(row, "reply_to"),
                        return_path=cell(row, "return_path"),
                        message_id=cell(row, "message_id"),
                        subject=subject,
                        body=body,
                        auth={k: cell(row, k) for k in ("spf", "dkim", "dmarc")},
                        attachments=attachments_from_names(cell(row, "attachments")),
                        true_label=cell(row, "label"),
                        max_body_chars=max_body_chars,
                    )
                )
            except EmailParseError as exc:
                errors.append(f"{source} row {row_number}: {exc}")
    except csv.Error as exc:
        errors.append(f"{source} row {row_number + 1}: CSV error ({exc})")
    return emails, errors


def parse_csv_bytes(
    data: bytes, *, source: str = "<csv>", max_body_chars: int = DEFAULT_MAX_BODY_CHARS
) -> tuple[list[ParsedEmail], list[str]]:
    return parse_csv_text(data.decode("utf-8-sig", errors="replace"), source=source, max_body_chars=max_body_chars)


def parse_csv(
    path: Union[str, Path], *, max_body_chars: int = DEFAULT_MAX_BODY_CHARS
) -> tuple[list[ParsedEmail], list[str]]:
    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise EmailParseError(f"{p}: cannot read file ({exc})") from exc
    return parse_csv_bytes(data, source=str(p), max_body_chars=max_body_chars)


# --------------------------------------------------------------------------- dispatcher

def load_emails(
    path: Union[str, Path], *, max_body_chars: int = DEFAULT_MAX_BODY_CHARS
) -> tuple[list[ParsedEmail], list[str]]:
    """Load emails from a ``.eml`` file, a ``.csv`` file, or a directory containing ``.eml`` files.

    Returns ``(emails, errors)``. Problems with individual files or rows are collected in ``errors``;
    problems that make the whole input unusable raise :class:`EmailParseError`.
    """
    p = Path(path)
    if not p.exists():
        raise EmailParseError(f"Path does not exist: {p}")
    if p.is_dir():
        files = sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() == ".eml")
        if not files:
            raise EmailParseError(f"No .eml files found in directory: {p}")
        emails, errors = [], []
        for f in files:
            try:
                emails.append(parse_eml_file(f, max_body_chars=max_body_chars))
            except EmailParseError as exc:
                errors.append(str(exc))
        return emails, errors
    suffix = p.suffix.lower()
    if suffix == ".eml":
        return [parse_eml_file(p, max_body_chars=max_body_chars)], []
    if suffix == ".csv":
        return parse_csv(p, max_body_chars=max_body_chars)
    raise EmailParseError(f"Unsupported input type {suffix or '(none)'!r}: use .eml, .csv or a directory of .eml files")
