"""Header and content feature extraction.

All analysis is purely static string/URL analysis. URLs are **never** resolved, fetched or opened,
no DNS lookups are made, and attachments are judged by file name only.
"""

from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

from .models import ParsedEmail

# Public-suffix approximation: enough for the demo without shipping the full PSL.
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "net.in", "org.in",
    "co.jp", "com.br", "co.nz", "co.za", "com.cn", "com.mx",
}

_URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'\])}]+)""")
_DOMAIN_IN_TEXT_RE = re.compile(r"(?i)(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?")
_CURRENCY_RE = re.compile(
    r"(?i)(?:[$€£₹]\s?\d[\d,]*(?:\.\d+)?|\b\d[\d,]*(?:\.\d+)?\s?(?:usd|eur|gbp|inr|dollars)\b)"
)
_UNSUBSCRIBE_RE = re.compile(r"(?i)\bunsubscribe\b")
_LEET_SINGLE = {"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
_MAX_EXAMPLES = 5


# --------------------------------------------------------------------------- domain helpers

def is_ip_host(host: str) -> bool:
    """True for IPv4/IPv6 literals and for decimal / hexadecimal integer hosts (e.g. http://3232235777/)."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    return bool(re.fullmatch(r"\d{8,10}", host) or re.fullmatch(r"0x[0-9a-f]{6,8}", host, re.IGNORECASE))


def registered_domain(host: str) -> str:
    """Approximate the registrable domain (``a.b.example.co.uk`` -> ``example.co.uk``)."""
    host = (host or "").strip().strip(".").lower()
    if not host or is_ip_host(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return last_two


def tld_of(host: str) -> str:
    host = (host or "").strip(".").lower()
    return host.rsplit(".", 1)[-1] if "." in host else ""


def _domain_matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _normalise_variants(text: str) -> list[str]:
    """Undo common look-alike substitutions (paypa1 -> paypal, micr0soft -> microsoft)."""
    base = text.lower()
    variants = []
    for one in ("l", "i"):  # the digit 1 can stand in for either letter
        t = base.replace("1", one)
        t = "".join(_LEET_SINGLE.get(ch, ch) for ch in t)
        t = t.replace("rn", "m").replace("vv", "w")
        variants.append(t)
    return list(dict.fromkeys(variants + [base]))


# --------------------------------------------------------------------------- HTML inspection

class _HTMLInspector(HTMLParser):
    """Collects visible text, links (href + anchor text) and form details from an HTML body."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self.has_form = False
        self.has_password_input = False
        self._skip = 0
        self._href: Optional[str] = None
        self._anchor_text: list[str] = []

    def _finish_link(self) -> None:
        if self._href is not None:
            self.links.append((self._href, " ".join("".join(self._anchor_text).split())))
        self._href = None
        self._anchor_text = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._finish_link()
            self._href = attr.get("href", "")
        elif tag == "form":
            self.has_form = True
        elif tag == "input" and attr.get("type", "").lower() == "password":
            self.has_password_input = True
        elif tag in ("br", "p", "div", "tr", "li"):
            self.text_parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        elif tag == "a":
            self._finish_link()

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._anchor_text.append(data)

    @property
    def text(self) -> str:
        return re.sub(r"[ \t]+", " ", "".join(self.text_parts)).strip()


def inspect_html(html: str) -> _HTMLInspector:
    parser = _HTMLInspector()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # malformed markup: keep whatever was collected
        pass
    parser._finish_link()
    return parser


# --------------------------------------------------------------------------- extractor

def _compile_phrases(phrases: Iterable[str]) -> Optional[re.Pattern[str]]:
    items = sorted({p.strip().lower() for p in phrases if p and p.strip()}, key=len, reverse=True)
    if not items:
        return None
    return re.compile(r"(?<!\w)(?:" + "|".join(re.escape(p) for p in items) + r")(?!\w)", re.IGNORECASE)


def _find_phrases(rx: Optional[re.Pattern[str]], text: str) -> list[str]:
    if rx is None:
        return []
    return list(dict.fromkeys(m.group(0).lower() for m in rx.finditer(text)))


class FeatureExtractor:
    """Turns a :class:`ParsedEmail` into a flat feature dictionary consumed by the scoring engine."""

    def __init__(self, config: dict[str, Any]) -> None:
        lex, ind = config["lexicons"], config["indicators"]
        self._rx = {name: _compile_phrases(phrases) for name, phrases in lex.items()}
        self._shorteners = {d.lower() for d in ind["url_shorteners"]}
        self._bad_tlds = {t.lower().lstrip(".") for t in ind["suspicious_tlds"]}
        self._free_mail = {d.lower() for d in ind["free_mail_domains"]}
        self._dangerous = {e.lower().lstrip(".") for e in ind["dangerous_extensions"]}
        self._macro = {e.lower().lstrip(".") for e in ind["macro_extensions"]}
        self._html_ext = {e.lower().lstrip(".") for e in ind["html_extensions"]}
        self._archive = {e.lower().lstrip(".") for e in ind["archive_extensions"]}
        self._exec_rx = _compile_phrases(ind["executive_titles"])
        doc_ext = "pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|zip|rar|csv"
        self._double_ext_rx = re.compile(
            r"(?i)\.(?:" + doc_ext + r")\.(?:" + "|".join(re.escape(e) for e in sorted(self._dangerous)) + r")$"
        )
        self._brands = []
        for brand in config["brands"]:
            keywords = [k.lower() for k in brand["keywords"]]
            self._brands.append(
                {
                    "name": brand["name"],
                    "keywords": keywords,
                    "domains": [d.lower() for d in brand["domains"]],
                    "name_rx": _compile_phrases(keywords),
                }
            )

    # ---- brand helpers -------------------------------------------------------

    def _is_brand_domain(self, host: str, brand: dict[str, Any]) -> bool:
        return any(_domain_matches(host, d) for d in brand["domains"])

    def find_brand_in_host(self, host: str) -> str:
        """Return the brand name imitated by ``host`` (including look-alikes), or ''.

        Keywords of 6+ characters are matched as substrings of the normalised host; shorter keywords
        (e.g. 'apple', 'dhl', 'chase') must match a whole dot/hyphen-separated token to limit false
        positives such as 'purchase' containing 'chase'.
        """
        host = (host or "").lower().strip(".")
        if not host or is_ip_host(host):
            return ""
        for variant in _normalise_variants(host):
            tokens = [t for t in re.split(r"[^a-z0-9]+", variant) if t]
            squashed = re.sub(r"[^a-z0-9]", "", variant)
            for brand in self._brands:
                if self._is_brand_domain(host, brand):
                    continue
                for kw in brand["keywords"]:
                    kw_squashed = kw.replace(" ", "")
                    if len(kw_squashed) >= 6:
                        if kw_squashed in squashed:
                            return brand["name"]
                    elif kw_squashed in tokens:
                        return brand["name"]
        return ""

    def _display_name_brand(self, from_name: str, from_domain: str) -> str:
        if not from_name or not from_domain:
            return ""
        for brand in self._brands:
            if brand["name_rx"] is None or not brand["name_rx"].search(from_name):
                continue
            if not self._is_brand_domain(from_domain, brand):
                return brand["name"]
        return ""

    # ---- URL analysis ---------------------------------------------------------

    def _analyse_url(self, raw: str) -> dict[str, Any]:
        flags: list[str] = []
        host = ""
        try:
            parts = urlsplit(raw if "://" in raw else "http://" + raw)
            host = (parts.hostname or "").lower().rstrip(".")
            netloc = parts.netloc
        except ValueError:
            return {"url": raw, "host": "", "flags": ["malformed"], "brand": ""}
        if is_ip_host(host):
            flags.append("ip_host")
        if "@" in netloc:
            flags.append("at_symbol")
        if "xn--" in host:
            flags.append("punycode")
        reg = registered_domain(host)
        if host in self._shorteners or reg in self._shorteners:
            flags.append("shortener")
        if host and not is_ip_host(host) and tld_of(host) in self._bad_tlds:
            flags.append("suspicious_tld")
        if len([label for label in host.split(".") if label]) >= 5:
            flags.append("many_subdomains")
        if host.count("-") >= 3:
            flags.append("excess_hyphens")
        brand = self.find_brand_in_host(host)
        if brand:
            flags.append("brand_mismatch")
        return {"url": raw, "host": host, "flags": flags, "brand": brand}

    @staticmethod
    def _clean_url(url: str) -> str:
        return url.rstrip(".,;:!?)'\"")

    def _collect_urls(self, text: str, links: list[tuple[str, str]]) -> list[str]:
        found: list[str] = []
        for match in _URL_RE.finditer(text):
            found.append(self._clean_url(match.group(1)))
        for href, _ in links:
            href = (href or "").strip()
            if href.lower().startswith(("http://", "https://")):
                found.append(self._clean_url(href))
        return list(dict.fromkeys(u for u in found if u))

    # ---- attachments ------------------------------------------------------------

    @staticmethod
    def _extension(filename: str) -> str:
        name = filename.strip().lower()
        return name.rsplit(".", 1)[-1] if "." in name else ""

    # ---- main entry point ----------------------------------------------------------

    def extract(self, email: ParsedEmail) -> dict[str, Any]:
        f: dict[str, Any] = {}

        # --- sender / header features
        from_addr = email.from_addr or ""
        from_domain = from_addr.rsplit("@", 1)[-1] if "@" in from_addr else ""
        from_reg = registered_domain(from_domain)
        reply_domain = email.reply_to_addr.rsplit("@", 1)[-1] if "@" in (email.reply_to_addr or "") else ""
        rpath_domain = email.return_path_addr.rsplit("@", 1)[-1] if "@" in (email.return_path_addr or "") else ""
        mid = (email.message_id or "").strip().strip("<>")
        mid_domain = mid.rsplit("@", 1)[-1].lower() if "@" in mid else ""

        f["from_name"] = email.from_name
        f["from_addr"] = from_addr
        f["from_domain"] = from_domain
        f["reply_to_addr"] = email.reply_to_addr
        f["reply_to_domain"] = reply_domain
        f["reply_to_mismatch"] = bool(
            reply_domain and from_reg and registered_domain(reply_domain) != from_reg
        )
        f["return_path_mismatch"] = bool(rpath_domain and from_reg and registered_domain(rpath_domain) != from_reg)
        f["message_id_domain_mismatch"] = bool(mid_domain and from_reg and registered_domain(mid_domain) != from_reg)
        f["sender_free_mail"] = from_reg in self._free_mail
        f["sender_suspicious_tld"] = bool(from_domain and tld_of(from_domain) in self._bad_tlds)
        f["display_name_brand_mismatch"] = self._display_name_brand(email.from_name, from_domain)
        f["lookalike_brand_domain"] = self.find_brand_in_host(from_domain)
        f["executive_free_mail"] = bool(
            f["sender_free_mail"] and self._exec_rx is not None and self._exec_rx.search(email.from_name or "")
        )

        # --- authentication results
        auth = {k: (email.auth or {}).get(k, "missing") for k in ("spf", "dkim", "dmarc")}
        f.update({k: v for k, v in auth.items()})
        f["auth_fail_count"] = sum(1 for v in auth.values() if v in ("fail", "softfail", "permerror"))
        f["auth_pass_count"] = sum(1 for v in auth.values() if v == "pass")
        f["auth_present"] = any(v != "missing" for v in auth.values())
        f["auth_summary"] = ", ".join(f"{k}={v}" for k, v in auth.items())

        # --- content
        html = inspect_html(email.body_html) if email.body_html else None
        html_text = html.text if html else ""
        body_text = email.body_text if email.body_text.strip() else html_text
        content = " ".join(body_text.split())
        analysed = f"{email.subject} {content}"
        letters = [c for c in analysed if c.isalpha()]
        subject_letters = [c for c in email.subject if c.isalpha()]

        f["subject"] = email.subject
        f["subject_empty"] = not email.subject.strip()
        f["body_length"] = len(body_text)
        f["caps_ratio"] = round(sum(c.isupper() for c in letters) / len(letters), 3) if len(letters) >= 20 else 0.0
        f["subject_caps_ratio"] = (
            round(sum(c.isupper() for c in subject_letters) / len(subject_letters), 3)
            if len(subject_letters) >= 8
            else 0.0
        )
        f["exclamation_count"] = analysed.count("!")
        f["currency_amount_count"] = len(_CURRENCY_RE.findall(analysed))
        f["has_unsubscribe"] = bool(
            "list-unsubscribe" in (email.headers or {}) or _UNSUBSCRIBE_RE.search(content)
        )
        for key, label in (
            ("spam_keywords", "spam_keywords"),
            ("urgency_phrases", "urgency_phrases"),
            ("credential_requests", "credential_phrases"),
            ("threats", "threat_phrases"),
            ("financial_lures", "financial_lure_phrases"),
        ):
            hits = _find_phrases(self._rx.get(key), analysed)
            f[label] = hits
        f["spam_keyword_count"] = len(f["spam_keywords"])
        f["urgency_count"] = len(f["urgency_phrases"])
        f["credential_count"] = len(f["credential_phrases"])
        f["threat_count"] = len(f["threat_phrases"])
        f["financial_lure_count"] = len(f["financial_lure_phrases"])

        # --- URLs (static analysis only)
        links = html.links if html else []
        url_text = body_text if not html_text else f"{body_text}\n{html_text}"
        urls = self._collect_urls(f"{email.subject}\n{url_text}", links)
        analyses = [self._analyse_url(u) for u in urls]
        url_flags: dict[str, list[str]] = {}
        for a in analyses:
            for flag in a["flags"]:
                bucket = url_flags.setdefault(flag, [])
                label = a["host"] or a["url"]
                if label not in bucket and len(bucket) < _MAX_EXAMPLES:
                    bucket.append(label)
        f["urls"] = [a["url"] for a in analyses][:50]
        f["url_count"] = len(analyses)
        f["unique_url_domain_count"] = len({registered_domain(a["host"]) for a in analyses if a["host"]})
        f["url_flags"] = url_flags
        f["url_has_ip_host"] = "ip_host" in url_flags
        f["url_has_at_symbol"] = "at_symbol" in url_flags
        f["url_has_punycode"] = "punycode" in url_flags
        f["url_has_shortener"] = "shortener" in url_flags
        f["url_has_suspicious_tld"] = "suspicious_tld" in url_flags
        f["url_has_many_subdomains"] = "many_subdomains" in url_flags
        f["url_has_excess_hyphens"] = "excess_hyphens" in url_flags
        brands = list(dict.fromkeys(a["brand"] for a in analyses if a["brand"]))
        f["url_brand_mismatch"] = ", ".join(brands)

        # anchor text vs href mismatch
        mismatches: list[str] = []
        for href, anchor_text in links:
            if not href.lower().startswith(("http://", "https://")) or not anchor_text:
                continue
            try:
                href_host = (urlsplit(href).hostname or "").lower()
            except ValueError:
                continue
            m = _DOMAIN_IN_TEXT_RE.search(anchor_text)
            if not m or not href_host:
                continue
            shown = m.group(1).lower()
            if registered_domain(shown) != registered_domain(href_host):
                mismatches.append(f"text shows '{shown}' but link goes to '{href_host}'")
        f["anchor_mismatches"] = list(dict.fromkeys(mismatches))[:_MAX_EXAMPLES]
        f["anchor_mismatch_count"] = len(f["anchor_mismatches"])
        f["credential_request_with_link"] = bool(f["credential_count"] and f["url_count"])
        f["has_form"] = bool(html and html.has_form)
        f["has_password_form"] = bool(html and html.has_password_input)

        # --- attachments (metadata only)
        names = [a.filename for a in email.attachments]
        by_ext = {n: self._extension(n) for n in names}
        f["attachment_count"] = len(names)
        f["attachment_names"] = names[:20]
        f["dangerous_attachments"] = [n for n, e in by_ext.items() if e in self._dangerous]
        f["double_extension_attachments"] = [n for n in names if self._double_ext_rx.search(n.strip())]
        f["macro_attachments"] = [n for n, e in by_ext.items() if e in self._macro]
        f["html_attachments"] = [n for n, e in by_ext.items() if e in self._html_ext]
        f["archive_attachments"] = [n for n, e in by_ext.items() if e in self._archive]
        f["has_dangerous_attachment"] = bool(f["dangerous_attachments"])
        f["has_double_extension"] = bool(f["double_extension_attachments"])
        f["has_macro_attachment"] = bool(f["macro_attachments"])
        f["has_html_attachment"] = bool(f["html_attachments"])
        f["has_archive_attachment"] = bool(f["archive_attachments"])
        return f


def scalar_features(features: dict[str, Any]) -> dict[str, Any]:
    """Compact, JSON-friendly view of the features (scalars plus short lists), for reports."""
    out: dict[str, Any] = {}
    for key, value in features.items():
        if isinstance(value, (bool, int, float, str)) or value is None:
            out[key] = value
        elif isinstance(value, list):
            out[key] = value[:10]
        elif isinstance(value, dict):
            out[key] = {k: v[:_MAX_EXAMPLES] if isinstance(v, list) else v for k, v in value.items()}
    return out
