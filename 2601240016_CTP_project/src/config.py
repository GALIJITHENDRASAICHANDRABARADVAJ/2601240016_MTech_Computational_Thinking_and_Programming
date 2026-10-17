"""Loading and validation of the JSON rule configuration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional, Union

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "rules.json"

VALID_CATEGORIES = {"phishing", "spam", "both"}
VALID_OPS = {"true", "gte", "eq", "in"}
REQUIRED_LEXICONS = ("spam_keywords", "urgency_phrases", "credential_requests", "threats", "financial_lures")
REQUIRED_INDICATORS = (
    "url_shorteners",
    "suspicious_tlds",
    "free_mail_domains",
    "dangerous_extensions",
    "macro_extensions",
    "html_extensions",
    "archive_extensions",
    "executive_titles",
)


class ConfigError(ValueError):
    """Raised when the configuration file is missing or invalid."""


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def validate_config(cfg: Any) -> dict[str, Any]:
    """Validate a configuration dict and return it unchanged. Raises ConfigError."""
    if not isinstance(cfg, dict):
        raise ConfigError("Configuration root must be a JSON object.")

    thresholds = cfg.get("thresholds")
    if not isinstance(thresholds, dict):
        raise ConfigError("'thresholds' must be an object with 'phishing' and 'spam'.")
    for key in ("phishing", "spam"):
        value = thresholds.get(key)
        if not _is_number(value) or not 0 < value <= 100:
            raise ConfigError(f"thresholds.{key} must be a number in (0, 100].")

    greedy = cfg.get("greedy")
    if not isinstance(greedy, dict) or not _is_number(greedy.get("decisive_score")):
        raise ConfigError("'greedy.decisive_score' must be a number.")
    if greedy["decisive_score"] <= 0:
        raise ConfigError("'greedy.decisive_score' must be positive.")

    limits = cfg.get("limits", {})
    if not isinstance(limits, dict) or not _is_number(limits.get("max_body_chars", 1)) or limits.get("max_body_chars", 1) <= 0:
        raise ConfigError("'limits.max_body_chars' must be a positive number.")

    lexicons = cfg.get("lexicons")
    if not isinstance(lexicons, dict):
        raise ConfigError("'lexicons' must be an object.")
    for name in REQUIRED_LEXICONS:
        items = lexicons.get(name)
        if not isinstance(items, list) or not all(isinstance(x, str) and x.strip() for x in items):
            raise ConfigError(f"lexicons.{name} must be a list of non-empty strings.")

    indicators = cfg.get("indicators")
    if not isinstance(indicators, dict):
        raise ConfigError("'indicators' must be an object.")
    for name in REQUIRED_INDICATORS:
        items = indicators.get(name)
        if not isinstance(items, list) or not all(isinstance(x, str) for x in items):
            raise ConfigError(f"indicators.{name} must be a list of strings.")

    brands = cfg.get("brands")
    if not isinstance(brands, list):
        raise ConfigError("'brands' must be a list.")
    for i, brand in enumerate(brands):
        if not isinstance(brand, dict) or not brand.get("name"):
            raise ConfigError(f"brands[{i}] needs a 'name'.")
        for key in ("keywords", "domains"):
            if not isinstance(brand.get(key), list) or not brand[key]:
                raise ConfigError(f"brands[{i}].{key} must be a non-empty list.")

    rules = cfg.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ConfigError("'rules' must be a non-empty list.")
    seen: set[str] = set()
    for i, rule in enumerate(rules):
        where = f"rules[{i}]"
        if not isinstance(rule, dict):
            raise ConfigError(f"{where} must be an object.")
        rid = rule.get("id")
        if not isinstance(rid, str) or not rid:
            raise ConfigError(f"{where} needs a string 'id'.")
        if rid in seen:
            raise ConfigError(f"Duplicate rule id: {rid}")
        seen.add(rid)
        where = f"rule {rid}"
        if not rule.get("name"):
            raise ConfigError(f"{where} needs a 'name'.")
        if rule.get("category") not in VALID_CATEGORIES:
            raise ConfigError(f"{where}: category must be one of {sorted(VALID_CATEGORIES)}.")
        if not _is_number(rule.get("weight")):
            raise ConfigError(f"{where}: weight must be a number.")
        cond = rule.get("condition")
        if not isinstance(cond, dict) or not isinstance(cond.get("feature"), str):
            raise ConfigError(f"{where}: condition.feature must be a string.")
        op = cond.get("op")
        if op not in VALID_OPS:
            raise ConfigError(f"{where}: condition.op must be one of {sorted(VALID_OPS)}.")
        if op != "true" and "value" not in cond:
            raise ConfigError(f"{where}: condition.value is required for op '{op}'.")
        if op == "in" and not isinstance(cond["value"], list):
            raise ConfigError(f"{where}: condition.value must be a list for op 'in'.")
        if "per_hit" in rule:
            if not _is_number(rule["per_hit"]) or rule["per_hit"] <= 0:
                raise ConfigError(f"{where}: per_hit must be a positive number.")
            if rule["weight"] <= 0:
                raise ConfigError(f"{where}: per_hit requires a positive weight (the cap).")
    return cfg


def load_config(path: Optional[Union[str, Path]] = None) -> dict[str, Any]:
    """Load and validate a rule configuration file (defaults to config/rules.json)."""
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    try:
        with config_path.open("r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except FileNotFoundError as exc:
        raise ConfigError(f"Configuration file not found: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Configuration file is not valid JSON ({config_path}): {exc}") from exc
    return validate_config(cfg)
