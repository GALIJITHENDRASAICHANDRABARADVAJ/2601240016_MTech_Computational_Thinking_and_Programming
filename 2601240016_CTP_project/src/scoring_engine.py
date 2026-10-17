"""Configurable greedy rule-based scoring engine.

How the "greedy" strategy works
-------------------------------
1. All rules are sorted once, by ``|weight|`` descending (ties broken by rule id). The most
   influential evidence is therefore examined first.
2. Rules are evaluated in that order. Every rule that matches adds its contribution to the phishing
   score, the spam score, or both (``category``: ``phishing`` | ``spam`` | ``both``).
3. As soon as either running score reaches ``greedy.decisive_score`` (default 90) the engine stops
   ("early exit"): the verdict can no longer realistically be reversed by the remaining, smaller
   rules, so evaluating them only costs time. The result records ``early_exit`` and
   ``rules_evaluated`` so this is transparent. The trade-off: mitigating (negative) rules that
   would have been evaluated later are skipped on early exit.
4. Final scores are clamped to the range 0-100.

Rules with ``per_hit`` scale with the feature value: ``contribution = min(weight, per_hit * value)``,
so ``weight`` acts as a cap for that rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .models import RuleMatch


@dataclass
class Rule:
    rule_id: str
    name: str
    category: str
    weight: float
    feature: str
    op: str
    value: Any = None
    per_hit: Optional[float] = None
    evidence: Optional[str] = None
    description: str = ""

    @classmethod
    def from_config(cls, raw: dict[str, Any]) -> "Rule":
        cond = raw["condition"]
        return cls(
            rule_id=raw["id"],
            name=raw["name"],
            category=raw["category"],
            weight=float(raw["weight"]),
            feature=cond["feature"],
            op=cond["op"],
            value=cond.get("value"),
            per_hit=float(raw["per_hit"]) if raw.get("per_hit") is not None else None,
            evidence=raw.get("evidence"),
            description=raw.get("description", ""),
        )


@dataclass
class ScoreOutcome:
    phishing_score: float = 0.0
    spam_score: float = 0.0
    matches: list[RuleMatch] = field(default_factory=list)
    rules_evaluated: int = 0
    early_exit: bool = False


def resolve_path(features: dict[str, Any], path: str) -> Any:
    """Look up ``a`` or ``a.b`` in a nested feature dict; missing keys give None."""
    current: Any = features
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _format_evidence(value: Any) -> str:
    if value is None or value == "" or value == [] or value is False:
        return ""
    if isinstance(value, (list, tuple)):
        shown = ", ".join(str(v) for v in value[:5])
        return shown + (f" (+{len(value) - 5} more)" if len(value) > 5 else "")
    return str(value)


class ScoringEngine:
    """Evaluates the configured rules against a feature dictionary."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.rules: list[Rule] = sorted(
            (Rule.from_config(r) for r in config["rules"]),
            key=lambda r: (-abs(r.weight), r.rule_id),
        )
        self.decisive_score: float = float(config["greedy"]["decisive_score"])

    @staticmethod
    def _holds(rule: Rule, value: Any) -> bool:
        if rule.op == "true":
            return bool(value)
        if value is None:
            return False
        try:
            if rule.op == "gte":
                return float(value) >= float(rule.value)
            if rule.op == "eq":
                return value == rule.value
            if rule.op == "in":
                return value in rule.value
        except (TypeError, ValueError):
            return False
        return False

    @staticmethod
    def _contribution(rule: Rule, value: Any) -> float:
        if rule.per_hit is None:
            return rule.weight
        try:
            return min(rule.weight, rule.per_hit * float(value))
        except (TypeError, ValueError):
            return 0.0

    def score(self, features: dict[str, Any]) -> ScoreOutcome:
        out = ScoreOutcome()
        phishing = spam = 0.0
        for rule in self.rules:
            out.rules_evaluated += 1
            value = resolve_path(features, rule.feature)
            if not self._holds(rule, value):
                continue
            amount = self._contribution(rule, value)
            if rule.category in ("phishing", "both"):
                phishing += amount
            if rule.category in ("spam", "both"):
                spam += amount
            evidence = _format_evidence(resolve_path(features, rule.evidence)) if rule.evidence else ""
            detail = f"{rule.feature}={_format_evidence(value) if not isinstance(value, bool) else value}"
            if evidence and evidence != detail:
                detail += f" [{evidence}]"
            out.matches.append(
                RuleMatch(rule_id=rule.rule_id, name=rule.name, category=rule.category, weight=round(amount, 2), detail=detail)
            )
            if amount > 0 and max(phishing, spam) >= self.decisive_score:
                out.early_exit = rule is not self.rules[-1]
                break
        out.phishing_score = round(min(100.0, max(0.0, phishing)), 2)
        out.spam_score = round(min(100.0, max(0.0, spam)), 2)
        return out
