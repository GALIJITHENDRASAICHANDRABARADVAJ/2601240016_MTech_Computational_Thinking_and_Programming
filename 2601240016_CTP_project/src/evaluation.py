"""Evaluation metrics computed from labelled data: accuracy, precision, recall, F1, confusion matrix.

Implemented from scratch (no scikit-learn dependency). Convention: confusion-matrix rows are the
TRUE labels, columns are the PREDICTED labels, in the order given by ``labels``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional, Sequence

from .models import ERROR_LABEL, LABELS, ClassificationResult


@dataclass
class ClassMetrics:
    precision: float
    recall: float
    f1: float
    support: int


@dataclass
class EvaluationReport:
    labels: list[str]
    total: int
    accuracy: float
    per_class: dict[str, ClassMetrics]
    macro_avg: dict[str, float]
    weighted_avg: dict[str, float]
    confusion_matrix: list[list[int]]
    skipped: int = 0  # results ignored because they had no ground truth or failed
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    def format_text(self) -> str:
        w = max(len(label) for label in self.labels + ["weighted avg"]) + 2
        lines = [
            f"Samples evaluated: {self.total}   (skipped: {self.skipped})",
            f"Accuracy: {self.accuracy:.4f}",
            "",
            f"{'':<{w}}{'precision':>10}{'recall':>10}{'f1-score':>10}{'support':>10}",
        ]
        for label in self.labels:
            m = self.per_class[label]
            lines.append(f"{label:<{w}}{m.precision:>10.4f}{m.recall:>10.4f}{m.f1:>10.4f}{m.support:>10d}")
        for name, avg in (("macro avg", self.macro_avg), ("weighted avg", self.weighted_avg)):
            lines.append(f"{name:<{w}}{avg['precision']:>10.4f}{avg['recall']:>10.4f}{avg['f1']:>10.4f}{self.total:>10d}")
        lines += ["", "Confusion matrix (rows = true label, columns = predicted label):"]
        header = f"{'':<{w}}" + "".join(f"{label[:10]:>12}" for label in self.labels)
        lines.append(header)
        for label, row in zip(self.labels, self.confusion_matrix):
            lines.append(f"{label:<{w}}" + "".join(f"{v:>12d}" for v in row))
        return "\n".join(lines)


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def compute_metrics(
    y_true: Sequence[str],
    y_pred: Sequence[str],
    labels: Sequence[str] = LABELS,
) -> EvaluationReport:
    """Compute metrics for aligned lists of true and predicted labels."""
    if len(y_true) != len(y_pred):
        raise ValueError(f"y_true ({len(y_true)}) and y_pred ({len(y_pred)}) must have the same length")
    label_list = list(labels)
    index = {label: i for i, label in enumerate(label_list)}
    for name, seq in (("y_true", y_true), ("y_pred", y_pred)):
        unknown = {v for v in seq if v not in index}
        if unknown:
            raise ValueError(f"{name} contains labels not in {label_list}: {sorted(unknown)}")

    k = len(label_list)
    matrix = [[0] * k for _ in range(k)]
    for t, p in zip(y_true, y_pred):
        matrix[index[t]][index[p]] += 1

    total = len(y_true)
    correct = sum(matrix[i][i] for i in range(k))
    per_class: dict[str, ClassMetrics] = {}
    for i, label in enumerate(label_list):
        tp = matrix[i][i]
        fp = sum(matrix[r][i] for r in range(k)) - tp
        fn = sum(matrix[i]) - tp
        precision, recall = _safe_div(tp, tp + fp), _safe_div(tp, tp + fn)
        per_class[label] = ClassMetrics(
            precision=precision,
            recall=recall,
            f1=_safe_div(2 * precision * recall, precision + recall),
            support=sum(matrix[i]),
        )
    macro = {m: _safe_div(sum(getattr(c, m) for c in per_class.values()), k) for m in ("precision", "recall", "f1")}
    weighted = {
        m: _safe_div(sum(getattr(c, m) * c.support for c in per_class.values()), total)
        for m in ("precision", "recall", "f1")
    }
    return EvaluationReport(
        labels=label_list,
        total=total,
        accuracy=_safe_div(correct, total),
        per_class=per_class,
        macro_avg=macro,
        weighted_avg=weighted,
        confusion_matrix=matrix,
    )


def evaluate_results(results: Sequence[ClassificationResult]) -> Optional[EvaluationReport]:
    """Evaluate classification results against their ``true_label``.

    Results without ground truth, or that failed with an error, are skipped (and counted in
    ``skipped``). Returns None when nothing could be evaluated.
    """
    pairs = [(r.true_label, r.label) for r in results if r.true_label in LABELS and r.label != ERROR_LABEL]
    if not pairs:
        return None
    report = compute_metrics([t for t, _ in pairs], [p for _, p in pairs])
    report.skipped = len(results) - len(pairs)
    return report
