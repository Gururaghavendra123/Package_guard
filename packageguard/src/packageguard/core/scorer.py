"""Risk scorer — HEURISTIC PLACEHOLDER.

This is a transparent linear model in log-odds space. It exists so the whole pipeline (CLI +
HUD) works end-to-end today. In Sem 7 Weeks 3-4 it is replaced by a trained **XGBoost** model
with real **SHAP** attributions; the public interface (``score()`` returning a score plus
per-feature contributions) stays the same so nothing downstream changes.

Contributions are reported as deviation from a per-feature benign baseline, mirroring how SHAP
values read (negative = pushes toward safe/green, positive = pushes toward risky/red).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from packageguard.core.features import Feature

# log-odds weights (placeholder — learned by XGBoost later)
WEIGHTS: dict[str, float] = {
    "name_similarity": 3.4,
    "install_script": 3.0,
    "author_age": 1.6,
    "publish_timing": 0.5,
    "dep_count": 0.7,
}
# typical benign value per feature; contributions are measured relative to this
BENIGN_PRIOR: dict[str, float] = {
    "name_similarity": 0.05,
    "install_script": 0.10,
    "author_age": 0.35,
    "publish_timing": 0.20,
    "dep_count": 0.30,
}
BIAS = -1.7


@dataclass
class Contribution:
    key: str
    label: str
    value: float          # raw feature risk [0,1]
    contribution: float   # signed log-odds deviation from baseline
    detail: str

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "value": round(self.value, 4),
            "contribution": round(self.contribution, 4),
            "detail": self.detail,
        }


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def score(features: list[Feature]) -> tuple[float, list[Contribution]]:
    """Return (risk_score in [0,1], per-feature contributions)."""
    logit = BIAS
    contribs: list[Contribution] = []
    for f in features:
        w = WEIGHTS.get(f.key, 0.0)
        logit += w * f.value
        deviation = w * (f.value - BENIGN_PRIOR.get(f.key, 0.0))
        contribs.append(Contribution(f.key, f.label, f.value, deviation, f.detail))
    return _sigmoid(logit), contribs


def verdict(score_value: float) -> tuple[str, str]:
    """Map a score to (verdict text, level)."""
    if score_value >= 0.75:
        return "DO NOT INSTALL", "critical"
    if score_value >= 0.50:
        return "RISKY", "high"
    if score_value >= 0.30:
        return "CAUTION", "medium"
    return "LIKELY SAFE", "low"
