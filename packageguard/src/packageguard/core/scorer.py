"""Risk scorer.

Two backends behind one interface (`score()` returns risk in [0,1] + per-feature
Contributions — nothing downstream, CLI or HUD, needs to change when the backend swaps):

1. **Trained XGBoost + SHAP** (`src/packageguard/models/xgboost_model.joblib`) — used
   automatically when present. Real model trained in `training/train_xgboost.py` on the
   dataset built by `training/build_dataset.py` (Phase 1/2).
2. **Heuristic fallback** — a transparent hand-weighted linear model in log-odds space.
   Used when no trained model exists yet (fresh clone before training) or if loading the
   model fails for any reason. Never crashes the CLI/HUD for a missing model file.

Contributions are reported as log-odds deviations, mirroring how SHAP values read
(negative = pushes toward safe/green, positive = pushes toward risky/red) — this is why
the heuristic and the trained model produce visually consistent output.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from packageguard.core.features import FEATURE_ORDER, Feature

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "xgboost_model.joblib"

# --- heuristic fallback weights (log-odds space) ---
WEIGHTS: dict[str, float] = {
    "name_similarity": 3.4,
    "install_script": 3.0,
    "author_age": 1.6,
    "publish_timing": 0.5,
    "dep_count": 0.7,
    "version_count": 1.4,       # Phase 1: real-data AUC 0.81
    "description_quality": 1.2,  # Phase 1: real-data AUC 0.81
    "maintainer_count": 0.8,     # Phase 1: real-data AUC 0.75
}
BENIGN_PRIOR: dict[str, float] = {
    "name_similarity": 0.05,
    "install_script": 0.10,
    "author_age": 0.35,
    "publish_timing": 0.20,
    "dep_count": 0.30,
    "version_count": 0.20,
    "description_quality": 0.15,
    "maintainer_count": 0.20,
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


@lru_cache(maxsize=1)
def _load_ml_backend():
    """Load the trained model + SHAP explainer once. Returns None if unavailable —
    caller falls back to the heuristic. Any failure here is non-fatal by design."""
    if not MODEL_PATH.exists():
        return None
    try:
        import joblib

        from packageguard.core.explainer import ShapExplainer

        model = joblib.load(MODEL_PATH)
        return model, ShapExplainer(model)
    except Exception:  # noqa: BLE001 — deliberately broad: never let a bad model file crash scoring
        return None


def backend_name() -> str:
    """'xgboost' or 'heuristic' — surfaced in CLI/API output so results are never unlabeled."""
    return "xgboost" if _load_ml_backend() is not None else "heuristic"


def _score_ml(features: list[Feature]) -> tuple[float, list[Contribution]]:
    model, explainer = _load_ml_backend()
    row = {f.key: f.value for f in features}
    X = [[row[k] for k in FEATURE_ORDER]]
    proba = float(model.predict_proba(X)[0, 1])
    shap_contribs = dict(explainer.explain(row))

    contribs = [
        Contribution(f.key, f.label, f.value, shap_contribs.get(f.key, 0.0), f.detail)
        for f in features
    ]
    return proba, contribs


def _score_heuristic(features: list[Feature]) -> tuple[float, list[Contribution]]:
    logit = BIAS
    contribs: list[Contribution] = []
    for f in features:
        w = WEIGHTS.get(f.key, 0.0)
        logit += w * f.value
        deviation = w * (f.value - BENIGN_PRIOR.get(f.key, 0.0))
        contribs.append(Contribution(f.key, f.label, f.value, deviation, f.detail))
    return _sigmoid(logit), contribs


def score(features: list[Feature], prefer_ml: bool = True) -> tuple[float, list[Contribution]]:
    """Return (risk_score in [0,1], per-feature contributions).

    ``prefer_ml=True`` uses the trained XGBoost model when available. Set ``prefer_ml=False``
    when the feature values are the *offline synthetic fallback* (no live npm metadata) — the
    model was trained on real live features, so feeding it hash-derived offline values is
    incoherent and gives meaningless scores. In that case the heuristic (which was designed
    for those fallback values) is the correct backend."""
    if prefer_ml and _load_ml_backend() is not None:
        try:
            return _score_ml(features)
        except Exception:  # noqa: BLE001 — a bad prediction should degrade, not crash
            pass
    return _score_heuristic(features)


def used_ml(prefer_ml: bool) -> bool:
    """Whether score() with this prefer_ml actually used the trained model."""
    return prefer_ml and _load_ml_backend() is not None


def verdict(score_value: float) -> tuple[str, str]:
    """Map a score to (verdict text, level)."""
    if score_value >= 0.75:
        return "DO NOT INSTALL", "critical"
    if score_value >= 0.50:
        return "RISKY", "high"
    if score_value >= 0.30:
        return "CAUTION", "medium"
    return "LIKELY SAFE", "low"
