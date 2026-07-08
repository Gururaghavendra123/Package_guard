"""SHAP wrapper — per-prediction feature attribution for the trained XGBoost model.

TreeExplainer on an XGBoost binary classifier returns SHAP values in **margin (log-odds)
space** by default: base_value + sum(shap_values) == raw model margin before the sigmoid.
That matches the heuristic scorer's log-odds design (see scorer.py), so switching from
stub to trained model requires no change to how contributions are displayed.
"""

from __future__ import annotations

import shap

from packageguard.core.features import FEATURE_ORDER


class ShapExplainer:
    def __init__(self, model) -> None:
        self._explainer = shap.TreeExplainer(model)

    def explain(self, feature_row: dict[str, float]) -> list[tuple[str, float]]:
        """Return [(feature_key, contribution), ...] in canonical feature order."""
        x = [[feature_row[k] for k in FEATURE_ORDER]]
        shap_values = self._explainer.shap_values(x)
        row = shap_values[0] if hasattr(shap_values, "__len__") else shap_values
        return list(zip(FEATURE_ORDER, [float(v) for v in row]))
