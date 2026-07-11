"""Score combiner (Sem 8): merges the per-package XGBoost score with the graph (GNN) score.

Two honest properties (both were explicit design requirements):
1. **Stacking, not a hand-picked weighted average.** When a trained meta-learner
   (`models/combiner.joblib`, a logistic regression over [xgb_score, graph_score]) is present,
   it is used. Its output is a calibrated probability.
2. **Logit-space attribution.** The "+X from the dependency graph" number shown in the UI is a
   genuine additive contribution in log-odds space:
       logit(combined) = logit(xgb) + graph_delta
   so reporting `graph_delta` as the graph driver is mathematically valid (this is what the
   v3 plan got wrong by calling an additive story a "weighted average").

If no meta-learner is trained yet, a transparent logit-space fallback is used with a fixed
graph weight — same interface, so nothing downstream changes when the real combiner lands.
"""

from __future__ import annotations

import math
from pathlib import Path

COMBINER_PATH = Path(__file__).resolve().parent.parent / "models" / "combiner.joblib"
_GRAPH_WEIGHT = 1.0   # fallback log-odds weight on the graph signal
_EPS = 1e-6


def _logit(p: float) -> float:
    p = min(1.0 - _EPS, max(_EPS, p))
    return math.log(p / (1.0 - p))


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _load_meta_learner():
    if not COMBINER_PATH.exists():
        return None
    try:
        import joblib
        return joblib.load(COMBINER_PATH)
    except Exception:  # noqa: BLE001
        return None


def combine(xgb_score: float, graph_score: float) -> tuple[float, float]:
    """Return (combined_score, graph_contribution_in_logit_space).

    `graph_score` is the neighbourhood risk from the GNN (e.g. max malicious-prob over the
    dependency subgraph). `graph_contribution` is what the UI shows as the "+ graph" driver.
    """
    model = _load_meta_learner()
    base_logit = _logit(xgb_score)

    if model is not None:
        import numpy as np
        combined = float(model.predict_proba(np.array([[xgb_score, graph_score]]))[0, 1])
    else:
        # The dependency-graph signal is only evidence of DANGER (a poisoned dependency),
        # never of safety — the absence of a malicious neighbour must not lower a package's
        # own risk (and must not tank a no-dependency package to ~0). So the graph can only
        # ADD to the log-odds, never subtract.
        graph_delta = max(0.0, _GRAPH_WEIGHT * _logit(graph_score))
        combined = _sigmoid(base_logit + graph_delta)

    graph_contribution = _logit(combined) - base_logit
    return combined, graph_contribution
