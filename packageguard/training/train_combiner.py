"""Phase 5 — train the real stacking combiner (logistic regression over
[xgb_score, graph_score] -> combined probability), replacing the fallback log-odds formula
in core/combiner.py with an actually-fitted meta-learner. Same interface either way.

Training data is built for free from existing artifacts (no new npm calls): for every node in
the graph dataset (training/graph_dataset.npz) we already know its own per-package XGBoost
score and its neighbours' GNN scores — pairing those two numbers with the node's true label is
exactly the [xgb_score, graph_score] -> label training signal the combiner needs, mirroring
what core/engine.analyze_graph computes live for a package's root.

Caveat (stated honestly, not hidden): the base XGBoost and GNN models were themselves fit on
this same graph's nodes, so this is not a fully independent test set — it's the best available
without a second rate-limited data pull. The held-out split below is still meaningful for
choosing/validating the combiner's own parameters, just not a clean end-to-end generalization
claim.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

DATA = Path(__file__).resolve().parent / "graph_dataset.npz"
COMBINER_OUT = Path(__file__).resolve().parent.parent / "src" / "packageguard" / "models" / "combiner.joblib"


def main() -> None:
    import torch
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import average_precision_score
    from sklearn.model_selection import train_test_split

    from packageguard.core.gnn_scorer import GnnScorer

    if not DATA.exists():
        print("graph_dataset.npz missing — run build_graph_dataset.py first.", file=sys.stderr)
        sys.exit(1)

    d = np.load(DATA, allow_pickle=True)
    x, edge_index, y = d["x"], d["edge_index"], d["y"].astype(int)
    n = len(y)
    print(f"graph: {n} nodes, {edge_index.shape[1]//2} edges")

    xgb = joblib.load(Path(__file__).resolve().parent.parent / "src" / "packageguard"
                      / "models" / "xgboost_model.joblib")
    xgb_probs = xgb.predict_proba(x)[:, 1]

    gnn = GnnScorer()
    if not gnn.available():
        print("GNN model not trained — run train_gnn.py first.", file=sys.stderr)
        sys.exit(1)
    gnn_probs = np.array(gnn.score_nodes(x.tolist(), edge_index.tolist()))

    # adjacency (undirected — edges already stored both directions)
    neighbours: dict[int, list[int]] = {i: [] for i in range(n)}
    src, dst = edge_index[0], edge_index[1]
    for a, b in zip(src, dst):
        neighbours[int(a)].append(int(b))

    graph_score = np.array([
        max((gnn_probs[j] for j in neighbours[i]), default=0.0) for i in range(n)
    ])

    X = np.column_stack([xgb_probs, graph_score])
    idx = np.arange(n)
    tr, te = train_test_split(idx, test_size=0.25, random_state=42, stratify=y)

    meta = LogisticRegression(class_weight="balanced")
    meta.fit(X[tr], y[tr])

    pred = meta.predict_proba(X[te])[:, 1]
    combiner_ap = average_precision_score(y[te], pred)
    xgb_only_ap = average_precision_score(y[te], xgb_probs[te])

    print("\n=== Combiner evaluation (held-out nodes; base models NOT independently held out — see caveat) ===")
    print(f"XGBoost alone     PR-AUC: {xgb_only_ap:.4f}")
    print(f"Trained combiner  PR-AUC: {combiner_ap:.4f}")
    print(f"Learned weights: xgb_score={meta.coef_[0][0]:.3f}  graph_score={meta.coef_[0][1]:.3f}  "
          f"intercept={meta.intercept_[0]:.3f}")

    COMBINER_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(meta, COMBINER_OUT)
    meta_path = COMBINER_OUT.with_suffix(".meta.json")
    meta_path.write_text(json.dumps({
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_nodes": n,
        "combiner_pr_auc_heldout_nodes": round(float(combiner_ap), 4),
        "xgb_only_pr_auc_heldout_nodes": round(float(xgb_only_ap), 4),
        "coef_xgb_score": round(float(meta.coef_[0][0]), 4),
        "coef_graph_score": round(float(meta.coef_[0][1]), 4),
        "intercept": round(float(meta.intercept_[0]), 4),
        "caveat": "Base XGBoost/GNN were fit on this same graph's nodes; this is not a fully "
                  "independent generalization test, only the best available without a new "
                  "rate-limited npm pull.",
    }, indent=2), encoding="utf-8")
    print(f"\nCombiner saved: {COMBINER_OUT}")


if __name__ == "__main__":
    main()
