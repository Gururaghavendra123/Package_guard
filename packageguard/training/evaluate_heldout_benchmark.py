"""Phase 6 — evaluate three detectors on the held-out-unknown poisoned-chain benchmark.

Detectors compared, on the SAME 18 real positive + 18 negative cases from
`heldout_benchmark.json`:

1. **XGBoost alone** — the parent package's own per-package score. Expected to mostly MISS
   the positives, by construction: these are cases where the parent looks clean and only a
   dependency is suspicious.
2. **Deterministic DB traversal** — does any dependency match `known_malware.json`? Expected
   to score ~0 recall: none of these malicious dependency names were ever manually curated
   into the DB, simulating a zero-day the DB doesn't know about yet.
3. **GNN / graph-augmented** — the same mechanism `core.engine.analyze_graph` uses live: the
   worst GNN score among the parent's dependencies. Does NOT depend on the DB — only on
   structure + each dependency's own features, so it can catch a threat the DB has never
   heard of.

This is the fair test of the concern flagged since the original project plan: does the GNN
generalize beyond "the DB already knows this name," or does it just duplicate `scan`'s lookup?
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from packageguard.core.features import extract_features, FEATURE_ORDER  # noqa: E402
from packageguard.core.gnn_scorer import GnnScorer  # noqa: E402
from packageguard.core.lockfile import Dependency  # noqa: E402
from packageguard.core.remediation import find_issues  # noqa: E402
from packageguard.core import registry  # noqa: E402

BENCH = Path(__file__).resolve().parent / "heldout_benchmark.json"
XGB_MODEL = Path(__file__).resolve().parent.parent / "src" / "packageguard" / "models" / "xgboost_model.joblib"
GRAPH = Path(__file__).resolve().parent / "graph_dataset.npz"

MAL_THRESHOLD = 0.70  # matches core.engine's poisoned-chain threshold (recalibrated Phase 7)


def main() -> None:
    bench = json.loads(BENCH.read_text(encoding="utf-8"))
    positives, negatives = bench["positives"], bench["negatives"]

    xgb = joblib.load(XGB_MODEL)
    d = np.load(GRAPH, allow_pickle=True)
    ids = list(d["ids"])
    idx = {name: i for i, name in enumerate(ids)}
    x_all, ei_all, y_all = d["x"], d["edge_index"], d["y"]

    gnn = GnnScorer()
    gnn_probs = np.array(gnn.score_nodes(x_all.tolist(), ei_all.tolist())) if gnn.available() else None

    # adjacency for graph_score lookup (max GNN score among a node's dependencies)
    neighbours: dict[int, list[int]] = {i: [] for i in range(len(ids))}
    for a, b in zip(ei_all[0], ei_all[1]):
        neighbours[int(a)].append(int(b))

    def xgb_alone(name: str) -> float:
        i = idx.get(name)
        if i is None:
            return 0.0
        return float(xgb.predict_proba(x_all[i:i + 1])[0, 1])

    def db_traversal(name: str, dep_names: list[str]) -> bool:
        for dep in dep_names:
            if find_issues([Dependency(dep, "*", dep)]):
                return True
        return False

    def graph_score(name: str) -> float:
        i = idx.get(name)
        if i is None or gnn_probs is None:
            return 0.0
        nbrs = neighbours[i]
        return max((gnn_probs[j] for j in nbrs), default=0.0)

    rows = []
    for case in positives:
        parent, dep = case["parent"], case["malicious_dep"]
        rows.append({
            "case": parent, "label": 1,
            "xgb_alone": xgb_alone(parent),
            "db_hit": db_traversal(parent, [dep]),
            "graph_score": graph_score(parent),
        })
    for case in negatives:
        parent = case["parent"]
        i = idx.get(parent)
        dep_names = [ids[j] for j in neighbours.get(i, [])] if i is not None else []
        rows.append({
            "case": parent, "label": 0,
            "xgb_alone": xgb_alone(parent),
            "db_hit": db_traversal(parent, dep_names),
            "graph_score": graph_score(parent),
        })

    y = np.array([r["label"] for r in rows])

    def recall_fpr(pred_positive: np.ndarray) -> tuple[float, float]:
        tp = ((pred_positive == 1) & (y == 1)).sum()
        fn = ((pred_positive == 0) & (y == 1)).sum()
        fp = ((pred_positive == 1) & (y == 0)).sum()
        tn = ((pred_positive == 0) & (y == 0)).sum()
        recall = tp / max(1, tp + fn)
        fpr = fp / max(1, fp + tn)
        return recall, fpr

    xgb_pred = np.array([1 if r["xgb_alone"] >= 0.5 else 0 for r in rows])
    db_pred = np.array([1 if r["db_hit"] else 0 for r in rows])
    graph_pred = np.array([1 if r["graph_score"] >= MAL_THRESHOLD else 0 for r in rows])
    combined_pred = np.array([1 if (r["xgb_alone"] >= 0.5 or r["graph_score"] >= MAL_THRESHOLD)
                              else 0 for r in rows])

    print(f"Benchmark: {len(positives)} real poisoned-chain positives, "
          f"{len(negatives)} clean negatives\n")
    print(f"{'Detector':<30} {'Recall (catch the threat)':<28} {'False positive rate':<20}")
    for name, pred in [
        ("XGBoost alone (per-package)", xgb_pred),
        ("Deterministic DB traversal", db_pred),
        ("GNN / graph score", graph_pred),
        ("Combined (either flags)", combined_pred),
    ]:
        r, f = recall_fpr(pred)
        print(f"{name:<30} {r:<28.2%} {f:<20.2%}")

    out = Path(__file__).resolve().parent / "heldout_benchmark_results.json"
    out.write_text(json.dumps({
        "n_positive": len(positives), "n_negative": len(negatives),
        "xgb_alone": dict(zip(["recall", "fpr"], recall_fpr(xgb_pred))),
        "db_traversal": dict(zip(["recall", "fpr"], recall_fpr(db_pred))),
        "graph_score": dict(zip(["recall", "fpr"], recall_fpr(graph_pred))),
        "combined": dict(zip(["recall", "fpr"], recall_fpr(combined_pred))),
        "rows": rows,
    }, indent=2), encoding="utf-8")
    print(f"\nSaved -> {out}")


if __name__ == "__main__":
    main()
