"""Train the GraphSAGE node classifier + ablation vs per-package XGBoost (Sem 8).

Transductive node classification on the cache-built dependency graph. The ablation is the
whole point: it compares the GNN (features + graph structure) against the XGBoost model
(features only) on the *same* held-out nodes, to show whether graph structure adds signal.

Usage: python training/train_gnn.py
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

DATA = Path(__file__).resolve().parent / "graph_dataset.npz"


def main() -> None:
    import torch
    from sklearn.metrics import average_precision_score, roc_auc_score
    from sklearn.model_selection import train_test_split

    from packageguard.core.gnn_scorer import MODEL_PATH, build_model

    if not DATA.exists():
        print("graph_dataset.npz missing — run build_graph_dataset.py first.", file=sys.stderr)
        sys.exit(1)

    d = np.load(DATA, allow_pickle=True)
    x = torch.tensor(d["x"], dtype=torch.float)
    edge_index_np = d["edge_index"]
    edge_index = torch.tensor(edge_index_np, dtype=torch.long)
    y_np = d["y"].astype(int)
    y = torch.tensor(y_np, dtype=torch.float)
    n_pos, n_neg = int(y_np.sum()), int((y_np == 0).sum())
    print(f"graph: {x.shape[0]} nodes, {edge_index.shape[1]//2} edges, "
          f"{n_pos} malicious / {n_neg} benign")

    idx = np.arange(len(y_np))
    tr, te = train_test_split(idx, test_size=0.3, stratify=y_np, random_state=42)
    train_mask = torch.zeros(len(y_np), dtype=torch.bool); train_mask[tr] = True
    test_mask = torch.zeros(len(y_np), dtype=torch.bool); test_mask[te] = True

    # Hard-example oversampling: malicious nodes whose neighbourhood is majority-benign are
    # the exact "clean parent, poisoned dependency" shape the held-out benchmark tests
    # (training/evaluate_heldout_benchmark.py) — and only ~5% of malicious nodes have this
    # shape, so mean-aggregation over mostly-benign neighbours can smooth their embedding
    # toward "looks benign" unless the loss specifically emphasises them. Boost their weight.
    src_np, dst_np = edge_index_np[0], edge_index_np[1]
    neighbours: dict[int, list[int]] = {i: [] for i in range(len(y_np))}
    for a, b in zip(src_np, dst_np):
        neighbours[int(a)].append(int(b))
    sample_weight = np.ones(len(y_np), dtype=np.float32)
    n_hard = 0
    for i in range(len(y_np)):
        if y_np[i] == 1 and neighbours[i]:
            benign_frac = sum(y_np[j] == 0 for j in neighbours[i]) / len(neighbours[i])
            if benign_frac > 0.5:
                sample_weight[i] = 4.0
                n_hard += 1
    print(f"  hard-example oversampling: {n_hard} majority-benign-neighbour malicious nodes "
          f"upweighted 4x in the training loss")
    sample_weight_t = torch.tensor(sample_weight, dtype=torch.float)

    torch.manual_seed(42)
    model = build_model(hidden=32)
    pos_weight = torch.tensor([n_neg / max(1, n_pos)], dtype=torch.float)
    loss_fn = torch.nn.BCEWithLogitsLoss(pos_weight=pos_weight, reduction="none")
    opt = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=5e-4)

    for epoch in range(300):
        model.train(); opt.zero_grad()
        out = model(x, edge_index)
        per_node_loss = loss_fn(out[train_mask], y[train_mask])
        loss = (per_node_loss * sample_weight_t[train_mask]).mean()
        loss.backward(); opt.step()
        if (epoch + 1) % 100 == 0:
            print(f"  epoch {epoch+1}: loss {loss.item():.4f}")

    model.eval()
    with torch.no_grad():
        prob = torch.sigmoid(model(x, edge_index)).numpy()
    y_te = y_np[te]
    gnn_ap = average_precision_score(y_te, prob[te])
    gnn_roc = roc_auc_score(y_te, prob[te])

    # --- Ablation: per-package XGBoost (features only) on the SAME test nodes ---
    xgb_ap = xgb_roc = None
    try:
        import joblib
        xgb = joblib.load(MODEL_PATH.parent / "xgboost_model.joblib")
        xgb_prob = xgb.predict_proba(d["x"][te])[:, 1]
        xgb_ap = average_precision_score(y_te, xgb_prob)
        xgb_roc = roc_auc_score(y_te, xgb_prob)
    except Exception as e:  # noqa: BLE001
        print(f"  (xgb ablation skipped: {e})")

    print("\n=== Node-classification results (held-out test nodes) ===")
    print(f"GNN (GraphSAGE, features+structure): PR-AUC {gnn_ap:.3f}  ROC-AUC {gnn_roc:.3f}")
    if xgb_ap is not None:
        print(f"XGBoost (features only)            : PR-AUC {xgb_ap:.3f}  ROC-AUC {xgb_roc:.3f}")
        print(f"Structure delta (GNN - XGB PR-AUC) : {gnn_ap - xgb_ap:+.3f}")

    torch.save(model.state_dict(), MODEL_PATH)
    meta = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_nodes": int(x.shape[0]), "n_edges": int(edge_index.shape[1] // 2),
        "n_malicious": n_pos, "n_benign": n_neg,
        "gnn_pr_auc": round(gnn_ap, 4), "gnn_roc_auc": round(gnn_roc, 4),
        "xgb_pr_auc": round(xgb_ap, 4) if xgb_ap else None,
    }
    (MODEL_PATH.with_suffix(".meta.json")).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"\nModel saved: {MODEL_PATH}")


if __name__ == "__main__":
    main()
