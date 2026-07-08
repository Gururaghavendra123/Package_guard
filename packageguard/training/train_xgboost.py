"""Phase 2 — train the real XGBoost risk model on the dataset built in Phase 1.

Reports honest metrics (PR-AUC as the headline, per plan v4 — accuracy is misleading
under class imbalance). Saves the model + a metadata sidecar (feature order, dataset
size, metrics, training date) so `core/scorer.py` can load it and so the numbers are
traceable in a review document.

Usage:
    python training/train_xgboost.py --dataset training/dataset.parquet
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from packageguard.core.features import FEATURE_ORDER  # noqa: E402

MODEL_DIR = Path(__file__).resolve().parent.parent / "src" / "packageguard" / "models"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", type=Path, default=Path(__file__).resolve().parent / "dataset.parquet")
    ap.add_argument("--test-size", type=float, default=0.25)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, default=MODEL_DIR / "xgboost_model.joblib")
    args = ap.parse_args()

    if not args.dataset.exists():
        print(f"Dataset not found: {args.dataset}. Run build_dataset.py first.", file=sys.stderr)
        sys.exit(1)

    df = pd.read_parquet(args.dataset)
    n_total = len(df)
    n_pos = int(df["label"].sum())
    n_neg = n_total - n_pos
    print(f"Dataset: {n_total} rows ({n_pos} malicious, {n_neg} benign) from {args.dataset}")

    if n_total < 100:
        print("WARNING: dataset is small — metrics below are preliminary, not final results. "
              "Scale up training/build_dataset.py before reporting these numbers as conclusive.",
              file=sys.stderr)

    X = df[list(FEATURE_ORDER)]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.seed, stratify=y,
    )

    scale_pos_weight = n_neg / max(1, n_pos)  # per plan: handle ~imbalance honestly
    model = XGBClassifier(
        n_estimators=200,
        max_depth=3,
        learning_rate=0.1,
        scale_pos_weight=scale_pos_weight,
        eval_metric="logloss",
        random_state=args.seed,
    )
    model.fit(X_train, y_train)

    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)

    pr_auc = average_precision_score(y_test, proba)
    report = classification_report(y_test, pred, target_names=["benign", "malicious"],
                                    zero_division=0)
    cm = confusion_matrix(y_test, pred).tolist()

    print("\n=== Evaluation (held-out test split, honest — small-sample caveat above) ===")
    print(f"PR-AUC (headline metric): {pr_auc:.4f}")
    print(report)
    print(f"Confusion matrix [[TN, FP], [FN, TP]]: {cm}")

    importances = dict(zip(FEATURE_ORDER, model.feature_importances_.round(4).tolist()))
    print(f"\nFeature importances: {importances}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.out)

    meta = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_path": str(args.dataset),
        "n_total": n_total,
        "n_malicious": n_pos,
        "n_benign": n_neg,
        "test_size": args.test_size,
        "feature_order": list(FEATURE_ORDER),
        "pr_auc": round(pr_auc, 4),
        "feature_importances": importances,
        "confusion_matrix": cm,
        "small_sample_warning": n_total < 100,
    }
    meta_path = args.out.with_suffix(".meta.json")
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"\nModel saved: {args.out}")
    print(f"Metadata saved: {meta_path}")


if __name__ == "__main__":
    main()
