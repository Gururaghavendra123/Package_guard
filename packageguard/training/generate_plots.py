"""Generate report/slide-ready figures from the real trained model + evaluation artifacts.

Reads: dataset.parquet, models/xgboost_model.joblib, heldout_benchmark_results.json.
Writes 5 PNGs to review_prep/figures/ (personal report material, not part of the shipped tool).

Usage: python training/generate_plots.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from packageguard.core.features import FEATURE_ORDER  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent  # final_year_project/
TRAINING = Path(__file__).resolve().parent
OUT = ROOT / "review_prep" / "figures"
OUT.mkdir(parents=True, exist_ok=True)

# clean, presentation-friendly style — not the HUD theme, this is for slides/report
plt.rcParams.update({
    "figure.facecolor": "white", "axes.facecolor": "white",
    "font.family": "sans-serif", "font.size": 11,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": 0.25, "grid.linestyle": "--",
})
C_OK, C_WARN, C_CRIT, C_CYAN, C_INK = "#1e9e6b", "#e0a012", "#d64545", "#1f7ac2", "#2a2f36"


def fig1_confounder_journey():
    """The methodology story: naive -> matched -> stratified -> scaled+8-features."""
    stages = ["Popular benign\n(naive, inflated)", "Age/size-matched\n(hard negatives)",
              "Matched + stratified\n5 features, n=394", "+3 features\n+ scaled, n=1,531"]
    values = [0.987, 0.974, 0.941, 0.971]
    colors = [C_CRIT, C_WARN, C_CYAN, C_OK]
    labels = ["inflated\n(age confounder)", "confounder fixed", "honest baseline", "final (CV)"]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(stages, values, color=colors, width=0.55, edgecolor=C_INK, linewidth=0.8)
    for bar, v, lbl in zip(bars, values, labels):
        ax.text(bar.get_x() + bar.get_width() / 2, v + 0.012, f"{v:.3f}",
                ha="center", fontweight="bold", fontsize=11)
        ax.text(bar.get_x() + bar.get_width() / 2, 0.03, lbl, ha="center",
                fontsize=8.5, color="white", fontweight="bold")
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("PR-AUC")
    ax.set_title("The confounder-removal journey — naive metrics were high and wrong",
                fontweight="bold", fontsize=13)
    fig.tight_layout()
    fig.savefig(OUT / "1_confounder_journey.png", dpi=180)
    plt.close(fig)


def fig2_pr_curve(model, X_test, y_test):
    from sklearn.metrics import PrecisionRecallDisplay, average_precision_score
    proba = model.predict_proba(X_test)[:, 1]
    ap = average_precision_score(y_test, proba)

    fig, ax = plt.subplots(figsize=(6.5, 6))
    PrecisionRecallDisplay.from_predictions(y_test, proba, ax=ax, color=C_CYAN, linewidth=2.5)
    ax.fill_between(*_pr_xy(y_test, proba), alpha=0.12, color=C_CYAN)
    ax.set_title(f"XGBoost precision-recall curve\nPR-AUC = {ap:.3f}", fontweight="bold")
    ax.get_legend().remove() if ax.get_legend() else None
    fig.tight_layout()
    fig.savefig(OUT / "2_pr_curve.png", dpi=180)
    plt.close(fig)


def _pr_xy(y_test, proba):
    from sklearn.metrics import precision_recall_curve
    p, r, _ = precision_recall_curve(y_test, proba)
    return r, p


def fig3_confusion_matrix(model, X_test, y_test):
    from sklearn.metrics import confusion_matrix
    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    cm = confusion_matrix(y_test, pred)

    fig, ax = plt.subplots(figsize=(5.5, 5))
    im = ax.imshow(cm, cmap="Blues")
    labels = ["Benign", "Malicious"]
    ax.set_xticks([0, 1]); ax.set_xticklabels(labels)
    ax.set_yticks([0, 1]); ax.set_yticklabels(labels)
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                    fontsize=20, fontweight="bold",
                    color="white" if cm[i, j] > cm.max() / 2 else C_INK)
    ax.set_title("XGBoost confusion matrix (held-out test split)", fontweight="bold")
    ax.grid(False)
    fig.colorbar(im, ax=ax, shrink=0.8)
    fig.tight_layout()
    fig.savefig(OUT / "3_confusion_matrix.png", dpi=180)
    plt.close(fig)


def fig4_feature_importance(model):
    importances = model.feature_importances_
    order = np.argsort(importances)
    names = [FEATURE_ORDER[i].replace("_", " ").title() for i in order]
    vals = importances[order]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.barh(names, vals, color=C_CYAN, edgecolor=C_INK, linewidth=0.6)
    for bar, v in zip(bars, vals):
        ax.text(v + 0.008, bar.get_y() + bar.get_height() / 2, f"{v:.3f}",
                va="center", fontsize=9.5)
    ax.set_xlabel("XGBoost feature importance (gain)")
    ax.set_title("What the model actually learned to weight", fontweight="bold", fontsize=13)
    ax.set_xlim(0, max(vals) * 1.2)
    fig.tight_layout()
    fig.savefig(OUT / "4_feature_importance.png", dpi=180)
    plt.close(fig)


def fig5_heldout_benchmark():
    results_path = TRAINING / "heldout_benchmark_results.json"
    r = json.loads(results_path.read_text(encoding="utf-8"))
    detectors = ["Deterministic\nDB traversal", "XGBoost alone\n(per-package)", "GraphSAGE GNN\n(graph context)"]
    keys = ["db_traversal", "xgb_alone", "graph_score"]
    recall = [r[k]["recall"] for k in keys]
    fpr = [r[k]["fpr"] for k in keys]

    x = np.arange(len(detectors))
    w = 0.32
    fig, ax = plt.subplots(figsize=(9, 5.5))
    b1 = ax.bar(x - w / 2, recall, w, label="Recall (catches the real threat)",
               color=C_OK, edgecolor=C_INK, linewidth=0.6)
    b2 = ax.bar(x + w / 2, fpr, w, label="False positive rate",
               color=C_CRIT, edgecolor=C_INK, linewidth=0.6)
    for bars in (b1, b2):
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.02, f"{h:.0%}",
                    ha="center", fontweight="bold", fontsize=10)
    ax.set_xticks(x); ax.set_xticklabels(detectors)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Rate")
    ax.set_title(f"Held-out-unknown poisoned-chain benchmark\n"
                f"({r['n_positive']} real threats never in our own database, "
                f"{r['n_negative']} clean controls)", fontweight="bold", fontsize=12.5)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2, frameon=False)
    fig.tight_layout()
    fig.savefig(OUT / "5_heldout_benchmark.png", dpi=180)
    plt.close(fig)


def main() -> None:
    dataset_path = TRAINING / "dataset.parquet"
    model_path = TRAINING.parent / "src" / "packageguard" / "models" / "xgboost_model.joblib"
    bench_path = TRAINING / "heldout_benchmark_results.json"

    print("Figure 1/5: confounder-removal journey (from documented historical results)...")
    fig1_confounder_journey()

    if dataset_path.exists() and model_path.exists():
        from sklearn.model_selection import train_test_split
        df = pd.read_parquet(dataset_path)
        X, y = df[list(FEATURE_ORDER)], df["label"]
        _, X_test, _, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
        model = joblib.load(model_path)

        print("Figure 2/5: precision-recall curve...")
        fig2_pr_curve(model, X_test, y_test)
        print("Figure 3/5: confusion matrix...")
        fig3_confusion_matrix(model, X_test, y_test)
        print("Figure 4/5: feature importance...")
        fig4_feature_importance(model)
    else:
        print("  [skip 2-4] dataset.parquet or xgboost_model.joblib not found — "
              "run build_dataset.py + train_xgboost.py first.", file=sys.stderr)

    if bench_path.exists():
        print("Figure 5/5: held-out-unknown benchmark...")
        fig5_heldout_benchmark()
    else:
        print("  [skip 5] heldout_benchmark_results.json not found — "
              "run build_heldout_benchmark.py + evaluate_heldout_benchmark.py first.",
              file=sys.stderr)

    print(f"\nSaved to {OUT}")


if __name__ == "__main__":
    main()
