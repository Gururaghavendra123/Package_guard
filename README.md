# 🛡️ PackageGuard

A supply-chain security tool that scores a software package's risk **before** you install it,
and scans an existing project for compromised dependencies with exact remediation steps.

Two faces, one engine:
- **CLI** — `packageguard check <pkg>` / `packageguard scan <path>`
- **HUD dashboard** — `packageguard serve` → a tactical security console in your browser

> Final-year project by **Gururaghavendra P (23CZ037)** and **Tharun K S (23CZ055)**.
> The source lives in [`packageguard/`](packageguard/).

---

## What it does

| Command | Purpose |
| ------- | ------- |
| `packageguard check <pkg>` | Score a package for supply-chain risk and explain *why* (per-feature attribution). |
| `packageguard scan <project>` | Parse `package-lock.json`, flag known-malicious dependencies, print fix steps. |
| `packageguard graph <pkg>` | Analyse a package's dependency graph with the GNN (catches poisoned chains). |
| `packageguard serve` | Launch the HUD dashboard (all of the above in the browser). |

## How it works

- **Per-package model** — a trained **XGBoost** classifier over 5 metadata features
  (name similarity / typosquat, install scripts, author age, publish timing, dependency count),
  with **SHAP** attributions. Falls back to a transparent heuristic when offline.
- **Graph model (Sem 8)** — a **GraphSAGE** GNN scores a package using its dependency-graph
  neighbourhood, catching *poisoned chains* (a clean-looking package whose dependency is
  malicious) that per-package scoring cannot see. A stacking combiner merges the two scores.
- **Scan** — pure lockfile parsing (no code execution) + a bundled known-malware database.

## Results (honest, small-sample)

- Per-package XGBoost: **PR-AUC ~0.90** (5-fold CV 0.94 ± 0.02).
- GNN ablation (node classification): **GraphSAGE 0.87 vs XGBoost 0.79** PR-AUC — **+0.07 from
  dependency structure**.
- Poisoned-chain demo: a package XGBoost scores 0.12 (safe) is flagged **RISKY** once the GNN
  sees its compromised dependency.

See [`packageguard/training/RESULTS.md`](packageguard/training/RESULTS.md) and
[`TECHNICAL_REPORT.md`](TECHNICAL_REPORT.md) for the full writeup, including the
confounder-removal methodology.

## Quick start

```bash
cd packageguard
python -m venv .venv
.venv\Scripts\activate            # Windows  (source .venv/bin/activate on macOS/Linux)
pip install -e ".[ml,gnn]"

packageguard check co1ors         # typosquat -> DO NOT INSTALL
packageguard check express        # clean     -> LIKELY SAFE
packageguard scan ./sample        # project with malware
packageguard graph safe-wrapper   # poisoned-chain demo (GNN)
packageguard serve                # HUD dashboard at localhost:8000
```

> Trained models are not committed (regenerate them, offline-safe):
> `python training/build_dataset.py && python training/train_xgboost.py`
> and `python training/build_graph_dataset.py && python training/train_gnn.py`.
> Without them the tool still runs on its heuristic fallback.

## Tech

Python · Typer · Rich · FastAPI · vanilla HTML/CSS/JS HUD · XGBoost · SHAP · scikit-learn ·
PyTorch Geometric (GraphSAGE) · httpx · pandas.

MIT licensed.
