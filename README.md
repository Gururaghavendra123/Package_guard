# 🛡️ PackageGuard

A supply-chain security tool that scores a software package's risk **before** you install it,
scans an existing project for compromised dependencies, and uses a **graph neural network** to
catch threats hiding *inside* a dependency — validated on a held-out-unknown benchmark of real,
previously-unseen threats.

Two faces, one engine:
- **CLI** — `packageguard check <pkg>` / `packageguard scan <path>` / `packageguard graph <pkg>`
- **HUD dashboard** — `packageguard serve` → a tactical threat-console in your browser, with a
  home page, live CHECK/SCAN/GRAPH tools, and a supply-chain security awareness page

> Final-year project by **Gururaghavendra P (23CZ037)** and **Tharun K S (23CZ055)**.
> The source lives in [`packageguard/`](packageguard/).

---

## What it does

| Command | Purpose |
| ------- | ------- |
| `packageguard check <pkg>` | Score a package for supply-chain risk and explain *why* (per-feature attribution). |
| `packageguard scan <project>` | Parse `package-lock.json`, flag known-malicious dependencies, print fix steps. |
| `packageguard graph <pkg>` | Analyse a package's dependency graph with the GNN (catches poisoned chains). |
| `packageguard serve` | Launch the HUD dashboard — home page, all three tools, and a security awareness page. |

## How it works

- **Per-package model** — a trained **XGBoost** classifier over **8** metadata features (name
  similarity/typosquat, install scripts, author age, publish timing, dependency count, release
  history, description quality, maintainer count), with **SHAP** attributions. Falls back to a
  transparent heuristic when offline.
- **Graph model** — a **GraphSAGE** GNN scores a package using its dependency-graph neighbourhood,
  catching *poisoned chains* (a clean-looking package whose dependency is malicious) that
  per-package scoring structurally cannot see. Combined via a transparent additive log-odds
  formula (a trained stacking combiner was attempted twice and deliberately not shipped — see
  results doc for why, kept as a documented negative result).
- **Scan** — pure lockfile parsing (no code execution) + a bundled known-malware database, with
  historical-incident awareness (a package whose *current* version is safe but had a past
  incident shows an informational note, not a false alarm).

## Results (honest, real data)

- Per-package XGBoost: **held-out test PR-AUC 0.988** on 10,420 real labeled rows (7,788
  malicious / 2,632 benign).
- Graph model: GraphSAGE trained on a **13,159-node, 11,737-edge** real dependency graph,
  node-classification **PR-AUC 0.979**.
- **Held-out-unknown benchmark (the headline result):** on 179 real poisoned-chain cases mined
  from live npm data — where none of the malicious dependencies were ever in our own
  database — the GNN catches **77.7% of them at a 3.4% false-alarm rate**, while a deterministic
  database-lookup baseline catches **0%** and XGBoost alone catches **4%**. This is the direct
  answer to "does the graph model generalize, or does it just memorize the malware list?"
- Full confounder-removal methodology, feature-leakage screening, and every honest negative
  result along the way: [`packageguard/training/RESULTS.md`](packageguard/training/RESULTS.md).

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
> `python training/build_dataset.py && python training/train_xgboost.py`,
> `python training/build_graph_dataset.py && python training/train_gnn.py`, and
> `python training/build_heldout_benchmark.py && python training/evaluate_heldout_benchmark.py`
> to reproduce the held-out benchmark. Without trained models the tool runs on its heuristic
> fallback.

## Tech

Python · Typer · Rich · FastAPI · vanilla HTML/CSS/JS HUD · XGBoost · SHAP · scikit-learn ·
PyTorch Geometric (GraphSAGE) · httpx · pandas.

MIT licensed.
