# PackageGuard — Example Suite (for the demo / viva)

Everything you can show, where it lives, and what it proves. All examples run through the **real
trained models** (XGBoost + GraphSAGE) unless marked "curated demo".

---

## CHECK tab — score a single package

The chips regenerate every load (hit **⟳** for new ones). Three kinds, colour-coded:

| Kind | Example inputs | What it proves | Source |
| ---- | -------------- | -------------- | ------ |
| 🟢 Clean | `express`, `lodash`, `react`, `chalk`, `axios` | Real popular packages score **LIKELY SAFE** | random real npm packages (`data/top_packages.json`) |
| 🔴 Typosquat | `loadash`, `expres`, `axioss`, `micr0-cors`, `w5-rpc` | The **ML model** flags look-alike names — *generated live*, not hardcoded | `engine._make_typosquat()` mutates a real name |
| 🔴 Known malware | `event-stream@3.3.6`, `eslint-scope@3.7.2`, `ua-parser-js`, `coa`, `crossenv` | Matches the known-malware database → DO NOT INSTALL | `data/known_malware.json` |

Also worth typing live: `@types/node`, `@babel/core` → **SAFE** (proves the popularity allowlist
stops false positives on legit scoped packages).

## SCAN tab — scan a whole project

One-click chips scan bundled demo projects; you can also drag in any real `package-lock.json`.

| Chip | Project folder | Contains | Result |
| ---- | -------------- | -------- | ------ |
| event-stream attack | `packageguard/sample/` | event-stream@3.3.6, flatmap-stream, malicious-logger | 3 issues (2 critical, 1 high) |
| typosquats | `packageguard/sample_typosquat/` | crossenv, loadsh, twilio-npm | 3 issues |
| 2021 coa/rc hijack | `packageguard/sample_hijack/` | coa@2.0.3, rc@1.2.9 | 2 critical |
| crypto-wallet backdoor | `packageguard/sample_wallet/` | electron-native-notify, eslint-scope, bootstrap-sass, 1337qq-js | 4 critical |
| clean project ✓ | `packageguard/sample_clean/` | only legitimate packages | **0 issues** (no false alarms) |

Each issue card shows the dependency path, why it's malicious, and step-by-step remediation.

## GRAPH tab — dependency-graph analysis (GNN)

| Chip | What it shows | Source |
| ---- | ------------- | ------ |
| `safe-wrapper ⚠` | Credential harvester 2 hops deep — root looks SAFE (XGBoost 0.08) but GNN flags the chain | curated demo (`data/demo_graphs.json`) |
| `ui-toolkit ⚠` | UI library transitively pulling a cryptominer | curated demo |
| `api-client ⚠` | Retry helper that exfiltrates env vars | curated demo |
| `build-tool ⚠` | Hijacked config parser (file wiper) | curated demo |
| `express`, real names | Live 2-hop npm graph — all green, no poison | live npm API |

**The money shot:** any curated demo shows the poisoned node pulsing red with the risk chain
glowing up to the clean root, and the side panel shows *per-package (XGBoost) safe → +graph (GNN)
→ combined RISKY*. That's the exact attack per-package scoring misses.

> Why the demos are curated: real dependency graphs of clean packages don't contain known malware
> (malware is usually a leaf nothing depends on). The demos construct the poisoned-chain scenario
> with malware-like features so the **real** GraphSAGE model flags them. Say this openly — it's
> honest and it's the whole point of the graph model.

---

## Where to add more examples

- **Check malware / scan targets** → add records to `packageguard/src/packageguard/data/known_malware.json`.
- **Scan projects** → add a folder `packageguard/sample_<name>/package-lock.json`, then add its name to
  `_SAMPLE_PROJECTS` in `api/app.py` and to the `scan_suite` list in `engine.examples()`.
- **Graph poisoned-chain demos** → add an entry to `packageguard/src/packageguard/data/demo_graphs.json`
  (list nodes with `role: clean|poison` and edges). It appears automatically as a graph chip.
- **Clean/typosquat check chips** → generated automatically from `data/top_packages.json`; nothing to edit.

## Talking points (proof it's really trained)

- **5-fold CV PR-AUC 0.94 ± 0.02** for the XGBoost scorer (`training/RESULTS.md`).
- **GNN 0.87 vs XGBoost 0.79** node-classification ablation — +0.07 from graph structure.
- Models regenerate from scripts: `training/train_xgboost.py`, `training/train_gnn.py`.
- Honest confounder-removal story (0.987 inflated → 0.90 real) — see `TECHNICAL_REPORT.md`.
