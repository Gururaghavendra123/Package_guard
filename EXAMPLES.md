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
| 🔴 Known malware | `event-stream@3.3.6`, `coa`, `crossenv` | Matches the known-malware database → DO NOT INSTALL | `data/known_malware.json` |
| 🟡 Historical incident | `eslint-scope`, `ua-parser-js` (no version = latest) | Current version is safe, but shows an amber note about a past incident — real context without a false alarm | `remediation.history_for_name()` |

Also worth typing live: `@types/node`, `@babel/core` → **SAFE** (proves the popularity allowlist
stops false positives on legit scoped packages). And a fake name (`zzznotarealpkg`) → **NOT
FOUND**, not a random score — proves the tool doesn't fabricate results for garbage input.

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

6 curated poisoned-chain demos (chips rotate on ⟳, shown with ⚠) + real live packages:

| Chip | What it shows | Source |
| ---- | ------------- | ------ |
| `safe-wrapper ⚠` | Credential harvester 2 hops deep — root looks SAFE but GNN flags the chain | curated demo (`data/demo_graphs.json`) |
| `ui-toolkit ⚠` | UI library transitively pulling a cryptominer | curated demo |
| `api-client ⚠` | Retry helper that exfiltrates env vars | curated demo |
| `build-tool ⚠` | Hijacked config parser (file wiper) | curated demo |
| `payment-sdk ⚠` | Payment SDK's currency formatter skims card details | curated demo |
| `logger-lib ⚠` | Logging library loads a keystroke/env harvester | curated demo |
| `express`, real names | Live 2-hop npm graph — all green, no poison | live npm API |

**The money shot:** any curated demo shows the poisoned node pulsing red with the risk chain
glowing up to the clean root, and the side panel shows *per-package (XGBoost) safe → +graph (GNN)
→ combined RISKY*. That's the exact attack per-package scoring misses.

> Why the demos are curated: real dependency graphs of clean packages don't naturally contain
> known malware (malware is usually a leaf nothing depends on). The demos construct the
> poisoned-chain scenario with malware-like features so the **real** GraphSAGE model flags them.
> Say this openly. **The real proof isn't the demo — it's the held-out-unknown benchmark**: 18
> genuine cases mined from live npm data, none in our own malware database, where the GNN catches
> 89% of real threats with 0% false alarms while a lookup-table approach catches 0%. That number
> is what makes the demo credible, not the other way around. See `TECHNICAL_REPORT.md` §8.3.

---

## Where to add more examples

- **Check malware / scan targets** → add records to `packageguard/src/packageguard/data/known_malware.json`.
- **Scan projects** → add a folder `packageguard/sample_<name>/package-lock.json`, then add its name to
  `_SAMPLE_PROJECTS` in `api/app.py` and to the `scan_suite` list in `engine.examples()`.
- **Graph poisoned-chain demos** → add an entry to `packageguard/src/packageguard/data/demo_graphs.json`
  (list nodes with `role: clean|poison` and edges). It appears automatically as a graph chip.
- **Clean/typosquat check chips** → generated automatically from `data/top_packages.json`; nothing to edit.

## Talking points (proof it's really trained)

- **5-fold CV PR-AUC 0.971 ± 0.006** for the XGBoost scorer, 8 features, 1,531 real rows.
- **Held-out-unknown benchmark (the strongest result): GNN 89% recall / 0% false alarms vs. 0%
  recall for a deterministic DB lookup** — real npm data, zero-day simulation. See
  `training/RESULTS.md` §Phase 6.
- Models regenerate from scripts: `training/train_xgboost.py`, `training/train_gnn.py`,
  `training/build_heldout_benchmark.py` → `training/evaluate_heldout_benchmark.py`.
- Honest confounder-removal story (0.987 inflated → 0.90 real, then 0.97 with more/better data)
  — see `TECHNICAL_REPORT.md`.
