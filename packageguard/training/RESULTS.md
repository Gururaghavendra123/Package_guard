# PackageGuard — Phase 1/2 Results (Sem 7 model)

Honest write-up of the trained-model work. Every number here is from real npm data via the
pipeline in this folder. **All results are preliminary / small-sample** (see Limitations) —
directional, not final. Reproduce with `build_dataset.py` → `train_xgboost.py`.

## What the model is

Binary risk classifier (XGBoost) over 5 per-package metadata features, replacing the initial
heuristic scorer. Applies only to live-fetched packages; offline falls back to the heuristic.
Serves both the CLI and the HUD dashboard through one engine.

## The headline finding: modern malware ≠ typosquats

The original plan assumed typosquatting + install scripts were the dominant attack signals
(citing the 2020 Backstabber paper's 174 hand-curated cases). The real, current bulk data
tells a different story:

| Attack type | Share of 51,449 labeled npm malware |
| ----------- | ----------------------------------- |
| malicious_intent (novel throwaway names) | ~96.5% |
| compromised_lib (hijacked real packages) | ~3.5% (1,624) |
| true typosquats (edit-distance-1 to a popular pkg) | ~0.1% (44) |

Consequences, both empirically confirmed:
- **Typosquat detection is a minor signal**, not the headline — there are only ~44 real
  typosquats in the entire dataset.
- **Install scripts are almost never declared** in the fetched manifests (1 of 194 malicious
  packages). Modern malware ships its payload in tarball code (import-time / `bin`), not the
  manifest `scripts` field. So metadata-only analysis has a real ceiling.

## The confounder-removal journey (the core methodological result)

Naive numbers looked great and were **wrong**. Each step removed one specific flaw:

| Benign set | PR-AUC | `name_similarity` learned | What was wrong |
| ---------- | ------ | ------------------------- | -------------- |
| Popular (naive) | 0.987 | **backwards** | Benign = old/famous, malicious = new/small → model learned "new = bad", not "malicious = bad" (age confounder). |
| Age/size-matched (hard negatives) | 0.974 | still backwards | Age confounder removed by sampling young legit packages from the npm `_changes` feed. |
| **Matched + attack-type-stratified** | **~0.90** | **correct ✓** | Forced the rare compromised_lib + typosquat cases into the set so the typosquat feature had real positives. |

The honest number is **~0.90 PR-AUC** (single split), and **0.94 ± 0.02 by 5-fold
cross-validation** — not 0.98. The 0.98 was age-cheating.

**False-positive control (added in hardening):** a popularity allowlist caps risk for
verified-popular packages (e.g. `@types/node`, `@babel/core`) — the model otherwise slightly
over-reads "0 dependencies" as suspicious. The known-malware DB still overrides the allowlist,
so a compromised version of a popular package is still flagged. Invalid names / malformed
lockfiles are rejected cleanly (regression-tested), so nothing crashes during a demo.

## Honest per-attack-type recall (combined model)

Test split, small n — directional:

| Attack type | Recall |
| ----------- | ------ |
| malicious_intent | ~0.91 |
| typosquat | ~0.86 (7 test cases) |
| compromised_lib | ~0.78 (18 test cases) |

`compromised_lib` (hijacked real packages) is hardest because on metadata they look
legitimate — which is precisely the case the **Sem 8 GNN** is designed for (their maliciousness
is visible in the dependency graph / version history, not per-package metadata).

## Feature importances (combined model)

| Feature | Importance | Note |
| ------- | ---------- | ---- |
| author_age (first-publish-date proxy) | ~0.44 | Strongest, but a proxy — npm doesn't expose true account age. |
| name_similarity | ~0.31 | Now correctly signed; catches the rare typosquats. |
| dep_count | ~0.16 | Real-ish (throwaway malware often has 0 deps) but weak/gameable. |
| publish_timing | ~0.09 | Weak, as predicted (timezone-confounded). |
| install_script (presence) | **0.00** | Dead weight — scripts not declared in these manifests. |

## Limitations (state these plainly in review)

- **Small sample:** 394 rows (194 malicious / 200 benign). Metrics are preliminary. Scaling to
  ~1000+ each is the next validation step.
- **author_age is a proxy** (first-publish date, not account creation — npm doesn't expose it).
- **~3% of labeled malware is already purged from npm** and cannot be feature-extracted (skipped,
  reported honestly, not synthesized).
- **Young-benign label noise:** benign young packages come from the unlabeled `_changes` feed
  filtered by a legitimacy heuristic (has repo + description); a freshly-published,
  not-yet-detected malicious package could slip in. Rate is low, documented not hidden.
- **Metadata ceiling:** the dominant malware class (novel throwaway packages) is only weakly
  separable on metadata without confounders. True behavioral detection needs tarball/code
  analysis — deliberately out of scope for Sem 7 (would require downloading live malware source
  to disk). This is the motivation for Sem 8 (graph) + future behavioral work, not a defect.

## Why this is a strong result to present

Not "we hit 0.98." Instead: "we discovered our threat assumptions didn't match current data,
built controls to remove three separate confounders, and report an honest ~0.90 with a clear
account of what metadata can and cannot do — which directly motivates the graph model." That is
a more credible, more defensible research narrative than an inflated number.
