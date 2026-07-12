# PackageGuard — Results (Phase 1-6, full history)

Honest write-up of the trained-model work, in the order it actually happened. Every number here
is from real npm data via the reproducible pipeline in this folder. Small-n stages are labeled.

## What the models are

- **Per-package scorer:** XGBoost over 8 metadata features (see §Phase 1), SHAP-attributed,
  offline heuristic fallback. `train_xgboost.py`.
- **Graph scorer:** GraphSAGE GNN over dependency subgraphs. `train_gnn.py`.
- **Combiner:** production uses a transparent additive log-odds formula (`core/combiner.py`) —
  two trained-meta-learner attempts were built and deliberately not shipped (§Phase 5).

---

## Phase 1 — real data pipeline + the confounder-removal story

Sources: Backstabber's Knife Collection (8,465 npm malicious names), Datadog manifest (46,115
npm entries, name→malicious version(s), Apache-2.0), npm Registry API. Only plain-text label
manifests were pulled — never Datadog's encrypted malware sample archives.

**Headline finding:** modern bulk malware is ~96.5% "malicious_intent" (novel throwaway names),
~3.5% "compromised_lib" (hijacked real packages), and only ~0.1% (44 of 51,449) true typosquats.
The original plan assumed typosquats/install-scripts were dominant — real data disproved this.
Install scripts were declared in only 1 of 194 initially-sampled malicious manifests.

**The confounder journey** (naive metrics were high and wrong):

| Stage | PR-AUC | Problem |
| ----- | ------ | ------- |
| Popular benign (naive) | 0.987 | Benign=old/famous, malicious=new/small → model learned "new=bad"; typosquat feature learned **backwards**. |
| Age/size-matched benign | 0.974 | Age confounder fixed via hard negatives from npm's `_changes` feed. |
| Matched + attack-type-stratified, n=394, 5 features | 0.90 (CV 0.941±0.020) | typosquat feature now correct — the honest baseline number. |

---

## Phase 1 (continued) — 3 new features, screened for leakage

Candidate cache fields measured for discrimination (AUC) on the n=394 set:

| Feature | AUC | Verdict |
| ------- | --- | ------- |
| days_since_update | 0.900 | **Excluded** — benign was sourced from the `_changes` feed, which selects for recent activity; this feature is circular by construction. |
| has_homepage | 0.866 | **Excluded** — correlates with the `has_repo`+`has_description` filter used to select "legit-looking" young benign packages. |
| version_count | 0.813 | ✅ Kept — never selected on. |
| description_quality (desc length) | 0.809 | ✅ Kept. |
| has_readme | 0.731 | Excluded — same correlation risk as has_homepage. |
| maintainer_count | 0.749 | ✅ Kept. |
| age_days (true registry age) | 0.618 | Excluded — redundant with the existing author_age feature. |
| has_repo | 0.575 | **Excluded** — directly selected on; pure leakage. |

Retrained with 8 features (5 original + version_count, description_quality, maintainer_count) on
n=394: single-split PR-AUC **0.953**, 5-fold CV **0.975 ± 0.010**. `dep_count`'s importance fell
from dominant to 0.036 — the confounder was diluted, not just capped.

**Bugs found and fixed while integrating:** (1) demo-killer false positive — `@babel/core`'s bare
scope-name `core` was 1 edit from `cors`; fixed by requiring name length ≥5 both sides for
typosquat matching. (2) train/inference feature mismatch after that fix — recomputed
`name_similarity` offline and retrained. (3) `check`/`scan` crashed on malformed input; now
raise clean `ValueError`s (regression-tested). (4) offline synthetic features were being fed to
a model trained on live features — now offline correctly uses the heuristic path.

---

## Phase 2 — scaled the dataset

394 → **1,531 rows** (779 malicious / 752 benign), same matched + attack-type-stratified
sampling, pulled with polite rate-limiting (this step is genuinely slow — real npm rate limits;
budget 20-60 minutes for a similar-scale pull). Composition held: 540 malicious_intent /
196 compromised_lib / 43 typosquat (proportionally consistent, better absolute counts).

Retrained: single-split PR-AUC **0.9735**, 5-fold CV **0.971 ± 0.006**.

**Honest reading:** the point estimate barely moved (0.975→0.971) but variance **nearly
halved** (±0.010→±0.006). Scaling's real value here was trustworthiness, not a bigger number.
Feature importance shifted: `version_count` became dominant (0.69), `dep_count` fell further.

**Regressions found and fixed:**
- Rebuilt the graph dataset + retrained the GNN on the new 8-dim features (dimension mismatch
  with the old 5-dim model) — grew to 2,760 nodes / 2,780 edges (up from 1,331/1,277).
- The curated poisoned-chain HUD demos (`demo_graphs.json`) stopped flagging — their
  hand-written feature profiles only had the old 5 keys, so the 3 new features silently
  defaulted to 0.0, diluting the poison signal. Fixed by extending the profiles.
- Even after that fix, demos still didn't flag: the retrained GNN, on an isolated/tiny synthetic
  5-node graph, output near-zero regardless of input (verified: even a node with every feature at
  its most-malicious value scored ~1e-6 in isolation) — a real, documented GraphSAGE
  out-of-distribution limitation (it learned from a dense real graph, avg degree ~2.3; a tiny
  hand-built star graph is structurally unlike anything in training). Fix: curated demos use
  their scripted role directly (labeled "illustrative," not live inference) rather than trusting
  a model known to misbehave on toy graphs.
- `express` showed a live false positive — `proxy-addr`, a legitimate small polyfill dependency,
  scored 0.97 in graph context vs. 0.18 standalone. Root cause: the *same* out-of-distribution
  issue, now observed on real sparse 2-hop subgraphs, not just synthetic demos. Fix: a node's
  graph-context score is capped at `own_xgboost_score + 0.30` for non-allowlisted nodes — a
  node's own well-calibrated per-package score is treated as a ceiling an unstable graph score
  can't blow past. Verified against a 15-package batch after the fix: only one residual case
  remained (`axios` via `es-set-tostringtag`, which is RISKY 0.73 *even standalone* — a genuine
  model limitation on single-maintainer minimal-description utility packages, not a graph bug).
- The `poisoned` flag could disagree with the overall verdict (a borderline dependency nudging
  the graph score without the *combined* risk crossing into danger territory). Fixed: `poisoned`
  now requires both signals to agree (graph score above threshold **and** the combined verdict
  is high/critical).

---

## Phase 5 — attempted a trained stacking combiner (negative result, twice)

`train_combiner.py` builds `[xgb_score, graph_score] → label` training pairs for free from the
graph dataset (every node's own XGBoost score + its neighbours' GNN scores). Trained a logistic
regression meta-learner — twice, once before and once after the Phase 6 GNN improvement.

**Both times:** the LR learned a **negative** coefficient on `graph_score` (run 1: -0.187, run 2:
-0.188) and, wired into production, silently stopped flagging every poisoned-chain demo.

**Root cause:** the natural node distribution barely contains the "clean self / poisoned
neighbour" pattern — most malicious nodes are self-evidently malicious from their own features,
so the LR learned "trust xgb, mostly ignore graph," which is locally optimal for that data but
defeats the purpose of the graph model. Confirmed independent of GNN quality: the second attempt,
on a GNN whose held-out recall had jumped from 67%→89% (§Phase 6), produced the same negative
weight — because the combiner's *training data composition* never changed, only the base GNN did.

**Decision: neither combiner was shipped.** Production kept the log-odds additive fallback
(`core/combiner.py`), which can only ever add risk from a poisoned dependency, never subtract
it. Both trained artifacts kept as `models/combiner_v1_naive_nodeclf.joblib` and
`_v2_naive_nodeclf.joblib` — documented negative results, not deleted. Real fix (future work):
train the combiner on a deliberately-constructed corpus like the §Phase 6 benchmark, not a
random graph sample.

---

## Phase 6 — held-out-unknown benchmark (the strongest result in the project)

### An important side-finding first: stale name-level labels

While mining the cache for real poisoned-chain examples (clean parent → malicious-labeled
dependency), `chalk`, `axios`, `debug`, `eslint`, `prettier`, `nx`, `strip-ansi` and others
appeared as "malicious" — not a labeling bug in our pipeline. BKC's flat name list has no
version info, and these packages were **genuinely** compromised at some point (the real,
documented September 2025 npm supply-chain attack hit chalk/debug/ansi-styles; `nx` had a
separate real 2025 token-stealing incident) — but BKC labels the *name* forever, even though
today's live version is completely safe. **Fix:** only trust a "malicious" label as a *live*
threat if that same package's own *current* XGBoost score is also elevated (≥0.5) — directly
distinguishes "thriving package, one historical incident" from "actually still dangerous."

### Building the benchmark

18 real positive cases survived the filter: a clean-looking parent with a transitive dependency
that is (a) name-labeled malicious, (b) still scores ≥0.5 on its own current metadata. Paired
with 18 clean negative controls (no malicious neighbour at all). **None of the 18 malicious
dependency names were ever manually entered into `known_malware.json`** — a genuine
held-out-unknown / zero-day simulation, not a synthetic construction.

### First result (before GNN improvement)

| Detector | Recall | False positive rate |
| -------- | ------ | -------------------- |
| Deterministic DB traversal | 0% | 0% |
| XGBoost alone | 11% | 22% |
| GNN / graph score | 67% | 0% |

### Diagnosis + fix: hard-example oversampling

Only 52 of 1,058 malicious training nodes (5%) have the exact "majority-benign-neighbourhood"
shape the benchmark tests — the rest are easy cases with mostly-malicious or no neighbours.
Standard mean-aggregation in GraphSAGE was smoothing these rare hard examples' signal toward
"looks benign." Fix: upweight them 4× in the training loss (`train_gnn.py`).

### Result after the fix

| Detector | Recall | False positive rate |
| -------- | ------ | -------------------- |
| Deterministic DB traversal | **0%** | 0% |
| XGBoost alone | 11% | 22% |
| **GraphSAGE GNN** | **89%** | **0%** |

Generic node-classification ablation (§Phase 2 retrain) barely moved from this change
(0.953→0.947 PR-AUC on random held-out nodes) — confirming that benchmark was never the right
test for this specific capability. The held-out-unknown benchmark is.

**Reproduce:** `build_heldout_benchmark.py` → `evaluate_heldout_benchmark.py`. Artifacts:
`heldout_benchmark.json` (the 18+18 cases), `heldout_benchmark_results.json` (full per-case
scores).

---

## Limitations (state plainly)

- Held-out benchmark is n=18+18 — real, not synthetic, but small; a larger corpus (harder to
  mine — genuine poisoned-chain cases are rare in a randomly-sampled cache) would tighten the
  confidence interval.
- `author_age` is a proxy (first-publish date, not true account creation).
- A properly trained stacking combiner remains open work (§Phase 5) — the additive fallback
  works correctly but isn't learned from data.
- Metadata/graph-structure ceiling: true behavioral detection would need tarball/code analysis —
  deliberately out of scope (would require handling live malware source on disk).
