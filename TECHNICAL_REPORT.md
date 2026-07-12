# PackageGuard — Technical Report (Semester 7 / early Semester 8)

**Team:** Gururaghavendra P (23CZ037), Tharun K S (23CZ055)
**Guide:** Mr. Prabhu
**Type:** Final-year project — software supply-chain security tool (ML + systems)

> Written for a reader who knows ML but not security. Every number is from real data via the
> reproducible pipeline in `packageguard/training/`. Results are honest and caveated where small.

---

## 1. Problem

Modern apps are assembled from thousands of third-party packages (npm, PyPI). Attackers publish
**malicious packages** — either standalone malware with plausible names, or by hijacking a real
popular package — and developers install them by mistake. This is the *software supply-chain
attack* class (real incidents: `event-stream`, `ua-parser-js`, the 2025 chalk/debug hijack, the
2025 `nx` token-stealing attack). Existing tools like `npm audit` only know about *disclosed
CVEs*, so they miss brand-new malware.

**PackageGuard** is a tool that scores a package's risk **before** you install it, scans an
existing project to find compromised dependencies with fix steps, and — uniquely — analyses a
package's **dependency graph** to catch threats hiding in a transitive dependency.

---

## 2. What it does

| Command | Purpose |
| ------- | ------- |
| `packageguard check <pkg>` | Score one package's install risk + explain why (per-feature attribution). |
| `packageguard scan <project>` | Parse a project's `package-lock.json`, flag known-malicious dependencies, give remediation steps. |
| `packageguard graph <pkg>` | Analyse a package's dependency graph with a graph neural network (catches poisoned chains). |
| `packageguard serve` | Launch the **HUD dashboard** — the same engine in a browser UI. |

One engine (`packageguard.core`), two front-ends (CLI + FastAPI web). No logic is duplicated.

---

## 3. How it works (architecture)

```
                 ┌────────────────── packageguard.core ──────────────────┐
 CLI (Typer) ───▶│ features → XGBoost/heuristic → verdict                │
 Web (FastAPI)──▶│ dependency graph → GraphSAGE GNN → combiner → verdict │
                 │ lockfile parser → known-malware DB → remediation      │
                 └──────────────┬─────────────────────┬───────────────────┘
                                │                      │
                       npm Registry API        bundled models + malware DB
```

- **Per-package scorer** — trained **XGBoost** for live-fetched packages; a transparent
  **heuristic** fallback for offline use.
- **Graph scorer** — a trained **GraphSAGE** GNN scores a package's dependency neighbourhood,
  catching *poisoned chains* the per-package scorer structurally cannot see.
- **Explainability** — SHAP-style per-feature attribution shown as diverging bars.
- **Scan** — pure `package-lock.json` parsing (no code execution) + a bundled known-malware
  database + a rule-based remediation generator.

---

## 4. Data

| Source | Content | Verified size |
| ------ | ------- | -------------- |
| Backstabber's Knife Collection | Malicious package **names** | 8,465 npm + 3,892 PyPI |
| Datadog Malicious Packages | `manifest.json`: name → malicious version(s) | 46,115 npm entries |
| npm Registry API | Live per-package metadata (author, deps, scripts, dates, versions, description, maintainers) | on demand, cached |
| npm `_changes` feed | Recently-published packages (for young, hard-negative benign) | on demand |

**Safety:** only plain-text label manifests were downloaded. The actual malware sample archives
(Datadog's encrypted zips, explicitly marked "do not run") were **never** pulled.

**Training dataset (scaled):** 1,531 labeled rows (779 malicious / 752 benign), matched-benign +
attack-type-stratified sampling (up from an initial 394-row proof-of-concept).

**8 features** (5 original + 3 added after screening the registry cache for real, non-leaked
signal): name similarity to popular packages (typosquat detector), install-script presence,
author account age (first-publish-date proxy), publish-timing anomaly, dependency count,
**release/version count**, **description quality**, **maintainer count**. Four candidate fields
(`has_repo`, `has_homepage`, `has_readme`, `days_since_update`) were measured (AUC 0.57–0.90) but
**excluded** — they correlate with the filters used to select benign training samples (selecting
"legit-looking young packages" partly *by* repo/description presence, and via the recency-biased
`_changes` feed) and would have been circular, silently-leaked features.

---

## 5. Per-package model — the honest story

### 5.1 Key empirical finding: modern malware ≠ typosquats

The project originally assumed typosquatting + install scripts were the dominant signals. The
real current data disproves this:

| Attack type | Share of 51,449 malicious npm packages |
| ----------- | -------------------------------------- |
| malicious_intent (novel throwaway names) | ~96.5% |
| compromised_lib (hijacked real packages) | ~3.5% |
| true typosquats | ~0.1% (44 total) |

Install scripts were declared in only **1 of 194** malicious manifests initially sampled — modern
malware ships its payload in tarball code, not the manifest. Metadata alone has a real ceiling on
this dominant attack class — the direct motivation for the graph model (§8).

### 5.2 The confounder-removal journey (core methodological contribution)

Naive metrics were high and **wrong**. Each step removed one specific flaw:

| Stage | PR-AUC | Problem removed |
| ----- | ------ | --------------- |
| Popular benign (naive) | 0.987 | none yet — benign was old/famous, malicious new/small → model learned "new = bad", and the typosquat feature learned **backwards**. |
| Age/size-matched (hard negatives from `_changes` feed) | 0.974 | age confounder |
| Matched + attack-type-stratified, 5 features, n=394 | 0.90 (CV 0.941 ± 0.020) | typosquat feature now correct |
| **+3 clean features (§4), n=1,531** | **CV 0.971 ± 0.006** | dilutes the `dep_count` confounder; tighter variance from more data |

### 5.3 Honest metrics (current model)

- **5-fold cross-validated PR-AUC = 0.971 ± 0.006.** Scaling the dataset ~4x (394→1,531 rows)
  barely moved the point estimate (0.975→0.971 at the 8-feature stage) but **nearly halved the
  variance** — the honest value of more data here was trustworthiness, not a bigger number.
- Feature importance shifted materially with the 3 new features: `version_count` and
  `description_quality` now dominate; `dep_count`'s earlier outsized weight (a confounder) fell
  to near-negligible; `install_script` remains ~0.00 (still rarely declared).

### 5.4 False-positive fixes (found via testing, not assumed)

Real bugs caught and fixed during hardening, not hidden:
- **Scoped bare-name collision** — `@babel/core`'s bare name `core` was 1 edit from `cors`,
  falsely flagging a top-10 package. Fixed: typosquat matching requires length ≥5 both sides.
- **A popularity allowlist** caps risk for verified-popular packages (standard practice in real
  scanners); the known-malware DB still overrides it, so a compromised version of a popular
  package is still flagged.
- **NOT FOUND state** — checking a name that doesn't exist on npm (e.g. a typo) now says so
  explicitly instead of scoring a meaningless "ghost" result from offline synthetic features.
- **Historical-incident notice** — a package whose *current* version is safe but which had a
  **past** recorded incident (e.g. `eslint-scope`, hijacked in 2018, long since patched) now shows
  an amber informational note rather than either a false alarm or silence.
- **Robust input handling** — invalid names and malformed lockfiles are rejected with clear
  errors instead of crashing (regression-tested).

---

## 6. Limitations (state these plainly)

- `author_age` is a proxy (first-publish date; npm doesn't expose true account age).
- A small fraction of labeled malware is already purged from npm and can't be feature-extracted
  (skipped, reported honestly, not synthesized).
- Young-benign packages come from an unlabeled feed filtered by a legitimacy heuristic; low
  residual label noise, documented.
- **Package-name-level malware labels can be stale.** Investigating Phase 6 (§8) surfaced that
  BKC's flat malicious-name list has no version info, so it can label a package name malicious
  forever even after a brief, real, long-patched incident (e.g. the 2025 chalk/debug/ansi-styles
  hijack, or the 2025 `nx` attack) — the *name* is flagged even though today's live version is
  completely safe. Any pipeline step that trusts the raw name list without checking current
  metadata risks this false-positive class; we corrected for it when building the held-out
  benchmark (§8) by requiring the labeled dependency to *also* score suspicious on its own
  current metadata.
- Metadata ceiling: true behavioral detection needs tarball/code analysis (out of scope — would
  require handling live malware source). This motivates the graph model.

---

## 7. Tech stack

Python · Typer (CLI) · Rich (terminal UI) · FastAPI + Uvicorn (web) · vanilla HTML/CSS/JS HUD ·
XGBoost + scikit-learn + SHAP (ML) · httpx (registry client) · pandas/pyarrow (data) ·
PyTorch Geometric (GraphSAGE).

---

## 8. The graph neural network — dependency-graph scoring

The per-package model scores each package **in isolation**, so it structurally cannot catch a
*poisoned chain*: a clean-looking package whose transitive dependency is malicious. A
**GraphSAGE GNN** scores packages using their **dependency-graph neighbourhood** instead.

### 8.1 Method
- A 2-layer GraphSAGE (PyTorch Geometric) does node classification over dependency subgraphs;
  node features are the same 8 per-package features, so any lift is attributable to *structure*.
- Training graph is built from the registry cache (2,760 nodes, 2,780 edges — grown from an
  initial 1,331-node graph as more packages were analysed) — real dependency structure, zero
  dedicated new API calls.
- **Hard-example oversampling:** only ~5% of malicious training nodes have the exact
  "majority-benign-neighbourhood" shape a real poisoned chain has; standard mean-aggregation was
  smoothing their signal toward "looks benign." Upweighting these ~52 hard examples 4× in the
  training loss was the single most effective GNN change made (§8.3).

### 8.2 Generic ablation — does structure add signal on random nodes?

On held-out nodes from the cache graph (a *general* node-classification benchmark, not
specifically poisoned-chain cases):

| Model | PR-AUC | ROC-AUC |
| ----- | ------ | ------- |
| XGBoost (features only) | 0.95 | 0.96 |
| GraphSAGE (features + structure) | 0.95 | 0.96 |
| Structure delta | ~0 |  |

Honest reading: as the per-package features got richer (§5), this *generic* benchmark's
structure advantage shrank to near-zero. This does **not** mean the graph model is useless — it
means generic node classification isn't the right test for what the graph model is *for*. §8.3
is the right test.

### 8.3 The real test: a held-out-unknown poisoned-chain benchmark

Built from **real** cache data, not synthetic: 18 genuine cases where a clean-looking parent
package has a transitive dependency that is (a) labeled malicious in BKC/Datadog, and (b) still
scores suspicious on its own *current* metadata (filtering out the stale-label false-positive
class from §6). Paired with 18 clean negative controls (no malicious neighbour at all).

**Critically, none of the 18 malicious dependency names were ever manually entered into our own
known-malware database** — a genuine held-out-unknown / zero-day simulation, answering the
concern raised in the original project plan: does the GNN generalise, or does it just duplicate
a lookup table?

| Detector | Recall (catches the real threat) | False positive rate |
| -------- | --------------------------------- | -------------------- |
| Deterministic DB traversal (what `scan` does) | **0%** | 0% |
| XGBoost alone (per-package) | 11% | 22% |
| **GraphSAGE GNN (graph context)** | **89%** | **0%** |

The DB traversal scoring exactly 0% is the point being proven: a lookup table cannot know about
a threat it has never seen. XGBoost alone mostly misses these cases by construction (the parent
itself looks clean). The GNN — using only structure and each dependency's own features, never
the DB — catches 89% of real, previously-unlabeled threats with zero false alarms on clean
projects. This is the strongest evidence in the project for the graph model's value.

Reproduce: `training/build_heldout_benchmark.py` → `training/evaluate_heldout_benchmark.py`.

### 8.4 A negative result, kept honest: the stacking combiner

A **real** logistic-regression meta-learner was trained (`training/train_combiner.py`) to merge
`[xgb_score, graph_score]` into a calibrated probability — twice, once before and once after the
GNN improvement in §8.1. Both times it learned a **negative** weight on the graph signal and, when
wired into production, silently stopped flagging every poisoned-chain case.

Root cause, verified: the combiner's natural training distribution (any node's own score vs. its
neighbours' scores) contains very little of the specific "clean parent / poisoned dependency"
pattern — most malicious nodes are self-evidently malicious from their own features, so the
model learned "trust the per-package score, mostly ignore the graph" for that distribution. This
is distinct from (and confirmed independent of) the GNN's own accuracy, which improved
substantially over the same period (§8.1, §8.3).

**Decision: neither trained combiner was shipped.** Production uses a transparent log-odds
formula in `core/combiner.py` that can only ever *add* risk from a poisoned dependency, never
subtract it — a design that cannot fail the way the trained version did. Both trained artifacts
are kept (`combiner_v1_naive_nodeclf.joblib`, `combiner_v2_naive_nodeclf.joblib`) as documented
negative results rather than deleted. A real stacking combiner needs a training set built the
same deliberate way as the §8.3 benchmark, not a random graph sample — clear future work.

### 8.5 The poisoned-chain demo (visualised live in the HUD)

For a clean-looking parent with a malicious transitive dependency:
- XGBoost (per-package): **~0.1 → looks safe** (misses it entirely).
- GNN flags the malicious dependency at **~0.95**; combined score rises into RISKY/DO NOT INSTALL.

The HUD GRAPH panel visualises this live: the poisoned node pulses red, risk propagates up the
edges to the clean-looking parent — exactly the failure mode of per-package scanners, and exactly
what §8.3 proves the model does on real, previously-unseen threats.

### 8.6 Status

- **Per-package model (done):** CLI + HUD, trained XGBoost on 1,531 rows / 8 features, honest
  cross-validated evaluation, reproducible pipeline.
- **Graph model (done):** GraphSAGE GNN with hard-example oversampling, held-out-unknown
  benchmark with a deterministic-traversal baseline (the exact rigor flagged as needed in the
  original plan), live HUD visualisation.
- **Documented, not hidden, open item:** a properly trained stacking combiner needs a larger,
  deliberately-constructed poisoned-chain training corpus (§8.4) — the honest state of the art
  right now is the additive fallback formula, which works correctly in practice (§8.3, §8.5).
