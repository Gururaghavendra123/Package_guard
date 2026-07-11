# PackageGuard — Technical Report (Semester 7)

**Team:** Gururaghavendra P (23CZ037), Tharun K S (23CZ055)
**Guide:** Mr. Prabhu
**Type:** Final-year project — software supply-chain security tool (ML + systems)

> Written for a reader who knows ML but not security. Every number is from real data via the
> reproducible pipeline in `packageguard/training/`. Results are honest and small-sample-caveated.

---

## 1. Problem

Modern apps are assembled from thousands of third-party packages (npm, PyPI). Attackers publish
**malicious packages** — either standalone malware with plausible names, or by hijacking a real
popular package — and developers install them by mistake. This is the *software supply-chain
attack* class (real incidents: `event-stream`, `ua-parser-js`, `node-ipc`). Existing tools like
`npm audit` only know about *disclosed CVEs*, so they miss brand-new malware.

**PackageGuard** is a tool that scores a package's risk **before** you install it, and scans an
existing project to find compromised dependencies with fix steps.

---

## 2. What it does

| Command | Purpose |
| ------- | ------- |
| `packageguard check <pkg>` | Score one package's install risk + explain why (per-feature attribution). |
| `packageguard scan <project>` | Parse a project's `package-lock.json`, flag known-malicious dependencies, give remediation steps. |
| `packageguard serve` | Launch the **HUD dashboard** — the same engine in a browser UI (for demos / non-CLI users). |

One engine (`packageguard.core`), two front-ends (CLI + FastAPI web). No logic is duplicated.

---

## 3. How it works (architecture)

```
                 ┌─────────── packageguard.core (one engine) ───────────┐
 CLI (Typer) ───▶│  features → scorer (XGBoost / heuristic) → verdict   │
 Web (FastAPI)──▶│  lockfile parser → known-malware DB → remediation    │
                 └──────────────┬─────────────────────┬─────────────────┘
                                │                      │
                       npm Registry API        bundled model + malware DB
```

- **Feature extraction** — 5 per-package signals from npm metadata.
- **Scorer** — trained **XGBoost** for live-fetched packages; a transparent **heuristic** fallback
  for offline use (the model is trained on live features, so feeding it offline synthetic values
  would be incoherent — it correctly falls back).
- **Explainability** — SHAP-style per-feature attribution (why a package was flagged), shown as
  diverging bars in the CLI and HUD.
- **Scan** — pure `package-lock.json` parsing (no code execution) + a bundled known-malware
  database + a rule-based remediation generator.

---

## 4. Data

| Source | Content | Verified size (2026-07) |
| ------ | ------- | ----------------------- |
| Backstabber's Knife Collection | Malicious package **names** | 8,465 npm + 3,892 PyPI |
| Datadog Malicious Packages | `manifest.json`: name → malicious version(s) | 46,115 npm entries |
| npm Registry API | Live per-package metadata (author, deps, scripts, dates) | on demand |
| npm `_changes` feed | Recently-published packages (for young benign) | on demand |

**Safety:** only plain-text label manifests were downloaded. The actual malware sample archives
(Datadog's encrypted zips, explicitly marked "do not run") were **never** pulled. No malicious
code touches the machine.

**Features (5):** name similarity to popular packages (Levenshtein-based typosquat detector),
install-script presence, author account age (first-publish-date proxy), publish-timing anomaly,
dependency count.

---

## 5. Model & results — the honest story

### 5.1 Key empirical finding: modern malware ≠ typosquats

The project originally assumed typosquatting + install scripts were the dominant signals. The real
current data disproves this:

| Attack type | Share of 51,449 malicious npm packages |
| ----------- | -------------------------------------- |
| malicious_intent (novel throwaway names) | ~96.5% |
| compromised_lib (hijacked real packages) | ~3.5% |
| true typosquats | ~0.1% (44 total) |

Install scripts were declared in only **1 of 194** malicious manifests — modern malware ships its
payload in tarball code, not the manifest. **Metadata alone therefore has a ceiling** — an
important, defensible finding, not a defect.

### 5.2 The confounder-removal journey (core methodological contribution)

Naive metrics were high and **wrong**. We removed three confounders in sequence:

| Benign set | PR-AUC | Problem removed |
| ---------- | ------ | --------------- |
| Popular (naive) | 0.987 | none yet — benign was old/famous, malicious new/small → model learned "new = bad" (age confounder), and the typosquat feature learned *backwards*. |
| Age/size-matched (hard negatives from `_changes` feed) | 0.974 | age confounder |
| Matched + attack-type-stratified | **~0.90** | typosquat feature now has real positives → learns correctly. This is the honest number. |

### 5.3 Honest metrics (combined model)

- **5-fold cross-validated PR-AUC = 0.94 ± 0.02** (ROC-AUC 0.94 ± 0.02). PR-AUC is the headline
  metric — chosen over accuracy because of class imbalance. Single held-out split ≈ 0.90; CV is
  the more robust figure on a small dataset.
- Per-attack-type recall: malicious_intent ~0.91, typosquat ~0.86, compromised_lib ~0.78.
- Feature importance: author_age ~0.41, name_similarity ~0.39, dep_count ~0.13,
  publish_timing ~0.07, install_script ~0.00.
- `compromised_lib` (hijacked packages) is hardest on metadata — precisely the case the
  **Sem 8 graph model** is designed to catch.

### 5.4 False-positive control

Two guardrails keep legitimate packages from being wrongly flagged:
- **Popularity allowlist** — packages in npm's verified-popular set (e.g. `@types/node`,
  `@babel/core`) have their risk capped. This is standard in real scanners and offsets a known
  confounder: the model slightly over-reads "0 runtime dependencies" as suspicious, which would
  otherwise misfire on legitimate 0-dep packages like `@types/*`. The known-malware database still
  overrides the allowlist, so a *compromised version* of a popular package is still flagged.
- **Robust input handling** — invalid package names and malformed lockfiles are rejected with
  clear errors instead of crashing (covered by regression tests).

---

## 6. Limitations (state these plainly)

- Small sample (few hundred rows) — metrics are preliminary; scaling up is the next step.
- `author_age` is a proxy (first-publish date; npm doesn't expose true account age).
- ~3% of labeled malware is already purged from npm and can't be feature-extracted (skipped, not
  faked).
- Young-benign packages come from an unlabeled feed filtered by a legitimacy heuristic; low
  residual label noise, documented.
- Metadata ceiling: true behavioral detection needs tarball/code analysis (out of scope for Sem 7
  — would require handling live malware source). This motivates Sem 8.

---

## 7. Tech stack

Python · Typer (CLI) · Rich (terminal UI) · FastAPI + Uvicorn (web) · vanilla HTML/CSS/JS HUD ·
XGBoost + scikit-learn + SHAP (ML) · httpx (registry client) · pandas/pyarrow (data) ·
PyTorch Geometric (GraphSAGE, Sem 8).

---

## 8. Semester split

- **Sem 7 (done):** working CLI + HUD, real trained XGBoost model, honest evaluation, reproducible
  data pipeline. A real tool, not a prototype.
- **Sem 8 (planned):** GraphSAGE GNN over the dependency graph to catch the hijacked-package case
  metadata misses; a stacking combiner; the live dependency-graph panel in the HUD; a
  held-out-unknown benchmark + ablation study.
