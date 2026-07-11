# Data Sources — Provenance

Real, verified sources only. No fabricated numbers. Counts below were checked against the
live repositories on 2026-07-08 — re-verify if you re-pull later, upstream datasets grow.

## 1. Backstabber's Knife Collection

- Site: https://dasfreak.github.io/Backstabbers-Knife-Collection/
- Repo: https://github.com/dasfreak/Backstabbers-Knife-Collection
- File used: `data/packages.json`
- **Format:** flat dict of `{ecosystem: [package_name, ...]}`. Names only — no version,
  no publish date, no per-package metadata. We fetch metadata ourselves via the npm Registry
  API (`packageguard.core.registry`).
- **Verified counts (2026-07-08):** composer 5, gem 835, maven 13, npm **8,465**,
  pypi **3,892**, vscode-extension 35.
- Note: the original 2020 paper (arXiv:2005.09535) analyzed 174 hand-curated packages;
  the live dataset has grown well beyond that since. Cite the paper for the methodology,
  the live repo for the current package list.
- License: check repo for terms before redistribution; used here for research/education only.

## 2. Datadog Malicious Software Packages Dataset

- Repo: https://github.com/DataDog/malicious-software-packages-dataset
- License: **Apache-2.0**, attribution required (see repo `NOTICE`/`LICENSE`).
- Files used: `samples/npm/manifest.json`, `samples/pypi/manifest.json`
- **Format:** `{package_name: null | [version, ...]}`. `null` = every version is malicious
  (malicious-intent package); a version list = only those versions are compromised
  (supply-chain hijack of an otherwise-legitimate package).
- **Verified counts (2026-07-08):** 46,115 npm manifest entries; smaller PyPI manifest
  (~50KB vs npm's ~1.5MB).
- **Deliberately NOT downloaded:** the actual malware sample archives under `samples/*/`
  (encrypted zips, password `infected`). The repo's own README states "this repository
  contains actively malicious software... do not run it on your machine." We only need
  labels (name + version), which the manifest provides — no reason to pull live malware
  payloads onto a development machine.

## Correction to earlier planning docs

`packageguard_v3_final.md` / `packageguard_v4_final.md` originally estimated "~2,500"
(Backstabber) and "~10,000+" (Datadog) packages. Those were placeholder guesses written
before the datasets were actually inspected. Real verified figures are the ones above —
larger in both cases. v4 has been corrected; this file is the source of truth going forward.

## What "benign" packages come from

Not a curated dataset — pulled live from the npm Registry API:
- npm's own **most-depended-upon** package list (`https://registry.npmjs.org` + a static
  top-1000 seed list already in `core/features.py::TOP_PACKAGES`, expanded for training).
- Deliberately includes **hard negatives**: legitimate packages that have install/lifecycle
  scripts, are recently published, or have low download counts — so the model doesn't just
  learn "has a script = bad" from an unrepresentative benign set.

## Pipeline

See `training/build_dataset.py` — pulls the manifests above (already cached in
`training/raw_data/`), resolves each labeled name (+ version where known) against the live
npm Registry API through `packageguard.core.registry`, runs the existing
`packageguard.core.features.extract_features()` over every resolved package, and writes one
labeled Parquet file for `train_xgboost.py` to consume.
