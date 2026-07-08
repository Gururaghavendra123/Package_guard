"""Phase 1 — build the labeled feature dataset from real sources.

Sources (see DATA_SOURCES.md for provenance/counts):
  - Backstabber's Knife Collection (malicious package *names*, no version info)
  - Datadog malicious-software-packages-dataset manifest (name -> malicious version(s))
  - npm Registry search API (benign candidates, incl. deliberate hard negatives)

Every row is backed by a REAL npm Registry API response. If a labeled malicious package
has been removed from the registry (common after takedown) we SKIP it rather than
synthesize a value — training data integrity matters more than row count. Skip rate is
reported, not hidden.

Usage:
    python training/build_dataset.py --malicious-limit 400 --benign-limit 400 \
        --out training/dataset.parquet
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from packageguard.core import registry  # noqa: E402
from packageguard.core.features import extract_features  # noqa: E402

RAW_DIR = Path(__file__).resolve().parent / "raw_data"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
NPM_CHANGES = "https://replicate.npmjs.com/_changes"

# Diverse + deliberately hard-negative-inducing search terms. Not just "popular" —
# native-addon / install-script terms surface legitimate packages that DO ship
# lifecycle scripts, so the benign set isn't trivially separable from malware.
BENIGN_SEARCH_TERMS = [
    "react", "vue", "webpack", "babel", "eslint", "test", "cli", "util", "http",
    "server", "auth", "logger", "date", "parser", "stream", "crypto", "aws", "docker",
    "graphql", "database",
    # hard-negative bait: legitimate packages commonly ship install/build scripts
    "node-gyp", "prebuild", "native addon", "postinstall", "bcrypt", "sharp", "canvas",
]


def load_malicious_labels(ecosystem: str = "npm") -> list[dict]:
    """Merge BKC names + Datadog manifest into one labeled list. Real data only."""
    labels: dict[str, dict] = {}

    bkc = json.loads((RAW_DIR / "bkc_packages.json").read_text(encoding="utf-8"))
    for name in bkc.get(ecosystem, []):
        labels[name] = {"name": name, "version": None, "source": "bkc"}

    dd_file = RAW_DIR / f"datadog_{ecosystem}_manifest.json"
    if dd_file.exists():
        manifest = json.loads(dd_file.read_text(encoding="utf-8"))
        for name, versions in manifest.items():
            version = versions[0] if isinstance(versions, list) and versions else None
            # Datadog entry wins if both sources list it (has more precise version info)
            labels[name] = {"name": name, "version": version, "source": "datadog"}

    values = list(labels.values())
    # IMPORTANT: source JSON order is NOT random — BKC/Datadog list order clusters by
    # ingestion batch, not by attack type. Slicing [:limit] without shuffling first
    # systematically under-samples certain attack types (e.g. typosquats), which is
    # exactly what happened in the first real run of this pipeline. Shuffle with a
    # fixed seed so any --malicious-limit gets a representative cross-section, and
    # results are still reproducible.
    random.Random(42).shuffle(values)
    return values


def fetch_popular_benign(limit: int, exclude: set[str]) -> list[str]:
    """Pull popular (old, established) benign names from npm's live search API."""
    names: dict[str, None] = {}
    per_term = max(20, limit // len(BENIGN_SEARCH_TERMS) + 1)
    for term in BENIGN_SEARCH_TERMS:
        if len(names) >= limit:
            break
        try:
            resp = httpx.get(NPM_SEARCH, params={"text": term, "size": per_term}, timeout=10)
            resp.raise_for_status()
            for obj in resp.json().get("objects", []):
                name = obj["package"]["name"]
                if name not in exclude:
                    names[name] = None
        except httpx.HTTPError as e:
            print(f"  [warn] search '{term}' failed: {e}", file=sys.stderr)
        time.sleep(0.15)
    return list(names)[:limit]


def _is_legit_benign(name: str) -> bool:
    """Light legitimacy filter for young benign candidates pulled from the changes feed.

    Requires a linked repository AND a description. Rationale: throwaway malware packages
    published to the feed usually lack both; legitimate young packages usually have them.
    This is a HEURISTIC to reduce (not eliminate) label noise — the feed is unlabeled, so a
    freshly-published, not-yet-detected malicious package could slip in. Residual noise is
    documented, not hidden. Note: `repository`/`description` are NOT model features, so this
    filter does not leak into or bias the 5 trained features.
    """
    doc = registry.fetch_raw_doc(name)
    if not doc:
        return False
    latest = (doc.get("dist-tags") or {}).get("latest")
    manifest = (doc.get("versions") or {}).get(latest, {}) if latest else {}
    has_repo = bool(manifest.get("repository") or doc.get("repository"))
    has_desc = bool(manifest.get("description") or doc.get("description"))
    return has_repo and has_desc


def fetch_recent_benign(limit: int, exclude: set[str], pool_multiplier: int = 6) -> list[str]:
    """Pull recently-published (young, small) legitimate packages from npm's `_changes` feed.

    These are the HARD NEGATIVES: young + small like the malicious set, so the model can't
    separate classes on the age/size confounder. Pages the descending changes feed, skips
    design docs and known-malicious names, then keeps only names passing `_is_legit_benign`.
    """
    candidates: list[str] = []
    seen: set[str] = set()
    since: int | None = None
    target_pool = limit * pool_multiplier
    while len(candidates) < target_pool:
        params = {"descending": "true", "limit": 400}
        if since is not None:
            params["since"] = since
        try:
            resp = httpx.get(NPM_CHANGES, params=params, timeout=20)
            resp.raise_for_status()
            results = resp.json().get("results", [])
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            print(f"  [warn] changes feed page failed: {e}", file=sys.stderr)
            break
        if not results:
            break
        for item in results:
            nid = item.get("id", "")
            since = item.get("seq", since)
            if nid and not nid.startswith("_") and nid not in exclude and nid not in seen:
                seen.add(nid)
                candidates.append(nid)
        time.sleep(0.3)

    print(f"  collected {len(candidates)} recent candidates; filtering for legitimacy...")
    legit: list[str] = []
    for name in candidates:
        if _is_legit_benign(name):
            legit.append(name)
        if len(legit) >= limit:
            break
        time.sleep(0.02)
    return legit


def build_rows(entries: list[dict], label: int, sleep: float) -> tuple[list[dict], int]:
    """Fetch real npm metadata + extract features for each entry. Returns (rows, skipped)."""
    rows: list[dict] = []
    skipped = 0
    total = len(entries)
    for i, entry in enumerate(entries, 1):
        name = entry["name"] if isinstance(entry, dict) else entry
        version = entry.get("version") if isinstance(entry, dict) else None
        meta = registry.fetch_npm(name, version)
        if meta is None:
            skipped += 1
            continue
        feats = extract_features(name, meta)
        row = {"name": name, "label": label, "source": entry.get("source", "npm_search")
               if isinstance(entry, dict) else "npm_search"}
        for f in feats:
            row[f.key] = f.value
        rows.append(row)
        if i % 50 == 0 or i == total:
            print(f"  [{'malicious' if label else 'benign'}] {i}/{total} "
                  f"(skipped so far: {skipped})")
        time.sleep(sleep)
    return rows, skipped


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--malicious-limit", type=int, default=300,
                    help="Cap on malicious rows to fetch (real npm calls, rate-limited).")
    ap.add_argument("--benign-limit", type=int, default=300)
    ap.add_argument("--sleep", type=float, default=0.05, help="Delay between npm calls (s).")
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "dataset.parquet")
    ap.add_argument("--benign-strategy", choices=["popular", "matched"], default="matched",
                    help="'popular' = old/established packages (inflates metrics via age "
                         "confounder). 'matched' = mostly young/small legit packages from the "
                         "changes feed (hard negatives) + some popular for diversity. Default "
                         "matched — the honest one.")
    ap.add_argument("--matched-young-frac", type=float, default=0.7,
                    help="Fraction of benign drawn from young/recent packages (matched mode).")
    args = ap.parse_args()

    print("Loading malicious labels (BKC + Datadog manifest)...")
    malicious = load_malicious_labels("npm")
    print(f"  {len(malicious)} unique labeled malicious npm package names available")
    malicious = malicious[: args.malicious_limit]

    print(f"Fetching real npm metadata for {len(malicious)} malicious packages...")
    mal_rows, mal_skipped = build_rows(malicious, label=1, sleep=args.sleep)

    exclude = {e["name"] for e in load_malicious_labels("npm")}
    if args.benign_strategy == "popular":
        print("Fetching POPULAR benign candidates (npm search)...")
        benign_names = fetch_popular_benign(args.benign_limit, exclude)
    else:
        n_young = int(args.benign_limit * args.matched_young_frac)
        n_pop = args.benign_limit - n_young
        print(f"Fetching MATCHED benign: {n_young} young (changes feed) + {n_pop} popular...")
        young = fetch_recent_benign(n_young, exclude)
        popular = fetch_popular_benign(n_pop, exclude | set(young))
        benign_names = young + popular
        print(f"  {len(young)} young + {len(popular)} popular = {len(benign_names)} benign")
    print(f"  {len(benign_names)} benign candidates found")

    print(f"Fetching real npm metadata for {len(benign_names)} benign packages...")
    ben_rows, ben_skipped = build_rows(benign_names, label=0, sleep=args.sleep)

    all_rows = mal_rows + ben_rows
    if not all_rows:
        print("No rows produced — aborting (check network connectivity).", file=sys.stderr)
        sys.exit(1)

    import pandas as pd
    df = pd.DataFrame(all_rows)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(args.out, index=False)

    print("\n=== Dataset build summary (honest counts) ===")
    print(f"Benign strategy: {args.benign_strategy}")
    print(f"Malicious: requested {len(malicious)}, fetched {len(mal_rows)}, "
          f"skipped (not found on npm) {mal_skipped} "
          f"({mal_skipped / max(1, len(malicious)):.0%})")
    print(f"Benign:    requested {len(benign_names)}, fetched {len(ben_rows)}, "
          f"skipped {ben_skipped}")
    print(f"Total rows written: {len(df)} -> {args.out}")
    print(f"Label balance: {df['label'].value_counts().to_dict()}")


if __name__ == "__main__":
    main()
