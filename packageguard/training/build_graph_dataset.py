"""Build a real dependency graph for GNN training — from the registry CACHE (no new fetches).

Every package we've ever looked up is cached under ~/.packageguard/registry_cache as its full
npm document (which includes its dependency list). This script stitches those cached docs into
one dependency graph:
  - nodes  = cached packages
  - edges  = package -> dependency (when the dependency is also cached)
  - node features = the 5 per-package features
  - node label = 1 if the package name is in the malicious set (BKC + Datadog), else 0

Output: training/graph_dataset.npz  (x, edge_index, y, node ids)

This is a real graph with real structure and real labels, built offline in seconds. The
poisoned-chain *demo* graphs (clean parent + malicious descendant) are constructed separately
at inference time — see core/subgraph.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from packageguard.core import registry  # noqa: E402
from packageguard.core.features import FEATURE_ORDER, extract_features  # noqa: E402

RAW_DIR = Path(__file__).resolve().parent / "raw_data"
OUT = Path(__file__).resolve().parent / "graph_dataset.npz"


def malicious_name_set() -> set[str]:
    names: set[str] = set()
    bkc = json.loads((RAW_DIR / "bkc_packages.json").read_text(encoding="utf-8"))
    names |= set(bkc.get("npm", []))
    dd = RAW_DIR / "datadog_npm_manifest.json"
    if dd.exists():
        names |= set(json.loads(dd.read_text(encoding="utf-8")).keys())
    return names


def main() -> None:
    cache_dir = registry.CACHE_DIR
    if not cache_dir.exists():
        print("No registry cache found — run build_dataset.py first.", file=sys.stderr)
        sys.exit(1)

    mal = malicious_name_set()
    cache_files = list(cache_dir.glob("*.json"))
    print(f"Reading {len(cache_files)} cached package docs...")

    # First pass: collect node names + their dependency lists from cache.
    deps_of: dict[str, list[str]] = {}
    for f in cache_files:
        name = f.stem.replace("__", "/")
        meta = registry.fetch_npm(name)  # cache hit
        if meta is None:
            continue
        deps_of[name] = list((meta.get("dependencies") or {}).keys())

    node_ids = list(deps_of)
    idx = {n: i for i, n in enumerate(node_ids)}
    print(f"{len(node_ids)} nodes")

    # Edges: package -> dependency, only when both endpoints are known nodes. Undirected.
    src: list[int] = []
    dst: list[int] = []
    for name, deps in deps_of.items():
        for d in deps:
            if d in idx:
                a, b = idx[name], idx[d]
                src += [a, b]
                dst += [b, a]
    print(f"{len(src)//2} edges")

    # Node features + labels.
    x = np.zeros((len(node_ids), len(FEATURE_ORDER)), dtype=np.float32)
    y = np.zeros(len(node_ids), dtype=np.int64)
    for name, i in idx.items():
        meta = registry.fetch_npm(name)
        feats = {f.key: f.value for f in extract_features(name, meta)}
        x[i] = [feats.get(k, 0.0) for k in FEATURE_ORDER]
        y[i] = 1 if name in mal else 0

    edge_index = np.array([src, dst], dtype=np.int64) if src else np.zeros((2, 0), np.int64)
    print(f"labels: malicious={int(y.sum())} benign={int((y == 0).sum())}")

    np.savez(OUT, x=x, edge_index=edge_index, y=y, ids=np.array(node_ids, dtype=object))
    print(f"saved -> {OUT}")


if __name__ == "__main__":
    main()
