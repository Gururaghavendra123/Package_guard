"""Lazy dependency-subgraph builder (Sem 8).

Given a package, fetch its N-hop dependency neighbourhood from the npm registry and build a
graph with per-node features. The same structure feeds two consumers:
  - the GraphSAGE GNN scorer (converted to a PyTorch Geometric `Data` object), and
  - the HUD graph panel (returned directly as JSON for cytoscape.js).

No live daemon / no full-registry graph in memory — subgraphs are built on demand and rely on
the registry cache. Node count is capped so a pathological dependency tree can't blow up.
"""

from __future__ import annotations

from collections import deque

from packageguard.core import registry, scorer
from packageguard.core.features import FEATURE_ORDER, extract_features


def build_subgraph(name: str, version: str | None = None,
                   max_depth: int = 2, max_nodes: int = 120) -> dict:
    """Return {root, nodes:[...], edges:[...]} for `name`'s dependency neighbourhood.

    Each node carries its 5 features + per-package XGBoost score. Edges are dependency
    relations (source depends on target). BFS to `max_depth`, capped at `max_nodes`.
    """
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    seen: set[str] = set()
    q: deque[tuple[str, str | None, int]] = deque([(name, version, 0)])

    while q and len(nodes) < max_nodes:
        n, v, depth = q.popleft()
        if n in seen:
            continue
        seen.add(n)

        meta = registry.fetch_npm(n, v)
        feats = extract_features(n, meta)
        score, _ = scorer.score(feats, prefer_ml=(meta is not None))
        nodes[n] = {
            "id": n,
            "depth": depth,
            "xgb_score": round(float(score), 3),
            "features": {f.key: round(f.value, 4) for f in feats},
        }

        if meta and depth < max_depth:
            for dep in (meta.get("dependencies") or {}):
                edges.append({"source": n, "target": dep})
                if dep not in seen and len(nodes) + len(q) < max_nodes:
                    q.append((dep, None, depth + 1))

    # keep only edges whose endpoints both made it into the node set
    node_ids = set(nodes)
    edges = [e for e in edges if e["source"] in node_ids and e["target"] in node_ids]
    return {"root": name, "nodes": list(nodes.values()), "edges": edges}


def subgraph_to_arrays(graph: dict) -> tuple[list[list[float]], list[list[int]], list[str]]:
    """Convert a subgraph dict to (node_feature_matrix, edge_index, node_ids) for PyG.

    edge_index is the 2×E COO form. Edges are made undirected (both directions) so message
    passing propagates risk up the chain as well as down.
    """
    ids = [n["id"] for n in graph["nodes"]]
    idx = {nid: i for i, nid in enumerate(ids)}
    x = [[n["features"].get(k, 0.0) for k in FEATURE_ORDER] for n in graph["nodes"]]
    src: list[int] = []
    dst: list[int] = []
    for e in graph["edges"]:
        a, b = idx[e["source"]], idx[e["target"]]
        src += [a, b]
        dst += [b, a]
    edge_index = [src, dst]
    return x, edge_index, ids
