"""High-level engine — the single entry point shared by the CLI and the web API.

`check()` and `scan()` return plain JSON-able dicts. The CLI renders them with Rich; the API
returns them as JSON. Keep all logic here or deeper; keep the CLI/API layers thin.
"""

from __future__ import annotations

import re

from packageguard.core import registry, scorer
from packageguard.core.features import TOP_PACKAGES, extract_features
from packageguard.core.lockfile import Dependency, parse_lockfile
from packageguard.core.remediation import find_issues

# Verified-popular packages (built from live npm popularity data). Standard practice in real
# scanners: allowlist widely-used packages to suppress false positives. Membership caps the
# risk score — BUT the known-malware DB override still runs afterward, so a compromised
# version of a popular package (event-stream@3.3.6) is still flagged. Newly-compromised
# popular packages not yet in the DB are the Sem-8 GNN's job, not this allowlist's.
_POPULAR = set(TOP_PACKAGES)
_POPULAR_CAP = 0.20

# Practical npm package-name validity: optional @scope/, then name; url-safe chars only.
# Rejects empty / whitespace / "@" / paths / shell-injection-shaped input before we ever
# build a registry URL from it.
_VALID_NAME = re.compile(r"^(@[a-z0-9._~-]+/)?[a-z0-9._~-]+$", re.IGNORECASE)


def _valid_package_name(name: str) -> bool:
    return bool(name) and ".." not in name and bool(_VALID_NAME.match(name))


def split_spec(spec: str) -> tuple[str, str | None]:
    """Split 'name@version' into (name, version), respecting npm scopes (@scope/name)."""
    spec = spec.strip()
    if spec.startswith("@"):
        at = spec.find("@", 1)
        return (spec, None) if at == -1 else (spec[:at], spec[at + 1:])
    if "@" in spec:
        name, ver = spec.rsplit("@", 1)
        return name, ver
    return spec, None


def _signal_level(value: float) -> str:
    if value >= 0.60:
        return "critical"
    if value >= 0.30:
        return "warn"
    return "ok"


def check(spec: str) -> dict:
    """Score a single package for risk. `spec` is 'name' or 'name@version'.

    Raises ValueError for empty/malformed names (handled by the CLI/API entry points).
    """
    name, version = split_spec(spec or "")
    if not _valid_package_name(name):
        raise ValueError(f"'{spec}' is not a valid package name")
    meta = registry.fetch_npm(name, version)
    source = "live" if meta else "offline"
    resolved_version = (meta or {}).get("version") or version or "latest"

    features = extract_features(name, meta)
    # Only apply the trained model to REAL (live) features — it was trained on live npm
    # metadata; offline synthetic fallback features would produce meaningless scores, so
    # those go to the heuristic instead (see scorer.score docstring).
    prefer_ml = source == "live"
    score_value, contribs = scorer.score(features, prefer_ml=prefer_ml)

    # Definitive override: package itself is in the known-malware DB. Match on the version
    # the user explicitly asked about if given — a known-malicious version (e.g.
    # event-stream@3.3.6) may have been purged from npm and thus resolve to a clean latest,
    # but the user asked about the bad one, so we must still flag it.
    db_version = version or resolved_version
    known_hit = find_issues([Dependency(name, db_version, name)])
    signals = [
        {"level": _signal_level(c.value), "text": c.detail, "feature": c.label}
        for c in contribs
    ]

    # Allowlist: cap risk for verified-popular packages (reduces false positives on legit
    # packages like @types/node that trip metadata confounders such as "0 dependencies").
    if name in _POPULAR and score_value > _POPULAR_CAP:
        score_value = _POPULAR_CAP
        signals.insert(0, {
            "level": "ok",
            "text": "Verified widely-used package (npm popularity allowlist)",
            "feature": "Established package",
        })

    if known_hit:
        score_value = max(score_value, 0.97)
        signals.insert(0, {
            "level": "critical",
            "text": f"Listed in known-malware database: {known_hit[0]['reason']}",
            "feature": "Known malware",
        })

    verdict_text, level = scorer.verdict(score_value)

    return {
        "name": name,
        "version": resolved_version,
        "ecosystem": "npm",
        "score": round(score_value, 4),
        "verdict": verdict_text,
        "level": level,
        "xgboost_score": round(score_value, 4),  # stub == combined until GNN lands (Sem 8)
        "graph_score": None,                      # Sem 8
        "source": source,
        "features": [c.to_dict() for c in contribs],
        "signals": signals,
        "graph": None,                            # Sem 8: subgraph for the HUD graph panel
        "scorer": "xgboost" if scorer.used_ml(prefer_ml) else "heuristic",
        "note": (None if scorer.used_ml(prefer_ml)
                 else "Heuristic scorer used (offline / no live metadata, or no trained "
                      "model). Trained XGBoost applies only to live-fetched packages."),
    }


def _demo_poisoned_graph() -> dict:
    """A curated poisoned-chain example for the HUD graph panel.

    Real dependency graphs of clean packages don't naturally contain known malware (malware is
    usually leaf packages nothing depends on), so this constructs the canonical scenario the GNN
    exists for: a clean-looking parent whose transitive dependency is malicious. Feature values
    are realistic (clean parents look clean; the poisoned leaf carries malware-like features), so
    the GraphSAGE model flags the leaf and the risk propagates up to the parent.
    """
    clean = {"name_similarity": 0.02, "install_script": 0.03, "author_age": 0.0,
             "publish_timing": 0.1, "dep_count": 0.05}
    poisoned = {"name_similarity": 1.0, "install_script": 0.95, "author_age": 0.98,
                "publish_timing": 0.45, "dep_count": 0.0}
    nodes = [
        {"id": "safe-wrapper", "depth": 0, "xgb_score": 0.12, "features": clean},
        {"id": "string-utils", "depth": 1, "xgb_score": 0.08, "features": clean},
        {"id": "config-loader", "depth": 1, "xgb_score": 0.10, "features": clean},
        {"id": "helper-utils", "depth": 2, "xgb_score": 0.19, "features": clean},
        {"id": "event-logger", "depth": 2, "xgb_score": 0.91, "features": poisoned},  # the poison
    ]
    edges = [
        {"source": "safe-wrapper", "target": "string-utils"},
        {"source": "safe-wrapper", "target": "config-loader"},
        {"source": "string-utils", "target": "helper-utils"},
        {"source": "config-loader", "target": "event-logger"},
    ]
    return {"root": "safe-wrapper", "nodes": nodes, "edges": edges, "demo": True}


def analyze_graph(spec: str, max_depth: int = 2, max_nodes: int = 60) -> dict:
    """Build a dependency subgraph, score every node with the GNN, and combine the root's
    per-package score with the graph signal. Powers the HUD GRAPH panel (Sem 8).

    Special demo trigger: 'safe-wrapper' returns the curated poisoned-chain example above.
    """
    from packageguard.core import combiner, subgraph
    from packageguard.core.gnn_scorer import GnnScorer

    name, version = split_spec(spec or "")
    if not _valid_package_name(name):
        raise ValueError(f"'{spec}' is not a valid package name")

    graph = (_demo_poisoned_graph() if name == "safe-wrapper"
             else subgraph.build_subgraph(name, version, max_depth, max_nodes))

    gnn = GnnScorer()
    gnn_available = gnn.available() and bool(graph["nodes"])
    if gnn_available:
        x, edge_index, _ = subgraph.subgraph_to_arrays(graph)
        probs = gnn.score_nodes(x, edge_index)
        for node, p in zip(graph["nodes"], probs):
            node["gnn_score"] = round(float(p), 3)
    else:
        for node in graph["nodes"]:
            node["gnn_score"] = None

    root = graph["nodes"][0] if graph["nodes"] else None
    xgb_root = float(root["xgb_score"]) if root else 0.0
    # graph signal = worst GNN malice among the *dependencies* (not the root itself)
    neighbour_probs = [n.get("gnn_score") or 0.0 for n in graph["nodes"][1:]]
    graph_score = max(neighbour_probs) if neighbour_probs else 0.0

    if gnn_available:
        combined, graph_contribution = combiner.combine(xgb_root, graph_score)
    else:
        combined, graph_contribution = xgb_root, 0.0

    verdict_text, level = scorer.verdict(combined)
    # find the worst dependency for the explanation line
    worst = max(graph["nodes"][1:], key=lambda n: n.get("gnn_score") or 0.0, default=None) \
        if len(graph["nodes"]) > 1 else None

    return {
        "root": name,
        "xgb_score": round(xgb_root, 4),
        "graph_score": round(graph_score, 4),
        "graph_contribution": round(graph_contribution, 4),
        "combined_score": round(combined, 4),
        "verdict": verdict_text,
        "level": level,
        "gnn_available": gnn_available,
        "worst_dependency": (worst["id"] if worst else None),
        "nodes": graph["nodes"],
        "edges": graph["edges"],
        "demo": graph.get("demo", False),
    }


def scan(path: str) -> dict:
    """Scan a project directory (or lockfile) for compromised dependencies."""
    deps = parse_lockfile(path)
    issues = find_issues(deps)
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for issue in issues:
        summary[issue["severity"]] = summary.get(issue["severity"], 0) + 1
    return {
        "path": str(path),
        "total_dependencies": len(deps),
        "issue_count": len(issues),
        "summary": summary,
        "issues": issues,
    }
