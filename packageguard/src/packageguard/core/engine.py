"""High-level engine — the single entry point shared by the CLI and the web API.

`check()` and `scan()` return plain JSON-able dicts. The CLI renders them with Rich; the API
returns them as JSON. Keep all logic here or deeper; keep the CLI/API layers thin.
"""

from __future__ import annotations

import json
import random
import re
from functools import lru_cache
from pathlib import Path

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

    # Not on npm? Show a clear NOT FOUND instead of scoring a ghost from offline features.
    # Known-malware names (e.g. purged typosquats like co1ors) are exempt — still flag those.
    # Only trigger when npm *definitively* 404s (registry.exists() is False), never when the
    # user is simply offline (None).
    if meta is None:
        db_hit = find_issues([Dependency(name, version or "latest", name)])
        if not db_hit and registry.exists(name) is False:
            return {
                "name": name, "version": version or "latest", "ecosystem": "npm",
                "not_found": True, "score": None, "verdict": "NOT FOUND", "level": "low",
                "xgboost_score": None, "graph_score": None, "source": "live",
                "features": [], "scorer": "n/a", "graph": None, "note": None,
                "signals": [{"level": "ok", "feature": "Registry",
                             "text": f"'{name}' does not exist on the npm registry — nothing to install."}],
            }

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
        "not_found": False,
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


_DEMO_GRAPHS_PATH = Path(__file__).resolve().parent.parent / "data" / "demo_graphs.json"
# feature profiles: a clean node looks harmless; a poison node carries malware-like features so
# the trained GraphSAGE flags it and the risk propagates up the chain to the clean root.
_CLEAN_PROFILE = {"name_similarity": 0.02, "install_script": 0.03, "author_age": 0.0,
                  "publish_timing": 0.10, "dep_count": 0.05}
_POISON_PROFILE = {"name_similarity": 1.0, "install_script": 0.95, "author_age": 0.98,
                   "publish_timing": 0.45, "dep_count": 0.0}


@lru_cache(maxsize=1)
def _demo_graph_library() -> dict:
    try:
        return json.loads(_DEMO_GRAPHS_PATH.read_text(encoding="utf-8")).get("graphs", {})
    except (OSError, json.JSONDecodeError):
        return {}


def demo_graph_names() -> list[str]:
    return list(_demo_graph_library())


def _build_demo_graph(name: str) -> dict:
    """Expand a curated poisoned-chain scenario (by role) into a scored subgraph dict."""
    spec = _demo_graph_library()[name]
    nodes = []
    for n in spec["nodes"]:
        poison = n["role"] == "poison"
        nodes.append({
            "id": n["id"], "depth": n["depth"],
            "xgb_score": 0.91 if poison else round(0.08 + n["depth"] * 0.04, 2),
            "features": dict(_POISON_PROFILE if poison else _CLEAN_PROFILE),
        })
    return {"root": spec["nodes"][0]["id"], "nodes": nodes, "edges": spec["edges"],
            "demo": True, "story": spec.get("story", "")}


def analyze_graph(spec: str, max_depth: int = 2, max_nodes: int = 36) -> dict:
    """Build a dependency subgraph, score every node with the GNN, and combine the root's
    per-package score with the graph signal. Powers the HUD GRAPH panel (Sem 8).

    Special demo trigger: 'safe-wrapper' returns the curated poisoned-chain example above.
    """
    from packageguard.core import combiner, subgraph
    from packageguard.core.gnn_scorer import GnnScorer

    name, version = split_spec(spec or "")
    if not _valid_package_name(name):
        raise ValueError(f"'{spec}' is not a valid package name")

    is_demo = name in _demo_graph_library()
    # For a real (non-demo) lookup, confirm the package actually exists on npm before drawing
    # a graph — otherwise a made-up name would render a lone "ghost" node with a meaningless
    # score. Curated demos are exempt (they don't exist on npm by design).
    if not is_demo and registry.fetch_npm(name, version) is None:
        return {
            "root": name, "not_found": True,
            "verdict": "NOT FOUND", "level": "low",
            "xgb_score": None, "graph_score": None, "graph_contribution": None,
            "combined_score": None, "poisoned": False, "gnn_available": GnnScorer().available(),
            "node_count": 0, "worst_dependency": None, "worst_score": None,
            "nodes": [], "edges": [], "demo": False, "story": "",
        }

    graph = (_build_demo_graph(name) if is_demo
             else subgraph.build_subgraph(name, version, max_depth, max_nodes))

    gnn = GnnScorer()
    gnn_available = gnn.available() and bool(graph["nodes"])
    if gnn_available:
        x, edge_index, _ = subgraph.subgraph_to_arrays(graph)
        probs = gnn.score_nodes(x, edge_index)
        for node, p in zip(graph["nodes"], probs):
            score = round(float(p), 3)
            # Apply the popularity allowlist to graph nodes too: legitimate popular
            # dependencies (e.g. express's own deps like `qs`, `send`) otherwise trip the
            # GNN into borderline scores. Cap them so the graph doesn't cry wolf.
            if node["id"] in _POPULAR:
                node["allowlisted"] = True
                score = min(score, 0.12)
            node["gnn_score"] = score
    else:
        for node in graph["nodes"]:
            node["gnn_score"] = None

    root = graph["nodes"][0] if graph["nodes"] else None
    xgb_root = float(root["xgb_score"]) if root else 0.0
    # graph signal = worst GNN malice among the *dependencies* (not the root itself).
    # Only genuinely-high node scores count as a poisoned chain (threshold, not any bump).
    MAL_THRESHOLD = 0.80
    neighbour_probs = [n.get("gnn_score") or 0.0 for n in graph["nodes"][1:]]
    top_neighbour = max(neighbour_probs) if neighbour_probs else 0.0
    graph_score = top_neighbour if top_neighbour >= MAL_THRESHOLD else min(top_neighbour, 0.25)

    if gnn_available:
        combined, graph_contribution = combiner.combine(xgb_root, graph_score)
    else:
        combined, graph_contribution = xgb_root, 0.0

    verdict_text, level = scorer.verdict(combined)
    poisoned = top_neighbour >= MAL_THRESHOLD
    worst = max(graph["nodes"][1:], key=lambda n: n.get("gnn_score") or 0.0, default=None) \
        if len(graph["nodes"]) > 1 else None
    worst_dependency = worst["id"] if (worst and poisoned) else None

    return {
        "root": name,
        "not_found": False,
        "xgb_score": round(xgb_root, 4),
        "graph_score": round(graph_score, 4),
        "graph_contribution": round(graph_contribution, 4),
        "combined_score": round(combined, 4),
        "verdict": verdict_text,
        "level": level,
        "poisoned": poisoned,
        "gnn_available": gnn_available,
        "node_count": len(graph["nodes"]),
        "worst_dependency": worst_dependency,
        "worst_score": round(worst["gnn_score"], 3) if (worst and poisoned) else None,
        "nodes": graph["nodes"],
        "edges": graph["edges"],
        "demo": graph.get("demo", False),
        "story": graph.get("story", ""),
    }


# Famous, instantly-recognizable packages — examples are drawn from these so the demo chips
# read as real, well-known names (not obscure entries from the raw 7k-name list).
_FAMOUS = (
    "react", "express", "lodash", "vue", "axios", "webpack", "chalk", "moment", "typescript",
    "eslint", "jquery", "angular", "redux", "next", "commander", "dotenv", "mongoose", "prettier",
    "jest", "bootstrap", "socket.io", "nodemon", "babel", "sequelize", "passport", "cheerio",
)
# single-word famous names that produce a clean, obvious typosquat when mutated
_SQUAT_SEEDS = ("react", "express", "lodash", "axios", "chalk", "moment", "eslint", "jquery",
                "redux", "babel", "mongoose", "webpack", "bootstrap")


def _make_typosquat(name: str) -> str:
    """Mutate a famous single-word name into an OBVIOUS typosquat (e.g. react->reactt)."""
    homoglyph = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4"}
    ops = [lambda n: n + n[-1]]                                     # double last char: expres->express? -> reactt
    if len(name) > 4:
        ops.append(lambda n: n[:-1])                               # drop last: express->expres
        j = random.randrange(0, len(name) - 1)
        ops.append(lambda n, j=j: n[:j] + n[j + 1] + n[j] + n[j + 2:])  # swap adjacent
    for ch, sub in homoglyph.items():
        if ch in name:
            ops.append(lambda n, ch=ch, sub=sub: n.replace(ch, sub, 1))  # react->r3act
    return random.choice(ops)(name)


@lru_cache(maxsize=1)
def _malware_names() -> list[str]:
    path = Path(__file__).resolve().parent.parent / "data" / "known_malware.json"
    try:
        recs = json.loads(path.read_text(encoding="utf-8")).get("records", [])
        return [r["name"] for r in recs]
    except (OSError, json.JSONDecodeError):
        return []


def examples() -> dict:
    """Fresh example sets for each tab (regenerated per request), drawn from famous packages
    so the chips are recognizable and convincing."""
    clean = random.sample(_FAMOUS, 3)
    # threats are drawn from the real known-malware DB (co1ors, crossenv, event-stream, coa, ...)
    # — all real, all recognizable typosquats/hijacks, and none trip the NOT-FOUND path.
    threats = random.sample(_malware_names(), min(4, len(_malware_names())))

    # graph: every curated poisoned-chain demo + a couple of real famous packages (7-8 chips)
    demos = demo_graph_names()
    graph_examples = [{"pkg": d, "kind": "demo", "label": f"{d} ⚠"} for d in demos]
    graph_examples += [{"pkg": p, "kind": "clean"} for p in random.sample(_FAMOUS, 2)]

    scan_suite = [
        {"path": "sample", "kind": "malware", "label": "event-stream attack"},
        {"path": "sample_typosquat", "kind": "malware", "label": "typosquats"},
        {"path": "sample_hijack", "kind": "malware", "label": "2021 coa/rc hijack"},
        {"path": "sample_wallet", "kind": "malware", "label": "crypto-wallet backdoor"},
        {"path": "sample_clean", "kind": "clean", "label": "clean project ✓"},
    ]

    return {
        "check": (
            [{"pkg": p, "kind": "clean"} for p in clean]
            + [{"pkg": t, "kind": "malware"} for t in threats]
        ),
        "graph": graph_examples,
        "scan": scan_suite,
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
