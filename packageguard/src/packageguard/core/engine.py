"""High-level engine — the single entry point shared by the CLI and the web API.

`check()` and `scan()` return plain JSON-able dicts. The CLI renders them with Rich; the API
returns them as JSON. Keep all logic here or deeper; keep the CLI/API layers thin.
"""

from __future__ import annotations

from packageguard.core import registry, scorer
from packageguard.core.features import extract_features
from packageguard.core.lockfile import Dependency, parse_lockfile
from packageguard.core.remediation import find_issues


def split_spec(spec: str) -> tuple[str, str | None]:
    """Split 'name@version' into (name, version), respecting npm scopes (@scope/name)."""
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
    """Score a single package for risk. `spec` is 'name' or 'name@version'."""
    name, version = split_spec(spec)
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
