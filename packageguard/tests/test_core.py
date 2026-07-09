"""Hermetic unit tests for the core engine (no network)."""

from pathlib import Path

from packageguard.core import scorer
from packageguard.core.features import extract_features, levenshtein
from packageguard.core.lockfile import parse_lockfile
from packageguard.core.remediation import find_issues
from packageguard.core import engine

SAMPLE = Path(__file__).resolve().parent.parent / "sample"


def test_levenshtein():
    assert levenshtein("colors", "colors") == 0
    assert levenshtein("co1ors", "colors") == 1
    assert levenshtein("expres", "express") == 1


def test_typosquat_scores_high():
    feats = {f.key: f for f in extract_features("co1ors")}
    assert feats["name_similarity"].value >= 0.9  # 1 edit from "colors"


def test_popular_package_name_is_clean():
    feats = {f.key: f for f in extract_features("express")}
    assert feats["name_similarity"].value < 0.1


def test_scorer_orders_risk_heuristic():
    # extract_features() with no meta = offline synthetic features, which are scored by the
    # heuristic (prefer_ml=False), not the trained model. This asserts the offline-path
    # invariant: a typosquat outranks a clean popular package.
    bad = extract_features("co1ors")
    good = extract_features("express")
    assert scorer.score(bad, prefer_ml=False)[0] > scorer.score(good, prefer_ml=False)[0]


def test_verdict_bands():
    assert scorer.verdict(0.9)[1] == "critical"
    assert scorer.verdict(0.1)[1] == "low"


def test_lockfile_parse_sample():
    deps = parse_lockfile(SAMPLE)
    names = {d.name for d in deps}
    assert "event-stream" in names
    assert "malicious-logger" in names


def test_scan_flags_known_malware():
    deps = parse_lockfile(SAMPLE)
    issues = find_issues(deps)
    names = {i["name"] for i in issues}
    assert "event-stream" in names          # critical
    assert "malicious-logger" in names      # transitive high
    assert issues[0]["severity"] == "critical"  # sorted


def test_engine_scan_sample():
    result = engine.scan(str(SAMPLE))
    assert result["issue_count"] >= 3
    assert result["summary"]["critical"] >= 1
