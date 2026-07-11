"""Hermetic unit tests for the core engine (no network)."""

import tempfile
from pathlib import Path

import pytest

from packageguard.core import scorer
from packageguard.core.features import extract_features, levenshtein
from packageguard.core.lockfile import parse_lockfile
from packageguard.core.remediation import find_issues
from packageguard.core import engine

SAMPLE = Path(__file__).resolve().parent.parent / "sample"


def _feat(name, key):
    return {f.key: f for f in extract_features(name)}[key].value


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


def test_engine_scan_clean_sample_no_false_alarm():
    # the clean demo project must report zero issues (proves the scanner doesn't cry wolf)
    clean = Path(__file__).resolve().parent.parent / "sample_clean"
    result = engine.scan(str(clean))
    assert result["issue_count"] == 0
    assert result["total_dependencies"] > 0


# --- edge-case regression tests (Phase 5 hardening) ---

@pytest.mark.parametrize("bad", ["", "   ", "@", "../../etc/passwd", "a; rm -rf /", "packagé"])
def test_check_rejects_invalid_names(bad):
    # invalid names raise ValueError BEFORE any network call (hermetic)
    with pytest.raises(ValueError):
        engine.check(bad)


@pytest.mark.parametrize("content", ["{ broken json", "", "null", "[1,2,3]"])
def test_scan_rejects_malformed_lockfile(content):
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "package-lock.json").write_text(content, encoding="utf-8")
        with pytest.raises(ValueError):
            engine.scan(d)


def test_no_typosquat_false_positive_on_short_scope_name():
    # "@babel/core" -> bare "core" must NOT be flagged as a typosquat of "cors"
    assert _feat("@babel/core", "name_similarity") < 0.5
    assert _feat("@types/node", "name_similarity") < 0.5


def test_real_typosquat_still_detected():
    assert _feat("loadash", "name_similarity") >= 0.5   # ~ lodash
    assert _feat("co1ors", "name_similarity") >= 0.5    # ~ colors


def test_scan_handles_large_lockfile():
    import json
    pkgs = {"": {}}
    pkgs.update({f"node_modules/pkg{i}": {"version": "1.0.0"} for i in range(1500)})
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "package-lock.json").write_text(
            json.dumps({"name": "big", "lockfileVersion": 3, "packages": pkgs}), encoding="utf-8")
        result = engine.scan(d)
    assert result["total_dependencies"] == 1500
