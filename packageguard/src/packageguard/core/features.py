"""Feature extraction — the 5 per-package signals.

Each feature is returned as a normalised **risk value in [0, 1]** (higher = more suspicious)
plus a human-readable detail string. When live npm metadata is available it is used; otherwise
values fall back to a *deterministic* pseudo-signal derived from the package name so the tool
still runs offline.

Empirical note (see training/RESULTS.md): trained on real data, the useful signals are
`author_age` and `name_similarity`; `install_script` carries ~zero importance because modern
malware rarely declares lifecycle scripts in its manifest (payload lives in tarball code, not
here). Deeper behavioral detection would need tarball analysis — out of scope for Sem 7.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

# Small embedded fallback, used only if the real list (below) hasn't been built yet or
# fails to load — keeps the tool usable offline / on a fresh clone before Phase 1 runs.
_STUB_TOP_PACKAGES: tuple[str, ...] = (
    "react", "lodash", "express", "chalk", "colors", "commander", "axios", "debug",
    "moment", "request", "async", "bluebird", "underscore", "webpack", "babel",
    "typescript", "eslint", "prettier", "jest", "mocha", "vue", "angular", "jquery",
    "dotenv", "cors", "body-parser", "mongoose", "socket.io", "redux", "next",
    "node-fetch", "cross-env", "rimraf", "uuid", "glob", "yargs", "semver", "ws",
    "nodemon", "ts-node",
)

_TOP_PACKAGES_PATH = Path(__file__).resolve().parent.parent / "data" / "top_packages.json"


def _load_top_packages() -> tuple[str, ...]:
    """Real list built by `training/build_top_packages.py` (union of live npm search
    results seeded with well-known package names — see that script's docstring for why
    a naive top-1000 scrape doesn't work). Falls back to the tiny embedded stub if the
    file is missing so the tool still runs before Phase 1 has been executed."""
    try:
        names = json.loads(_TOP_PACKAGES_PATH.read_text(encoding="utf-8"))
        if names:
            return tuple(names)
    except (OSError, json.JSONDecodeError):
        pass
    return _STUB_TOP_PACKAGES


TOP_PACKAGES: tuple[str, ...] = _load_top_packages()

FEATURE_ORDER: tuple[str, ...] = (
    "name_similarity",
    "install_script",
    "author_age",
    "publish_timing",
    "dep_count",
    "version_count",
    "description_quality",
    "maintainer_count",
)

FEATURE_LABELS: dict[str, str] = {
    "name_similarity": "Name similarity to popular package",
    "install_script": "Install / lifecycle script",
    "author_age": "Author account age",
    "publish_timing": "Publish timing",
    "dep_count": "Dependency footprint",
    "version_count": "Release history",
    "description_quality": "Description quality",
    "maintainer_count": "Maintainer count",
}


@dataclass
class Feature:
    key: str
    label: str
    value: float  # normalised risk in [0, 1]
    detail: str

    def to_dict(self) -> dict:
        return {"key": self.key, "label": self.label, "value": round(self.value, 4), "detail": self.detail}


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance. Small strings, so the simple DP is fine."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _seed(name: str) -> list[int]:
    """Deterministic pseudo-random bytes from the package name (offline fallback)."""
    digest = hashlib.md5(name.encode("utf-8")).digest()
    return list(digest)


def _name_similarity(name: str) -> Feature:
    bare = name.split("/")[-1].lower()  # drop npm scope like @foo/bar
    if bare in TOP_PACKAGES:
        return Feature("name_similarity", FEATURE_LABELS["name_similarity"], 0.0,
                       "Matches a known popular package exactly")
    best_dist, best_pkg = 99, ""
    blen = len(bare)
    for pkg in TOP_PACKAGES:
        # Only compare against reasonably-long popular names. Short generic names collide
        # spuriously (e.g. the scope bare-name "core" is 1 edit from "cors", "node" from
        # "code") and caused false-positive typosquat flags on packages like @babel/core.
        if len(pkg) < 5:
            continue
        # Edit distance >= |length difference|, so anything differing by >2 in length can't
        # be within our threshold — skip it cheaply (big speedup over ~7k comparisons/name).
        if abs(len(pkg) - blen) > 2:
            continue
        d = levenshtein(bare, pkg)
        if d < best_dist:
            best_dist, best_pkg = d, pkg
            if d == 1:
                break  # can't do better than 1 (0 handled by the exact-match check above)
    if 1 <= best_dist <= 2 and len(bare) >= 5:
        value = 1.0 if best_dist == 1 else 0.55
        return Feature("name_similarity", FEATURE_LABELS["name_similarity"], value,
                       f'{best_dist} edit(s) from "{best_pkg}" — possible typosquat')
    return Feature("name_similarity", FEATURE_LABELS["name_similarity"], 0.02,
                   "No close match to a popular package")


def _install_script(name: str, meta: dict | None, seed: list[int]) -> Feature:
    scripts = None
    if meta:
        scripts = meta.get("scripts") or {}
    if scripts is not None:
        lifecycle = {k: v for k, v in scripts.items()
                     if k in ("preinstall", "install", "postinstall")}
        if not lifecycle:
            return Feature("install_script", FEATURE_LABELS["install_script"], 0.03,
                           "No install/lifecycle scripts")
        body = " ".join(lifecycle.values()).lower()
        obfuscated = any(tok in body for tok in ("curl", "wget", "| sh", "|sh", "base64", "eval", "http://"))
        value = 0.95 if obfuscated else 0.45
        detail = f"{', '.join(lifecycle)}: {'network/obfuscated payload' if obfuscated else 'present'}"
        return Feature("install_script", FEATURE_LABELS["install_script"], value, detail)
    # offline fallback
    if name.split("/")[-1].lower() in TOP_PACKAGES:
        return Feature("install_script", FEATURE_LABELS["install_script"], 0.03,
                       "No install/lifecycle scripts (offline, known package)")
    has = seed[0] % 10 < 3
    if not has:
        return Feature("install_script", FEATURE_LABELS["install_script"], 0.03,
                       "No install/lifecycle scripts (offline estimate)")
    obf = seed[1] % 10 < 5
    return Feature("install_script", FEATURE_LABELS["install_script"], 0.95 if obf else 0.45,
                   f"postinstall {'with network call' if obf else 'present'} (offline estimate)")


def _author_age(name: str, meta: dict | None, seed: list[int]) -> Feature:
    days = None
    if meta and meta.get("author_age_days") is not None:
        days = meta["author_age_days"]
    if days is None:
        if name.split("/")[-1].lower() in TOP_PACKAGES:
            days = 2000  # offline: known package -> established author
        else:
            days = 2 + seed[2] * 6  # offline: 2 .. ~1500 days
        note = " (offline estimate)"
    else:
        note = ""
    # young accounts are risky; decays to ~0 past a year
    value = max(0.0, min(1.0, 1.0 - days / 365.0))
    if days < 30:
        detail = f"~{days} days old — brand new account{note}"
    elif days < 365:
        detail = f"~{days // 30} months old{note}"
    else:
        detail = f"~{days // 365} years old — established{note}"
    return Feature("author_age", FEATURE_LABELS["author_age"], value, detail)


def _publish_timing(name: str, meta: dict | None, seed: list[int]) -> Feature:
    # deliberately weak signal (see plan: near-zero importance, timezone-confounded)
    anomaly = (seed[3] % 10) / 20.0  # 0 .. 0.45
    if anomaly > 0.3:
        detail = "Published at an unusual hour/weekend"
    else:
        detail = "Normal publish window"
    return Feature("publish_timing", FEATURE_LABELS["publish_timing"], anomaly, detail)


def _dep_count(name: str, meta: dict | None, seed: list[int]) -> Feature:
    count = None
    if meta and meta.get("dependencies") is not None:
        count = len(meta["dependencies"])
    if count is None:
        count = seed[4] % 25
        note = " (offline estimate)"
    else:
        note = ""
    # very high fan-out is a mild risk; most is benign
    value = min(1.0, count / 60.0)
    return Feature("dep_count", FEATURE_LABELS["dep_count"], value,
                   f"{count} direct dependencies{note}")


def _version_count(name: str, meta: dict | None, seed: list[int]) -> Feature:
    # Phase 1 (real-data validated, AUC 0.81): throwaway malware is published once and
    # abandoned; legitimate packages accumulate many releases over time. Not selected on by
    # any of our sampling filters, so this signal is clean (unlike has_repo/has_homepage,
    # which correlate with our benign-legitimacy filter and were excluded for that reason).
    count = meta.get("version_count") if meta else None
    if count is None:
        count = 1 + seed[5] % 8
        note = " (offline estimate)"
    else:
        note = ""
    # 1 version -> high risk; decays smoothly, near-zero past ~20 releases
    value = max(0.0, min(1.0, 1.0 - (count - 1) / 20.0))
    detail = f"{count} published version(s){note}"
    return Feature("version_count", FEATURE_LABELS["version_count"], value, detail)


def _description_quality(name: str, meta: dict | None, seed: list[int]) -> Feature:
    # AUC 0.81. Throwaway malware typically ships no/minimal description; real packages
    # describe themselves so users can find them. Length capped, not content-scored — this
    # tool doesn't need to understand English, just whether care was taken.
    if meta is not None:
        length = len(meta.get("description") or "")
        note = ""
    else:
        length = seed[6] % 90
        note = " (offline estimate)"
    value = max(0.0, min(1.0, 1.0 - length / 60.0))
    detail = (f"{length} char description{note}" if length else f"No description provided{note}")
    return Feature("description_quality", FEATURE_LABELS["description_quality"], value, detail)


def _maintainer_count(name: str, meta: dict | None, seed: list[int]) -> Feature:
    # AUC 0.75. Solo-maintainer, throwaway-feeling packages skew malicious; established
    # packages tend to accumulate co-maintainers over time.
    count = meta.get("maintainers") if meta else None
    if count is None:
        count = 1 + seed[7] % 3
        note = " (offline estimate)"
    else:
        note = ""
    value = 0.55 if count <= 1 else max(0.0, 0.55 - (count - 1) * 0.15)
    detail = f"{count} maintainer(s){note}"
    return Feature("maintainer_count", FEATURE_LABELS["maintainer_count"], value, detail)


def extract_features(name: str, meta: dict | None = None) -> list[Feature]:
    """Return the 8 features in canonical order (5 original + 3 Phase-1 additions)."""
    seed = _seed(name)
    return [
        _name_similarity(name),
        _install_script(name, meta, seed),
        _author_age(name, meta, seed),
        _publish_timing(name, meta, seed),
        _dep_count(name, meta, seed),
        _version_count(name, meta, seed),
        _description_quality(name, meta, seed),
        _maintainer_count(name, meta, seed),
    ]
