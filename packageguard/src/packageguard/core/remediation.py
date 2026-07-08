"""Known-malware matching + remediation for `scan`.

Rule-based engine over the bundled database. Sem 7 Weeks 5-6 adds a second tier: flag
transitive deps whose ML risk score exceeds a threshold even if they are not in the DB.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from packageguard.core.lockfile import Dependency

_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "known_malware.json"

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@lru_cache(maxsize=1)
def _load_db() -> list[dict]:
    data = json.loads(_DB_PATH.read_text(encoding="utf-8"))
    return data.get("records", [])


def _matches(record: dict, dep: Dependency) -> bool:
    if record["name"] != dep.name:
        return False
    versions = record.get("versions") or ["*"]
    return "*" in versions or dep.version in versions


def find_issues(deps: list[Dependency]) -> list[dict]:
    """Return issues sorted by severity (critical first)."""
    db = _load_db()
    issues: list[dict] = []
    for dep in deps:
        for record in db:
            if _matches(record, dep):
                issues.append({
                    "severity": record["severity"],
                    "name": dep.name,
                    "version": dep.version,
                    "path": dep.path,
                    "reason": record["reason"],
                    "replacement": record.get("replacement"),
                    "remediation": record["remediation"],
                })
                break
    issues.sort(key=lambda i: SEVERITY_RANK.get(i["severity"], 9))
    return issues
