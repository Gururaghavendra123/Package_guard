"""npm Registry API client.

Fetches package metadata used by the feature extractor. Everything is best-effort: on any
network/parse failure it returns ``None`` and the extractor falls back to offline estimates,
so the tool always produces a result. Responses are cached on disk to respect npm rate limits.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

CACHE_DIR = Path.home() / ".packageguard" / "registry_cache"
CACHE_TTL_SECONDS = 24 * 3600
NPM_BASE = "https://registry.npmjs.org"


def _cache_path(name: str) -> Path:
    safe = name.replace("/", "__")
    return CACHE_DIR / f"{safe}.json"


def _read_cache(name: str) -> dict | None:
    path = _cache_path(name)
    if not path.exists():
        return None
    if time.time() - path.stat().st_mtime > CACHE_TTL_SECONDS:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(name: str, doc: dict) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path(name).write_text(json.dumps(doc), encoding="utf-8")
    except OSError:
        pass


def _days_since(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except ValueError:
        return None


def fetch_raw_doc(name: str, timeout: float = 5.0) -> dict | None:
    """Return the raw npm registry document (cached), or ``None`` if unavailable.

    Shared by ``fetch_npm`` (normalised features) and dataset tooling that needs fields not
    in the normalised view (repository, description, version history) — e.g. filtering
    young benign candidates for legitimacy.
    """
    if not name or not name.strip():
        return None
    doc = _read_cache(name)
    if doc is None:
        try:
            resp = httpx.get(f"{NPM_BASE}/{name}", timeout=timeout,
                             headers={"Accept": "application/json"})
            resp.raise_for_status()
            doc = resp.json()
            _write_cache(name, doc)
        except (httpx.HTTPError, json.JSONDecodeError):
            return None
    return doc


def fetch_npm(name: str, version: str | None = None, timeout: float = 5.0) -> dict | None:
    """Return normalised metadata for a package, or ``None`` if unavailable.

    Note on ``author_age_days``: the npm registry does not expose maintainer account creation
    date, so we use the package's *first publish* date as a documented proxy (see plan §Data
    Landmines). Replace with a real signal if a source becomes available.
    """
    doc = fetch_raw_doc(name, timeout=timeout)
    if doc is None:
        return None

    versions = doc.get("versions") or {}
    if version and version in versions:
        manifest = versions[version]
    else:
        latest = (doc.get("dist-tags") or {}).get("latest")
        manifest = versions.get(latest, {})
        version = latest

    times = doc.get("time") or {}
    created = times.get("created")

    return {
        "version": version,
        "scripts": manifest.get("scripts") or {},
        "dependencies": manifest.get("dependencies") or {},
        "author_age_days": _days_since(created),
        "maintainers": len(doc.get("maintainers") or []),
    }
