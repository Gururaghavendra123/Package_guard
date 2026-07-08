"""package-lock.json parser.

Enumerates direct + transitive dependencies without executing any code. Supports npm
lockfileVersion 2 and 3 (the ``packages`` map) and falls back to v1 (``dependencies`` tree)
and to a plain ``package.json`` when no lockfile exists.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Dependency:
    name: str
    version: str
    path: str  # human-readable dependency path, e.g. "my-app > some-util > malicious-logger"

    def to_dict(self) -> dict:
        return {"name": self.name, "version": self.version, "path": self.path}


def _from_packages_map(data: dict, root: str) -> list[Dependency]:
    """lockfileVersion 2/3: flat ``packages`` keyed by node_modules path."""
    deps: list[Dependency] = []
    for pkg_path, meta in (data.get("packages") or {}).items():
        if not pkg_path:  # "" is the project root itself
            continue
        # node_modules/a/node_modules/b -> a > b
        parts = [p for p in pkg_path.split("node_modules/") if p]
        chain = [p.strip("/") for p in parts]
        name = chain[-1] if chain else pkg_path
        version = meta.get("version", "?")
        path = " > ".join([root, *chain])
        deps.append(Dependency(name, version, path))
    return deps


def _from_dependencies_tree(data: dict, root: str) -> list[Dependency]:
    """lockfileVersion 1: nested ``dependencies``."""
    deps: list[Dependency] = []

    def walk(node: dict, trail: list[str]) -> None:
        for name, meta in (node.get("dependencies") or {}).items():
            version = meta.get("version", "?")
            path = " > ".join([root, *trail, name])
            deps.append(Dependency(name, version, path))
            walk(meta, [*trail, name])

    walk(data, [])
    return deps


def parse_lockfile(path: str | Path) -> list[Dependency]:
    """Parse a project directory or a lockfile path into a flat dependency list."""
    p = Path(path)
    if p.is_dir():
        lock = p / "package-lock.json"
        pkg = p / "package.json"
        target = lock if lock.exists() else pkg
    else:
        target = p

    if not target.exists():
        raise FileNotFoundError(f"No package-lock.json or package.json found at {path}")

    data = json.loads(target.read_text(encoding="utf-8"))
    root = data.get("name", target.parent.name or "project")

    if target.name == "package.json":
        return [Dependency(n, v, f"{root} > {n}")
                for n, v in (data.get("dependencies") or {}).items()]

    if "packages" in data:
        return _from_packages_map(data, root)
    return _from_dependencies_tree(data, root)
