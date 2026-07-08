"""PackageGuard core engine — shared by both the CLI and the web API.

No I/O framework concerns live here. `engine.check()` and `engine.scan()` return plain
dicts that the CLI renders with Rich and the API returns as JSON. One brain, two faces.
"""

from packageguard.core.engine import check, scan

__all__ = ["check", "scan"]
