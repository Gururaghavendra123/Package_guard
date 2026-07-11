"""FastAPI application — serves the HUD dashboard and the check/scan JSON endpoints."""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from packageguard.api.schemas import CheckRequest
from packageguard.core import engine

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(title="PackageGuard", version="0.1.0",
              description="Supply-chain risk scoring + project scanning.")


@app.middleware("http")
async def no_cache(request: Request, call_next):
    """Never let the browser serve a stale HUD asset — a local dev tool that changes often
    should always reflect the current files on disk."""
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@app.get("/api/health")
def health() -> dict:
    from packageguard.core import scorer
    from packageguard.core.gnn_scorer import GnnScorer
    return {"status": "ok", "service": "packageguard",
            "scorer": scorer.backend_name(), "gnn": GnnScorer().available()}


@app.get("/api/examples")
def examples() -> dict:
    """Fresh example sets for the UI chips (regenerated each call)."""
    return engine.examples()


@app.post("/api/check")
def api_check(req: CheckRequest) -> dict:
    package = req.package.strip()
    if not package:
        raise HTTPException(status_code=400, detail="package is required")
    try:
        return engine.check(package)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


_SAMPLE_PROJECTS = {"sample", "sample_clean", "sample_typosquat", "sample_hijack", "sample_wallet"}


@app.get("/api/scan-sample")
def api_scan_sample(name: str) -> dict:
    """Scan one of the bundled demo projects (for the UI example chips)."""
    if name not in _SAMPLE_PROJECTS:
        raise HTTPException(status_code=400, detail="unknown sample")
    sample_dir = Path(__file__).resolve().parent.parent.parent.parent / name
    try:
        return engine.scan(str(sample_dir))
    except (ValueError, FileNotFoundError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/graph")
def api_graph(req: CheckRequest) -> dict:
    """Dependency-graph analysis (Sem 8): per-node GNN scores + combined root score."""
    package = req.package.strip()
    if not package:
        raise HTTPException(status_code=400, detail="package is required")
    try:
        return engine.analyze_graph(package)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/scan")
async def api_scan(file: UploadFile) -> JSONResponse:
    contents = await file.read()
    filename = (file.filename or "").lower()
    lock_name = "package.json" if filename.endswith("package.json") and "lock" not in filename \
        else "package-lock.json"
    with tempfile.TemporaryDirectory() as d:
        target = Path(d) / lock_name
        target.write_bytes(contents)
        try:
            result = engine.scan(str(d))
        except (ValueError, FileNotFoundError) as e:
            raise HTTPException(status_code=400, detail=f"Could not parse lockfile: {e}")
    return JSONResponse(result)


# Static HUD UI. Mounted last so the /api/* routes above take precedence.
app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
