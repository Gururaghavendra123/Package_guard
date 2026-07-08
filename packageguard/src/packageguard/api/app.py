"""FastAPI application — serves the HUD dashboard and the check/scan JSON endpoints."""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from packageguard.api.schemas import CheckRequest, CheckResponse
from packageguard.core import engine

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

app = FastAPI(title="PackageGuard", version="0.1.0",
              description="Supply-chain risk scoring + project scanning.")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "packageguard", "scorer": "heuristic-placeholder"}


@app.post("/api/check", response_model=CheckResponse)
def api_check(req: CheckRequest) -> dict:
    package = req.package.strip()
    if not package:
        raise HTTPException(status_code=400, detail="package is required")
    return engine.check(package)


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
