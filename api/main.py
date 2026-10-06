"""SAT-SA FastAPI Application."""
from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import duckdb
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from engine.audit.log import AuditLog
from engine.ingestion.loader import open_connection


# Global state
_con: duckdb.DuckDBPyConnection | None = None
_audit: AuditLog | None = None


def get_con() -> duckdb.DuckDBPyConnection:
    if _con is None:
        raise RuntimeError("Database not initialized")
    return _con


def get_audit() -> AuditLog:
    if _audit is None:
        raise RuntimeError("Audit log not initialized")
    return _audit


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _con, _audit
    db_path = Path(os.environ.get("SATSA_DB_PATH", "data/satsa.db"))
    audit_path = db_path.parent / "audit.db"
    _con = open_connection(db_path)
    _audit = AuditLog(audit_path)
    yield
    if _con:
        _con.close()
    if _audit:
        _audit.close()


app = FastAPI(
    title="SAT-SA API",
    description="Supervisory Analytics Tool for SOC Assessment — NCIIPC",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:8000"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Import and include routers
from api.routers import entities, detectors, sampling, audit_router, compliance

app.include_router(entities.router, prefix="/api/entities", tags=["entities"])
app.include_router(detectors.router, prefix="/api/detectors", tags=["detectors"])
app.include_router(sampling.router, prefix="/api/sampling", tags=["sampling"])
app.include_router(audit_router.router, prefix="/api/audit", tags=["audit"])
app.include_router(compliance.router, prefix="/api/compliance", tags=["compliance"])


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


# Serve React UI (production build)
ui_dist = Path(__file__).parent.parent / "ui" / "dist"
if ui_dist.exists():
    app.mount("/assets", StaticFiles(directory=str(ui_dist / "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        index = ui_dist / "index.html"
        if index.exists():
            return FileResponse(str(index))
        raise HTTPException(status_code=404, detail="UI not built. Run: cd ui && npm run build")
