"""Audit log API routes."""
from __future__ import annotations
from fastapi import APIRouter, Query
from api.main import get_audit

router = APIRouter()


@router.get("/recent")
async def get_recent_audit(limit: int = Query(default=50, le=500)):
    """Get recent audit log entries for the examiner audit log viewer."""
    audit = get_audit()
    entries = audit.recent_entries(limit=limit)
    return {"entries": entries, "total": len(entries)}


@router.get("/verify")
async def verify_audit_chain():
    """Verify the audit log hash chain integrity."""
    audit = get_audit()
    valid, message = audit.verify_chain()
    return {"valid": valid, "message": message}
