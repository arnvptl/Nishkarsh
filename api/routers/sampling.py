"""Sampling / Review Manifest API routes."""
from __future__ import annotations
from fastapi import APIRouter, Query
from fastapi.responses import PlainTextResponse
from api.main import get_con, get_audit

router = APIRouter()


@router.get("/{entity_id}/manifest")
async def get_review_manifest(
    entity_id: str,
    cycle_id: str = Query(default="DEMO"),
):
    """Get the prioritized review manifest for an entity."""
    con = get_con()
    audit = get_audit()

    rows = con.execute("""
        SELECT alert_id, stratum, priority_rank, detector_score, sampled_by, seed
        FROM review_manifests
        WHERE entity_id = ? AND cycle_id = ?
        ORDER BY priority_rank ASC
    """, [entity_id, cycle_id]).fetchall()

    cols = ["alert_id", "stratum", "priority_rank", "detector_score", "sampled_by", "seed"]
    manifest = [dict(zip(cols, r)) for r in rows]

    n_flagged = sum(1 for r in manifest if r["sampled_by"] == "FLAGGED_80PCT")
    n_random = sum(1 for r in manifest if r["sampled_by"] == "RANDOM_20PCT")

    audit.log_export("api", "manifest", entity_id, len(manifest))
    return {
        "entity_id": entity_id,
        "cycle_id": cycle_id,
        "total": len(manifest),
        "n_flagged": n_flagged,
        "n_random": n_random,
        "seed": manifest[0]["seed"] if manifest else None,
        "rows": manifest,
    }


@router.get("/{entity_id}/manifest/csv")
async def download_manifest_csv(
    entity_id: str,
    cycle_id: str = Query(default="DEMO"),
):
    """Download the review manifest as CSV."""
    con = get_con()
    audit = get_audit()

    rows = con.execute("""
        SELECT alert_id, entity_id, stratum, priority_rank, detector_score, sampled_by, seed
        FROM review_manifests
        WHERE entity_id = ? AND cycle_id = ?
        ORDER BY priority_rank ASC
    """, [entity_id, cycle_id]).fetchall()

    cols = ["alert_id", "entity_id", "stratum", "priority_rank", "detector_score", "sampled_by", "seed"]
    lines = [",".join(cols)]
    for r in rows:
        lines.append(",".join(str(v) for v in r))

    audit.log_export("api", "manifest_csv", entity_id, len(rows))
    return PlainTextResponse(
        content="\n".join(lines),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=manifest_{entity_id}_{cycle_id}.csv"},
    )
