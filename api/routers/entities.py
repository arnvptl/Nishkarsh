"""Entity-level API routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from api.main import get_con, get_audit

router = APIRouter()


@router.get("/")
async def list_entities(
    sector: str | None = Query(default=None),
    cycle_id: str = Query(default="DEMO"),
):
    """List all entities with their latest risk scores."""
    con = get_con()
    audit = get_audit()

    query = """
        SELECT e.entity_id, e.name, e.sector, e.asset_class, e.size_band,
               rs.score, rs.band, rs.run_ts
        FROM entities e
        LEFT JOIN (
            SELECT entity_id, score, band, run_ts,
                   ROW_NUMBER() OVER (PARTITION BY entity_id ORDER BY run_ts DESC) as rn
            FROM risk_scores WHERE cycle_id = ?
        ) rs ON rs.entity_id = e.entity_id AND rs.rn = 1
        WHERE 1=1
    """
    params = [cycle_id]
    if sector:
        query += " AND e.sector = ?"
        params.append(sector)
    query += " ORDER BY COALESCE(rs.score, 0) DESC"

    rows = con.execute(query, params).fetchall()
    cols = ["entity_id", "name", "sector", "asset_class", "size_band", "score", "band", "run_ts"]
    result = [dict(zip(cols, r)) for r in rows]
    audit.log_query("api", "list_entities", {"sector": sector, "cycle_id": cycle_id})
    return {"entities": result, "total": len(result)}


@router.get("/{entity_id}")
async def get_entity_detail(entity_id: str, cycle_id: str = Query(default="DEMO")):
    """Get entity detail with full risk score breakdown."""
    con = get_con()
    audit = get_audit()

    entity = con.execute(
        "SELECT * FROM entities WHERE entity_id = ?", [entity_id]
    ).fetchone()
    if not entity:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"Entity {entity_id} not found")

    import json
    score_row = con.execute("""
        SELECT score, band, run_ts, component_json, weights_version, binary_mode
        FROM risk_scores WHERE entity_id = ? AND cycle_id = ?
        ORDER BY run_ts DESC LIMIT 1
    """, [entity_id, cycle_id]).fetchone()

    alert_count = con.execute(
        "SELECT COUNT(*) FROM alerts WHERE entity_id = ?", [entity_id]
    ).fetchone()[0]

    audit.log_query("api", "get_entity_detail", {"entity_id": entity_id, "cycle_id": cycle_id})

    return {
        "entity": {
            "entity_id": entity[0], "name": entity[1], "sector": entity[2],
            "asset_class": entity[3], "size_band": entity[4],
        },
        "risk_score": {
            "score": score_row[0] if score_row else None,
            "band": score_row[1] if score_row else None,
            "run_ts": str(score_row[2]) if score_row else None,
            "components": json.loads(score_row[3]) if score_row else {},
            "weights_version": score_row[4] if score_row else None,
        },
        "alert_count": alert_count,
    }


@router.get("/{entity_id}/history")
async def get_entity_score_history(entity_id: str):
    """Get risk score time series for chart rendering."""
    con = get_con()
    rows = con.execute("""
        SELECT cycle_id, score, band, run_ts FROM risk_scores
        WHERE entity_id = ? ORDER BY run_ts ASC
    """, [entity_id]).fetchall()
    return {
        "entity_id": entity_id,
        "history": [
            {"cycle_id": r[0], "score": r[1], "band": r[2], "run_ts": str(r[3])}
            for r in rows
        ]
    }
