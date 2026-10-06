"""Detector results API routes."""
from __future__ import annotations
import json
from fastapi import APIRouter, Query
from api.main import get_con, get_audit

router = APIRouter()


@router.get("/{entity_id}")
async def get_detector_results(
    entity_id: str,
    cycle_id: str = Query(default="DEMO"),
    detector_id: str | None = Query(default=None),
):
    """Get all detector results for an entity, with full drill-down data."""
    con = get_con()
    audit = get_audit()

    q = """
        SELECT detector_id, detector_name, test_name, statistic, p_value, score,
               flag, threshold_tier, confidence_note, sample_size, parameters,
               fi_value, result_json, run_ts
        FROM detector_results
        WHERE entity_id = ? AND cycle_id = ?
    """
    params = [entity_id, cycle_id]
    if detector_id:
        q += " AND detector_id = ?"
        params.append(detector_id)
    q += " ORDER BY flag DESC, fi_value DESC"

    rows = con.execute(q, params).fetchall()
    cols = ["detector_id","detector_name","test_name","statistic","p_value","score",
            "flag","threshold_tier","confidence_note","sample_size","parameters",
            "fi_value","result_json","run_ts"]

    results = []
    for row in rows:
        d = dict(zip(cols, row))
        # Parse JSON fields
        if d["parameters"]:
            try: d["parameters"] = json.loads(d["parameters"])
            except: pass
        if d["result_json"]:
            try:
                full = json.loads(d["result_json"])
                d["linked_alert_ids"] = full.get("linked_alert_ids", [])
                d["linked_case_ids"] = full.get("linked_case_ids", [])
                d["linked_analyst_ids"] = full.get("linked_analyst_ids", [])
                d["asymmetric_cells"] = full.get("asymmetric_cells")
            except: pass
        d.pop("result_json", None)
        results.append(d)

    audit.log_query("api", "get_detector_results",
                    {"entity_id": entity_id, "cycle_id": cycle_id, "detector_id": detector_id})
    return {"entity_id": entity_id, "cycle_id": cycle_id, "results": results}


@router.get("/summary/flagged")
async def get_flagged_summary(
    cycle_id: str = Query(default="DEMO"),
    sector: str | None = Query(default=None),
):
    """Get count of flagged entities per detector for dashboard heatmap."""
    con = get_con()

    q = """
        SELECT dr.detector_id, COUNT(DISTINCT dr.entity_id) as flagged_count
        FROM detector_results dr
        JOIN entities e ON e.entity_id = dr.entity_id
        WHERE dr.cycle_id = ? AND dr.flag = TRUE
    """
    params = [cycle_id]
    if sector:
        q += " AND e.sector = ?"
        params.append(sector)
    q += " GROUP BY dr.detector_id ORDER BY flagged_count DESC"

    rows = con.execute(q, params).fetchall()
    return {"cycle_id": cycle_id, "flagged_by_detector": [
        {"detector_id": r[0], "flagged_count": r[1]} for r in rows
    ]}
