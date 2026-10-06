"""CERT-In compliance tracking routes (isolated from SOC performance metrics)."""
from __future__ import annotations
from fastapi import APIRouter, Query
from api.main import get_con, get_audit

router = APIRouter()


@router.get("/windows")
async def get_compliance_windows(
    cycle_id: str = Query(default="DEMO"),
):
    """
    Track mandatory CERT-In reporting windows.
    ISOLATED from SOC performance metrics per design requirement.
    """
    con = get_con()
    # Check P1 alerts that required 6-hour initial reporting
    rows = con.execute("""
        SELECT
            a.alert_id,
            a.entity_id,
            a.severity_initial,
            a.created_ts,
            a.close_ts,
            DATEDIFF('hour', a.created_ts, COALESCE(a.close_ts, CURRENT_TIMESTAMP)) AS hours_to_close,
            CASE
                WHEN DATEDIFF('hour', a.created_ts, a.close_ts) > 6 THEN 'POSSIBLE_LATE_REPORT'
                ELSE 'WITHIN_WINDOW'
            END AS cert_in_status
        FROM alerts a
        WHERE a.severity_initial = 'P1'
          AND a.source_is_soar = FALSE
        ORDER BY a.created_ts DESC
        LIMIT 100
    """).fetchall()

    cols = ["alert_id", "entity_id", "severity_initial", "created_ts",
            "close_ts", "hours_to_close", "cert_in_status"]

    return {
        "note": "CERT-In 6-hour window tracking. Isolated from SOC performance scoring.",
        "legal_basis": "CERT-In Directions 2022, Section 70B IT Act",
        "alerts": [dict(zip(cols, r)) for r in rows],
    }
