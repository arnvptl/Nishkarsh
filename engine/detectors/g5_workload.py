"""
G5: Workload Inconsistency Detector.

Detects analysts claiming more active investigation time than physically
possible within their shift (e.g., 14 hours of active tasks in an 8-hour shift).

Method:
  For each (analyst_id, shift_id) pair:
    ratio = active_minutes / net_shift_minutes
  where net_shift_minutes is from config/capacity.yaml (default 480, configurable
  per shift, net of breaks).

  Flag if ratio > max_ratio_for_internal_flag (default 1.0) for internal triage,
  or ratio > max_ratio_for_legal_finding (default 1.5) for legal tier.

Note:
  This detector does NOT claim that the analyst committed fraud. It identifies
  a pattern that *requires investigation*. The examiner must determine whether
  the root cause is data entry error, SOAR miscounting, or genuine overclaiming.
  See docs/methods_and_limitations.md §G5.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

import duckdb
import yaml

from engine.detectors.base import DetectorResult

logger = logging.getLogger(__name__)

_DEFAULT_CAPACITY_YAML = "config/capacity.yaml"


def _load_capacity_config(config_path: str = _DEFAULT_CAPACITY_YAML) -> dict:
    """Load capacity configuration from YAML."""
    try:
        with open(config_path) as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning(f"Capacity config not found at {config_path}; using defaults")
        return {"defaults": {"shift_duration_minutes": 480}, "shift_overrides": {}}


def _get_net_shift_minutes(
    shift_id: str,
    config: dict,
) -> float:
    """
    Get net shift duration in minutes for a given shift_id.

    Checks shift_overrides first; falls back to defaults.

    Args:
        shift_id: The shift identifier.
        config: Loaded capacity.yaml config dict.

    Returns:
        Net shift duration in minutes (after breaks).
    """
    overrides = config.get("shift_overrides", {}) or {}
    if shift_id in overrides:
        return float(overrides[shift_id].get("shift_duration_minutes", 480))
    return float(config["defaults"]["shift_duration_minutes"])


def run_g5(
    con: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    max_ratio_internal: float = 1.0,
    max_ratio_legal: float = 1.5,
    min_tasks: int = 3,
    threshold_tier: str = "internal",
    config_path: str = _DEFAULT_CAPACITY_YAML,
    run_ts: Optional[datetime] = None,
) -> DetectorResult:
    """
    Run G5 (Workload Inconsistency) detector for a single entity.

    Args:
        con: Active DuckDB connection.
        entity_id: Target entity identifier.
        max_ratio_internal: Internal flag threshold (active_min / shift_min).
        max_ratio_legal: Legal finding threshold.
        min_tasks: Minimum task count before evaluating an analyst/shift pair.
        threshold_tier: "internal" or "legal".
        config_path: Path to capacity.yaml.
        run_ts: Detector run timestamp.

    Returns:
        DetectorResult with score = max over-capacity ratio observed.
    """
    if run_ts is None:
        run_ts = datetime.utcnow()

    capacity_cfg = _load_capacity_config(config_path)
    max_ratio = max_ratio_legal if threshold_tier == "legal" else max_ratio_internal

    # ── Fetch workflow effort per analyst/shift ───────────────────────────────
    # Also count number of tasks (cases) to respect min_tasks threshold
    query = """
        SELECT
            we.analyst_id,
            we.shift_id,
            we.active_minutes,
            COUNT(c.case_id) AS task_count,
            ARRAY_AGG(DISTINCT c.case_id) AS case_ids,
            ARRAY_AGG(DISTINCT a.alert_id) AS alert_ids
        FROM workflow_effort we
        JOIN cases c ON c.analyst_id = we.analyst_id AND c.shift_id = we.shift_id
        JOIN alerts a ON a.alert_id = c.alert_id
        WHERE a.entity_id = ?
        GROUP BY we.analyst_id, we.shift_id, we.active_minutes
        HAVING COUNT(c.case_id) >= ?
    """
    rows = con.execute(query, [entity_id, min_tasks]).fetchall()
    cols = ["analyst_id", "shift_id", "active_minutes", "task_count", "case_ids", "alert_ids"]
    data = [dict(zip(cols, row)) for row in rows]

    parameters = {
        "max_ratio_internal": max_ratio_internal,
        "max_ratio_legal": max_ratio_legal,
        "max_ratio_applied": max_ratio,
        "min_tasks": min_tasks,
        "threshold_tier": threshold_tier,
        "config_path": config_path,
    }

    if not data:
        return DetectorResult(
            detector_id="G5",
            detector_name="Workload Inconsistency",
            entity_id=entity_id,
            run_ts=run_ts,
            test_name="Capacity Threshold Check",
            statistic=0.0,
            p_value=None,
            score=0.0,
            parameters=parameters,
            sample_size=0,
            flag=False,
            threshold_tier=threshold_tier,
            confidence_note="NO DATA: no workflow effort records found",
        )

    # ── Compute ratios ────────────────────────────────────────────────────────
    flagged_records = []
    all_ratios = []
    linked_case_ids: list[str] = []
    linked_alert_ids: list[str] = []
    linked_analyst_ids: list[str] = []

    for row in data:
        net_minutes = _get_net_shift_minutes(row["shift_id"], capacity_cfg)
        ratio = row["active_minutes"] / net_minutes if net_minutes > 0 else 0.0
        all_ratios.append(ratio)

        if ratio > max_ratio:
            flagged_records.append({
                "analyst_id": row["analyst_id"],
                "shift_id": row["shift_id"],
                "active_minutes": row["active_minutes"],
                "net_shift_minutes": net_minutes,
                "ratio": round(ratio, 4),
                "task_count": row["task_count"],
            })
            # case_ids and alert_ids may be DuckDB list objects
            cases = list(row["case_ids"]) if row["case_ids"] else []
            alerts = list(row["alert_ids"]) if row["alert_ids"] else []
            linked_case_ids.extend(cases)
            linked_alert_ids.extend(alerts)
            linked_analyst_ids.append(row["analyst_id"])

    max_ratio_observed = max(all_ratios) if all_ratios else 0.0
    flagged = len(flagged_records) > 0

    # Score: how far over capacity the worst case is
    # Capped at 1.0 for ratios > 2x capacity
    score = min(1.0, max(0.0, (max_ratio_observed - 1.0))) if max_ratio_observed > 1.0 else 0.0

    parameters["max_ratio_observed"] = round(max_ratio_observed, 4)
    parameters["n_flagged_shifts"] = len(flagged_records)
    parameters["flagged_records"] = flagged_records[:20]

    return DetectorResult(
        detector_id="G5",
        detector_name="Workload Inconsistency",
        entity_id=entity_id,
        run_ts=run_ts,
        test_name="Capacity Threshold Check",
        statistic=round(max_ratio_observed, 6),
        p_value=None,
        score=round(score, 6),
        parameters=parameters,
        sample_size=len(data),
        flag=flagged,
        threshold_tier=threshold_tier,
        confidence_note=(
            "This detector identifies patterns requiring investigation. "
            "It does NOT claim intent. Root causes may include: data entry errors, "
            "SOAR task-time miscounting, or overlapping task attribution. "
            "See docs/methods_and_limitations.md §G5."
        ),
        linked_alert_ids=list(set(linked_alert_ids))[:500],
        linked_case_ids=list(set(linked_case_ids))[:500],
        linked_analyst_ids=list(set(linked_analyst_ids))[:200],
    )
