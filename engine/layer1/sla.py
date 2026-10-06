"""
Layer 1: SLA Violations Detector.

Identifies overt SLA breaches in alert lifecycle:
  1. Critical alerts unacknowledged past configured time limits.
  2. Alerts closed without completing required escalation steps.

This is a rule-based detector (no statistical test).
It produces DetectorResult objects with score = violation_count / total_alerts.

Configuration: config/thresholds.yaml → sla_limits
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

import duckdb
import yaml

from engine.detectors.base import DetectorResult

logger = logging.getLogger(__name__)

_DEFAULT_THRESHOLDS_PATH = "config/thresholds.yaml"


def _load_sla_config(path: str = _DEFAULT_THRESHOLDS_PATH) -> dict:
    """Load SLA limits from thresholds.yaml."""
    try:
        with open(path) as f:
            cfg = yaml.safe_load(f)
        return cfg.get("sla_limits", {})
    except FileNotFoundError:
        logger.warning(f"Thresholds config not found at {path}; using hardcoded defaults")
        return {
            "ack_limits_minutes": {"P1": 15, "P2": 60, "P3": 240, "P4": 1440, "P5": 4320},
            "required_escalation_steps": {
                "P1": ["triage", "escalate_to_l2", "notify_management"],
                "P2": ["triage", "escalate_to_l2"],
                "P3": ["triage"],
            },
        }


def run_l1_sla(
    con: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    threshold_tier: str = "internal",
    config_path: str = _DEFAULT_THRESHOLDS_PATH,
    run_ts: Optional[datetime] = None,
) -> DetectorResult:
    """
    Run Layer 1 SLA Violations detector for a single entity.

    Checks:
    - Unacknowledged alerts past severity-specific time limits.
    - Alerts closed without required escalation steps.

    Args:
        con: Active DuckDB connection.
        entity_id: Target entity identifier.
        threshold_tier: "internal" or "legal".
        config_path: Path to thresholds.yaml.
        run_ts: Detector run timestamp.

    Returns:
        DetectorResult with score = violation_rate.
    """
    if run_ts is None:
        run_ts = datetime.utcnow()

    sla_cfg = _load_sla_config(config_path)
    ack_limits = sla_cfg.get("ack_limits_minutes", {})
    required_steps = sla_cfg.get("required_escalation_steps", {})

    parameters = {
        "ack_limits_minutes": ack_limits,
        "required_escalation_steps": required_steps,
        "threshold_tier": threshold_tier,
    }

    # ── 1. Unacknowledged past SLA ────────────────────────────────────────────
    ack_violation_ids: list[str] = []

    for severity, limit_min in ack_limits.items():
        query = """
            SELECT alert_id
            FROM alerts
            WHERE entity_id = ?
              AND severity_initial = ?
              AND source_is_soar = FALSE
              AND (
                ack_ts IS NULL OR
                DATEDIFF('minute', created_ts, ack_ts) > ?
              )
              AND close_ts IS NOT NULL
        """
        rows = con.execute(query, [entity_id, severity, limit_min]).fetchall()
        ack_violation_ids.extend(r[0] for r in rows)

    # ── 2. Closed without required escalation steps ───────────────────────────
    esc_violation_case_ids: list[str] = []
    esc_violation_alert_ids: list[str] = []

    for severity, steps in required_steps.items():
        if not steps:
            continue

        # Find closed cases for alerts at this severity level
        case_query = """
            SELECT DISTINCT c.case_id, c.alert_id
            FROM cases c
            JOIN alerts a ON a.alert_id = c.alert_id
            WHERE a.entity_id = ?
              AND a.severity_final = ?
              AND c.closed_ts IS NOT NULL
        """
        closed_cases = con.execute(case_query, [entity_id, severity]).fetchall()

        for case_id, alert_id in closed_cases:
            # Check each required step
            for step in steps:
                step_query = """
                    SELECT COUNT(*) FROM escalations
                    WHERE case_id = ?
                      AND step_name = ?
                      AND performed = TRUE
                """
                count = con.execute(step_query, [case_id, step]).fetchone()[0]
                if count == 0:
                    esc_violation_case_ids.append(case_id)
                    esc_violation_alert_ids.append(alert_id)
                    break  # One missing step is enough to flag the case

    # ── Aggregate ─────────────────────────────────────────────────────────────
    total_query = """
        SELECT COUNT(*) FROM alerts
        WHERE entity_id = ? AND source_is_soar = FALSE AND close_ts IS NOT NULL
    """
    total_closed = con.execute(total_query, [entity_id]).fetchone()[0] or 1

    all_alert_ids = list(set(ack_violation_ids + esc_violation_alert_ids))
    all_case_ids = list(set(esc_violation_case_ids))
    violation_count = len(set(ack_violation_ids)) + len(set(esc_violation_case_ids))
    violation_rate = violation_count / total_closed

    flagged = violation_count > 0

    parameters["ack_violation_count"] = len(set(ack_violation_ids))
    parameters["escalation_violation_count"] = len(set(esc_violation_case_ids))
    parameters["total_closed_alerts"] = total_closed
    parameters["violation_rate"] = round(violation_rate, 4)

    # Fetch analyst IDs for linked alerts
    if all_alert_ids:
        ph = ", ".join("?" * len(all_alert_ids))
        analyst_rows = con.execute(
            f"SELECT DISTINCT analyst_id FROM cases WHERE alert_id IN ({ph})",
            all_alert_ids,
        ).fetchall()
        analyst_ids = [r[0] for r in analyst_rows]
    else:
        analyst_ids = []

    return DetectorResult(
        detector_id="L1_SLA",
        detector_name="SLA Violation",
        entity_id=entity_id,
        run_ts=run_ts,
        test_name="SLA Rule-Based Threshold Check",
        statistic=float(violation_count),
        p_value=None,
        score=round(min(1.0, violation_rate), 6),
        parameters=parameters,
        sample_size=total_closed,
        flag=flagged,
        threshold_tier=threshold_tier,
        confidence_note=(
            "Rule-based check; no statistical inference. "
            "Each violation corresponds to a specific missed SLA requirement "
            "documented in thresholds.yaml."
        ),
        linked_alert_ids=all_alert_ids[:500],
        linked_case_ids=all_case_ids[:500],
        linked_analyst_ids=analyst_ids[:200],
    )
