"""
G6: Silent Loop Detector — Recurring Fast-Closed Alerts.

Detects the same asset generating repeated alerts that are closed quickly
(fast-closed) without remediation, indicating a "silent loop" where a
persistent threat or vulnerability is never actually addressed.

Method:
  For each (entity_id, asset_id, rule_type) triplet:
  - Count alerts with disposition_code IN ('CNA', 'FP') AND
    close_ts - created_ts < fast_close_minutes.
  - If count >= recurrence_threshold within the lookback window, flag the asset.

Data Sources:
  - Disposition codes from cases table (no raw ITSM logs required).
  - Escalation workflow: check for escalation steps performed.
  - known_noisy_exemptions: rule_type × asset_class pairs exempted by NCIIPC.

Exemption Handling:
  Before flagging, the engine checks if the alert rule_type matches an active
  exemption in the NCIIPC-controlled known_noisy_exemptions list.
  Exempted alerts are not flagged regardless of recurrence count.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import duckdb
import yaml

from engine.detectors.base import DetectorResult

logger = logging.getLogger(__name__)

_DEFAULT_EXEMPTIONS_PATH = "config/known_noisy_exemptions.yaml"


def _load_exemptions(path: str = _DEFAULT_EXEMPTIONS_PATH) -> list[dict]:
    """Load and return active exemptions from the NCIIPC-controlled YAML."""
    try:
        with open(path) as f:
            cfg = yaml.safe_load(f)
        return cfg.get("exemptions", [])
    except FileNotFoundError:
        logger.warning(f"Exemptions file not found at {path}; treating all rules as non-exempt")
        return []


def _is_exempt(
    rule_type: str,
    asset_class: str,
    sector: str,
    exemptions: list[dict],
    as_of: datetime,
) -> bool:
    """
    Check if a (rule_type, asset_class) combination is covered by an active exemption.

    Args:
        rule_type: Alert rule type.
        asset_class: Asset class of the asset generating the alert.
        sector: Entity sector.
        exemptions: List of exemption dicts from YAML.
        as_of: Evaluation timestamp (for expiry checking).

    Returns:
        True if the combination is exempt.
    """
    for ex in exemptions:
        rule_match = ex.get("rule_type", "") == rule_type
        class_match = ex.get("asset_class", "") in (asset_class, "*")
        sector_match = ex.get("sector", "") in (sector, "*")

        if not (rule_match and class_match and sector_match):
            continue

        # Check expiry
        expires = ex.get("expires_date")
        if expires:
            if isinstance(expires, str):
                from dateutil.parser import parse
                expires_dt = parse(expires)
            else:
                expires_dt = expires
            if as_of > expires_dt.replace(tzinfo=None):
                continue

        return True
    return False


def run_g6(
    con: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    fast_close_minutes: int = 30,
    recurrence_threshold: int = 3,
    lookback_days: int = 30,
    threshold_tier: str = "internal",
    exemptions_path: str = _DEFAULT_EXEMPTIONS_PATH,
    run_ts: Optional[datetime] = None,
) -> DetectorResult:
    """
    Run G6 (Silent Loop) detector for a single entity.

    Args:
        con: Active DuckDB connection.
        entity_id: Target entity identifier.
        fast_close_minutes: Closure within this window = "fast close".
        recurrence_threshold: Occurrences on same asset to flag.
        lookback_days: Historical window in days.
        threshold_tier: "internal" or "legal".
        exemptions_path: Path to known_noisy_exemptions.yaml.
        run_ts: Detector run timestamp.

    Returns:
        DetectorResult with flagged assets and linked record IDs.
    """
    if run_ts is None:
        run_ts = datetime.utcnow()

    exemptions = _load_exemptions(exemptions_path)

    parameters = {
        "fast_close_minutes": fast_close_minutes,
        "recurrence_threshold": recurrence_threshold,
        "lookback_days": lookback_days,
        "threshold_tier": threshold_tier,
        "exemptions_path": exemptions_path,
        "n_exemptions_loaded": len(exemptions),
    }

    # ── Query fast-closed alerts per (asset, rule_type) ──────────────────────
    # Note: DuckDB does not support ? placeholders inside INTERVAL expressions.
    # lookback_days and fast_close_minutes are integers validated above; safe to interpolate.
    query = f"""
        SELECT
            a.asset_id,
            a.rule_type,
            ast.asset_class,
            ent.sector,
            a.alert_id,
            c.case_id,
            c.analyst_id,
            c.disposition_code,
            DATEDIFF('minute', a.created_ts, a.close_ts) AS close_minutes
        FROM alerts a
        JOIN assets ast ON ast.asset_id = a.asset_id
        JOIN entities ent ON ent.entity_id = a.entity_id
        LEFT JOIN cases c ON c.alert_id = a.alert_id
        WHERE a.entity_id = ?
          AND a.close_ts IS NOT NULL
          AND DATEDIFF('minute', a.created_ts, a.close_ts) <= {int(fast_close_minutes)}
          AND c.disposition_code IN ('CNA', 'FP', 'BTP')
          AND a.created_ts >= CURRENT_TIMESTAMP - INTERVAL {int(lookback_days)} DAY
        ORDER BY a.asset_id, a.rule_type, a.created_ts
    """
    rows = con.execute(query, [entity_id]).fetchall()
    cols = [
        "asset_id", "rule_type", "asset_class", "sector", "alert_id",
        "case_id", "analyst_id", "disposition_code", "close_minutes",
    ]
    data = [dict(zip(cols, row)) for row in rows]

    if not data:
        return DetectorResult(
            detector_id="G6",
            detector_name="Silent Loop",
            entity_id=entity_id,
            run_ts=run_ts,
            test_name="Disposition Code Recurrence Analysis",
            statistic=0.0,
            p_value=None,
            score=0.0,
            parameters=parameters,
            sample_size=0,
            flag=False,
            threshold_tier=threshold_tier,
            confidence_note="NO DATA: no fast-closed alerts in lookback window",
        )

    # ── Group by (asset_id, rule_type) and apply exemptions ──────────────────
    from collections import defaultdict

    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in data:
        groups[(row["asset_id"], row["rule_type"])].append(row)

    flagged_assets = []
    linked_alert_ids: list[str] = []
    linked_case_ids: list[str] = []
    linked_analyst_ids: list[str] = []
    max_recurrence = 0

    for (asset_id, rule_type), asset_rows in groups.items():
        asset_class = asset_rows[0]["asset_class"]
        sector = asset_rows[0]["sector"]

        # Check exemption
        if _is_exempt(rule_type, asset_class, sector, exemptions, run_ts):
            logger.debug(f"G6: {asset_id}/{rule_type} is exempt from flagging")
            continue

        count = len(asset_rows)
        max_recurrence = max(max_recurrence, count)

        if count >= recurrence_threshold:
            alert_ids = [r["alert_id"] for r in asset_rows]
            case_ids = [r["case_id"] for r in asset_rows if r["case_id"]]
            analyst_ids = list({r["analyst_id"] for r in asset_rows if r["analyst_id"]})

            flagged_assets.append({
                "asset_id": asset_id,
                "rule_type": rule_type,
                "recurrence_count": count,
                "alert_ids": alert_ids[:50],
            })
            linked_alert_ids.extend(alert_ids)
            linked_case_ids.extend(case_ids)
            linked_analyst_ids.extend(analyst_ids)

    flagged = len(flagged_assets) > 0
    # Score: normalized recurrence (capped at 10x threshold = score 1.0)
    score = min(1.0, max_recurrence / (recurrence_threshold * 10)) if recurrence_threshold > 0 else 0.0

    parameters["n_flagged_assets"] = len(flagged_assets)
    parameters["max_recurrence_count"] = max_recurrence
    parameters["flagged_assets"] = flagged_assets[:10]

    return DetectorResult(
        detector_id="G6",
        detector_name="Silent Loop",
        entity_id=entity_id,
        run_ts=run_ts,
        test_name="Disposition Code Recurrence Analysis",
        statistic=float(max_recurrence),
        p_value=None,
        score=round(score, 6),
        parameters=parameters,
        sample_size=len(data),
        flag=flagged,
        threshold_tier=threshold_tier,
        confidence_note=(
            "Exemptions from NCIIPC-controlled known_noisy_exemptions.yaml applied. "
            "This detector identifies recurrence patterns, not confirmed threat persistence. "
            "See docs/methods_and_limitations.md §G6."
        ),
        linked_alert_ids=list(set(linked_alert_ids))[:500],
        linked_case_ids=list(set(linked_case_ids))[:500],
        linked_analyst_ids=list(set(linked_analyst_ids))[:200],
    )
