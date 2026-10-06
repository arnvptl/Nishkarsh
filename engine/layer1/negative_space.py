"""
Layer 1: Negative Space Detector — Matched-Cohort Quantile Comparison.

Identifies entities with suspiciously low alert volumes in specific rule
categories (e.g., Lateral Movement, Credential Access), which may indicate
monitoring blind spots rather than genuinely secure environments.

Method:
  Matched-Cohort Quantile Comparison.
  Entities are grouped by (asset_class, sector, size_band).
  For each entity, its 90-day alert volume (per category) is compared against
  the 5th percentile (p5) of its matched cohort.
  If the entity falls below p5, it is flagged as potentially under-reporting.

Key Design Principle:
  "Absence of evidence is not evidence of absence."
  A zero-alert count is only suspicious when the cohort (similar entities)
  consistently generates alerts in that category. This avoids flagging entities
  whose asset profile genuinely produces no alerts.

Limitations:
  - Cohort size < 5: LOW_COHORT_CONFIDENCE label is applied.
  - The test cannot distinguish between: (a) genuine absence of threats and
    (b) monitoring gaps. It only quantifies statistical unusualness vs. peers.
  - Cohort matching is by (asset_class, sector, size_band). Entities with unique
    profiles may have no valid cohort.

Configuration:
  - min_cohort_size: 5 (below this → LOW_COHORT_CONFIDENCE)
  - negative_space_percentile: 5 (p5 threshold)
  - lookback_days: 90
  - target_rule_types: ["Lateral Movement", "Credential Access", "Privilege Escalation"]
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

import duckdb
import numpy as np

from engine.detectors.base import DetectorResult

logger = logging.getLogger(__name__)

# Alert rule categories that should generate consistent volumes in most CSEs
TARGET_RULE_CATEGORIES = [
    "Lateral Movement",
    "Credential Access",
    "Privilege Escalation",
    "Data Exfiltration",
    "Command and Control",
]

MIN_COHORT_SIZE = 5
NEGATIVE_SPACE_PERCENTILE = 5
LOOKBACK_DAYS = 90


def run_l1_negative_space(
    con: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    min_cohort_size: int = MIN_COHORT_SIZE,
    percentile: int = NEGATIVE_SPACE_PERCENTILE,
    lookback_days: int = LOOKBACK_DAYS,
    target_rule_categories: list[str] = TARGET_RULE_CATEGORIES,
    threshold_tier: str = "internal",
    run_ts: Optional[datetime] = None,
) -> DetectorResult:
    """
    Run Layer 1 Negative Space (Matched-Cohort Quantile Comparison) for one entity.

    Args:
        con: Active DuckDB connection.
        entity_id: Target entity identifier.
        min_cohort_size: Minimum peers required for reliable comparison.
        percentile: Flag if entity falls below this percentile of cohort volume.
        lookback_days: Historical window for alert counting.
        target_rule_categories: Rule types to check for negative space.
        threshold_tier: "internal" or "legal".
        run_ts: Detector run timestamp.

    Returns:
        DetectorResult with score = worst-case percentile shortfall.
    """
    if run_ts is None:
        run_ts = datetime.utcnow()

    # ── Fetch entity profile ──────────────────────────────────────────────────
    entity_row = con.execute(
        "SELECT sector, asset_class, size_band FROM entities WHERE entity_id = ?",
        [entity_id],
    ).fetchone()

    parameters = {
        "min_cohort_size": min_cohort_size,
        "percentile": percentile,
        "lookback_days": lookback_days,
        "target_rule_categories": target_rule_categories,
        "threshold_tier": threshold_tier,
    }

    if not entity_row:
        return DetectorResult(
            detector_id="L1_NS",
            detector_name="Negative Space",
            entity_id=entity_id,
            run_ts=run_ts,
            test_name="Matched-Cohort Quantile Comparison",
            statistic=0.0,
            p_value=None,
            score=0.0,
            parameters=parameters,
            sample_size=0,
            flag=False,
            threshold_tier=threshold_tier,
            confidence_note="ERROR: entity not found in entities table",
        )

    sector, asset_class, size_band = entity_row

    # ── Build cohort (matched peers) ─────────────────────────────────────────
    cohort_query = """
        SELECT entity_id FROM entities
        WHERE sector = ?
          AND asset_class = ?
          AND size_band = ?
          AND entity_id != ?
    """
    cohort_rows = con.execute(cohort_query, [sector, asset_class, size_band, entity_id]).fetchall()
    cohort_ids = [r[0] for r in cohort_rows]
    cohort_size = len(cohort_ids)

    confidence_note = ""
    if cohort_size < min_cohort_size:
        confidence_note = (
            f"LOW COHORT CONFIDENCE: cohort size n={cohort_size} < minimum {min_cohort_size}. "
            f"Statistical comparison unreliable. "
            f"Cohort: sector={sector}, asset_class={asset_class}, size_band={size_band}."
        )

    # ── Count alerts per rule category ───────────────────────────────────────
    flagged_categories = []
    all_scores = []

    for rule_cat in target_rule_categories:
        # Count for target entity
        entity_count_row = con.execute(f"""
            SELECT COUNT(*) FROM alerts
            WHERE entity_id = ?
              AND rule_type LIKE ?
              AND created_ts >= CURRENT_TIMESTAMP - INTERVAL {int(lookback_days)} DAY
        """, [entity_id, f"%{rule_cat}%"]).fetchone()
        entity_count = entity_count_row[0] if entity_count_row else 0

        if cohort_size == 0:
            continue

        # Count for each cohort peer
        if cohort_ids:
            ph = ", ".join("?" * len(cohort_ids))
            peer_counts_rows = con.execute(f"""
                SELECT entity_id, COUNT(*) as cnt
                FROM alerts
                WHERE entity_id IN ({ph})
                  AND rule_type LIKE ?
                  AND created_ts >= CURRENT_TIMESTAMP - INTERVAL {int(lookback_days)} DAY
                GROUP BY entity_id
            """, cohort_ids + [f"%{rule_cat}%"]).fetchall()
            peer_counts = [r[1] for r in peer_counts_rows]
            # Include zeros for cohort members with no alerts in this category
            peer_counts.extend([0] * (cohort_size - len(peer_counts)))
        else:
            peer_counts = []

        if not peer_counts or all(c == 0 for c in peer_counts):
            # Cohort also has no alerts; cannot distinguish
            continue

        cohort_p5 = float(np.percentile(peer_counts, percentile))

        if entity_count <= cohort_p5:
            # How far below the percentile (as a fraction of p5)
            shortfall = (cohort_p5 - entity_count) / max(cohort_p5, 1)
            flagged_categories.append({
                "rule_category": rule_cat,
                "entity_count": entity_count,
                "cohort_p5": round(cohort_p5, 1),
                "cohort_median": round(float(np.median(peer_counts)), 1),
                "shortfall_fraction": round(shortfall, 4),
            })
            all_scores.append(shortfall)

    flagged = len(flagged_categories) > 0
    max_score = max(all_scores) if all_scores else 0.0

    parameters["cohort_size"] = cohort_size
    parameters["cohort_profile"] = {"sector": sector, "asset_class": asset_class, "size_band": size_band}
    parameters["flagged_categories"] = flagged_categories

    if cohort_size < min_cohort_size and flagged:
        flagged = False  # Don't auto-flag with low confidence cohort
        confidence_note += " Flag suppressed due to LOW COHORT CONFIDENCE."

    return DetectorResult(
        detector_id="L1_NS",
        detector_name="Negative Space",
        entity_id=entity_id,
        run_ts=run_ts,
        test_name="Matched-Cohort Quantile Comparison",
        statistic=float(max_score),
        p_value=None,
        score=round(min(1.0, max_score), 6),
        parameters=parameters,
        sample_size=cohort_size,
        flag=flagged,
        threshold_tier=threshold_tier,
        confidence_note=confidence_note,
        linked_alert_ids=[],  # Negative space: no specific alerts to link
        linked_case_ids=[],
        linked_analyst_ids=[],
    )
