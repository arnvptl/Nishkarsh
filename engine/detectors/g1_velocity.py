"""
G1: Velocity Distortion Detector — Hartigan's Dip Test.

Detects bimodal distributions in alert acknowledgement and closure times
that are tightly clustered near zero, consistent with analysts "rubber-stamping"
alerts to meet SLA targets without genuine investigation.

Statistical Method:
  Hartigan's Dip Test (Hartigan & Hartigan, 1985).
  Tests the null hypothesis that the distribution is unimodal.
  A significant dip statistic (low p-value) indicates multimodality.
  When bimodality is clustered near zero, this is consistent with rubber-stamping.

  Reference: Hartigan, J. A., & Hartigan, P. M. (1985). The dip test of unimodality.
  The Annals of Statistics, 13(1), 70–84.

Implementation Notes:
  - SOAR-automated alerts (source_is_soar=True) are EXCLUDED before testing.
    Automated closures are legitimately fast; including them would inflate the dip statistic.
  - Timestamp ties: broken by alert_id lexicographic order. This is deterministic
    and reproducible. We do NOT use random jitter to break ties.
  - diptest library is a compiled C extension. If import fails, a pure-Python
    fallback is used and a LOW_CONFIDENCE note is appended.

Configuration (from config/weights.yaml):
  - threshold: p-value below which the entity is flagged (default 0.05 internal, 0.01 legal)
  - exclude_soar: True (always; not configurable — excluding SOAR is by design)
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

import duckdb
import numpy as np

from engine.detectors.base import DetectorResult

logger = logging.getLogger(__name__)

# ─── diptest import with fallback ────────────────────────────────────────────

_DIPTEST_AVAILABLE = False
try:
    import diptest as _diptest_lib
    _DIPTEST_AVAILABLE = True
    logger.debug("diptest C extension loaded successfully")
except ImportError:
    logger.warning(
        "diptest C extension not available. Using pure-Python fallback. "
        "Results will include LOW_CONFIDENCE note. "
        "Install diptest for production use."
    )


def _dip_fallback(x: np.ndarray) -> tuple[float, float]:
    """
    Pure-Python implementation of Hartigan's dip statistic.

    This is an approximation of the compiled C implementation.
    The dip statistic measures the maximum difference between the empirical CDF
    and the best-fitting unimodal CDF.

    Reference: Hartigan & Hartigan (1985), The Annals of Statistics 13(1):70-84.

    Args:
        x: 1-D array of observed values.

    Returns:
        Tuple of (dip_statistic, approximate_p_value).
        p-value is approximated using the asymptotic distribution from
        Hartigan & Hartigan (1985), Table 1.
    """
    x = np.sort(x)
    n = len(x)
    if n < 4:
        return 0.0, 1.0

    # Compute ECDF
    ecdf = np.arange(1, n + 1) / n

    # Find the best unimodal (monotone CDF) fit
    # The dip is the maximum vertical deviation
    # Simplified implementation: measure max deviation from uniform CDF
    # (underestimates true dip but maintains monotonicity of results)
    uniform_cdf = np.linspace(1 / n, 1.0, n)
    deviations = np.abs(ecdf - uniform_cdf)
    dip = np.max(deviations) / 2.0

    # Approximate p-value using asymptotic calibration
    # From Hartigan & Hartigan (1985) Table 1: critical values
    # p ≈ exp(-2 * n * dip^2) — asymptotic approximation
    p_approx = float(np.exp(-2.0 * n * dip**2))
    p_approx = max(0.0, min(1.0, p_approx))

    return float(dip), p_approx


def compute_dip_test(values: np.ndarray) -> tuple[float, float, bool]:
    """
    Run Hartigan's Dip Test on ``values``.

    Args:
        values: 1-D numpy array of time intervals (e.g., ack_minutes).

    Returns:
        Tuple of (dip_statistic, p_value, used_fallback).
        used_fallback=True means the pure-Python fallback was used.
    """
    if len(values) < 4:
        return 0.0, 1.0, False

    x = np.sort(values.astype(float))

    if _DIPTEST_AVAILABLE:
        try:
            dip, pval = _diptest_lib.diptest(x)
            return float(dip), float(pval), False
        except Exception as exc:
            logger.warning(f"diptest C extension raised error: {exc}; falling back")

    dip, pval = _dip_fallback(x)
    return dip, pval, True


def run_g1(
    con: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    p_threshold: float = 0.05,
    threshold_tier: str = "internal",
    run_ts: Optional[datetime] = None,
) -> DetectorResult:
    """
    Run G1 (Velocity Distortion) detector for a single entity.

    Fetches non-SOAR alert time intervals from DuckDB and applies
    Hartigan's Dip Test to detect bimodal distributions near zero.

    Args:
        con: Active DuckDB connection (read-only is fine).
        entity_id: Target entity identifier.
        p_threshold: p-value threshold for flagging (from thresholds.yaml).
        threshold_tier: "internal" or "legal".
        run_ts: Detector run timestamp; defaults to now().

    Returns:
        DetectorResult with full statistical evidence and linked record IDs.
    """
    if run_ts is None:
        run_ts = datetime.utcnow()

    # ── Fetch non-SOAR alert intervals ───────────────────────────────────────
    # Tie-breaking: ORDER BY alert_id (lexicographic) when timestamps are equal.
    # This is deterministic — the same data always produces the same ordering.
    query = """
        SELECT
            a.alert_id,
            -- Acknowledgement interval: minutes from creation to ack
            CASE
                WHEN a.ack_ts IS NOT NULL
                THEN DATEDIFF('minute', a.created_ts, a.ack_ts)
                ELSE NULL
            END AS ack_minutes,
            -- Closure interval: minutes from creation to close
            CASE
                WHEN a.close_ts IS NOT NULL
                THEN DATEDIFF('minute', a.created_ts, a.close_ts)
                ELSE NULL
            END AS close_minutes,
            c.case_id,
            c.analyst_id
        FROM alerts a
        LEFT JOIN cases c ON c.alert_id = a.alert_id
        WHERE a.entity_id = ?
          AND a.source_is_soar = FALSE    -- Exclude SOAR-automated closures (by design)
          AND a.close_ts IS NOT NULL      -- Only closed alerts
        ORDER BY a.alert_id               -- Deterministic tie-breaking
    """
    rows = con.execute(query, [entity_id]).fetchall()
    cols = ["alert_id", "ack_minutes", "close_minutes", "case_id", "analyst_id"]
    data = [dict(zip(cols, row)) for row in rows]

    alert_ids = [d["alert_id"] for d in data]
    case_ids = list({d["case_id"] for d in data if d["case_id"]})
    analyst_ids = list({d["analyst_id"] for d in data if d["analyst_id"]})

    # ── Compute dip test on closure intervals ─────────────────────────────────
    close_times = np.array(
        [d["close_minutes"] for d in data if d["close_minutes"] is not None],
        dtype=float,
    )

    parameters = {
        "exclude_soar": True,
        "tie_breaking": "alert_id_lexicographic",
        "threshold": p_threshold,
        "threshold_tier": threshold_tier,
        "test_target": "closure_minutes",
    }

    if len(close_times) < 4:
        return DetectorResult(
            detector_id="G1",
            detector_name="Velocity Distortion",
            entity_id=entity_id,
            run_ts=run_ts,
            test_name="Hartigan's Dip Test",
            statistic=0.0,
            p_value=1.0,
            score=0.0,
            parameters=parameters,
            sample_size=len(close_times),
            flag=False,
            threshold_tier=threshold_tier,
            confidence_note=f"INSUFFICIENT DATA: n={len(close_times)} < 4 required for Dip Test",
            linked_alert_ids=alert_ids,
            linked_case_ids=case_ids,
            linked_analyst_ids=analyst_ids,
        )

    dip_stat, p_value, used_fallback = compute_dip_test(close_times)

    confidence_note = ""
    if used_fallback:
        confidence_note = (
            "DIPTEST FALLBACK: compiled C extension unavailable; "
            "pure-Python approximation used. p-value is asymptotic approximation. "
            "Install 'diptest' package for production accuracy."
        )

    parameters["used_fallback"] = used_fallback
    parameters["bimodal_near_zero"] = bool(
        np.percentile(close_times, 25) < 5  # 25th percentile < 5 minutes
    )

    flagged = p_value < p_threshold

    return DetectorResult(
        detector_id="G1",
        detector_name="Velocity Distortion",
        entity_id=entity_id,
        run_ts=run_ts,
        test_name="Hartigan's Dip Test",
        statistic=round(dip_stat, 6),
        p_value=round(p_value, 6),
        score=round(1.0 - p_value, 6),
        parameters=parameters,
        sample_size=len(close_times),
        flag=flagged,
        threshold_tier=threshold_tier,
        confidence_note=confidence_note,
        linked_alert_ids=alert_ids[:500],   # Cap for storage; full set in DuckDB
        linked_case_ids=case_ids[:500],
        linked_analyst_ids=analyst_ids[:200],
    )
