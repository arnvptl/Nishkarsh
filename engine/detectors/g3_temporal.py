"""
G3: Temporal Clustering Detector — Normalized Shannon Entropy.

Detects batch-closing of alerts at shift handover (shift-end gaming).
Analysts may close many alerts rapidly just before their shift ends to
meet SLA closure targets, without genuine investigation.

Statistical Method:
  Normalized Shannon Entropy H(X) / log₂(n):

    H(X) = -Σ p_k * log₂(p_k)

  where p_k = (count of alert closures in bin k) / total closures.

  Normalized by log₂(n) where n = number of non-empty bins, giving H ∈ [0, 1].
  H = 1: perfectly uniform distribution (random closures across shift).
  H ≈ 0: all closures concentrated in one bin (batch closure pattern).

  Flag condition: H < low_entropy_threshold (default 0.4).

Reference:
  Shannon, C. E. (1948). A Mathematical Theory of Communication.
  Bell System Technical Journal, 27(3), 379–423.

Configuration:
  - bin_minutes: Temporal bin width (default 15 minutes).
  - low_entropy_threshold: Flag if H/log₂(n) < this value.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

import duckdb
import numpy as np

from engine.detectors.base import DetectorResult

logger = logging.getLogger(__name__)


def _normalized_entropy(counts: np.ndarray) -> float:
    """
    Compute normalized Shannon entropy H(X) / log₂(n).

    Args:
        counts: Array of non-negative bin counts (zero bins are excluded from p_k
                computation but included in n for normalization base).

    Returns:
        Normalized entropy in [0, 1]. Returns 1.0 if all counts equal (maximum
        entropy, no clustering). Returns 0.0 if all closures in one bin.
    """
    counts = counts[counts > 0]
    n = len(counts)
    if n <= 1:
        return 0.0  # All in one bin = maximum clustering

    total = counts.sum()
    if total == 0:
        return 1.0

    probs = counts / total
    # Shannon entropy: -Σ p_k * log₂(p_k)
    raw_entropy = float(-np.sum(probs * np.log2(probs + 1e-15)))
    # Normalize by log₂(n): maximum possible entropy for n bins
    normalized = raw_entropy / np.log2(n)
    return float(np.clip(normalized, 0.0, 1.0))


def run_g3(
    con: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    bin_minutes: int = 15,
    low_entropy_threshold: float = 0.4,
    p_threshold: float = 0.05,
    threshold_tier: str = "internal",
    min_alerts_per_shift: int = 10,
    run_ts: Optional[datetime] = None,
) -> DetectorResult:
    """
    Run G3 (Temporal Clustering) detector for a single entity.

    Groups alert closures by analyst shift, computes normalized Shannon entropy
    per shift, and flags shifts with H < low_entropy_threshold.

    Args:
        con: Active DuckDB connection.
        entity_id: Target entity identifier.
        bin_minutes: Width of temporal bins in minutes.
        low_entropy_threshold: H/log₂(n) below this = batch-close pattern.
        p_threshold: Not used for G3 (score-based). Kept for API consistency.
        threshold_tier: "internal" or "legal".
        min_alerts_per_shift: Skip shifts with fewer than this many closures.
        run_ts: Detector run timestamp.

    Returns:
        DetectorResult with score = mean normalized entropy across flagged shifts.
    """
    if run_ts is None:
        run_ts = datetime.utcnow()

    # ── Fetch closure timestamps per analyst/shift ────────────────────────────
    query = """
        SELECT
            c.analyst_id,
            c.shift_id,
            c.case_id,
            a.alert_id,
            c.closed_ts,
            -- Minutes since start of the shift window for this analyst
            -- Using epoch minutes for binning
            EPOCH(c.closed_ts) / 60 AS close_epoch_minutes
        FROM cases c
        JOIN alerts a ON a.alert_id = c.alert_id
        WHERE a.entity_id = ?
          AND c.closed_ts IS NOT NULL
          AND c.analyst_id IS NOT NULL
          AND c.shift_id IS NOT NULL
        ORDER BY c.shift_id, c.analyst_id, c.closed_ts
    """
    rows = con.execute(query, [entity_id]).fetchall()
    cols = ["analyst_id", "shift_id", "case_id", "alert_id", "closed_ts", "close_epoch_minutes"]
    data = [dict(zip(cols, row)) for row in rows]

    if not data:
        return DetectorResult(
            detector_id="G3",
            detector_name="Temporal Clustering",
            entity_id=entity_id,
            run_ts=run_ts,
            test_name="Normalized Shannon Entropy",
            statistic=1.0,
            p_value=None,
            score=0.0,
            parameters={"bin_minutes": bin_minutes, "threshold": low_entropy_threshold},
            sample_size=0,
            flag=False,
            threshold_tier=threshold_tier,
            confidence_note="NO DATA: no closed cases found for entity",
        )

    # ── Group by (analyst_id, shift_id) and compute entropy ──────────────────
    from collections import defaultdict

    shift_groups: dict[tuple[str, str], list[float]] = defaultdict(list)
    shift_case_ids: dict[tuple[str, str], list[str]] = defaultdict(list)
    shift_alert_ids: dict[tuple[str, str], list[str]] = defaultdict(list)

    for row in data:
        key = (row["analyst_id"], row["shift_id"])
        shift_groups[key].append(row["close_epoch_minutes"])
        shift_case_ids[key].append(row["case_id"])
        shift_alert_ids[key].append(row["alert_id"])

    flagged_shifts = []
    all_entropies = []
    linked_alert_ids: list[str] = []
    linked_case_ids: list[str] = []
    linked_analyst_ids: list[str] = []

    for (analyst_id, shift_id), epoch_minutes in shift_groups.items():
        if len(epoch_minutes) < min_alerts_per_shift:
            continue

        times = np.array(epoch_minutes)
        # Bin relative to shift start
        shift_start = times.min()
        relative_times = times - shift_start
        bin_edges = np.arange(0, relative_times.max() + bin_minutes, bin_minutes)
        counts, _ = np.histogram(relative_times, bins=bin_edges)

        entropy = _normalized_entropy(counts)
        all_entropies.append(entropy)

        if entropy < low_entropy_threshold:
            flagged_shifts.append({
                "analyst_id": analyst_id,
                "shift_id": shift_id,
                "entropy": round(entropy, 4),
                "n_closures": len(epoch_minutes),
            })
            linked_alert_ids.extend(shift_alert_ids[(analyst_id, shift_id)])
            linked_case_ids.extend(shift_case_ids[(analyst_id, shift_id)])
            linked_analyst_ids.append(analyst_id)

    mean_entropy = float(np.mean(all_entropies)) if all_entropies else 1.0
    min_entropy = float(np.min(all_entropies)) if all_entropies else 1.0
    flagged = len(flagged_shifts) > 0

    # Score: how low the worst-case entropy is (1 - min_entropy, so higher = worse)
    score = round(1.0 - min_entropy, 6)

    parameters = {
        "bin_minutes": bin_minutes,
        "low_entropy_threshold": low_entropy_threshold,
        "min_alerts_per_shift": min_alerts_per_shift,
        "n_shifts_evaluated": len(all_entropies),
        "n_flagged_shifts": len(flagged_shifts),
        "flagged_shifts": flagged_shifts[:20],  # Cap for storage
        "threshold_tier": threshold_tier,
    }

    confidence_note = ""
    if len(all_entropies) < 3:
        confidence_note = (
            f"LOW CONFIDENCE: only {len(all_entropies)} shifts with ≥{min_alerts_per_shift} "
            "closures. More data needed for reliable entropy estimation."
        )

    return DetectorResult(
        detector_id="G3",
        detector_name="Temporal Clustering",
        entity_id=entity_id,
        run_ts=run_ts,
        test_name="Normalized Shannon Entropy",
        statistic=round(mean_entropy, 6),  # Primary statistic = mean entropy
        p_value=None,  # Score-based detector
        score=score,
        parameters=parameters,
        sample_size=len(data),
        flag=flagged,
        threshold_tier=threshold_tier,
        confidence_note=confidence_note,
        linked_alert_ids=list(set(linked_alert_ids))[:500],
        linked_case_ids=list(set(linked_case_ids))[:500],
        linked_analyst_ids=list(set(linked_analyst_ids))[:200],
    )
