"""
SAT-SA Stratified Alert Sampling Engine.

Generates a prioritized review manifest for examiner-set alert budgets.

Allocation Strategy:
  80% of the examiner's alert budget is drawn from alerts driving flagged
  anomalies (e.g., the specific alert IDs inside asymmetric Bowker cells,
  rubber-stamped alerts, etc.). This maximizes the hit rate per reviewed alert.

  20% is sampled randomly from the unflagged alert population, using a seeded
  RNG for reproducibility. This baseline sample:
    - Establishes the recall rate (false negative estimate) of the detectors.
    - Detects novel gaming methods not covered by G1-G6.

Per-Stratum Allocation (Neyman-style):
  When multiple detectors flag different alert subsets, the 80% budget is
  allocated proportionally across strata using Neyman allocation:
    n_h = n * (N_h * σ_h) / Σ(N_j * σ_j)
  where N_h is stratum size and σ_h is the stratum's detector score (F_i).

  For detectors without variance estimates, proportional allocation is used.

Output:
  A manifest CSV/dict with columns:
    alert_id, entity_id, stratum (detector_id or "RANDOM"), priority_rank,
    detector_score, sampled_by, seed

Legal basis for random seeding: logged in the audit log, reproducible on demand.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import numpy as np

from engine.detectors.base import DetectorResult

logger = logging.getLogger(__name__)


@dataclass
class ManifestRow:
    """A single row in the examiner review manifest."""

    alert_id: str
    entity_id: str
    stratum: str          # detector_id (e.g., "G2") or "RANDOM"
    priority_rank: int    # 1 = highest priority
    detector_score: float # F_i score from the detector, or 0.0 for random stratum
    sampled_by: str       # "FLAGGED_80PCT" or "RANDOM_20PCT"
    seed: int             # RNG seed used for random allocation (logged for audit)

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "entity_id": self.entity_id,
            "stratum": self.stratum,
            "priority_rank": self.priority_rank,
            "detector_score": round(self.detector_score, 4),
            "sampled_by": self.sampled_by,
            "seed": self.seed,
        }


@dataclass
class ReviewManifest:
    """Complete examiner review manifest for one entity/cycle."""

    entity_id: str
    cycle_id: str
    examiner_budget: int
    run_ts: datetime
    seed: int
    rows: list[ManifestRow] = field(default_factory=list)
    n_flagged: int = 0
    n_random: int = 0

    def to_dicts(self) -> list[dict]:
        return [r.to_dict() for r in self.rows]

    def to_csv_lines(self) -> list[str]:
        if not self.rows:
            return []
        header = ",".join(ManifestRow.__dataclass_fields__.keys())
        lines = [header]
        for r in self.rows:
            lines.append(",".join(str(v) for v in r.to_dict().values()))
        return lines


def generate_manifest(
    results: list[DetectorResult],
    entity_id: str,
    cycle_id: str,
    all_alert_ids: list[str],
    *,
    examiner_budget: int = 50,
    flagged_pct: float = 0.80,
    seed: int = 42,
    run_ts: Optional[datetime] = None,
) -> ReviewManifest:
    """
    Generate a prioritized review manifest for an examiner.

    Args:
        results: Detector results for this entity.
        entity_id: Target entity.
        cycle_id: Audit cycle identifier.
        all_alert_ids: Complete list of alert IDs for this entity in the cycle.
        examiner_budget: Total number of alerts to include in manifest.
        flagged_pct: Fraction of budget for flagged-alert stratum (default 0.80).
        seed: RNG seed for random stratum (logged in audit).
        run_ts: Manifest generation timestamp.

    Returns:
        ReviewManifest with rows sorted by priority_rank.
    """
    if run_ts is None:
        run_ts = datetime.utcnow()

    rng = np.random.default_rng(seed)

    n_flagged_budget = round(examiner_budget * flagged_pct)
    n_random_budget = examiner_budget - n_flagged_budget

    manifest = ReviewManifest(
        entity_id=entity_id,
        cycle_id=cycle_id,
        examiner_budget=examiner_budget,
        run_ts=run_ts,
        seed=seed,
    )

    # ── Collect flagged alerts per detector with scores ───────────────────────
    flagged_pool: dict[str, tuple[list[str], float]] = {}  # stratum → (alert_ids, score)

    for result in results:
        if result.flag and result.linked_alert_ids:
            fi = result.fi_value()
            flagged_pool[result.detector_id] = (result.linked_alert_ids, fi)

    # ── Neyman-style proportional allocation across strata ───────────────────
    all_flagged_alert_ids: set[str] = set()
    stratum_allocations: dict[str, int] = {}

    if flagged_pool:
        # Neyman allocation: n_h ∝ N_h * σ_h
        total_weight = sum(
            len(aids) * score for aids, score in flagged_pool.values()
        )
        for detector_id, (aids, score) in flagged_pool.items():
            if total_weight > 0:
                proportion = (len(aids) * score) / total_weight
            else:
                proportion = 1.0 / len(flagged_pool)
            stratum_allocations[detector_id] = max(1, round(n_flagged_budget * proportion))

        # Trim to exact budget
        total_allocated = sum(stratum_allocations.values())
        if total_allocated > n_flagged_budget:
            # Trim from the smallest strata
            sorted_strata = sorted(stratum_allocations.items(), key=lambda x: x[1])
            excess = total_allocated - n_flagged_budget
            for det_id, alloc in sorted_strata:
                trim = min(excess, alloc - 1)
                stratum_allocations[det_id] = alloc - trim
                excess -= trim
                if excess == 0:
                    break

    # ── Sample from each stratum ──────────────────────────────────────────────
    priority_rank = 1
    for detector_id, (alert_ids, score) in flagged_pool.items():
        n_to_sample = stratum_allocations.get(detector_id, 0)
        if n_to_sample == 0:
            continue

        # Sample without replacement from this stratum
        pool = list(dict.fromkeys(alert_ids))  # Deduplicate, preserve order
        if len(pool) <= n_to_sample:
            sampled = pool
        else:
            indices = rng.choice(len(pool), size=n_to_sample, replace=False)
            sampled = [pool[i] for i in sorted(indices)]

        for alert_id in sampled:
            if alert_id not in all_flagged_alert_ids:
                manifest.rows.append(ManifestRow(
                    alert_id=alert_id,
                    entity_id=entity_id,
                    stratum=detector_id,
                    priority_rank=priority_rank,
                    detector_score=score,
                    sampled_by="FLAGGED_80PCT",
                    seed=seed,
                ))
                all_flagged_alert_ids.add(alert_id)
                priority_rank += 1

    manifest.n_flagged = priority_rank - 1

    # ── Random 20% stratum ────────────────────────────────────────────────────
    unflagged_pool = [a for a in all_alert_ids if a not in all_flagged_alert_ids]

    if unflagged_pool and n_random_budget > 0:
        n_random = min(n_random_budget, len(unflagged_pool))
        indices = rng.choice(len(unflagged_pool), size=n_random, replace=False)
        random_sample = [unflagged_pool[i] for i in sorted(indices)]

        for alert_id in random_sample:
            manifest.rows.append(ManifestRow(
                alert_id=alert_id,
                entity_id=entity_id,
                stratum="RANDOM",
                priority_rank=priority_rank,
                detector_score=0.0,
                sampled_by="RANDOM_20PCT",
                seed=seed,
            ))
            priority_rank += 1

    manifest.n_random = len([r for r in manifest.rows if r.sampled_by == "RANDOM_20PCT"])

    logger.info(
        f"Manifest for {entity_id}: {manifest.n_flagged} flagged + "
        f"{manifest.n_random} random = {len(manifest.rows)} total "
        f"(budget: {examiner_budget}, seed: {seed})"
    )

    return manifest
