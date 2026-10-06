"""
SAT-SA Entity Composite Risk Scorer.

Aggregates detector results into a single entity risk score:

    R = min(100, sum(w_i * F_i))

where:
  - w_i = NCIIPC-defined weight for detector i (from config/weights.yaml)
  - F_i = graded value in [0, 1] from each DetectorResult.fi_value()
  - The sum is capped at 100.

Weights are read from config/weights.yaml. The score is NOT rounded internally;
rounding happens at display time.

Score interpretation:
  0-20:   Low risk — baseline monitoring sufficient
  21-50:  Medium risk — increased scrutiny recommended
  51-80:  High risk — prioritize for in-depth review
  81-100: Critical risk — immediate expert review required
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

from engine.detectors.base import DetectorResult

logger = logging.getLogger(__name__)

_DEFAULT_WEIGHTS_PATH = "config/weights.yaml"

# Mapping from detector_id → weights.yaml key
DETECTOR_WEIGHT_KEYS = {
    "G1": "G1_velocity_distortion",
    "G2": "G2_severity_laundering",
    "G3": "G3_temporal_clustering",
    "G4": "G4_template_collapse",
    "G5": "G5_workload_inconsistency",
    "G6": "G6_silent_loop",
    "L1_SLA": "L1_sla_violation",
    "L1_NS": "L1_negative_space",
}

SCORE_BANDS = [
    (81, 100, "CRITICAL"),
    (51, 80, "HIGH"),
    (21, 50, "MEDIUM"),
    (0, 20, "LOW"),
]


def _load_weights(path: str = _DEFAULT_WEIGHTS_PATH) -> tuple[dict[str, float], bool]:
    """
    Load detector weights from YAML.

    Returns:
        (weights_dict, binary_mode)
    """
    try:
        with open(path) as f:
            cfg = yaml.safe_load(f)
        weights = cfg.get("weights", {})
        binary_mode = cfg.get("binary_flag_mode", False)
        return weights, binary_mode
    except FileNotFoundError:
        logger.warning(f"Weights config not found at {path}; using equal weights")
        return {key: 10.0 for key in DETECTOR_WEIGHT_KEYS.values()}, False


@dataclass
class RiskScore:
    """Entity composite risk score with per-detector breakdown."""

    entity_id: str
    cycle_id: str
    run_ts: datetime
    score: float  # in [0, 100]
    band: str     # LOW / MEDIUM / HIGH / CRITICAL
    component_scores: dict[str, dict] = field(default_factory=dict)
    # component_scores: {detector_id: {weight, fi_value, contribution, flagged}}
    weights_version: str = "unknown"
    binary_mode: bool = False

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "cycle_id": self.cycle_id,
            "run_ts": self.run_ts.isoformat(),
            "score": round(self.score, 2),
            "band": self.band,
            "component_scores": self.component_scores,
            "weights_version": self.weights_version,
            "binary_mode": self.binary_mode,
        }


def _score_band(score: float) -> str:
    for low, high, label in SCORE_BANDS:
        if low <= score <= high:
            return label
    return "LOW"


def compute_risk_score(
    results: list[DetectorResult],
    entity_id: str,
    cycle_id: str,
    *,
    weights_path: str = _DEFAULT_WEIGHTS_PATH,
    run_ts: Optional[datetime] = None,
) -> RiskScore:
    """
    Compute entity composite risk score from a list of DetectorResults.

    R = min(100, sum(w_i * F_i))

    Args:
        results: All DetectorResult objects for this entity in this cycle.
        entity_id: Target entity identifier.
        cycle_id: Audit cycle identifier (e.g., "2024-Q4").
        weights_path: Path to config/weights.yaml.
        run_ts: Score computation timestamp.

    Returns:
        RiskScore with full per-detector breakdown.
    """
    if run_ts is None:
        run_ts = datetime.utcnow()

    weights, binary_mode = _load_weights(weights_path)

    # Index results by detector_id (last result wins if duplicates)
    result_map: dict[str, DetectorResult] = {r.detector_id: r for r in results}

    total_score = 0.0
    components: dict[str, dict] = {}

    for detector_id, weight_key in DETECTOR_WEIGHT_KEYS.items():
        weight = float(weights.get(weight_key, 0.0))
        result = result_map.get(detector_id)

        if result is None:
            components[detector_id] = {
                "weight": weight,
                "fi_value": 0.0,
                "contribution": 0.0,
                "flagged": False,
                "status": "NOT_RUN",
            }
            continue

        fi = result.fi_value(binary_mode=binary_mode)
        contribution = weight * fi
        total_score += contribution

        components[detector_id] = {
            "weight": weight,
            "fi_value": round(fi, 4),
            "contribution": round(contribution, 4),
            "flagged": result.flag,
            "statistic": result.statistic,
            "p_value": result.p_value,
            "score": result.score,
            "confidence_note": result.confidence_note,
            "status": "FLAGGED" if result.flag else "CLEAR",
        }

    final_score = min(100.0, max(0.0, total_score))

    try:
        weights_version = yaml.safe_load(open(weights_path)).get("version", "unknown")
    except Exception:
        weights_version = "unknown"

    return RiskScore(
        entity_id=entity_id,
        cycle_id=cycle_id,
        run_ts=run_ts,
        score=round(final_score, 4),
        band=_score_band(final_score),
        component_scores=components,
        weights_version=weights_version,
        binary_mode=binary_mode,
    )


def persist_results(
    con: "duckdb.DuckDBPyConnection",  # type: ignore[name-defined]
    risk_score: "RiskScore",
    detector_results: list,
    manifest: "SamplingManifest | None" = None,  # type: ignore[name-defined]
) -> None:
    """
    Persist risk scores, detector results, and sampling manifest to DuckDB.
    """
    import json
    import uuid

    # ── Upsert risk score ──────────────────────────────────────────────────────
    con.execute("""
        DELETE FROM risk_scores WHERE entity_id = ? AND cycle_id = ?
    """, [risk_score.entity_id, risk_score.cycle_id])

    rs_id = f"{risk_score.entity_id}_{risk_score.cycle_id}"
    con.execute("""
        INSERT INTO risk_scores (id, entity_id, cycle_id, run_ts, score, band, weights_version, binary_mode, component_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [
        rs_id,
        risk_score.entity_id,
        risk_score.cycle_id,
        risk_score.run_ts.isoformat() if risk_score.run_ts else None,
        risk_score.score,
        risk_score.band,
        risk_score.weights_version,
        risk_score.binary_mode,
        json.dumps(risk_score.component_scores),
    ])

    # ── Insert detector results (delete old first) ────────────────────────────
    con.execute("""
        DELETE FROM detector_results WHERE entity_id = ? AND cycle_id = ?
    """, [risk_score.entity_id, risk_score.cycle_id])

    for r in detector_results:
        det_id = f"{r.entity_id}_{risk_score.cycle_id}_{r.detector_id}"
        result_json = json.dumps({
            "linked_alert_ids": r.linked_alert_ids or [],
            "linked_case_ids": r.linked_case_ids or [],
            "linked_analyst_ids": r.linked_analyst_ids or [],
            "asymmetric_cells": (
                [vars(c) if hasattr(c, '__dict__') else c for c in r.asymmetric_cells]
                if r.asymmetric_cells else None
            ),
        })
        con.execute("""
            INSERT INTO detector_results (
                id, detector_id, detector_name, entity_id, cycle_id, run_ts,
                test_name, statistic, p_value, score, parameters, sample_size,
                flag, threshold_tier, confidence_note, fi_value, result_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            det_id, r.detector_id, r.detector_name, r.entity_id, risk_score.cycle_id,
            r.run_ts.isoformat() if r.run_ts else None, r.test_name,
            r.statistic, r.p_value, r.score,
            json.dumps(r.parameters) if r.parameters else None, r.sample_size,
            r.flag, r.threshold_tier, r.confidence_note,
            r.fi_value() if callable(getattr(r, "fi_value", None)) else getattr(r, "fi_value", r.score or 0.0),
            result_json
        ])

    # ── Insert manifest rows ───────────────────────────────────────────────────
    if manifest is not None:
        con.execute("""
            DELETE FROM review_manifests WHERE entity_id = ? AND cycle_id = ?
        """, [risk_score.entity_id, risk_score.cycle_id])
        for row in manifest.rows:
            man_id = f"{risk_score.entity_id}_{risk_score.cycle_id}_{row.alert_id}"
            con.execute("""
                INSERT INTO review_manifests (
                    id, entity_id, cycle_id, run_ts, alert_id, stratum,
                    priority_rank, detector_score, sampled_by, seed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                man_id, risk_score.entity_id, risk_score.cycle_id,
                risk_score.run_ts.isoformat() if risk_score.run_ts else None,
                row.alert_id, row.stratum,
                row.priority_rank, row.detector_score,
                row.sampled_by, manifest.seed,
            ])

    logger.debug(f"Persisted results for {risk_score.entity_id} cycle={risk_score.cycle_id} "
                 f"score={risk_score.score} band={risk_score.band}")

