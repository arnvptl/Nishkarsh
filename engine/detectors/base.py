"""
SAT-SA DetectorResult — shared output schema for all detectors (G1-G6, L1).

Every detector MUST return a list of DetectorResult objects.
No detector may return raw statistics without wrapping them in this schema.

This satisfies the hard explainability constraint:
  "every flag must show the test used, parameters, statistic, p-value/score,
   and the exact underlying Case IDs / Alert IDs / Analyst IDs"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class AsymmetricCell:
    """
    A pair of off-diagonal cells in the severity transition matrix (G2).
    Used to highlight specific P_i → P_j vs P_j → P_i asymmetries.
    """

    from_sev: str       # e.g. "P1"
    to_sev: str         # e.g. "P3"
    count_ij: int       # transitions from_sev → to_sev
    count_ji: int       # transitions to_sev → from_sev
    alert_ids: list[str] = field(default_factory=list)
    rationale_missing_count: int = 0

    @property
    def asymmetry_ratio(self) -> float:
        """How many times more common is i→j than j→i?"""
        if self.count_ji == 0:
            return float("inf")
        return self.count_ij / self.count_ji


@dataclass
class DetectorResult:
    """
    Canonical output record for any SAT-SA detector.

    All fields are required unless marked Optional.
    Callers (risk scorer, API, frontend) rely on this schema being stable.
    """

    # ── Identity ─────────────────────────────────────────────────────────────
    detector_id: str
    """Short identifier: G1, G2, ..., G6, L1_SLA, L1_NS"""

    detector_name: str
    """Human-readable name, e.g. 'Severity Laundering'"""

    entity_id: str

    run_ts: datetime
    """Wall-clock timestamp of this detector run."""

    # ── Statistical Evidence ──────────────────────────────────────────────────
    test_name: str
    """Name of the statistical test or method, e.g. "Hartigan's Dip Test"."""

    statistic: float
    """Primary test statistic (dip statistic, χ², H/log₂n, Jaccard, etc.)."""

    p_value: Optional[float]
    """
    p-value from hypothesis test, or None for score-based detectors (G4, G5, G6).
    None does NOT mean "not significant" — see score field.
    """

    score: Optional[float]
    """
    Normalized score in [0, 1] for score-based detectors.
    For p-value tests: score = 1 - p_value (used as F_i in risk scoring).
    None for detectors that only produce a p-value.
    """

    parameters: dict
    """
    All configurable parameters used in this run.
    E.g. {"permutation_n": 9999, "seed": 42, "exclude_soar": True}
    Ensures reproducibility: same parameters + same data = same result.
    """

    sample_size: int
    """Number of records (alerts/cases/effort rows) analyzed."""

    # ── Decision ─────────────────────────────────────────────────────────────
    flag: bool
    """
    True if the detector found an anomaly exceeding the configured threshold.
    The threshold used is stored in parameters["threshold"].
    """

    threshold_tier: str = "internal"
    """
    Which threshold tier triggered this flag: 'internal' or 'legal'.
    """

    # ── Explainability ────────────────────────────────────────────────────────
    confidence_note: str = ""
    """
    Human-readable caveat. Required for low-confidence results.
    E.g. "LOW COHORT CONFIDENCE: cohort size n=3 < minimum 5"
         "PERMUTATION APPROXIMATION: expected cell count < 5; Monte Carlo n=9999"
         "DIPTEST FALLBACK: compiled diptest unavailable; pure-Python implementation used"
    """

    linked_alert_ids: list[str] = field(default_factory=list)
    linked_case_ids: list[str] = field(default_factory=list)
    linked_analyst_ids: list[str] = field(default_factory=list)

    # ── G2-Specific ───────────────────────────────────────────────────────────
    asymmetric_cells: Optional[list[AsymmetricCell]] = None
    """
    Populated by G2 (Severity Laundering) only.
    Lists the specific off-diagonal pairs driving the Bowker test result.
    """

    def fi_value(self, binary_mode: bool = False) -> float:
        """
        Compute F_i ∈ [0, 1] for use in the risk score weighted sum.

        In default mode (binary_mode=False):
          - p-value tests:    F_i = 1 - p_value
          - score-based:      F_i = score
          - not flagged:      F_i = 0

        In binary_mode (binary_flag_mode=True in weights.yaml):
          - F_i = 1.0 if flag else 0.0

        Returns:
            float in [0, 1].
        """
        if binary_mode:
            return 1.0 if self.flag else 0.0

        if not self.flag:
            return 0.0

        if self.p_value is not None:
            return max(0.0, min(1.0, 1.0 - self.p_value))
        if self.score is not None:
            return max(0.0, min(1.0, self.score))
        # If neither, treat as binary
        return 1.0 if self.flag else 0.0

    def to_dict(self) -> dict:
        """Serialize to dict for API responses and audit logging."""
        d = {
            "detector_id": self.detector_id,
            "detector_name": self.detector_name,
            "entity_id": self.entity_id,
            "run_ts": self.run_ts.isoformat(),
            "test_name": self.test_name,
            "statistic": self.statistic,
            "p_value": self.p_value,
            "score": self.score,
            "parameters": self.parameters,
            "sample_size": self.sample_size,
            "flag": self.flag,
            "threshold_tier": self.threshold_tier,
            "confidence_note": self.confidence_note,
            "linked_alert_ids": self.linked_alert_ids,
            "linked_case_ids": self.linked_case_ids,
            "linked_analyst_ids": self.linked_analyst_ids,
            "fi_value": self.fi_value(),
        }
        if self.asymmetric_cells:
            d["asymmetric_cells"] = [
                {
                    "from_sev": c.from_sev,
                    "to_sev": c.to_sev,
                    "count_ij": c.count_ij,
                    "count_ji": c.count_ji,
                    "asymmetry_ratio": c.asymmetry_ratio,
                    "rationale_missing_count": c.rationale_missing_count,
                    "alert_ids": c.alert_ids[:100],  # Cap for API response size
                }
                for c in self.asymmetric_cells
            ]
        return d
