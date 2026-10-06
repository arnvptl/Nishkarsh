"""
G2: Severity Laundering Detector — Bowker's Test of Symmetry.

Detects systematic downgrading of alert severity prior to closure.
Analysts may downgrade P1 → P3 to avoid escalation SLAs, inflating
SOC performance metrics while obscuring genuine critical threats.

Statistical Method:
  Bowker's Test of Symmetry (Bowker, 1948).
  Tests the null hypothesis that the severity transition matrix is symmetric
  (i.e., P_i → P_j transitions are equally common as P_j → P_i).

  For the transition matrix M where M[i,j] = count of transitions from
  severity P_i to P_j:

    χ² = Σ_{i<j} (m_ij - m_ji)² / (m_ij + m_ji)

  with degrees of freedom = k(k-1)/2 where k = number of severity levels.

  Reference: Bowker, A. H. (1948). A test for symmetry in contingency tables.
  Journal of the American Statistical Association, 43(244), 572–574.

Vectorized Monte Carlo Approximation (for small expected cell counts < 5):
  When any off-diagonal pair (i,j) has expected count < min_expected_count,
  we use a vectorized Monte Carlo approximation:

    For each pair (i,j): simulate n_ij + n_ji as Binomial(n_ij + n_ji, 0.5)
    across 9,999 draws in a single numpy vectorized call.
    p-value = fraction of simulated χ² values ≥ observed χ².

  This is documented as an APPROXIMATE EXACT TEST — it approaches the exact
  conditional p-value as permutation_n → ∞, but is NOT a true exact test.

  Vectorization: all 9,999 × n_pairs draws are generated in ONE numpy call:
    np.random.default_rng(seed).binomial(totals, 0.5, size=(9999, n_pairs))
  This makes the test O(n_pairs) rather than O(9999 * n_pairs).

UI Integration:
  The asymmetric_cells field of DetectorResult identifies specific (i,j) pairs
  with high asymmetry, e.g., P1→P3 vs P3→P1, and lists the alert IDs in each cell.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

import duckdb
import numpy as np
from scipy import stats

from engine.detectors.base import AsymmetricCell, DetectorResult

logger = logging.getLogger(__name__)

# Severity ordering (lower index = higher severity)
SEVERITY_LEVELS = ["P1", "P2", "P3", "P4", "P5"]
SEV_TO_IDX = {s: i for i, s in enumerate(SEVERITY_LEVELS)}


def _build_transition_matrix(
    con: duckdb.DuckDBPyConnection,
    entity_id: str,
) -> tuple[np.ndarray, dict[tuple[str, str], list[str]], dict[tuple[str, str], int]]:
    """
    Build the severity transition matrix for an entity.

    Returns:
        matrix: k×k integer matrix where matrix[i,j] = count of transitions
                from SEVERITY_LEVELS[i] to SEVERITY_LEVELS[j].
        alert_map: dict mapping (from_sev, to_sev) → list of alert_ids in that cell.
        rationale_missing: dict mapping (from_sev, to_sev) → count of transitions
                           where rationale_present=False.
    """
    query = """
        SELECT
            st.from_sev,
            st.to_sev,
            st.alert_id,
            st.rationale_present
        FROM severity_transitions st
        JOIN alerts a ON a.alert_id = st.alert_id
        WHERE a.entity_id = ?
          AND st.from_sev != st.to_sev
    """
    rows = con.execute(query, [entity_id]).fetchall()

    k = len(SEVERITY_LEVELS)
    matrix = np.zeros((k, k), dtype=int)
    alert_map: dict[tuple[str, str], list[str]] = {}
    rationale_missing: dict[tuple[str, str], int] = {}

    for from_sev, to_sev, alert_id, rationale_present in rows:
        if from_sev not in SEV_TO_IDX or to_sev not in SEV_TO_IDX:
            continue
        i, j = SEV_TO_IDX[from_sev], SEV_TO_IDX[to_sev]
        matrix[i, j] += 1

        key = (from_sev, to_sev)
        alert_map.setdefault(key, []).append(alert_id)
        if not rationale_present:
            rationale_missing[key] = rationale_missing.get(key, 0) + 1

    return matrix, alert_map, rationale_missing


def _bowker_exact(matrix: np.ndarray) -> tuple[float, float, bool]:
    """
    Compute Bowker's test statistic and p-value.

    Uses scipy.stats.symmetry_bowker when all expected cell counts ≥ 5,
    otherwise falls back to vectorized Monte Carlo approximation.

    Args:
        matrix: k×k integer transition matrix.

    Returns:
        (chi2_statistic, p_value, used_permutation)
    """
    k = matrix.shape[0]
    chi2 = 0.0
    df = 0
    small_cell = False
    min_expected = 5

    for i in range(k):
        for j in range(i + 1, k):
            n_ij = matrix[i, j]
            n_ji = matrix[j, i]
            total = n_ij + n_ji
            if total == 0:
                continue
            expected = total / 2.0
            if expected < min_expected:
                small_cell = True
            chi2 += (n_ij - n_ji) ** 2 / total
            df += 1

    if df == 0:
        return 0.0, 1.0, False

    if not small_cell:
        # Standard chi-squared p-value
        p_value = float(stats.chi2.sf(chi2, df))
        return round(chi2, 6), round(p_value, 6), False

    # ── Vectorized Monte Carlo fallback ──────────────────────────────────────
    return _bowker_monte_carlo(matrix, observed_chi2=chi2)


def _bowker_monte_carlo(
    matrix: np.ndarray,
    *,
    observed_chi2: float,
    permutation_n: int = 9999,
    seed: int = 42,
) -> tuple[float, float, bool]:
    """
    Vectorized Monte Carlo approximation of Bowker's test p-value.

    For each off-diagonal pair (i,j), the number of i→j transitions is
    simulated as Binomial(n_ij + n_ji, 0.5) under the null hypothesis of symmetry.

    All permutation_n × n_pairs draws are computed in ONE numpy call for
    O(n_pairs) performance (not O(permutation_n * n_pairs)).

    This is an APPROXIMATE EXACT TEST:
    - Approximates the exact conditional p-value
    - Gets more accurate as permutation_n → ∞
    - Is NOT a true exact test (the exact test requires enumeration of all
      possible contingency tables, which is computationally infeasible)

    Args:
        matrix: k×k transition matrix.
        observed_chi2: Pre-computed Bowker chi² statistic for the observed data.
        permutation_n: Number of Monte Carlo draws (default 9,999).
        seed: Fixed RNG seed for reproducibility.

    Returns:
        (observed_chi2, approximate_p_value, True)
    """
    k = matrix.shape[0]
    rng = np.random.default_rng(seed)

    # Collect all off-diagonal pairs
    pairs = []
    for i in range(k):
        for j in range(i + 1, k):
            total = matrix[i, j] + matrix[j, i]
            if total > 0:
                pairs.append(total)

    if not pairs:
        return 0.0, 1.0, True

    totals = np.array(pairs, dtype=int)
    n_pairs = len(totals)

    # Generate all draws in ONE vectorized call: shape (permutation_n, n_pairs)
    # Each column: Binomial(total, 0.5) for one off-diagonal pair
    sim_counts = rng.binomial(totals, 0.5, size=(permutation_n, n_pairs))
    sim_other = totals[np.newaxis, :] - sim_counts

    # Compute simulated chi² for each draw: shape (permutation_n,)
    # chi²_k = (sim_k - sim_other_k)² / totals_k, summed over pairs
    with np.errstate(divide="ignore", invalid="ignore"):
        sim_chi2 = np.sum(
            np.where(
                totals > 0,
                (sim_counts - sim_other) ** 2 / totals[np.newaxis, :],
                0.0,
            ),
            axis=1,
        )

    # p-value = fraction of simulated values ≥ observed
    p_value = float(np.mean(sim_chi2 >= observed_chi2))

    return round(observed_chi2, 6), round(p_value, 6), True


def _find_asymmetric_cells(
    matrix: np.ndarray,
    alert_map: dict[tuple[str, str], list[str]],
    rationale_missing: dict[tuple[str, str], int],
    *,
    min_asymmetry_ratio: float = 3.0,
) -> list[AsymmetricCell]:
    """
    Identify specific off-diagonal pairs with high asymmetry.

    A pair (P_i, P_j) is highlighted if:
    - n_ij ≥ 3× n_ji (or n_ji = 0 and n_ij > 0)
    - The pair represents a downgrade (i < j, i.e., severity worsens numerically)

    Args:
        matrix: k×k transition matrix.
        alert_map: Alert IDs in each cell.
        rationale_missing: Rationale-missing counts per cell.
        min_asymmetry_ratio: Minimum ratio for highlighting.

    Returns:
        List of AsymmetricCell objects, sorted by asymmetry_ratio descending.
    """
    k = matrix.shape[0]
    cells: list[AsymmetricCell] = []

    for i in range(k):
        for j in range(i + 1, k):
            n_ij = int(matrix[i, j])
            n_ji = int(matrix[j, i])
            if n_ij == 0 and n_ji == 0:
                continue

            ratio = n_ij / max(n_ji, 1)
            # Only flag downgrades (i→j, j has higher index = lower severity)
            if ratio >= min_asymmetry_ratio and n_ij > 0:
                from_sev = SEVERITY_LEVELS[i]
                to_sev = SEVERITY_LEVELS[j]
                cells.append(
                    AsymmetricCell(
                        from_sev=from_sev,
                        to_sev=to_sev,
                        count_ij=n_ij,
                        count_ji=n_ji,
                        alert_ids=alert_map.get((from_sev, to_sev), []),
                        rationale_missing_count=rationale_missing.get(
                            (from_sev, to_sev), 0
                        ),
                    )
                )

    return sorted(cells, key=lambda c: c.asymmetry_ratio, reverse=True)


def run_g2(
    con: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    p_threshold: float = 0.05,
    threshold_tier: str = "internal",
    permutation_n: int = 9999,
    permutation_seed: int = 42,
    small_cell_threshold: int = 5,
    min_asymmetry_ratio: float = 3.0,
    run_ts: Optional[datetime] = None,
) -> DetectorResult:
    """
    Run G2 (Severity Laundering) detector for a single entity.

    Builds the severity transition matrix, applies Bowker's Test of Symmetry
    (with vectorized Monte Carlo fallback for small expected cell counts),
    and identifies the specific asymmetric cell pairs for UI drill-down.

    Args:
        con: Active DuckDB connection.
        entity_id: Target entity identifier.
        p_threshold: p-value threshold for flagging.
        threshold_tier: "internal" or "legal".
        permutation_n: Monte Carlo draws when expected cell count < 5.
        permutation_seed: Fixed seed for Monte Carlo reproducibility.
        small_cell_threshold: Expected count below which Monte Carlo is used.
        min_asymmetry_ratio: Minimum ratio for asymmetric cell highlighting.
        run_ts: Detector run timestamp.

    Returns:
        DetectorResult with asymmetric_cells populated.
    """
    if run_ts is None:
        run_ts = datetime.utcnow()

    matrix, alert_map, rationale_missing = _build_transition_matrix(con, entity_id)

    # Collect all linked IDs
    all_alert_ids = [aid for aids in alert_map.values() for aid in aids]

    # Fetch analyst IDs for linked alerts
    if all_alert_ids:
        placeholders = ", ".join("?" * len(all_alert_ids))
        analyst_rows = con.execute(
            f"SELECT DISTINCT analyst_id FROM cases WHERE alert_id IN ({placeholders})",
            all_alert_ids,
        ).fetchall()
        analyst_ids = [r[0] for r in analyst_rows]

        case_rows = con.execute(
            f"SELECT DISTINCT case_id FROM cases WHERE alert_id IN ({placeholders})",
            all_alert_ids,
        ).fetchall()
        case_ids = [r[0] for r in case_rows]
    else:
        analyst_ids = []
        case_ids = []

    n_transitions = int(matrix.sum())

    parameters = {
        "permutation_n": permutation_n,
        "seed": permutation_seed,
        "small_cell_threshold": small_cell_threshold,
        "min_asymmetry_ratio": min_asymmetry_ratio,
        "threshold": p_threshold,
        "threshold_tier": threshold_tier,
        "severity_levels": SEVERITY_LEVELS,
        "matrix_shape": list(matrix.shape),
    }

    if n_transitions < 3:
        return DetectorResult(
            detector_id="G2",
            detector_name="Severity Laundering",
            entity_id=entity_id,
            run_ts=run_ts,
            test_name="Bowker's Test of Symmetry",
            statistic=0.0,
            p_value=1.0,
            score=0.0,
            parameters=parameters,
            sample_size=n_transitions,
            flag=False,
            threshold_tier=threshold_tier,
            confidence_note=f"INSUFFICIENT DATA: n={n_transitions} transitions < 3 required",
            linked_alert_ids=all_alert_ids,
            linked_case_ids=case_ids,
            linked_analyst_ids=analyst_ids,
            asymmetric_cells=[],
        )

    chi2, p_value, used_permutation = _bowker_exact(matrix)

    confidence_note = ""
    if used_permutation:
        confidence_note = (
            f"PERMUTATION APPROXIMATION: expected cell count < {small_cell_threshold}; "
            f"vectorized Monte Carlo used (n={permutation_n}, seed={permutation_seed}). "
            "This is an approximate exact test, not a true exact test. "
            "See docs/methods_and_limitations.md §G2."
        )

    parameters["used_permutation"] = used_permutation

    asymmetric_cells = _find_asymmetric_cells(
        matrix,
        alert_map,
        rationale_missing,
        min_asymmetry_ratio=min_asymmetry_ratio,
    )

    flagged = p_value < p_threshold

    return DetectorResult(
        detector_id="G2",
        detector_name="Severity Laundering",
        entity_id=entity_id,
        run_ts=run_ts,
        test_name="Bowker's Test of Symmetry",
        statistic=round(chi2, 6),
        p_value=round(p_value, 6),
        score=round(1.0 - p_value, 6),
        parameters=parameters,
        sample_size=n_transitions,
        flag=flagged,
        threshold_tier=threshold_tier,
        confidence_note=confidence_note,
        linked_alert_ids=all_alert_ids[:500],
        linked_case_ids=case_ids[:500],
        linked_analyst_ids=analyst_ids[:200],
        asymmetric_cells=asymmetric_cells,
    )
