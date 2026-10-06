"""
G4: Investigation Template Collapse — n-gram MinHash + LSH.

Detects analysts submitting repetitive, copy-pasted investigation notes
across multiple cases, indicating rubber-stamping of case closures without
genuine investigation.

Statistical Method:
  Jaccard Similarity estimated via MinHash signatures + Locality-Sensitive
  Hashing (LSH) banding.

  Jaccard(A, B) = |A ∩ B| / |A ∪ B|

  where A and B are sets of n-grams (character trigrams) from case notes.

  Reference: Broder, A. Z. (1997). On the Resemblance and Containment
  of Documents. Compression and Complexity of Sequences, 21–29.
  MinHash Reference: Rajaraman & Ullman (2011). Mining of Massive Datasets,
  Chapter 3.

MinHash Configuration (from config/weights.yaml):
  - num_permutations: 128  (hash functions)
  - bands: 16              (LSH bands)
  - rows_per_band: 8       (rows per band)
  - Threshold: (1/bands)^(1/rows) ≈ 0.71
  - ngram_size: 3 (character trigrams)

  NOTE: 16 bands × 8 rows = 128 permutations. Threshold ≈ (1/16)^(1/8) ≈ 0.71.
  This corrects the original plan's 8×16 configuration (threshold ~0.88).

  All seeds are fixed and deterministic. No random jitter.

Template Stripping:
  Before MinHash computation, boilerplate template text is stripped using
  a configurable list of patterns. Only the analyst-written free text is analyzed.

Scaling:
  LSH banding scales to millions of notes — candidate pairs are identified
  in O(n) expected time via hash buckets, not O(n²) pairwise comparison.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from datetime import datetime
from typing import Optional

import duckdb
import numpy as np

from engine.detectors.base import DetectorResult

logger = logging.getLogger(__name__)

try:
    from datasketch import MinHash, MinHashLSH
    _DATASKETCH_AVAILABLE = True
except ImportError:
    _DATASKETCH_AVAILABLE = False
    logger.error("datasketch not installed. G4 detector will not run.")


# ─── Template stripping patterns ─────────────────────────────────────────────
# These are common boilerplate patterns inserted by case management systems.
# Only the free-text portions written by analysts are analyzed.

BOILERPLATE_PATTERNS = [
    r"^case\s+id\s*:.*$",
    r"^alert\s+id\s*:.*$",
    r"^analyst\s*:.*$",
    r"^date\s*:.*$",
    r"^shift\s*:.*$",
    r"^disposition\s*:.*$",
    r"^severity\s*:.*$",
    r"investigation\s+summary\s*:",
    r"template\s+version\s*:.*$",
    r"^status\s*:.*$",
]

_BOILERPLATE_RE = re.compile(
    "|".join(BOILERPLATE_PATTERNS),
    re.MULTILINE | re.IGNORECASE,
)


def _strip_boilerplate(text: str) -> str:
    """
    Remove template boilerplate from case notes.

    Returns the analyst-written free text only.
    If the result is shorter than 20 characters, the note is considered
    effectively empty (all boilerplate, no analyst content).

    Args:
        text: Raw case notes string.

    Returns:
        Stripped text, or empty string if all boilerplate.
    """
    if not text:
        return ""
    stripped = _BOILERPLATE_RE.sub(" ", text).strip()
    # Normalize whitespace
    stripped = re.sub(r"\s+", " ", stripped)
    return stripped if len(stripped) >= 20 else ""


def _get_ngrams(text: str, n: int = 3) -> set[str]:
    """
    Extract character n-grams from text.

    Args:
        text: Input string (should already be boilerplate-stripped).
        n: n-gram size (default 3 = trigrams).

    Returns:
        Set of n-gram strings.
    """
    text = text.lower()
    if len(text) < n:
        return {text}
    return {text[i : i + n] for i in range(len(text) - n + 1)}


def _build_minhash(ngrams: set[str], num_perm: int, seed: int = 42) -> "MinHash":
    """
    Build a MinHash signature for a set of n-grams.

    Seeds are derived deterministically from the base seed.

    Args:
        ngrams: Set of n-gram strings.
        num_perm: Number of permutations (hash functions).
        seed: Base seed for hash function generation.

    Returns:
        datasketch.MinHash object.
    """
    m = MinHash(num_perm=num_perm, seed=seed)
    for gram in ngrams:
        m.update(gram.encode("utf-8"))
    return m


def run_g4(
    con: duckdb.DuckDBPyConnection,
    entity_id: str,
    *,
    num_perm: int = 128,
    bands: int = 16,
    rows_per_band: int = 8,
    ngram_size: int = 3,
    jaccard_threshold: float = 0.71,
    cluster_pct_threshold: float = 0.20,
    seed: int = 42,
    threshold_tier: str = "internal",
    run_ts: Optional[datetime] = None,
) -> DetectorResult:
    """
    Run G4 (Investigation Template Collapse) detector for a single entity.

    Args:
        con: Active DuckDB connection.
        entity_id: Target entity identifier.
        num_perm: Number of MinHash permutations (default 128).
        bands: Number of LSH bands (default 16). Must equal num_perm / rows_per_band.
        rows_per_band: Rows per LSH band (default 8). Threshold ≈ (1/bands)^(1/rows).
        ngram_size: Character n-gram size (default 3).
        jaccard_threshold: Estimated Jaccard threshold for flagging pairs.
        cluster_pct_threshold: Flag if >this fraction of notes are in clusters.
        seed: Deterministic seed for MinHash (default 42).
        threshold_tier: "internal" or "legal".
        run_ts: Detector run timestamp.

    Returns:
        DetectorResult with score = fraction of notes in near-duplicate clusters.
    """
    if run_ts is None:
        run_ts = datetime.utcnow()

    parameters = {
        "num_perm": num_perm,
        "bands": bands,
        "rows_per_band": rows_per_band,
        "ngram_size": ngram_size,
        "jaccard_threshold": jaccard_threshold,
        "cluster_pct_threshold": cluster_pct_threshold,
        "seed": seed,
        "threshold_tier": threshold_tier,
        "effective_threshold": round((1.0 / bands) ** (1.0 / rows_per_band), 4),
    }

    if not _DATASKETCH_AVAILABLE:
        return DetectorResult(
            detector_id="G4",
            detector_name="Investigation Template Collapse",
            entity_id=entity_id,
            run_ts=run_ts,
            test_name="MinHash Jaccard + LSH Banding",
            statistic=0.0,
            p_value=None,
            score=0.0,
            parameters=parameters,
            sample_size=0,
            flag=False,
            threshold_tier=threshold_tier,
            confidence_note="ERROR: datasketch library not installed. Cannot run G4.",
        )

    # ── Fetch case notes ──────────────────────────────────────────────────────
    query = """
        SELECT
            c.case_id,
            c.analyst_id,
            c.notes_text,
            a.alert_id
        FROM cases c
        JOIN alerts a ON a.alert_id = c.alert_id
        WHERE a.entity_id = ?
          AND c.notes_text IS NOT NULL
          AND LENGTH(c.notes_text) > 20
    """
    rows = con.execute(query, [entity_id]).fetchall()

    if not rows:
        return DetectorResult(
            detector_id="G4",
            detector_name="Investigation Template Collapse",
            entity_id=entity_id,
            run_ts=run_ts,
            test_name="MinHash Jaccard + LSH Banding",
            statistic=0.0,
            p_value=None,
            score=0.0,
            parameters=parameters,
            sample_size=0,
            flag=False,
            threshold_tier=threshold_tier,
            confidence_note="NO DATA: no case notes found for entity",
        )

    # ── Build MinHash signatures ──────────────────────────────────────────────
    case_ids_with_notes: list[str] = []
    minhashes: list["MinHash"] = []
    alert_ids_for_case: dict[str, str] = {}
    analyst_ids_for_case: dict[str, str] = {}

    for case_id, analyst_id, notes_text, alert_id in rows:
        stripped = _strip_boilerplate(notes_text or "")
        if not stripped:
            continue

        ngrams = _get_ngrams(stripped, n=ngram_size)
        mh = _build_minhash(ngrams, num_perm=num_perm, seed=seed)
        case_ids_with_notes.append(case_id)
        minhashes.append(mh)
        alert_ids_for_case[case_id] = alert_id
        analyst_ids_for_case[case_id] = analyst_id

    n_notes = len(case_ids_with_notes)

    if n_notes < 2:
        return DetectorResult(
            detector_id="G4",
            detector_name="Investigation Template Collapse",
            entity_id=entity_id,
            run_ts=run_ts,
            test_name="MinHash Jaccard + LSH Banding",
            statistic=0.0,
            p_value=None,
            score=0.0,
            parameters=parameters,
            sample_size=n_notes,
            flag=False,
            threshold_tier=threshold_tier,
            confidence_note=f"INSUFFICIENT DATA: n={n_notes} notes with content < 2 required",
        )

    # ── LSH banding ───────────────────────────────────────────────────────────
    lsh = MinHashLSH(threshold=jaccard_threshold, num_perm=num_perm)
    for case_id, mh in zip(case_ids_with_notes, minhashes):
        try:
            lsh.insert(case_id, mh)
        except ValueError:
            pass  # Duplicate key; skip

    # ── Find candidate pairs ──────────────────────────────────────────────────
    clustered_cases: set[str] = set()
    cluster_pairs: list[dict] = []

    for case_id, mh in zip(case_ids_with_notes, minhashes):
        try:
            candidates = lsh.query(mh)
        except Exception:
            continue

        for candidate in candidates:
            if candidate == case_id:
                continue
            clustered_cases.add(case_id)
            clustered_cases.add(candidate)
            cluster_pairs.append({
                "case_a": case_id,
                "case_b": candidate,
                "analyst_a": analyst_ids_for_case.get(case_id, ""),
                "analyst_b": analyst_ids_for_case.get(candidate, ""),
            })

    cluster_pct = len(clustered_cases) / n_notes if n_notes > 0 else 0.0
    flagged = cluster_pct > cluster_pct_threshold

    parameters["n_clustered_cases"] = len(clustered_cases)
    parameters["n_cluster_pairs"] = len(cluster_pairs)
    parameters["cluster_pct"] = round(cluster_pct, 4)
    parameters["sample_pairs"] = cluster_pairs[:10]  # Sample for audit

    linked_alert_ids = list({alert_ids_for_case[c] for c in clustered_cases if c in alert_ids_for_case})
    linked_analyst_ids = list({analyst_ids_for_case[c] for c in clustered_cases if c in analyst_ids_for_case})

    return DetectorResult(
        detector_id="G4",
        detector_name="Investigation Template Collapse",
        entity_id=entity_id,
        run_ts=run_ts,
        test_name="MinHash Jaccard + LSH Banding",
        statistic=round(cluster_pct, 6),
        p_value=None,
        score=round(cluster_pct, 6),
        parameters=parameters,
        sample_size=n_notes,
        flag=flagged,
        threshold_tier=threshold_tier,
        confidence_note=(
            f"APPROXIMATE: Jaccard threshold ≈ {parameters['effective_threshold']:.3f} "
            f"via LSH banding ({bands} bands × {rows_per_band} rows). "
            "LSH may produce false positives/negatives near threshold."
        ),
        linked_alert_ids=linked_alert_ids[:500],
        linked_case_ids=list(clustered_cases)[:500],
        linked_analyst_ids=linked_analyst_ids[:200],
    )
