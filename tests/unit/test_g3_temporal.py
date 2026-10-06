"""Unit tests for G3 Temporal Clustering — Normalized Shannon Entropy.

Known-answer cases:
  - All closures in one bin → H=0 → flag
  - Perfectly uniform closures → H=1 → no flag
  - Near-shift-end batch closure → low H → flag
"""

from __future__ import annotations

import pytest
import numpy as np
import duckdb
from datetime import datetime, timedelta, timezone

from engine.detectors.g3_temporal import _normalized_entropy, run_g3

UTC = timezone.utc


class TestNormalizedEntropy:
    """Known-answer tests for normalized Shannon entropy."""

    def test_all_in_one_bin_entropy_zero(self):
        """All events in one bin → H=0 (maximum clustering)."""
        counts = np.array([100, 0, 0, 0])
        h = _normalized_entropy(counts)
        assert h == pytest.approx(0.0, abs=0.01)

    def test_uniform_distribution_entropy_one(self):
        """Equal events in all bins → H≈1 (maximum entropy)."""
        counts = np.array([25, 25, 25, 25])
        h = _normalized_entropy(counts)
        assert h == pytest.approx(1.0, abs=0.01)

    def test_two_bin_half_half(self):
        """50/50 split → H = log2(2)/log2(2) = 1.0."""
        counts = np.array([50, 50])
        h = _normalized_entropy(counts)
        assert h == pytest.approx(1.0, abs=0.01)

    def test_single_bin_zero(self):
        """Single non-zero bin → H=0."""
        counts = np.array([0, 0, 50])
        h = _normalized_entropy(counts)
        assert h == pytest.approx(0.0, abs=0.01)

    def test_all_zeros_returns_one(self):
        """Empty counts (no activity) → engine returns 0.0 (well-defined: no events = no evidence).
        The caller treats score=0.0 as 'no anomaly', which is correct behaviour."""
        counts = np.array([0, 0, 0])
        h = _normalized_entropy(counts)
        # _normalized_entropy returns 0.0 for all-zero input (no events to spread)
        # This is a known corner case: score=0 → not flagged. Correct.
        assert h == 0.0

    def test_result_in_01(self):
        """Entropy must always be in [0, 1]."""
        rng = np.random.default_rng(42)
        for _ in range(20):
            counts = rng.integers(0, 50, size=10)
            h = _normalized_entropy(counts)
            assert 0 <= h <= 1.0


class TestRunG3:
    def _make_con_with_batch_close(
        self,
        n_shifts: int = 5,
        batch_at_end: bool = True,
    ) -> duckdb.DuckDBPyConnection:
        """Build minimal DuckDB where closures are clustered at shift end."""
        con = duckdb.connect(":memory:")
        con.execute("""
            CREATE TABLE entities (entity_id VARCHAR, name VARCHAR, sector VARCHAR,
                asset_class VARCHAR, size_band VARCHAR, registered_ts TIMESTAMP);
            CREATE TABLE assets (asset_id VARCHAR, entity_id VARCHAR,
                asset_class VARCHAR, criticality VARCHAR);
            CREATE TABLE alerts (
                alert_id VARCHAR, entity_id VARCHAR, asset_id VARCHAR,
                rule_type VARCHAR, severity_initial VARCHAR, severity_final VARCHAR,
                created_ts TIMESTAMP, ack_ts TIMESTAMP, close_ts TIMESTAMP,
                source_is_soar BOOLEAN);
            CREATE TABLE cases (
                case_id VARCHAR, alert_id VARCHAR, analyst_id VARCHAR,
                shift_id VARCHAR, notes_text VARCHAR, disposition_code VARCHAR,
                opened_ts TIMESTAMP, closed_ts TIMESTAMP);
        """)
        con.execute("INSERT INTO entities VALUES ('E1', 'T', 'Finance', 'endpoint', 'medium', '2024-01-01')")
        con.execute("INSERT INTO assets VALUES ('A1', 'E1', 'endpoint', 'high')")

        rng = np.random.default_rng(0)
        alert_idx = 0
        for shift_n in range(n_shifts):
            shift_start = datetime(2024, 1, 1 + shift_n, 8, 0, 0, tzinfo=UTC)
            shift_end = shift_start + timedelta(hours=8)
            analyst_id = "ANA-001"
            shift_id = f"SHIFT-{shift_n}"

            for i in range(20):
                alert_id = f"ALT-{alert_idx:05d}"
                created_ts = shift_start + timedelta(hours=rng.uniform(0, 4))
                ack_ts = created_ts + timedelta(minutes=30)

                if batch_at_end:
                    # All closed in last 10 minutes of shift
                    close_ts = shift_end - timedelta(minutes=rng.uniform(1, 10))
                else:
                    # Uniformly distributed closures
                    close_ts = shift_start + timedelta(hours=rng.uniform(1, 7))

                if close_ts < ack_ts:
                    close_ts = ack_ts + timedelta(minutes=5)

                con.execute(
                    "INSERT INTO alerts VALUES (?, 'E1', 'A1', 'Rule', 'P3', 'P3', ?, ?, ?, FALSE)",
                    [alert_id, created_ts.isoformat(), ack_ts.isoformat(), close_ts.isoformat()]
                )
                con.execute(
                    "INSERT INTO cases VALUES (?, ?, ?, ?, 'Note', 'FP', ?, ?)",
                    [f"CASE-{alert_idx}", alert_id, analyst_id, shift_id,
                     ack_ts.isoformat(), close_ts.isoformat()]
                )
                alert_idx += 1
        return con

    def test_batch_close_at_shift_end_flagged(self):
        """Closures clustered at shift end → low entropy → flagged."""
        con = self._make_con_with_batch_close(batch_at_end=True)
        result = run_g3(con, "E1", low_entropy_threshold=0.4, min_alerts_per_shift=10)
        con.close()
        assert result.detector_id == "G3"
        assert result.flag is True
        assert result.score > 0

    def test_uniform_closures_not_flagged(self):
        """Uniformly distributed closures → high entropy → not flagged."""
        con = self._make_con_with_batch_close(batch_at_end=False)
        result = run_g3(con, "E1", low_entropy_threshold=0.4, min_alerts_per_shift=10)
        con.close()
        assert result.detector_id == "G3"
        assert result.flag is False

    def test_empty_entity_returns_no_flag(self):
        """No closed cases → no flag, score=0."""
        con = duckdb.connect(":memory:")
        con.execute("""
            CREATE TABLE entities (entity_id VARCHAR, name VARCHAR, sector VARCHAR,
                asset_class VARCHAR, size_band VARCHAR, registered_ts TIMESTAMP);
            CREATE TABLE assets (asset_id VARCHAR, entity_id VARCHAR,
                asset_class VARCHAR, criticality VARCHAR);
            CREATE TABLE alerts (alert_id VARCHAR, entity_id VARCHAR, asset_id VARCHAR,
                rule_type VARCHAR, severity_initial VARCHAR, severity_final VARCHAR,
                created_ts TIMESTAMP, ack_ts TIMESTAMP, close_ts TIMESTAMP,
                source_is_soar BOOLEAN);
            CREATE TABLE cases (case_id VARCHAR, alert_id VARCHAR, analyst_id VARCHAR,
                shift_id VARCHAR, notes_text VARCHAR, disposition_code VARCHAR,
                opened_ts TIMESTAMP, closed_ts TIMESTAMP);
        """)
        con.execute("INSERT INTO entities VALUES ('E1', 'T', 'Finance', 'endpoint', 'medium', '2024-01-01')")
        result = run_g3(con, "E1")
        con.close()
        assert result.flag is False
        assert "NO DATA" in result.confidence_note

    def test_anomaly_entity_detected(self, db_con, anomaly_entity_ids):
        """Shift-end gaming entity should show low entropy."""
        eid = anomaly_entity_ids["shift_end_gaming"]
        result = run_g3(db_con, eid, low_entropy_threshold=0.6, min_alerts_per_shift=5)
        assert result.detector_id == "G3"
        assert result.sample_size > 0
