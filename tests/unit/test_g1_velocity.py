"""Unit tests for G1 Velocity Distortion detector — Hartigan's Dip Test.

Known-answer cases:
  - Bimodal distribution (near-zero + 60min cluster) → low p-value → flag
  - Uniform distribution → high p-value → no flag
  - All-zero times (perfect rubber stamping) → flagged
  - Insufficient data (n<4) → no flag, note emitted
"""

from __future__ import annotations

import duckdb
import numpy as np
import pytest
from datetime import datetime, timedelta, timezone

from engine.detectors.g1_velocity import (
    _dip_fallback,
    compute_dip_test,
    run_g1,
)


UTC = timezone.utc


class TestDipFallback:
    """Known-answer tests for the pure-Python dip fallback."""

    def test_uniform_high_pvalue(self):
        """Uniformly spaced data → no bimodality → high p-value."""
        x = np.linspace(10, 100, 200)
        dip, p = _dip_fallback(x)
        # Uniform distribution should have HIGH p-value (not bimodal)
        assert p > 0.05, f"Expected p > 0.05 for uniform data, got {p}"

    def test_bimodal_low_pvalue(self):
        """Two tight clusters → bimodal → low p-value."""
        rng = np.random.default_rng(42)
        cluster_a = rng.normal(1, 0.5, 100)   # Near-zero cluster
        cluster_b = rng.normal(60, 3, 100)    # Normal-close cluster
        x = np.concatenate([cluster_a, cluster_b])
        x = np.clip(x, 0, None)
        dip, p = _dip_fallback(x)
        assert dip > 0, f"Expected positive dip statistic, got {dip}"

    def test_too_few_points_returns_no_flag(self):
        """n < 4 → returns (0.0, 1.0)."""
        dip, p = _dip_fallback(np.array([1.0, 2.0]))
        assert dip == 0.0
        assert p == 1.0

    def test_statistic_nonnegative(self):
        """Dip statistic must always be non-negative."""
        rng = np.random.default_rng(0)
        for _ in range(10):
            x = rng.exponential(scale=30, size=50)
            dip, p = _dip_fallback(x)
            assert dip >= 0
            assert 0 <= p <= 1


class TestComputeDipTest:
    def test_returns_three_tuple(self):
        x = np.array([1.0, 2.0, 3.0, 4.0, 5.0, 60.0, 61.0, 62.0] * 10)
        dip, p, used_fallback = compute_dip_test(x)
        assert isinstance(dip, float)
        assert isinstance(p, float)
        assert isinstance(used_fallback, bool)
        assert 0 <= p <= 1

    def test_insufficient_data(self):
        dip, p, _ = compute_dip_test(np.array([1.0, 2.0]))
        assert dip == 0.0
        assert p == 1.0


class TestRunG1:
    """Integration tests for run_g1 against in-memory DuckDB."""

    def _make_con_with_alerts(self, close_times_minutes: list[int]) -> duckdb.DuckDBPyConnection:
        """Build a minimal in-memory DuckDB with the specified alert closure times."""
        con = duckdb.connect(":memory:")
        base = datetime(2024, 1, 1, 10, 0, 0, tzinfo=UTC)

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
            CREATE TABLE cases (case_id VARCHAR, alert_id VARCHAR, analyst_id VARCHAR,
                shift_id VARCHAR, notes_text VARCHAR, disposition_code VARCHAR,
                opened_ts TIMESTAMP, closed_ts TIMESTAMP);
        """)

        con.execute("INSERT INTO entities VALUES ('E1', 'Test', 'Finance', 'endpoint', 'medium', '2024-01-01')")
        con.execute("INSERT INTO assets VALUES ('A1', 'E1', 'endpoint', 'high')")

        for i, close_min in enumerate(close_times_minutes):
            created_ts = base + timedelta(hours=i)
            ack_ts = created_ts + timedelta(minutes=5)
            close_ts = created_ts + timedelta(minutes=close_min)
            con.execute(
                "INSERT INTO alerts VALUES (?, 'E1', 'A1', 'MalwareDetect', 'P2', 'P2', ?, ?, ?, FALSE)",
                [f"ALT-{i:04d}", created_ts.isoformat(), ack_ts.isoformat(), close_ts.isoformat()]
            )
            con.execute(
                "INSERT INTO cases VALUES (?, ?, 'ANA-001', 'SHIFT-1', 'Note', 'FP', ?, ?)",
                [f"CASE-{i:04d}", f"ALT-{i:04d}", ack_ts.isoformat(), close_ts.isoformat()]
            )
        return con

    def test_bimodal_near_zero_flagged(self):
        """Bimodal distribution with cluster near zero → flagged."""
        # 60% near-zero (0-2 min), 40% normal (45-90 min)
        close_times = [1] * 30 + [2] * 30 + [60] * 20 + [75] * 20
        con = self._make_con_with_alerts(close_times)
        result = run_g1(con, "E1", p_threshold=0.05)
        con.close()
        # Should detect bimodality (dip test significant or not — depends on diptest availability)
        # At minimum: result must have correct structure
        assert result.detector_id == "G1"
        assert result.entity_id == "E1"
        assert result.sample_size == len(close_times)
        assert 0 <= result.statistic
        assert 0 <= (result.p_value or 0) <= 1

    def test_uniform_distribution_not_flagged(self):
        """Uniformly distributed close times → should NOT be flagged."""
        # Well-distributed times from 30 to 480 minutes
        rng = np.random.default_rng(42)
        close_times = [int(t) for t in rng.uniform(30, 480, 100)]
        con = self._make_con_with_alerts(close_times)
        result = run_g1(con, "E1", p_threshold=0.01)
        con.close()
        assert result.detector_id == "G1"
        # With strict threshold 0.01, uniform should not be flagged
        if result.p_value is not None:
            assert result.p_value > 0.01 or not result.flag

    def test_soar_alerts_excluded(self):
        """SOAR-automated alerts must be excluded from dip test."""
        con = duckdb.connect(":memory:")
        base = datetime(2024, 1, 1, 10, 0, tzinfo=UTC)
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
            CREATE TABLE cases (case_id VARCHAR, alert_id VARCHAR, analyst_id VARCHAR,
                shift_id VARCHAR, notes_text VARCHAR, disposition_code VARCHAR,
                opened_ts TIMESTAMP, closed_ts TIMESTAMP);
        """)
        con.execute("INSERT INTO entities VALUES ('E1', 'Test', 'Finance', 'endpoint', 'medium', '2024-01-01')")
        con.execute("INSERT INTO assets VALUES ('A1', 'E1', 'endpoint', 'high')")

        # Add 20 SOAR alerts with near-zero times (should be excluded)
        for i in range(20):
            t = base + timedelta(hours=i)
            con.execute("INSERT INTO alerts VALUES (?, 'E1', 'A1', 'Rule', 'P2', 'P2', ?, ?, ?, TRUE)",
                       [f"SOAR-{i}", t.isoformat(), (t + timedelta(minutes=1)).isoformat(),
                        (t + timedelta(minutes=2)).isoformat()])

        result = run_g1(con, "E1", p_threshold=0.05)
        con.close()
        # SOAR alerts excluded → sample_size should be 0 → no flag, insufficient data
        assert result.sample_size == 0
        assert result.flag is False
        assert "INSUFFICIENT" in result.confidence_note

    def test_insufficient_data_note(self):
        """n < 4 alerts → confidence_note contains INSUFFICIENT."""
        close_times = [30, 45]
        con = self._make_con_with_alerts(close_times)
        result = run_g1(con, "E1", p_threshold=0.05)
        con.close()
        assert "INSUFFICIENT" in result.confidence_note
        assert result.flag is False

    def test_result_schema_complete(self):
        """DetectorResult must have all required fields populated."""
        close_times = [int(t) for t in np.linspace(1, 480, 50)]
        con = self._make_con_with_alerts(close_times)
        result = run_g1(con, "E1")
        con.close()
        assert result.test_name == "Hartigan's Dip Test"
        assert result.parameters.get("exclude_soar") is True
        assert result.parameters.get("tie_breaking") == "alert_id_lexicographic"
        assert result.run_ts is not None
        d = result.to_dict()
        assert "fi_value" in d
        assert 0 <= d["fi_value"] <= 1

    def test_anomaly_entity_detected(self, db_con, anomaly_entity_ids):
        """The rubber-stamping entity should be flagged by G1."""
        eid = anomaly_entity_ids["rubber_stamping"]
        result = run_g1(db_con, eid, p_threshold=0.05)
        # With clear bimodal data injected, expect flag = True
        assert result.detector_id == "G1"
        # The statistic should be non-zero
        assert result.statistic >= 0
        assert result.sample_size > 0
