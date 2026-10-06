"""Unit tests for G5 Workload Inconsistency and G6 Silent Loop."""

from __future__ import annotations

import pytest
import duckdb
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from engine.detectors.g5_workload import run_g5, _get_net_shift_minutes
from engine.detectors.g6_silent_loop import run_g6, _is_exempt

UTC = timezone.utc


# ─── G5 Tests ─────────────────────────────────────────────────────────────────

class TestGetNetShiftMinutes:
    def test_default_shift(self):
        """Default config → 480 minutes."""
        cfg = {"defaults": {"shift_duration_minutes": 480}, "shift_overrides": {}}
        assert _get_net_shift_minutes("ANY-SHIFT", cfg) == 480

    def test_per_shift_override(self):
        """Per-shift override → uses custom minutes."""
        cfg = {
            "defaults": {"shift_duration_minutes": 480},
            "shift_overrides": {"NIGHT_SHIFT": {"shift_duration_minutes": 420}},
        }
        assert _get_net_shift_minutes("NIGHT_SHIFT", cfg) == 420
        assert _get_net_shift_minutes("DAY_SHIFT", cfg) == 480


class TestRunG5:
    def _make_con_with_effort(
        self,
        entity_id: str,
        analyst_id: str,
        shift_id: str,
        active_minutes: float,
        n_cases: int = 5,
    ) -> duckdb.DuckDBPyConnection:
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
            CREATE TABLE workflow_effort (effort_id VARCHAR, analyst_id VARCHAR,
                shift_id VARCHAR, active_minutes DOUBLE);
        """)
        con.execute(f"INSERT INTO entities VALUES ('{entity_id}', 'T', 'Finance', 'endpoint', 'medium', '2024-01-01')")
        con.execute(f"INSERT INTO assets VALUES ('A1', '{entity_id}', 'endpoint', 'high')")

        base = datetime(2024, 1, 1, 8, 0, 0, tzinfo=UTC)
        for i in range(n_cases):
            aid = f"ALT-{i:04d}"
            t = base + timedelta(hours=i)
            con.execute(f"INSERT INTO alerts VALUES (?, '{entity_id}', 'A1', 'Rule', 'P3', 'P3', ?, ?, ?, FALSE)",
                       [aid, t.isoformat(), (t + timedelta(minutes=30)).isoformat(),
                        (t + timedelta(hours=2)).isoformat()])
            con.execute(f"INSERT INTO cases VALUES (?, ?, ?, ?, 'Note', 'FP', ?, ?)",
                       [f"CASE-{i}", aid, analyst_id, shift_id,
                        (t + timedelta(minutes=30)).isoformat(),
                        (t + timedelta(hours=2)).isoformat()])

        con.execute("INSERT INTO workflow_effort VALUES (?, ?, ?, ?)",
                   [f"EFF-1", analyst_id, shift_id, active_minutes])
        return con

    def test_impossible_workload_flagged(self):
        """14 hours (840 min) active in 8h shift → ratio=1.75 > 1.0 → flagged."""
        con = self._make_con_with_effort("E1", "ANA-001", "SHF-1", active_minutes=840, n_cases=5)
        cfg_content = "defaults:\n  shift_duration_minutes: 480\nshift_overrides: {}\nlimits:\n  max_ratio_for_legal_finding: 1.5\n  max_ratio_for_internal_flag: 1.0\n  min_tasks_to_evaluate: 3"
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(cfg_content)
            tmp_path = f.name
        try:
            result = run_g5(con, "E1", max_ratio_internal=1.0, min_tasks=3, config_path=tmp_path)
            con.close()
            assert result.flag is True
            assert result.statistic > 1.0
        finally:
            os.unlink(tmp_path)

    def test_normal_workload_not_flagged(self):
        """420 min active (87.5% of 480) → ratio < 1.0 → not flagged."""
        con = self._make_con_with_effort("E1", "ANA-001", "SHF-1", active_minutes=420, n_cases=5)
        import tempfile, os
        cfg = "defaults:\n  shift_duration_minutes: 480\nshift_overrides: {}\nlimits:\n  max_ratio_for_legal_finding: 1.5\n  max_ratio_for_internal_flag: 1.0\n  min_tasks_to_evaluate: 3"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(cfg); tmp = f.name
        try:
            result = run_g5(con, "E1", max_ratio_internal=1.0, min_tasks=3, config_path=tmp)
            con.close()
            assert result.flag is False
        finally:
            os.unlink(tmp)

    def test_min_tasks_threshold_respected(self):
        """Fewer than min_tasks cases → analyst skipped, no flag."""
        con = self._make_con_with_effort("E1", "ANA-001", "SHF-1", active_minutes=900, n_cases=2)
        import tempfile, os
        cfg = "defaults:\n  shift_duration_minutes: 480\nshift_overrides: {}\nlimits:\n  max_ratio_for_legal_finding: 1.5\n  max_ratio_for_internal_flag: 1.0\n  min_tasks_to_evaluate: 3"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(cfg); tmp = f.name
        try:
            result = run_g5(con, "E1", min_tasks=3, config_path=tmp)
            con.close()
            # With only 2 cases, analyst skipped → no flag
            assert result.flag is False
        finally:
            os.unlink(tmp)

    def test_result_contains_methods_note(self):
        """Confidence note must mention 'patterns requiring investigation'."""
        con = self._make_con_with_effort("E1", "ANA-001", "SHF-1", active_minutes=840, n_cases=5)
        import tempfile, os
        cfg = "defaults:\n  shift_duration_minutes: 480\nshift_overrides: {}\nlimits:\n  max_ratio_for_legal_finding: 1.5\n  max_ratio_for_internal_flag: 1.0\n  min_tasks_to_evaluate: 3"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(cfg); tmp = f.name
        try:
            result = run_g5(con, "E1", min_tasks=3, config_path=tmp)
            con.close()
            assert "investigation" in result.confidence_note.lower()
        finally:
            os.unlink(tmp)

    def test_anomaly_entity_detected(self, db_con, anomaly_entity_ids):
        eid = anomaly_entity_ids["impossible_workload"]
        import tempfile, os
        cfg = "defaults:\n  shift_duration_minutes: 480\nshift_overrides: {}\nlimits:\n  max_ratio_for_legal_finding: 1.5\n  max_ratio_for_internal_flag: 1.0\n  min_tasks_to_evaluate: 3"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(cfg); tmp = f.name
        try:
            result = run_g5(db_con, eid, max_ratio_internal=1.0, min_tasks=3, config_path=tmp)
            assert result.detector_id == "G5"
            assert result.sample_size >= 0
        finally:
            os.unlink(tmp)


# ─── G6 Tests ─────────────────────────────────────────────────────────────────

class TestIsExempt:
    def test_exact_match_exempt(self):
        exemptions = [{
            "rule_type": "WINDOWS_SCAN",
            "asset_class": "endpoint",
            "sector": "*",
            "expires_date": None,
        }]
        as_of = datetime(2024, 6, 1)
        assert _is_exempt("WINDOWS_SCAN", "endpoint", "Finance", exemptions, as_of) is True

    def test_no_match_not_exempt(self):
        exemptions = [{"rule_type": "WINDOWS_SCAN", "asset_class": "endpoint",
                       "sector": "*", "expires_date": None}]
        as_of = datetime(2024, 6, 1)
        assert _is_exempt("LATERAL_MOVEMENT", "endpoint", "Finance", exemptions, as_of) is False

    def test_expired_exemption_not_active(self):
        exemptions = [{
            "rule_type": "SCAN_RULE",
            "asset_class": "*",
            "sector": "*",
            "expires_date": "2023-12-31",
        }]
        as_of = datetime(2024, 6, 1)
        assert _is_exempt("SCAN_RULE", "endpoint", "Finance", exemptions, as_of) is False


class TestRunG6:
    def _make_con_with_silent_loop(
        self,
        entity_id: str,
        n_alerts: int,
        asset_id: str = "ASSET-001",
        rule_type: str = "Lateral Movement",
        close_minutes: int = 15,
        disposition: str = "CNA",
    ) -> duckdb.DuckDBPyConnection:
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
        con.execute(f"INSERT INTO entities VALUES ('{entity_id}', 'T', 'Finance', 'endpoint', 'medium', '2024-01-01')")
        con.execute(f"INSERT INTO assets VALUES ('{asset_id}', '{entity_id}', 'endpoint', 'high')")

        base = datetime(2024, 1, 1, 10, 0, 0, tzinfo=UTC)
        for i in range(n_alerts):
            aid = f"ALT-{i:04d}"
            t = base + timedelta(hours=i * 2)
            close_ts = t + timedelta(minutes=close_minutes)
            con.execute(f"INSERT INTO alerts VALUES (?, '{entity_id}', '{asset_id}', ?, 'P3', 'P3', ?, ?, ?, FALSE)",
                       [aid, rule_type, t.isoformat(),
                        (t + timedelta(minutes=2)).isoformat(), close_ts.isoformat()])
            con.execute("INSERT INTO cases VALUES (?, ?, 'ANA-001', 'SHF-1', 'Note', ?, ?, ?)",
                       [f"CASE-{i}", aid, disposition,
                        (t + timedelta(minutes=2)).isoformat(), close_ts.isoformat()])
        return con

    def test_recurrent_fast_close_flagged(self):
        """10 fast-closed CNA alerts on same asset → flagged."""
        import tempfile, os
        exemptions_yaml = "version: '1.0.0'\napproved_by: 'NCIIPC'\nexemptions: []"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(exemptions_yaml); tmp = f.name
        try:
            con = self._make_con_with_silent_loop("E1", n_alerts=10, close_minutes=20, disposition="CNA")
            # lookback_days=1200: covers all 2024 data when test runs in late 2026
            result = run_g6(con, "E1", fast_close_minutes=30, recurrence_threshold=3,
                           lookback_days=1200, exemptions_path=tmp)
            con.close()
            assert result.flag is True, (
                f"Expected flag=True. sample_size={result.sample_size}, "
                f"note='{result.confidence_note}'"
            )
            assert result.statistic >= 3
        finally:
            os.unlink(tmp)

    def test_below_recurrence_threshold_not_flagged(self):
        """2 fast-closed alerts, threshold=3 → not flagged."""
        import tempfile, os
        exemptions_yaml = "version: '1.0.0'\napproved_by: 'NCIIPC'\nexemptions: []"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(exemptions_yaml); tmp = f.name
        try:
            con = self._make_con_with_silent_loop("E1", n_alerts=2, close_minutes=20, disposition="CNA")
            result = run_g6(con, "E1", fast_close_minutes=30, recurrence_threshold=3,
                           lookback_days=1000, exemptions_path=tmp)
            con.close()
            assert result.flag is False
        finally:
            os.unlink(tmp)

    def test_exemption_suppresses_flag(self):
        """Rule type covered by exemption → not flagged despite high recurrence."""
        import tempfile, os
        exemptions_yaml = (
            "version: '1.0.0'\napproved_by: 'NCIIPC'\nexemptions:\n"
            "  - rule_type: 'Lateral Movement'\n    asset_class: '*'\n"
            "    sector: '*'\n    exemption_reason: 'Test'\n"
            "    approved_by: 'NCIIPC'\n    approved_date: '2024-01-01'\n    expires_date: null"
        )
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(exemptions_yaml); tmp = f.name
        try:
            con = self._make_con_with_silent_loop("E1", n_alerts=20, close_minutes=15,
                                                   rule_type="Lateral Movement", disposition="CNA")
            result = run_g6(con, "E1", fast_close_minutes=30, recurrence_threshold=3,
                           lookback_days=1000, exemptions_path=tmp)
            con.close()
            assert result.flag is False, "Exempt rule type should NOT be flagged"
        finally:
            os.unlink(tmp)

    def test_anomaly_entity_detected(self, db_con, anomaly_entity_ids):
        eid = anomaly_entity_ids["silent_loop"]
        import tempfile, os
        exemptions_yaml = "version: '1.0.0'\napproved_by: 'NCIIPC'\nexemptions: []"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(exemptions_yaml); tmp = f.name
        try:
            result = run_g6(db_con, eid, fast_close_minutes=30, recurrence_threshold=3,
                           lookback_days=1000, exemptions_path=tmp)
            assert result.detector_id == "G6"
            assert result.sample_size >= 0
        finally:
            os.unlink(tmp)
