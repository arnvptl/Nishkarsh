"""Unit tests for risk scoring, stratified sampling, and audit log."""

from __future__ import annotations

import hashlib
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from engine.detectors.base import DetectorResult
from engine.scoring.risk_score import compute_risk_score, _score_band
from engine.scoring.sampling import generate_manifest
from engine.audit.log import AuditLog

UTC = timezone.utc
RUN_TS = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)


def _make_result(
    detector_id: str,
    flag: bool,
    p_value: float | None = 0.01,
    score: float | None = None,
    entity_id: str = "E1",
) -> DetectorResult:
    return DetectorResult(
        detector_id=detector_id,
        detector_name=f"Detector {detector_id}",
        entity_id=entity_id,
        run_ts=RUN_TS,
        test_name="Test",
        statistic=1.0,
        p_value=p_value,
        score=score,
        parameters={},
        sample_size=100,
        flag=flag,
        linked_alert_ids=["ALT-001", "ALT-002"],
        linked_case_ids=["CASE-001"],
        linked_analyst_ids=["ANA-001"],
    )


# ─── Risk Score Tests ──────────────────────────────────────────────────────────

class TestScoreBand:
    def test_critical_band(self):
        assert _score_band(90) == "CRITICAL"

    def test_high_band(self):
        assert _score_band(65) == "HIGH"

    def test_medium_band(self):
        assert _score_band(35) == "MEDIUM"

    def test_low_band(self):
        assert _score_band(10) == "LOW"

    def test_boundary_81(self):
        assert _score_band(81) == "CRITICAL"

    def test_boundary_80(self):
        assert _score_band(80) == "HIGH"


class TestComputeRiskScore:
    def _make_weights_yaml(self, tmp_path: Path) -> str:
        """Write a test weights.yaml and return its path."""
        content = """
version: "test"
binary_flag_mode: false
weights:
  G2_severity_laundering: 35
  G1_velocity_distortion: 25
  G3_temporal_clustering: 15
  G4_template_collapse: 10
  G5_workload_inconsistency: 10
  G6_silent_loop: 10
  L1_sla_violation: 10
  L1_negative_space: 10
"""
        path = tmp_path / "weights.yaml"
        path.write_text(content)
        return str(path)

    def test_all_clear_score_zero(self, tmp_path):
        """No flags → all F_i = 0 → score = 0."""
        results = [
            _make_result("G1", flag=False, p_value=0.9),
            _make_result("G2", flag=False, p_value=0.8),
        ]
        wp = self._make_weights_yaml(tmp_path)
        risk = compute_risk_score(results, "E1", "CYCLE-1", weights_path=wp)
        assert risk.score == pytest.approx(0.0, abs=0.01)
        assert risk.band == "LOW"

    def test_all_flagged_score_capped_100(self, tmp_path):
        """All detectors flagged with high effect → score capped at 100."""
        results = [
            _make_result(did, flag=True, p_value=0.001)
            for did in ["G1", "G2", "G3", "G4", "G5", "G6", "L1_SLA", "L1_NS"]
        ]
        wp = self._make_weights_yaml(tmp_path)
        risk = compute_risk_score(results, "E1", "CYCLE-1", weights_path=wp)
        assert risk.score <= 100.0

    def test_g2_weight_dominates(self, tmp_path):
        """G2 weight=35 should dominate when only G2 flagged."""
        results = [_make_result("G2", flag=True, p_value=0.001)]
        wp = self._make_weights_yaml(tmp_path)
        risk = compute_risk_score(results, "E1", "CYCLE-1", weights_path=wp)
        assert risk.score > 0
        assert risk.component_scores["G2"]["flagged"] is True

    def test_binary_mode_fi_is_01(self, tmp_path):
        """In binary mode, F_i is exactly 0 or 1."""
        content = """
version: "test"
binary_flag_mode: true
weights:
  G2_severity_laundering: 35
  G1_velocity_distortion: 25
  G3_temporal_clustering: 15
  G4_template_collapse: 10
  G5_workload_inconsistency: 10
  G6_silent_loop: 10
  L1_sla_violation: 10
  L1_negative_space: 10
"""
        wp = tmp_path / "weights_binary.yaml"
        wp.write_text(content)
        results = [_make_result("G2", flag=True, p_value=0.03)]
        risk = compute_risk_score(results, "E1", "CYCLE-1", weights_path=str(wp))
        fi = risk.component_scores["G2"]["fi_value"]
        assert fi in (0.0, 1.0)

    def test_score_dict_contains_all_detectors(self, tmp_path):
        """component_scores must have entries for all 8 detectors."""
        wp = self._make_weights_yaml(tmp_path)
        risk = compute_risk_score([], "E1", "CYCLE-1", weights_path=wp)
        assert len(risk.component_scores) == 8


# ─── Sampling Tests ────────────────────────────────────────────────────────────

class TestGenerateManifest:
    def test_80_20_split_respected(self):
        """80% of budget from flagged stratum, 20% from random."""
        results = [_make_result("G2", flag=True, p_value=0.001,
                                entity_id="E1")]
        results[0].linked_alert_ids = [f"ALT-{i:04d}" for i in range(100)]

        all_alerts = [f"ALT-{i:04d}" for i in range(200)]
        manifest = generate_manifest(results, "E1", "CYC-1", all_alerts,
                                     examiner_budget=50, seed=42)
        flagged = [r for r in manifest.rows if r.sampled_by == "FLAGGED_80PCT"]
        random = [r for r in manifest.rows if r.sampled_by == "RANDOM_20PCT"]
        assert len(flagged) + len(random) == len(manifest.rows)
        assert len(flagged) >= 35  # ~80% of 50

    def test_no_duplicates_in_manifest(self):
        """Alert IDs must not appear in both flagged and random strata."""
        results = [_make_result("G1", flag=True, p_value=0.01, entity_id="E1")]
        results[0].linked_alert_ids = [f"ALT-{i:04d}" for i in range(50)]
        all_alerts = [f"ALT-{i:04d}" for i in range(200)]
        manifest = generate_manifest(results, "E1", "CYC-1", all_alerts,
                                     examiner_budget=60, seed=42)
        alert_ids = [r.alert_id for r in manifest.rows]
        assert len(alert_ids) == len(set(alert_ids)), "Duplicate alert IDs in manifest"

    def test_deterministic_with_same_seed(self):
        """Same inputs + same seed → identical manifest rows."""
        results = [_make_result("G3", flag=True, p_value=0.02, entity_id="E1")]
        results[0].linked_alert_ids = [f"ALT-{i:04d}" for i in range(80)]
        all_alerts = [f"ALT-{i:04d}" for i in range(200)]
        m1 = generate_manifest(results, "E1", "CYC", all_alerts, seed=42)
        m2 = generate_manifest(results, "E1", "CYC", all_alerts, seed=42)
        assert [r.alert_id for r in m1.rows] == [r.alert_id for r in m2.rows]

    def test_different_seed_different_random_stratum(self):
        """Different seeds → different random stratum (flagged may be same)."""
        results = [_make_result("G3", flag=True, p_value=0.02, entity_id="E1")]
        results[0].linked_alert_ids = [f"ALT-{i:04d}" for i in range(30)]
        all_alerts = [f"ALT-{i:04d}" for i in range(200)]
        m1 = generate_manifest(results, "E1", "CYC", all_alerts, seed=42)
        m2 = generate_manifest(results, "E1", "CYC", all_alerts, seed=99)
        rand1 = {r.alert_id for r in m1.rows if r.sampled_by == "RANDOM_20PCT"}
        rand2 = {r.alert_id for r in m2.rows if r.sampled_by == "RANDOM_20PCT"}
        assert rand1 != rand2

    def test_budget_respected(self):
        """Total rows must not exceed examiner_budget."""
        results = [_make_result("G2", flag=True, p_value=0.001, entity_id="E1")]
        results[0].linked_alert_ids = [f"ALT-{i:04d}" for i in range(500)]
        all_alerts = [f"ALT-{i:04d}" for i in range(1000)]
        manifest = generate_manifest(results, "E1", "CYC", all_alerts,
                                     examiner_budget=50, seed=42)
        assert len(manifest.rows) <= 50

    def test_csv_export(self):
        """to_csv_lines should produce header + data rows."""
        results = [_make_result("G1", flag=True, p_value=0.01, entity_id="E1")]
        results[0].linked_alert_ids = ["ALT-001", "ALT-002"]
        all_alerts = ["ALT-001", "ALT-002", "ALT-003", "ALT-004"]
        manifest = generate_manifest(results, "E1", "CYC", all_alerts,
                                     examiner_budget=4, seed=42)
        lines = manifest.to_csv_lines()
        assert len(lines) >= 2  # Header + at least one data row
        assert "alert_id" in lines[0]


# ─── Audit Log Tests ───────────────────────────────────────────────────────────

class TestAuditLog:
    def test_log_and_verify(self, tmp_path):
        """Appended entries → chain verifies successfully."""
        db = tmp_path / "audit_test.db"
        with AuditLog(db) as audit:
            audit.log("QUERY", "examiner-1", {"endpoint": "/api/entities"})
            audit.log("DETECTOR_RUN", "system", {"cycle_id": "CYC-1"})
            audit.log("EXPORT", "examiner-1", {"type": "manifest", "rows": 50})
            valid, msg = audit.verify_chain()
            assert valid is True, f"Chain verification failed: {msg}"

    def test_chain_breaks_on_tamper(self, tmp_path):
        """Tampered entry → verification detects broken chain."""
        import sqlite3
        db = tmp_path / "audit_tamper.db"
        with AuditLog(db) as audit:
            audit.log("QUERY", "examiner-1", "original_query")
            audit.log("QUERY", "examiner-1", "second_query")

        # Tamper: change the details of the first entry directly in SQLite
        con = sqlite3.connect(str(db))
        con.execute("UPDATE audit_log SET details = 'TAMPERED' WHERE id = 1")
        con.commit()
        con.close()

        with AuditLog(db) as audit:
            valid, msg = audit.verify_chain()
            assert valid is False
            assert "broken" in msg.lower() or "mismatch" in msg.lower()

    def test_empty_log_verifies_valid(self, tmp_path):
        """Empty audit log should report valid."""
        db = tmp_path / "audit_empty.db"
        with AuditLog(db) as audit:
            valid, msg = audit.verify_chain()
            assert valid is True
            assert "empty" in msg.lower()

    def test_recent_entries(self, tmp_path):
        """recent_entries returns at most limit rows in reverse order."""
        db = tmp_path / "audit_recent.db"
        with AuditLog(db) as audit:
            for i in range(10):
                audit.log("QUERY", "user", {"i": i})
            entries = audit.recent_entries(limit=5)
            assert len(entries) == 5

    def test_hash_is_sha256_hex(self, tmp_path):
        """entry_hash must be a 64-char hex string (SHA-256)."""
        db = tmp_path / "audit_hash.db"
        with AuditLog(db) as audit:
            audit.log("TEST", "system", "payload")
            entries = audit.recent_entries(limit=1)
            # entry_hash is truncated in display; check via SQLite directly
        import sqlite3
        con = sqlite3.connect(str(db))
        row = con.execute("SELECT entry_hash FROM audit_log LIMIT 1").fetchone()
        con.close()
        assert len(row[0]) == 64  # SHA-256 hex = 64 chars
        assert all(c in "0123456789abcdef" for c in row[0])
