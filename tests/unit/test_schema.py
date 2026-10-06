"""Unit tests for Pydantic schema models and validator."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from engine.schema.models import (
    Alert,
    Case,
    DispositionCode,
    Entity,
    Escalation,
    Severity,
    SeverityTransition,
    SizeBand,
    WorkflowEffort,
)
from engine.schema.validator import validate_table, ValidationReport


class TestSeverityEnum:
    def test_p1_numeric_lowest(self):
        assert Severity.P1.numeric == 1

    def test_p5_numeric_highest(self):
        assert Severity.P5.numeric == 5

    def test_ordering(self):
        assert Severity.P1.numeric < Severity.P3.numeric


class TestEntityModel:
    def test_valid_entity(self):
        e = Entity(
            entity_id="CSE-001",
            name="Test Entity",
            sector="Finance",
            asset_class="endpoint",
            size_band=SizeBand.MEDIUM,
            registered_ts=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        assert e.entity_id == "CSE-001"

    def test_empty_entity_id_rejected(self):
        with pytest.raises(ValidationError, match="entity_id"):
            Entity(
                entity_id="  ",
                name="X",
                sector="Finance",
                asset_class="endpoint",
                size_band=SizeBand.MEDIUM,
                registered_ts=datetime(2024, 1, 1, tzinfo=timezone.utc),
            )


class TestAlertModel:
    def _base_alert(self, **overrides):
        defaults = {
            "alert_id": "ALT-001",
            "entity_id": "CSE-001",
            "asset_id": "ASSET-001",
            "rule_type": "Lateral Movement",
            "severity_initial": Severity.P1,
            "severity_final": Severity.P1,
            "created_ts": datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc),
            "ack_ts": datetime(2024, 1, 1, 10, 10, tzinfo=timezone.utc),
            "close_ts": datetime(2024, 1, 1, 11, 0, tzinfo=timezone.utc),
            "source_is_soar": False,
        }
        defaults.update(overrides)
        return defaults

    def test_valid_alert(self):
        a = Alert(**self._base_alert())
        assert a.alert_id == "ALT-001"

    def test_ack_before_created_rejected(self):
        with pytest.raises(ValidationError, match="ack_ts"):
            Alert(**self._base_alert(
                ack_ts=datetime(2024, 1, 1, 9, 0, tzinfo=timezone.utc),
                created_ts=datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc),
            ))

    def test_close_before_created_rejected(self):
        """close_ts before created_ts → rejected with close_ts error."""
        with pytest.raises(ValidationError):
            Alert(**self._base_alert(
                # ack_ts is VALID (after created_ts); only close_ts is before created_ts
                created_ts=datetime(2024, 1, 1, 10, 0, tzinfo=timezone.utc),
                ack_ts=datetime(2024, 1, 1, 10, 15, tzinfo=timezone.utc),
                close_ts=datetime(2024, 1, 1, 9, 0, tzinfo=timezone.utc),
            ))

    def test_close_before_ack_rejected(self):
        with pytest.raises(ValidationError):
            Alert(**self._base_alert(
                ack_ts=datetime(2024, 1, 1, 10, 30, tzinfo=timezone.utc),
                close_ts=datetime(2024, 1, 1, 10, 20, tzinfo=timezone.utc),
            ))

    def test_no_ack_ts_ok(self):
        a = Alert(**self._base_alert(ack_ts=None))
        assert a.ack_ts is None


class TestEscalationModel:
    def test_performed_true_requires_ts(self):
        with pytest.raises(ValidationError, match="performed_ts"):
            Escalation(
                escalation_id="ESC-001",
                case_id="CASE-001",
                step_name="triage",
                required=True,
                performed=True,
                performed_ts=None,  # Missing!
            )

    def test_not_performed_no_ts_ok(self):
        e = Escalation(
            escalation_id="ESC-002",
            case_id="CASE-001",
            step_name="escalate_to_l2",
            required=True,
            performed=False,
            performed_ts=None,
        )
        assert e.performed is False


class TestSeverityTransitionModel:
    def test_same_severity_rejected(self):
        with pytest.raises(ValidationError, match="No-op"):
            SeverityTransition(
                transition_id="TRANS-001",
                alert_id="ALT-001",
                from_sev=Severity.P1,
                to_sev=Severity.P1,  # Same!
                ts=datetime(2024, 1, 1, tzinfo=timezone.utc),
                rationale_present=False,
            )

    def test_different_severity_ok(self):
        t = SeverityTransition(
            transition_id="TRANS-002",
            alert_id="ALT-001",
            from_sev=Severity.P1,
            to_sev=Severity.P3,
            ts=datetime(2024, 1, 1, tzinfo=timezone.utc),
            rationale_present=False,
        )
        assert t.from_sev == Severity.P1


class TestWorkflowEffortModel:
    def test_negative_minutes_rejected(self):
        with pytest.raises(ValidationError):
            WorkflowEffort(
                effort_id="EFF-001",
                analyst_id="ANA-001",
                shift_id="SHIFT-001",
                active_minutes=-10,
            )

    def test_zero_minutes_ok(self):
        w = WorkflowEffort(
            effort_id="EFF-002",
            analyst_id="ANA-001",
            shift_id="SHIFT-001",
            active_minutes=0.0,
        )
        assert w.active_minutes == 0.0


class TestValidator:
    def test_valid_rows_accepted(self):
        rows = [
            {
                "entity_id": "CSE-001",
                "name": "Test",
                "sector": "Finance",
                "asset_class": "endpoint",
                "size_band": "medium",
                "registered_ts": "2024-01-01T00:00:00",
            }
        ]
        report = validate_table("entities", rows)
        assert len(report.valid_rows) == 1
        assert len(report.invalid_rows) == 0

    def test_invalid_rows_quarantined(self):
        rows = [
            {"entity_id": "", "name": "Bad", "sector": "Finance",
             "asset_class": "ep", "size_band": "medium", "registered_ts": "2024-01-01"},
        ]
        report = validate_table("entities", rows)
        assert len(report.valid_rows) == 0
        assert len(report.invalid_rows) == 1

    def test_mixed_rows_partial_accept(self):
        rows = [
            {"entity_id": "CSE-001", "name": "Good", "sector": "Finance",
             "asset_class": "endpoint", "size_band": "medium", "registered_ts": "2024-01-01"},
            {"entity_id": "", "name": "Bad", "sector": "Finance",
             "asset_class": "endpoint", "size_band": "medium", "registered_ts": "2024-01-01"},
        ]
        report = validate_table("entities", rows)
        assert len(report.valid_rows) == 1
        assert len(report.invalid_rows) == 1

    def test_unknown_table_raises(self):
        with pytest.raises(KeyError):
            validate_table("nonexistent_table", [])

    def test_pass_rate_calculation(self):
        rows = [
            {"entity_id": "CSE-001", "name": "A", "sector": "Finance",
             "asset_class": "endpoint", "size_band": "medium", "registered_ts": "2024-01-01"},
            {"entity_id": "CSE-002", "name": "B", "sector": "Finance",
             "asset_class": "endpoint", "size_band": "medium", "registered_ts": "2024-01-01"},
        ]
        report = validate_table("entities", rows)
        assert report.pass_rate == 1.0
