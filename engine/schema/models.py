"""
SAT-SA Data Schema — Pydantic v2 models for all core tables.

These models define the data contract for SAT-SA. The ingestion validator
uses these models to reject or flag malformed input rows before they reach DuckDB.

Legal basis for Analyst ID processing: Section 7, DPDP Act 2023
(performance of State functions and legal obligations).

Severity scale: P1 (Critical) > P2 (High) > P3 (Medium) > P4 (Low) > P5 (Informational)
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ─── Enumerations ────────────────────────────────────────────────────────────


class Severity(str, Enum):
    """Alert severity levels. P1 is most critical."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P5 = "P5"

    @property
    def numeric(self) -> int:
        """Lower number = higher severity."""
        return int(self.value[1])


class SizeBand(str, Enum):
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"
    XLARGE = "xlarge"


class DispositionCode(str, Enum):
    """Standardized disposition codes. Used by G6 (Silent Loop) detector."""

    TRUE_POSITIVE = "TP"
    FALSE_POSITIVE = "FP"
    BENIGN_TRUE_POSITIVE = "BTP"
    DUPLICATE = "DUP"
    CLOSED_NO_ACTION = "CNA"   # Fast-closed; key for G6
    ESCALATED = "ESC"
    PENDING = "PENDING"


# ─── Core Table Models ────────────────────────────────────────────────────────


class Entity(BaseModel):
    """
    Critical Sector Entity (CSE) registry.
    One row per organization under supervisory review.
    """

    entity_id: str = Field(..., description="Unique CSE identifier")
    name: str = Field(..., description="Entity display name")
    sector: str = Field(..., description="e.g. Finance, Energy, Telecom")
    asset_class: str = Field(..., description="Primary asset class of the entity's SOC")
    size_band: SizeBand = Field(..., description="Organization size classification")
    registered_ts: datetime = Field(..., description="Date entity came under supervisory scope")

    @field_validator("entity_id")
    @classmethod
    def entity_id_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("entity_id must not be empty")
        return v.strip()


class Asset(BaseModel):
    """Individual asset monitored by an entity's SOC."""

    asset_id: str = Field(..., description="Unique asset identifier")
    entity_id: str = Field(..., description="Owning entity")
    asset_class: str = Field(..., description="e.g. endpoint, server, network, cloud")
    criticality: str = Field(..., description="Asset criticality: critical, high, medium, low")


class Alert(BaseModel):
    """
    Core alert metadata. The primary unit of analysis.

    Fields:
    - source_is_soar: If True, the alert was closed automatically by a SOAR/SIEM
      system. G1 (Velocity Distortion) MUST exclude SOAR-automated closures.
    - severity_initial: Severity at alert creation time.
    - severity_final: Severity at closure time (may differ due to downgrades).
    """

    alert_id: str
    entity_id: str
    asset_id: str
    rule_type: str = Field(..., description="Alert rule/detection type name")
    severity_initial: Severity
    severity_final: Severity
    created_ts: datetime
    ack_ts: Optional[datetime] = None
    close_ts: Optional[datetime] = None
    source_is_soar: bool = Field(default=False)

    @model_validator(mode="after")
    def timestamps_ordered(self) -> "Alert":
        """Validate temporal ordering of alert lifecycle timestamps."""
        if self.ack_ts and self.ack_ts < self.created_ts:
            raise ValueError(
                f"Alert {self.alert_id}: ack_ts ({self.ack_ts}) before created_ts ({self.created_ts})"
            )
        if self.close_ts and self.close_ts < self.created_ts:
            raise ValueError(
                f"Alert {self.alert_id}: close_ts ({self.close_ts}) before created_ts ({self.created_ts})"
            )
        if self.ack_ts and self.close_ts and self.close_ts < self.ack_ts:
            raise ValueError(
                f"Alert {self.alert_id}: close_ts before ack_ts"
            )
        return self


class Case(BaseModel):
    """
    Case management record. Links alerts to analyst investigation activities.

    notes_text is the analyst-written investigation summary used by G4 (Template Collapse).
    disposition_code is the standardized closure code used by G6 (Silent Loop).
    """

    case_id: str
    alert_id: str
    analyst_id: str = Field(..., description="Analyst identifier (DPDP Act §7 applies)")
    shift_id: str
    notes_text: Optional[str] = Field(default=None, description="Analyst-written investigation notes")
    disposition_code: DispositionCode
    opened_ts: datetime
    closed_ts: Optional[datetime] = None

    @model_validator(mode="after")
    def timestamps_ordered(self) -> "Case":
        if self.closed_ts and self.closed_ts < self.opened_ts:
            raise ValueError(
                f"Case {self.case_id}: closed_ts ({self.closed_ts}) before opened_ts ({self.opened_ts})"
            )
        return self


class Escalation(BaseModel):
    """
    Individual escalation workflow step. Used by Layer 1 SLA and G6 detectors.

    If required=True and performed=False, the step was skipped — a potential SLA violation.
    """

    escalation_id: str
    case_id: str
    step_name: str = Field(..., description="e.g. triage, escalate_to_l2, notify_management")
    required: bool
    performed: bool
    performed_ts: Optional[datetime] = Field(
        default=None,
        description="Timestamp when step was performed. None if not performed."
    )

    @model_validator(mode="after")
    def performed_requires_ts(self) -> "Escalation":
        if self.performed and self.performed_ts is None:
            raise ValueError(
                f"Escalation {self.escalation_id}: performed=True but no performed_ts"
            )
        return self


class SeverityTransition(BaseModel):
    """
    Audit trail of severity changes during an alert's lifecycle.
    Used by G2 (Severity Laundering) to build the transition matrix.

    rationale_present: True if analyst documented a reason for the change.
    G2 highlights asymmetric downgrade cells where rationale_present=False.
    """

    transition_id: str
    alert_id: str
    from_sev: Severity
    to_sev: Severity
    ts: datetime
    rationale_present: bool = Field(
        default=False,
        description="True if analyst provided documented rationale for severity change"
    )

    @model_validator(mode="after")
    def transition_must_change(self) -> "SeverityTransition":
        if self.from_sev == self.to_sev:
            raise ValueError(
                f"Transition {self.transition_id}: from_sev == to_sev ({self.from_sev}). "
                "No-op transitions should not be recorded."
            )
        return self


class WorkflowEffort(BaseModel):
    """
    Claimed analyst effort per shift. Used by G5 (Workload Inconsistency).

    active_minutes: Total minutes the analyst claims to have been actively
    investigating cases during this shift.
    """

    effort_id: str
    analyst_id: str
    shift_id: str
    active_minutes: float = Field(..., ge=0, description="Claimed active investigation minutes")

    @field_validator("active_minutes")
    @classmethod
    def minutes_non_negative(cls, v: float) -> float:
        if v < 0:
            raise ValueError("active_minutes must be non-negative")
        return v


class KnownNoisyExemption(BaseModel):
    """
    NCIIPC-controlled exemption for known high-volume benign alert rules.
    Used by G6 (Silent Loop) to exclude false positives.

    This table is populated from config/known_noisy_exemptions.yaml,
    which is controlled by NCIIPC and cannot be modified by CSEs.
    """

    rule_type: str
    asset_class: str = Field(..., description="Asset class or '*' for all")
    sector: str = Field(..., description="Sector or '*' for all")
    exemption_reason: str
    approved_by: str
    approved_date: datetime
    expires_date: Optional[datetime] = None

    def is_active(self, as_of: datetime) -> bool:
        """Return True if exemption is still valid as of the given timestamp."""
        if self.expires_date is None:
            return True
        return as_of <= self.expires_date


# ─── Ingestion Batch Model ────────────────────────────────────────────────────


class IngestBatch(BaseModel):
    """
    Top-level container for a full ingest payload.
    All tables are optional; omitted tables are skipped.
    The validator reports per-row errors without aborting the full batch.
    """

    entities: list[Entity] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    alerts: list[Alert] = Field(default_factory=list)
    cases: list[Case] = Field(default_factory=list)
    escalations: list[Escalation] = Field(default_factory=list)
    severity_transitions: list[SeverityTransition] = Field(default_factory=list)
    workflow_effort: list[WorkflowEffort] = Field(default_factory=list)
