"""
SAT-SA Synthetic Data Generator.

Generates a reproducible, seeded dataset with injected, ground-truth-labelled
anomalies for demonstration and validation purposes.

Usage:
    satsa gen --seed 42 --entities 40 --alerts 200000 --out data/

Ground truth labels are written to <out>/ground_truth.json for use ONLY
by the validation harness (tests/validation/). The labels file is NOT
read by any detector or scoring module.

Injected Anomalies (one entity each, with ground-truth labels):
    E01: Severity Laundering  — P1→P3 downgrades, no documented rationale
    E02: Rubber Stamping       — Bimodal near-zero ack/close times
    E03: Shift-End Gaming      — Batch closures at shift handover
    E04: Template Collapse     — Copy-pasted investigation notes
    E05: Impossible Workload   — Active minutes > shift duration
    E06: Silent Loop           — Recurring fast-closed alerts on one asset
    E07: Negative Space        — Alert volume below cohort p5
    E08-E40: Clean + noisy-benign entities (random mix)

All timestamps use UTC. All IDs are deterministic for a given seed.
"""

from __future__ import annotations

import csv
import json
import logging
import random
import string
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

UTC = timezone.utc

SECTORS = ["Finance", "Energy", "Telecom", "Health", "Transport", "Government"]
ASSET_CLASSES = ["endpoint", "server", "network", "cloud", "ot_scada"]
SIZE_BANDS = ["small", "medium", "large", "xlarge"]
RULE_TYPES = [
    "Lateral Movement", "Credential Access", "Privilege Escalation",
    "Data Exfiltration", "Command and Control", "Malware Detection",
    "Brute Force", "Phishing", "Ransomware", "Insider Threat",
    "DDoS", "Web Application Attack",
]
SEVERITIES = ["P1", "P2", "P3", "P4", "P5"]
SEVERITY_WEIGHTS = [0.05, 0.15, 0.30, 0.35, 0.15]  # Realistic distribution

ESCALATION_STEPS = {
    "P1": ["triage", "escalate_to_l2", "notify_management"],
    "P2": ["triage", "escalate_to_l2"],
    "P3": ["triage"],
    "P4": [],
    "P5": [],
}

DISPOSITIONS = ["TP", "FP", "BTP", "DUP", "CNA", "ESC"]
DISP_WEIGHTS = [0.35, 0.30, 0.10, 0.05, 0.15, 0.05]


# ─── Entity generator ────────────────────────────────────────────────────────

def _gen_entities(n: int, rng: random.Random, start_ts: datetime) -> list[dict]:
    """Generate n entities with deterministic IDs."""
    entities = []
    for i in range(1, n + 1):
        entity_id = f"CSE-{i:04d}"
        sector = SECTORS[(i - 1) % len(SECTORS)]
        asset_class = ASSET_CLASSES[(i - 1) % len(ASSET_CLASSES)]
        size_band = SIZE_BANDS[(i - 1) % len(SIZE_BANDS)]
        entities.append({
            "entity_id": entity_id,
            "name": f"Entity {i} ({sector})",
            "sector": sector,
            "asset_class": asset_class,
            "size_band": size_band,
            "registered_ts": (start_ts - timedelta(days=365)).isoformat(),
        })
    return entities


def _gen_assets(entities: list[dict], rng: random.Random) -> list[dict]:
    """Generate 3-8 assets per entity."""
    assets = []
    criticalities = ["critical", "high", "medium", "low"]
    for ent in entities:
        n_assets = rng.randint(3, 8)
        for j in range(1, n_assets + 1):
            assets.append({
                "asset_id": f"{ent['entity_id']}-ASSET-{j:03d}",
                "entity_id": ent["entity_id"],
                "asset_class": ent["asset_class"],
                "criticality": rng.choice(criticalities),
            })
    return assets


def _random_ts(base: datetime, min_minutes: int, max_minutes: int, rng: random.Random) -> datetime:
    offset = rng.randint(min_minutes, max_minutes)
    return base + timedelta(minutes=offset)


# ─── Normal alert/case generator ─────────────────────────────────────────────

def _gen_normal_alert(
    alert_id: str,
    entity: dict,
    asset: dict,
    start_ts: datetime,
    end_ts: datetime,
    rng: random.Random,
    np_rng: np.random.Generator,
) -> tuple[dict, dict, list[dict], list[dict]]:
    """
    Generate one normal alert with case, escalations, and severity transitions.
    Returns: (alert_row, case_row, escalation_rows, severity_transition_rows)
    """
    created_ts = start_ts + timedelta(
        seconds=int(rng.uniform(0, (end_ts - start_ts).total_seconds()))
    )
    severity_initial = np_rng.choice(SEVERITIES, p=SEVERITY_WEIGHTS)
    severity_final = severity_initial  # Normal: no change

    ack_delay_min = {"P1": 10, "P2": 30, "P3": 120, "P4": 300, "P5": 720}[severity_initial]
    ack_delay_max = {"P1": 14, "P2": 55, "P3": 220, "P4": 1400, "P5": 4000}[severity_initial]
    ack_ts = _random_ts(created_ts, ack_delay_min, ack_delay_max, rng)

    close_delay_min = {"P1": 30, "P2": 120, "P3": 480, "P4": 1440, "P5": 2880}[severity_initial]
    close_delay_max = {"P1": 120, "P2": 480, "P3": 2880, "P4": 7200, "P5": 14400}[severity_initial]
    close_ts = _random_ts(ack_ts, close_delay_min, close_delay_max, rng)

    source_is_soar = rng.random() < 0.15  # 15% auto-closed by SOAR

    alert_row = {
        "alert_id": alert_id,
        "entity_id": entity["entity_id"],
        "asset_id": asset["asset_id"],
        "rule_type": rng.choice(RULE_TYPES),
        "severity_initial": severity_initial,
        "severity_final": severity_final,
        "created_ts": created_ts.isoformat(),
        "ack_ts": ack_ts.isoformat(),
        "close_ts": close_ts.isoformat(),
        "source_is_soar": source_is_soar,
    }

    analyst_id = f"ANALYST-{rng.randint(1, 20):03d}"
    shift_id = f"SHIFT-{created_ts.strftime('%Y%m%d')}-{'DAY' if created_ts.hour < 16 else 'NIGHT'}"
    disposition = np_rng.choice(DISPOSITIONS, p=DISP_WEIGHTS)

    notes_templates = [
        f"Alert investigated. {rng.choice(['No malicious activity found.', 'False positive confirmed.', 'Threat mitigated.', 'Asset patched. No further action.'])}",
        f"Triaged by L1. {rng.choice(['Escalated to L2 for review.', 'Closed as benign.', 'Asset owner notified.'])}",
        f"Investigation complete. Evidence collected. Disposition: {disposition}.",
    ]

    case_row = {
        "case_id": f"CASE-{alert_id}",
        "alert_id": alert_id,
        "analyst_id": analyst_id,
        "shift_id": shift_id,
        "notes_text": rng.choice(notes_templates),
        "disposition_code": disposition,
        "opened_ts": ack_ts.isoformat(),
        "closed_ts": close_ts.isoformat(),
    }

    # Escalations
    escalation_rows = []
    required_steps = ESCALATION_STEPS.get(severity_initial, [])
    for k, step in enumerate(required_steps):
        performed = rng.random() < 0.92  # 92% compliance
        performed_ts = (_random_ts(ack_ts, 5, 60, rng)).isoformat() if performed else None
        escalation_rows.append({
            "escalation_id": f"ESC-{alert_id}-{k}",
            "case_id": case_row["case_id"],
            "step_name": step,
            "required": True,
            "performed": performed,
            "performed_ts": performed_ts,
        })

    # Severity transitions (rare in normal data)
    severity_transition_rows = []

    return alert_row, case_row, escalation_rows, severity_transition_rows


# ─── Anomaly injectors ────────────────────────────────────────────────────────

def _inject_severity_laundering(
    entity_id: str,
    assets: list[dict],
    alert_id_base: str,
    n_alerts: int,
    start_ts: datetime,
    rng: random.Random,
    np_rng: np.random.Generator,
) -> tuple[list[dict], list[dict], list[dict], list[dict], list[str]]:
    """
    E01: Severity Laundering.
    Generate alerts starting at P1, downgraded to P3 without rationale.
    """
    alerts, cases, escalations, transitions = [], [], [], []
    flagged_alert_ids = []

    for i in range(n_alerts):
        alert_id = f"{alert_id_base}-SL-{i:04d}"
        asset = assets[i % len(assets)]
        created_ts = start_ts + timedelta(hours=i * 3)
        ack_ts = created_ts + timedelta(minutes=rng.randint(8, 14))
        close_ts = ack_ts + timedelta(minutes=rng.randint(30, 90))

        alerts.append({
            "alert_id": alert_id,
            "entity_id": entity_id,
            "asset_id": asset["asset_id"],
            "rule_type": rng.choice(["Lateral Movement", "Credential Access"]),
            "severity_initial": "P1",
            "severity_final": "P3",  # Downgraded
            "created_ts": created_ts.isoformat(),
            "ack_ts": ack_ts.isoformat(),
            "close_ts": close_ts.isoformat(),
            "source_is_soar": False,
        })

        analyst_id = f"ANALYST-SL-{(i % 3) + 1:03d}"
        shift_id = f"SHIFT-SL-{created_ts.strftime('%Y%m%d')}-DAY"

        cases.append({
            "case_id": f"CASE-{alert_id}",
            "alert_id": alert_id,
            "analyst_id": analyst_id,
            "shift_id": shift_id,
            "notes_text": "Alert reviewed. Severity adjusted per assessment. Closed.",
            "disposition_code": "CNA",
            "opened_ts": ack_ts.isoformat(),
            "closed_ts": close_ts.isoformat(),
        })

        # P1 → P2 (minor step first, then P3)
        transitions.append({
            "transition_id": f"TRANS-{alert_id}-1",
            "alert_id": alert_id,
            "from_sev": "P1",
            "to_sev": "P3",
            "ts": (ack_ts + timedelta(minutes=5)).isoformat(),
            "rationale_present": False,  # No rationale — key for G2
        })

        flagged_alert_ids.append(alert_id)

        # Add required escalation steps (intentionally missing notify_management)
        for k, step in enumerate(["triage"]):
            escalations.append({
                "escalation_id": f"ESC-{alert_id}-{k}",
                "case_id": f"CASE-{alert_id}",
                "step_name": step,
                "required": True,
                "performed": True,
                "performed_ts": (ack_ts + timedelta(minutes=k * 5 + 2)).isoformat(),
            })

    return alerts, cases, escalations, transitions, flagged_alert_ids


def _inject_rubber_stamping(
    entity_id: str,
    assets: list[dict],
    alert_id_base: str,
    n_alerts: int,
    start_ts: datetime,
    rng: random.Random,
    np_rng: np.random.Generator,
) -> tuple[list[dict], list[dict], list[dict], list[dict], list[str]]:
    """
    E02: Rubber Stamping.
    Bimodal distribution: most alerts acked in < 2 minutes, some in 60+ minutes.
    """
    alerts, cases, escalations, transitions = [], [], [], []
    flagged_alert_ids = []

    for i in range(n_alerts):
        alert_id = f"{alert_id_base}-RS-{i:04d}"
        asset = assets[i % len(assets)]
        created_ts = start_ts + timedelta(hours=i * 2)

        # Bimodal: 80% near-zero, 20% normal
        if rng.random() < 0.80:
            ack_minutes = rng.randint(0, 2)  # Near-zero cluster
            close_minutes = rng.randint(1, 5)
        else:
            ack_minutes = rng.randint(45, 90)  # Normal cluster
            close_minutes = rng.randint(120, 480)

        ack_ts = created_ts + timedelta(minutes=ack_minutes)
        close_ts = ack_ts + timedelta(minutes=close_minutes)

        sev = np_rng.choice(["P2", "P3", "P4"], p=[0.3, 0.5, 0.2])
        alerts.append({
            "alert_id": alert_id,
            "entity_id": entity_id,
            "asset_id": asset["asset_id"],
            "rule_type": "Malware Detection",
            "severity_initial": sev,
            "severity_final": sev,
            "created_ts": created_ts.isoformat(),
            "ack_ts": ack_ts.isoformat(),
            "close_ts": close_ts.isoformat(),
            "source_is_soar": False,
        })

        analyst_id = f"ANALYST-RS-{(i % 4) + 1:03d}"
        shift_id = f"SHIFT-RS-{created_ts.strftime('%Y%m%d')}-DAY"

        cases.append({
            "case_id": f"CASE-{alert_id}",
            "alert_id": alert_id,
            "analyst_id": analyst_id,
            "shift_id": shift_id,
            "notes_text": "Alert reviewed and closed.",
            "disposition_code": "FP",
            "opened_ts": ack_ts.isoformat(),
            "closed_ts": close_ts.isoformat(),
        })

        flagged_alert_ids.append(alert_id)

    return alerts, cases, escalations, transitions, flagged_alert_ids


def _inject_shift_end_gaming(
    entity_id: str,
    assets: list[dict],
    alert_id_base: str,
    n_alerts: int,
    start_ts: datetime,
    rng: random.Random,
    np_rng: np.random.Generator,
) -> tuple[list[dict], list[dict], list[dict], list[dict], list[str]]:
    """
    E03: Shift-End Gaming.
    All alerts closed in the last 15 minutes of each shift.
    """
    alerts, cases, escalations, transitions = [], [], [], []
    flagged_alert_ids = []

    shift_duration_hours = 8
    n_shifts = max(1, n_alerts // 20)  # ~20 alerts per shift

    alert_idx = 0
    for shift_n in range(n_shifts):
        shift_start = start_ts + timedelta(hours=shift_n * shift_duration_hours)
        shift_end = shift_start + timedelta(hours=shift_duration_hours)
        # Batch close window: last 15 minutes of shift
        batch_start = shift_end - timedelta(minutes=15)

        analyst_id = f"ANALYST-SE-{(shift_n % 3) + 1:03d}"
        shift_id = f"SHIFT-SE-{shift_start.strftime('%Y%m%d-%H')}"

        n_in_shift = min(20, n_alerts - alert_idx)
        for i in range(n_in_shift):
            alert_id = f"{alert_id_base}-SE-{alert_idx:04d}"
            alert_idx += 1
            asset = assets[i % len(assets)]

            # Alert created during shift, acked early, but CLOSED at end of shift
            created_ts = shift_start + timedelta(minutes=rng.randint(10, 200))
            ack_ts = created_ts + timedelta(minutes=rng.randint(15, 60))

            # Closed in the batch window (last 15 min)
            close_ts = batch_start + timedelta(
                seconds=rng.randint(0, 15 * 60 - 1)
            )
            if close_ts < ack_ts:
                close_ts = ack_ts + timedelta(minutes=5)

            sev = np_rng.choice(SEVERITIES, p=SEVERITY_WEIGHTS)
            alerts.append({
                "alert_id": alert_id,
                "entity_id": entity_id,
                "asset_id": asset["asset_id"],
                "rule_type": rng.choice(RULE_TYPES),
                "severity_initial": sev,
                "severity_final": sev,
                "created_ts": created_ts.isoformat(),
                "ack_ts": ack_ts.isoformat(),
                "close_ts": close_ts.isoformat(),
                "source_is_soar": False,
            })

            cases.append({
                "case_id": f"CASE-{alert_id}",
                "alert_id": alert_id,
                "analyst_id": analyst_id,
                "shift_id": shift_id,
                "notes_text": f"Investigated and closed. Shift handover. Disposition: FP.",
                "disposition_code": "FP",
                "opened_ts": ack_ts.isoformat(),
                "closed_ts": close_ts.isoformat(),
            })

            flagged_alert_ids.append(alert_id)

    return alerts, cases, escalations, transitions, flagged_alert_ids


def _inject_template_collapse(
    entity_id: str,
    assets: list[dict],
    alert_id_base: str,
    n_alerts: int,
    start_ts: datetime,
    rng: random.Random,
    np_rng: np.random.Generator,
) -> tuple[list[dict], list[dict], list[dict], list[dict], list[str]]:
    """
    E04: Template Collapse.
    90% of case notes are near-identical (copy-pasted boilerplate).
    """
    alerts, cases, escalations, transitions = [], [], [], []
    flagged_alert_ids = []

    TEMPLATE_NOTE = (
        "Investigation complete. Alert reviewed against threat intelligence baseline. "
        "No indicators of compromise found. Asset validated as clean. "
        "Closed as false positive per standard operating procedure SOP-L1-042. "
        "No further action required. Reviewed by L1 analyst."
    )

    for i in range(n_alerts):
        alert_id = f"{alert_id_base}-TC-{i:04d}"
        asset = assets[i % len(assets)]
        created_ts = start_ts + timedelta(hours=i * 4)
        ack_ts = created_ts + timedelta(minutes=rng.randint(20, 60))
        close_ts = ack_ts + timedelta(minutes=rng.randint(30, 120))
        sev = np_rng.choice(SEVERITIES, p=SEVERITY_WEIGHTS)

        alerts.append({
            "alert_id": alert_id,
            "entity_id": entity_id,
            "asset_id": asset["asset_id"],
            "rule_type": rng.choice(RULE_TYPES),
            "severity_initial": sev,
            "severity_final": sev,
            "created_ts": created_ts.isoformat(),
            "ack_ts": ack_ts.isoformat(),
            "close_ts": close_ts.isoformat(),
            "source_is_soar": False,
        })

        analyst_id = f"ANALYST-TC-{(i % 5) + 1:03d}"
        shift_id = f"SHIFT-TC-{created_ts.strftime('%Y%m%d')}-DAY"

        # 90% copy-pasted note, 10% unique
        if rng.random() < 0.90:
            notes = TEMPLATE_NOTE
        else:
            notes = f"Unique investigation note {rng.randint(10000, 99999)}. Specific findings for alert {alert_id}. Asset {asset['asset_id']} examined."

        cases.append({
            "case_id": f"CASE-{alert_id}",
            "alert_id": alert_id,
            "analyst_id": analyst_id,
            "shift_id": shift_id,
            "notes_text": notes,
            "disposition_code": "FP",
            "opened_ts": ack_ts.isoformat(),
            "closed_ts": close_ts.isoformat(),
        })

        flagged_alert_ids.append(alert_id)

    return alerts, cases, escalations, transitions, flagged_alert_ids


def _inject_impossible_workload(
    entity_id: str,
    assets: list[dict],
    alert_id_base: str,
    n_alerts: int,
    start_ts: datetime,
    rng: random.Random,
    np_rng: np.random.Generator,
) -> tuple[list[dict], list[dict], list[dict], list[dict], list[dict], list[str]]:
    """
    E05: Impossible Workload.
    Analysts claim 14+ hours of active investigation in an 8-hour shift.
    Returns extra workflow_effort rows.
    """
    alerts, cases, escalations, transitions = [], [], [], []
    workflow_effort = []
    flagged_alert_ids = []

    for i in range(n_alerts):
        alert_id = f"{alert_id_base}-IW-{i:04d}"
        asset = assets[i % len(assets)]
        created_ts = start_ts + timedelta(hours=i * 6)
        ack_ts = created_ts + timedelta(minutes=rng.randint(30, 90))
        close_ts = ack_ts + timedelta(minutes=rng.randint(60, 240))
        sev = np_rng.choice(SEVERITIES, p=SEVERITY_WEIGHTS)

        alerts.append({
            "alert_id": alert_id,
            "entity_id": entity_id,
            "asset_id": asset["asset_id"],
            "rule_type": rng.choice(RULE_TYPES),
            "severity_initial": sev,
            "severity_final": sev,
            "created_ts": created_ts.isoformat(),
            "ack_ts": ack_ts.isoformat(),
            "close_ts": close_ts.isoformat(),
            "source_is_soar": False,
        })

        analyst_id = f"ANALYST-IW-{(i % 3) + 1:03d}"
        shift_id = f"SHIFT-IW-{created_ts.strftime('%Y%m%d')}-DAY"

        cases.append({
            "case_id": f"CASE-{alert_id}",
            "alert_id": alert_id,
            "analyst_id": analyst_id,
            "shift_id": shift_id,
            "notes_text": f"Thorough investigation completed for alert {alert_id}.",
            "disposition_code": rng.choice(["TP", "FP"]),
            "opened_ts": ack_ts.isoformat(),
            "closed_ts": close_ts.isoformat(),
        })

        # Claim impossible workload hours
        workflow_effort.append({
            "effort_id": f"EFFORT-{alert_id}",
            "analyst_id": analyst_id,
            "shift_id": shift_id,
            "active_minutes": rng.randint(840, 900),  # 14-15 hours
        })

        flagged_alert_ids.append(alert_id)

    return alerts, cases, escalations, transitions, workflow_effort, flagged_alert_ids


def _inject_silent_loop(
    entity_id: str,
    assets: list[dict],
    alert_id_base: str,
    n_alerts: int,
    start_ts: datetime,
    rng: random.Random,
    np_rng: np.random.Generator,
) -> tuple[list[dict], list[dict], list[dict], list[dict], list[str]]:
    """
    E06: Silent Loop.
    Same asset generates repeated fast-closed CNA alerts without remediation.
    """
    alerts, cases, escalations, transitions = [], [], [], []
    flagged_alert_ids = []

    # Pin to one specific asset for the loop
    loop_asset = assets[0]

    for i in range(n_alerts):
        alert_id = f"{alert_id_base}-SLO-{i:04d}"
        created_ts = start_ts + timedelta(hours=i * 2)
        close_ts = created_ts + timedelta(minutes=rng.randint(5, 20))  # Fast close

        alerts.append({
            "alert_id": alert_id,
            "entity_id": entity_id,
            "asset_id": loop_asset["asset_id"],  # Always same asset
            "rule_type": "Lateral Movement",     # Always same rule
            "severity_initial": "P3",
            "severity_final": "P3",
            "created_ts": created_ts.isoformat(),
            "ack_ts": (created_ts + timedelta(minutes=2)).isoformat(),
            "close_ts": close_ts.isoformat(),
            "source_is_soar": False,
        })

        analyst_id = f"ANALYST-SL2-{(i % 4) + 1:03d}"
        shift_id = f"SHIFT-SLO-{created_ts.strftime('%Y%m%d')}-DAY"

        cases.append({
            "case_id": f"CASE-{alert_id}",
            "alert_id": alert_id,
            "analyst_id": analyst_id,
            "shift_id": shift_id,
            "notes_text": "Alert reviewed. No action required. Known noisy rule.",
            "disposition_code": "CNA",  # Closed No Action — key for G6
            "opened_ts": (created_ts + timedelta(minutes=2)).isoformat(),
            "closed_ts": close_ts.isoformat(),
        })

        flagged_alert_ids.append(alert_id)

    return alerts, cases, escalations, transitions, flagged_alert_ids


def _inject_negative_space(
    entity_id: str,
    assets: list[dict],
    alert_id_base: str,
    start_ts: datetime,
    end_ts: datetime,
    rng: random.Random,
    np_rng: np.random.Generator,
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """
    E07: Negative Space.
    Entity generates almost NO Lateral Movement or Credential Access alerts
    while its cohort peers generate many.
    """
    alerts, cases, escalations, transitions = [], [], [], []

    # Only generate benign/low-severity alerts; no target rule types
    safe_rules = ["DDoS", "Web Application Attack", "Brute Force"]

    for i in range(30):  # Very low volume
        alert_id = f"{alert_id_base}-NS-{i:04d}"
        asset = assets[i % len(assets)]
        created_ts = start_ts + timedelta(
            hours=rng.randint(0, int((end_ts - start_ts).total_seconds() / 3600))
        )
        ack_ts = created_ts + timedelta(minutes=rng.randint(30, 120))
        close_ts = ack_ts + timedelta(minutes=rng.randint(60, 300))

        alerts.append({
            "alert_id": alert_id,
            "entity_id": entity_id,
            "asset_id": asset["asset_id"],
            "rule_type": rng.choice(safe_rules),  # No target categories
            "severity_initial": "P4",
            "severity_final": "P4",
            "created_ts": created_ts.isoformat(),
            "ack_ts": ack_ts.isoformat(),
            "close_ts": close_ts.isoformat(),
            "source_is_soar": False,
        })

        cases.append({
            "case_id": f"CASE-{alert_id}",
            "alert_id": alert_id,
            "analyst_id": f"ANALYST-NS-001",
            "shift_id": f"SHIFT-NS-{created_ts.strftime('%Y%m%d')}-DAY",
            "notes_text": "Low priority alert. Investigated. No action required.",
            "disposition_code": "FP",
            "opened_ts": ack_ts.isoformat(),
            "closed_ts": close_ts.isoformat(),
        })

    return alerts, cases, escalations, transitions


# ─── Main generator ──────────────────────────────────────────────────────────

def generate(
    seed: int = 42,
    n_entities: int = 40,
    n_alerts: int = 200_000,
    out_dir: Path = Path("data"),
) -> dict[str, Any]:
    """
    Generate complete synthetic dataset with injected anomalies.

    Args:
        seed: RNG seed for full reproducibility.
        n_entities: Total number of entities (min 8 required for anomalies).
        n_alerts: Total alert count (approximate; anomaly entities get fixed counts).
        out_dir: Directory to write CSV files.

    Returns:
        Dict with counts of generated records per table.
    """
    if n_entities < 8:
        raise ValueError("n_entities must be >= 8 (one per anomaly type)")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(seed)
    np_rng = np.random.default_rng(seed)

    start_ts = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    end_ts = datetime(2024, 12, 31, 23, 59, 59, tzinfo=UTC)

    logger.info(f"Generating synthetic data: seed={seed}, entities={n_entities}, alerts≈{n_alerts}")

    # ── Step 1: Generate all entities and assets ──────────────────────────────
    entities = _gen_entities(n_entities, rng, start_ts)
    assets_by_entity = {}
    all_assets = []
    for ent in entities:
        ent_assets = _gen_assets([ent], rng)
        assets_by_entity[ent["entity_id"]] = ent_assets
        all_assets.extend(ent_assets)

    # ── Step 2: Assign anomaly entities (first 7 entities) ──────────────────
    # Make all anomaly entities share the same cohort (Finance, endpoint, medium)
    # so that the negative space entity is clearly below its peers
    ANOMALY_SECTOR = "Finance"
    ANOMALY_ASSET_CLASS = "endpoint"
    ANOMALY_SIZE = "medium"

    anomaly_entity_ids = [entities[i]["entity_id"] for i in range(7)]
    for i in range(7):
        entities[i]["sector"] = ANOMALY_SECTOR
        entities[i]["asset_class"] = ANOMALY_ASSET_CLASS
        entities[i]["size_band"] = ANOMALY_SIZE

    ground_truth = {
        "seed": seed,
        "generated_at": datetime.utcnow().isoformat(),
        "anomaly_entities": {
            anomaly_entity_ids[0]: {"type": "severity_laundering", "label": "G2_FLAGGED"},
            anomaly_entity_ids[1]: {"type": "rubber_stamping",     "label": "G1_FLAGGED"},
            anomaly_entity_ids[2]: {"type": "shift_end_gaming",    "label": "G3_FLAGGED"},
            anomaly_entity_ids[3]: {"type": "template_collapse",   "label": "G4_FLAGGED"},
            anomaly_entity_ids[4]: {"type": "impossible_workload", "label": "G5_FLAGGED"},
            anomaly_entity_ids[5]: {"type": "silent_loop",         "label": "G6_FLAGGED"},
            anomaly_entity_ids[6]: {"type": "negative_space",      "label": "L1_NS_FLAGGED"},
        },
        "clean_entities": [e["entity_id"] for e in entities[7:]],
    }

    # ── Step 3: Generate anomaly data ─────────────────────────────────────────
    all_alerts: list[dict] = []
    all_cases: list[dict] = []
    all_escalations: list[dict] = []
    all_transitions: list[dict] = []
    all_workflow_effort: list[dict] = []

    ANOMALY_ALERT_COUNT = 80  # Per anomaly entity

    # E01: Severity Laundering
    a, c, e, t, flag_ids = _inject_severity_laundering(
        anomaly_entity_ids[0], assets_by_entity[anomaly_entity_ids[0]],
        anomaly_entity_ids[0], ANOMALY_ALERT_COUNT, start_ts, rng, np_rng
    )
    all_alerts += a; all_cases += c; all_escalations += e; all_transitions += t
    ground_truth["anomaly_entities"][anomaly_entity_ids[0]]["flagged_alert_ids"] = flag_ids

    # E02: Rubber Stamping
    a, c, e, t, flag_ids = _inject_rubber_stamping(
        anomaly_entity_ids[1], assets_by_entity[anomaly_entity_ids[1]],
        anomaly_entity_ids[1], ANOMALY_ALERT_COUNT, start_ts, rng, np_rng
    )
    all_alerts += a; all_cases += c; all_escalations += e; all_transitions += t
    ground_truth["anomaly_entities"][anomaly_entity_ids[1]]["flagged_alert_ids"] = flag_ids

    # E03: Shift-End Gaming
    a, c, e, t, flag_ids = _inject_shift_end_gaming(
        anomaly_entity_ids[2], assets_by_entity[anomaly_entity_ids[2]],
        anomaly_entity_ids[2], ANOMALY_ALERT_COUNT, start_ts, rng, np_rng
    )
    all_alerts += a; all_cases += c; all_escalations += e; all_transitions += t
    ground_truth["anomaly_entities"][anomaly_entity_ids[2]]["flagged_alert_ids"] = flag_ids

    # E04: Template Collapse
    a, c, e, t, flag_ids = _inject_template_collapse(
        anomaly_entity_ids[3], assets_by_entity[anomaly_entity_ids[3]],
        anomaly_entity_ids[3], ANOMALY_ALERT_COUNT, start_ts, rng, np_rng
    )
    all_alerts += a; all_cases += c; all_escalations += e; all_transitions += t
    ground_truth["anomaly_entities"][anomaly_entity_ids[3]]["flagged_alert_ids"] = flag_ids

    # E05: Impossible Workload
    a, c, e, t, wf, flag_ids = _inject_impossible_workload(
        anomaly_entity_ids[4], assets_by_entity[anomaly_entity_ids[4]],
        anomaly_entity_ids[4], ANOMALY_ALERT_COUNT, start_ts, rng, np_rng
    )
    all_alerts += a; all_cases += c; all_escalations += e; all_transitions += t
    all_workflow_effort += wf
    ground_truth["anomaly_entities"][anomaly_entity_ids[4]]["flagged_alert_ids"] = flag_ids

    # E06: Silent Loop
    a, c, e, t, flag_ids = _inject_silent_loop(
        anomaly_entity_ids[5], assets_by_entity[anomaly_entity_ids[5]],
        anomaly_entity_ids[5], ANOMALY_ALERT_COUNT, start_ts, rng, np_rng
    )
    all_alerts += a; all_cases += c; all_escalations += e; all_transitions += t
    ground_truth["anomaly_entities"][anomaly_entity_ids[5]]["flagged_alert_ids"] = flag_ids

    # E07: Negative Space (very few alerts in target categories)
    a, c, e, t = _inject_negative_space(
        anomaly_entity_ids[6], assets_by_entity[anomaly_entity_ids[6]],
        anomaly_entity_ids[6], start_ts, end_ts, rng, np_rng
    )
    all_alerts += a; all_cases += c; all_escalations += e; all_transitions += t

    # ── Step 4: Generate normal alerts for all entities ────────────────────────
    # Budget remaining after anomaly entities
    anomaly_alert_count = ANOMALY_ALERT_COUNT * 6 + 30  # E01-E06 + E07
    normal_budget = max(0, n_alerts - anomaly_alert_count)
    clean_entities = [e for e in entities if e["entity_id"] not in anomaly_entity_ids]

    alert_counter = anomaly_alert_count

    for ent in clean_entities:
        ent_assets = assets_by_entity[ent["entity_id"]]
        # Allocate proportional alerts to each clean entity
        ent_alert_count = max(50, normal_budget // max(len(clean_entities), 1))

        for i in range(ent_alert_count):
            alert_id = f"ALERT-{alert_counter:08d}"
            alert_counter += 1
            asset = ent_assets[i % len(ent_assets)]

            alert, case, escs, trans = _gen_normal_alert(
                alert_id, ent, asset, start_ts, end_ts, rng, np_rng
            )
            all_alerts.append(alert)
            all_cases.append(case)
            all_escalations.extend(escs)
            all_transitions.extend(trans)

            # Add normal workflow effort
            if rng.random() < 0.3:
                all_workflow_effort.append({
                    "effort_id": f"EFFORT-{alert_id}",
                    "analyst_id": case["analyst_id"],
                    "shift_id": case["shift_id"],
                    "active_minutes": rng.randint(30, 420),
                })

    # ── Step 5: Write CSV files ───────────────────────────────────────────────
    def write_csv(filename: str, rows: list[dict]) -> None:
        if not rows:
            return
        path = out_dir / filename
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        logger.info(f"Wrote {len(rows):,} rows to {path}")

    write_csv("entities.csv", entities)
    write_csv("assets.csv", all_assets)
    write_csv("alerts.csv", all_alerts)
    write_csv("cases.csv", all_cases)
    write_csv("escalations.csv", all_escalations)
    write_csv("severity_transitions.csv", all_transitions)
    write_csv("workflow_effort.csv", all_workflow_effort)

    # Ground truth (NOT read by any detector)
    gt_path = out_dir / "ground_truth.json"
    gt_path.write_text(json.dumps(ground_truth, indent=2), encoding="utf-8")
    logger.info(f"Ground truth written to {gt_path}")

    stats = {
        "entities": len(entities),
        "assets": len(all_assets),
        "alerts": len(all_alerts),
        "cases": len(all_cases),
        "escalations": len(all_escalations),
        "severity_transitions": len(all_transitions),
        "workflow_effort": len(all_workflow_effort),
        "anomaly_entities": list(ground_truth["anomaly_entities"].keys()),
    }
    logger.info(f"Generation complete: {stats}")
    return stats
