"""
SAT-SA Null Corpus Generator.

Generates a no-anomaly dataset for computing per-test false-positive rates
at the legal tier. Used by tests/validation/test_detector_precision.py.

The null corpus contains ONLY clean entities with realistic but benign
alert patterns — no injected anomalies of any kind.

Usage:
    satsa gen-null --seed 100 --entities 20 --alerts 50000 --out data/null/
"""

from __future__ import annotations

import csv
import json
import logging
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np

from datagen.generator import (
    RULE_TYPES, SECTORS, ASSET_CLASSES, SIZE_BANDS,
    SEVERITIES, SEVERITY_WEIGHTS, DISPOSITIONS, DISP_WEIGHTS,
    ESCALATION_STEPS, UTC,
    _gen_entities, _gen_assets, _gen_normal_alert,
)

logger = logging.getLogger(__name__)


def generate_null_corpus(
    seed: int = 100,
    n_entities: int = 20,
    n_alerts: int = 50_000,
    out_dir: Path = Path("data/null"),
) -> dict[str, Any]:
    """
    Generate a no-anomaly null corpus dataset.

    All entities have clean, realistic SOC behavior. No anomalies injected.
    The ground_truth_null.json file marks all entities as "CLEAN".

    Args:
        seed: RNG seed (use a DIFFERENT seed from the anomaly generator).
        n_entities: Number of clean entities.
        n_alerts: Total alerts to generate.
        out_dir: Output directory.

    Returns:
        Dict with record counts.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(seed)
    np_rng = np.random.default_rng(seed)

    start_ts = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
    end_ts = datetime(2024, 12, 31, 23, 59, 59, tzinfo=UTC)

    entities = _gen_entities(n_entities, rng, start_ts)
    all_assets = []
    assets_by_entity = {}
    for ent in entities:
        ent_assets = _gen_assets([ent], rng)
        assets_by_entity[ent["entity_id"]] = ent_assets
        all_assets.extend(ent_assets)

    all_alerts, all_cases, all_escalations, all_transitions, all_effort = [], [], [], [], []
    alert_counter = 0

    for ent in entities:
        ent_assets = assets_by_entity[ent["entity_id"]]
        ent_alert_count = max(50, n_alerts // n_entities)

        for i in range(ent_alert_count):
            alert_id = f"NULL-{alert_counter:08d}"
            alert_counter += 1
            asset = ent_assets[i % len(ent_assets)]

            alert, case, escs, trans = _gen_normal_alert(
                alert_id, ent, asset, start_ts, end_ts, rng, np_rng
            )
            all_alerts.append(alert)
            all_cases.append(case)
            all_escalations.extend(escs)
            all_transitions.extend(trans)

            if rng.random() < 0.3:
                all_effort.append({
                    "effort_id": f"EFFORT-{alert_id}",
                    "analyst_id": case["analyst_id"],
                    "shift_id": case["shift_id"],
                    "active_minutes": rng.randint(30, 420),
                })

    def write_csv(filename: str, rows: list[dict]) -> None:
        if not rows:
            return
        path = out_dir / filename
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

    write_csv("entities.csv", entities)
    write_csv("assets.csv", all_assets)
    write_csv("alerts.csv", all_alerts)
    write_csv("cases.csv", all_cases)
    write_csv("escalations.csv", all_escalations)
    write_csv("severity_transitions.csv", all_transitions)
    write_csv("workflow_effort.csv", all_effort)

    ground_truth = {
        "seed": seed,
        "corpus_type": "null",
        "generated_at": datetime.utcnow().isoformat(),
        "all_entities_clean": True,
        "entity_ids": [e["entity_id"] for e in entities],
    }
    (out_dir / "ground_truth_null.json").write_text(
        json.dumps(ground_truth, indent=2), encoding="utf-8"
    )

    return {
        "entities": len(entities),
        "assets": len(all_assets),
        "alerts": len(all_alerts),
        "cases": len(all_cases),
        "escalations": len(all_escalations),
        "severity_transitions": len(all_transitions),
        "workflow_effort": len(all_effort),
    }
