"""
SAT-SA Test Configuration and Shared Fixtures.

All tests use seeded data fixtures for deterministic, reproducible results.
The synthetic dataset is generated once per session and reused across tests.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
import duckdb

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from datagen.generator import generate
from engine.ingestion.loader import open_connection, ingest_from_csv_dir

# Use a small dataset for unit tests (fast)
UNIT_SEED = 42
UNIT_ENTITIES = 12
UNIT_ALERTS = 5_000

logging.basicConfig(level=logging.WARNING)  # Suppress verbose logging in tests


@pytest.fixture(scope="session")
def tmp_data_dir(tmp_path_factory):
    """Generate synthetic data once per session into a temp directory."""
    data_dir = tmp_path_factory.mktemp("satsa_data")
    generate(
        seed=UNIT_SEED,
        n_entities=UNIT_ENTITIES,
        n_alerts=UNIT_ALERTS,
        out_dir=data_dir,
    )
    return data_dir


@pytest.fixture(scope="session")
def db_con(tmp_data_dir, tmp_path_factory):
    """Open an in-memory DuckDB connection loaded with test data."""
    db_path = tmp_path_factory.mktemp("satsa_db") / "test.db"
    con = open_connection(db_path)
    ingest_from_csv_dir(tmp_data_dir, con, validate=False)
    yield con
    con.close()


@pytest.fixture(scope="session")
def ground_truth(tmp_data_dir) -> dict:
    """Load ground truth labels for the test dataset."""
    gt_path = tmp_data_dir / "ground_truth.json"
    return json.loads(gt_path.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def anomaly_entity_ids(ground_truth) -> dict:
    """Return dict of anomaly_type → entity_id for all injected anomalies."""
    return {
        info["type"]: eid
        for eid, info in ground_truth["anomaly_entities"].items()
    }


@pytest.fixture(scope="session")
def entity_ids(db_con) -> list[str]:
    """Return all entity IDs in the test database."""
    rows = db_con.execute("SELECT entity_id FROM entities").fetchall()
    return [r[0] for r in rows]
