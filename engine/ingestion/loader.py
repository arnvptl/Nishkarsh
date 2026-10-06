"""
SAT-SA DuckDB Loader — CSV ingestion pipeline.

Validates, ingests, and loads CSV data files into DuckDB.
All tables are created with exact schema matching the Pydantic models.

DuckDB pinned at version 1.1.3 (see pyproject.toml). If the DuckDB version
changes, run the migration check in docs/deployment.md.

Note: The DuckDB .db file is NOT AES-encrypted at the page level.
Data files are encrypted at rest (see engine/ingestion/encryption.py).
The DuckDB .db file should be protected by OS-level disk encryption.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import duckdb

from engine.schema.validator import validate_all_tables, print_validation_summary

logger = logging.getLogger(__name__)

# DuckDB schema DDL
_DDL = """
CREATE TABLE IF NOT EXISTS entities (
    entity_id    VARCHAR PRIMARY KEY,
    name         VARCHAR NOT NULL,
    sector       VARCHAR NOT NULL,
    asset_class  VARCHAR NOT NULL,
    size_band    VARCHAR NOT NULL,
    registered_ts TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id    VARCHAR PRIMARY KEY,
    entity_id   VARCHAR NOT NULL REFERENCES entities(entity_id),
    asset_class VARCHAR NOT NULL,
    criticality VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id         VARCHAR PRIMARY KEY,
    entity_id        VARCHAR NOT NULL REFERENCES entities(entity_id),
    asset_id         VARCHAR NOT NULL,
    rule_type        VARCHAR NOT NULL,
    severity_initial VARCHAR NOT NULL,
    severity_final   VARCHAR NOT NULL,
    created_ts       TIMESTAMP NOT NULL,
    ack_ts           TIMESTAMP,
    close_ts         TIMESTAMP,
    source_is_soar   BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS cases (
    case_id         VARCHAR PRIMARY KEY,
    alert_id        VARCHAR NOT NULL,
    analyst_id      VARCHAR NOT NULL,
    shift_id        VARCHAR NOT NULL,
    notes_text      VARCHAR,
    disposition_code VARCHAR NOT NULL,
    opened_ts       TIMESTAMP NOT NULL,
    closed_ts       TIMESTAMP
);

CREATE TABLE IF NOT EXISTS escalations (
    escalation_id VARCHAR PRIMARY KEY,
    case_id       VARCHAR NOT NULL,
    step_name     VARCHAR NOT NULL,
    required      BOOLEAN NOT NULL,
    performed     BOOLEAN NOT NULL,
    performed_ts  TIMESTAMP
);

CREATE TABLE IF NOT EXISTS severity_transitions (
    transition_id     VARCHAR PRIMARY KEY,
    alert_id          VARCHAR NOT NULL,
    from_sev          VARCHAR NOT NULL,
    to_sev            VARCHAR NOT NULL,
    ts                TIMESTAMP NOT NULL,
    rationale_present BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS workflow_effort (
    effort_id      VARCHAR PRIMARY KEY,
    analyst_id     VARCHAR NOT NULL,
    shift_id       VARCHAR NOT NULL,
    active_minutes DOUBLE NOT NULL
);

CREATE TABLE IF NOT EXISTS known_noisy_exemptions (
    rule_type        VARCHAR NOT NULL,
    asset_class      VARCHAR NOT NULL,
    sector           VARCHAR NOT NULL,
    exemption_reason VARCHAR NOT NULL,
    approved_by      VARCHAR NOT NULL,
    approved_date    TIMESTAMP NOT NULL,
    expires_date     TIMESTAMP
);

-- Runtime tables
CREATE TABLE IF NOT EXISTS detector_results (
    id             VARCHAR PRIMARY KEY,
    detector_id    VARCHAR NOT NULL,
    detector_name  VARCHAR NOT NULL,
    entity_id      VARCHAR NOT NULL,
    cycle_id       VARCHAR NOT NULL,
    run_ts         TIMESTAMP NOT NULL,
    test_name      VARCHAR NOT NULL,
    statistic      DOUBLE,
    p_value        DOUBLE,
    score          DOUBLE,
    parameters     JSON,
    sample_size    INTEGER,
    flag           BOOLEAN NOT NULL,
    threshold_tier VARCHAR NOT NULL,
    confidence_note VARCHAR,
    fi_value       DOUBLE,
    result_json    JSON
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id              VARCHAR PRIMARY KEY,
    entity_id       VARCHAR NOT NULL,
    cycle_id        VARCHAR NOT NULL,
    run_ts          TIMESTAMP NOT NULL,
    score           DOUBLE NOT NULL,
    band            VARCHAR NOT NULL,
    weights_version VARCHAR,
    binary_mode     BOOLEAN,
    component_json  JSON
);

CREATE TABLE IF NOT EXISTS review_manifests (
    id             VARCHAR PRIMARY KEY,
    entity_id      VARCHAR NOT NULL,
    cycle_id       VARCHAR NOT NULL,
    run_ts         TIMESTAMP NOT NULL,
    alert_id       VARCHAR NOT NULL,
    stratum        VARCHAR NOT NULL,
    priority_rank  INTEGER NOT NULL,
    detector_score DOUBLE,
    sampled_by     VARCHAR NOT NULL,
    seed           INTEGER NOT NULL
);
"""


def open_connection(db_path: Path) -> duckdb.DuckDBPyConnection:
    """
    Open a DuckDB connection and ensure schema exists.

    Args:
        db_path: Path to the DuckDB .db file.

    Returns:
        Active DuckDB connection.
    """
    con = duckdb.connect(str(db_path))
    con.execute(_DDL)
    logger.info(f"DuckDB connected: {db_path} (version {duckdb.__version__})")
    return con


def ingest_from_csv_dir(
    data_dir: Path,
    con: duckdb.DuckDBPyConnection,
    *,
    validate: bool = True,
    abort_on_errors: bool = False,
) -> dict[str, int]:
    """
    Ingest all CSV files from ``data_dir`` into DuckDB.

    Validates rows using Pydantic schema before insertion.
    Quarantined rows are skipped (not inserted).

    Args:
        data_dir: Directory containing <table>.csv files.
        con: Active DuckDB connection.
        validate: Run Pydantic validation before insertion (recommended).
        abort_on_errors: If True, raise on any validation error.

    Returns:
        Dict of {table_name: rows_inserted}.
    """
    TABLE_ORDER = [
        "entities", "assets", "alerts", "cases",
        "escalations", "severity_transitions", "workflow_effort",
        "known_noisy_exemptions",
    ]

    if validate:
        reports = validate_all_tables(data_dir, file_format="csv")
        print_validation_summary(reports)

        if abort_on_errors:
            for report in reports.values():
                if report.invalid_rows:
                    raise ValueError(
                        f"Validation failed for table '{report.table}': "
                        f"{len(report.invalid_rows)} errors. Aborting."
                    )

    inserted_counts: dict[str, int] = {}

    for table_name in TABLE_ORDER:
        csv_path = data_dir / f"{table_name}.csv"
        if not csv_path.exists():
            logger.debug(f"No CSV for table {table_name}, skipping")
            continue

        if validate and table_name in reports:
            report = reports[table_name]
            if not report.valid_rows:
                logger.warning(f"No valid rows for {table_name}; skipping insertion")
                continue
            # Write valid rows to a temp file for DuckDB's COPY
            import tempfile, csv as csv_mod
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".csv", delete=False, encoding="utf-8", newline=""
            ) as tmp:
                tmp_path = tmp.name
                writer = csv_mod.DictWriter(tmp, fieldnames=report.valid_rows[0].keys())
                writer.writeheader()
                writer.writerows(report.valid_rows)
        else:
            tmp_path = str(csv_path)

        try:
            # Use DuckDB's vectorized CSV reader for performance
            con.execute(f"""
                INSERT OR IGNORE INTO {table_name}
                SELECT * FROM read_csv_auto(?, all_varchar=false, header=true)
            """, [tmp_path])
            count = con.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
            inserted_counts[table_name] = count
            logger.info(f"Loaded {table_name}: {count:,} total rows in table")
        except Exception as exc:
            logger.error(f"Error loading {table_name}: {exc}")
            if abort_on_errors:
                raise

    return inserted_counts
