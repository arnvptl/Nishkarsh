"""
SAT-SA Ingestion Validator.

Validates incoming CSV/JSON data rows against Pydantic schema models.
Does NOT abort on first error — collects all row-level errors and returns
a ValidationReport so the examiner can see the full picture.

Rows that fail validation are quarantined (not ingested) and included
in the report with their row index and error message.
"""

from __future__ import annotations

import json
import csv
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from engine.schema.models import (
    Alert,
    Asset,
    Case,
    Entity,
    Escalation,
    KnownNoisyExemption,
    SeverityTransition,
    WorkflowEffort,
)

# Map table name → Pydantic model class
TABLE_MODELS: dict[str, Any] = {
    "entities": Entity,
    "assets": Asset,
    "alerts": Alert,
    "cases": Case,
    "escalations": Escalation,
    "severity_transitions": SeverityTransition,
    "workflow_effort": WorkflowEffort,
    "known_noisy_exemptions": KnownNoisyExemption,
}


@dataclass
class RowError:
    """A single row-level validation error."""

    table: str
    row_index: int
    raw_data: dict
    error_message: str


@dataclass
class ValidationReport:
    """
    Summary of a validation run.

    valid_rows:    Rows that passed validation, ready for ingestion.
    invalid_rows:  Rows that failed validation (quarantined).
    warnings:      Non-fatal issues (e.g., provenance gaps).
    """

    table: str
    valid_rows: list[dict] = field(default_factory=list)
    invalid_rows: list[RowError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.valid_rows) + len(self.invalid_rows)

    @property
    def pass_rate(self) -> float:
        if self.total == 0:
            return 1.0
        return len(self.valid_rows) / self.total

    def summary(self) -> str:
        return (
            f"Table '{self.table}': {len(self.valid_rows)}/{self.total} rows valid "
            f"({self.pass_rate:.1%}), {len(self.invalid_rows)} quarantined"
        )


def validate_table(
    table_name: str,
    rows: list[dict],
    *,
    warn_on_unknown_fields: bool = True,
) -> ValidationReport:
    """
    Validate a list of raw dicts against the schema model for ``table_name``.

    Args:
        table_name: One of the keys in TABLE_MODELS.
        rows: List of raw dictionaries (e.g., from CSV reader).
        warn_on_unknown_fields: Emit a warning if rows contain unexpected fields.

    Returns:
        ValidationReport with valid_rows ready for ingestion.

    Raises:
        KeyError: If table_name is not recognized.
    """
    if table_name not in TABLE_MODELS:
        raise KeyError(
            f"Unknown table '{table_name}'. Valid tables: {list(TABLE_MODELS.keys())}"
        )

    model_cls = TABLE_MODELS[table_name]
    report = ValidationReport(table=table_name)

    for idx, raw in enumerate(rows):
        try:
            validated = model_cls.model_validate(raw)
            valid_dict = validated.model_dump(mode="json")
            report.valid_rows.append(valid_dict)

            # Warn on unknown fields (not rejected, just flagged)
            if warn_on_unknown_fields:
                model_fields = set(model_cls.model_fields.keys())
                extra_fields = set(raw.keys()) - model_fields
                if extra_fields:
                    report.warnings.append(
                        f"Row {idx}: unknown fields ignored: {sorted(extra_fields)}"
                    )

        except ValidationError as exc:
            error_msg = "; ".join(
                f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}"
                for e in exc.errors()
            )
            report.invalid_rows.append(
                RowError(
                    table=table_name,
                    row_index=idx,
                    raw_data=raw,
                    error_message=error_msg,
                )
            )

    return report


def validate_csv_file(
    table_name: str,
    csv_path: Path,
    *,
    encoding: str = "utf-8",
) -> ValidationReport:
    """
    Read a CSV file and validate all rows against the schema for ``table_name``.

    Args:
        table_name: Target table name.
        csv_path: Path to the CSV file.
        encoding: File encoding (default utf-8).

    Returns:
        ValidationReport.
    """
    with csv_path.open(encoding=encoding, newline="") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)
    return validate_table(table_name, rows)


def validate_json_file(
    table_name: str,
    json_path: Path,
    *,
    encoding: str = "utf-8",
) -> ValidationReport:
    """
    Read a JSON file (list of objects) and validate all rows.

    Args:
        table_name: Target table name.
        json_path: Path to a JSON file containing a list of row objects.
        encoding: File encoding.

    Returns:
        ValidationReport.
    """
    with json_path.open(encoding=encoding) as fh:
        rows = json.load(fh)
    if not isinstance(rows, list):
        rows = [rows]
    return validate_table(table_name, rows)


def validate_all_tables(
    data_dir: Path,
    *,
    file_format: str = "csv",
) -> dict[str, ValidationReport]:
    """
    Validate all tables by scanning ``data_dir`` for files named
    ``<table_name>.csv`` (or ``.json``).

    Args:
        data_dir: Directory containing data files.
        file_format: "csv" or "json".

    Returns:
        Dict of table_name → ValidationReport. Only tables with files present
        are included.
    """
    reports: dict[str, ValidationReport] = {}

    for table_name in TABLE_MODELS:
        candidate = data_dir / f"{table_name}.{file_format}"
        if not candidate.exists():
            continue

        if file_format == "csv":
            report = validate_csv_file(table_name, candidate)
        elif file_format == "json":
            report = validate_json_file(table_name, candidate)
        else:
            raise ValueError(f"Unsupported file_format '{file_format}'")

        reports[table_name] = report

    return reports


def print_validation_summary(reports: dict[str, ValidationReport]) -> None:
    """Print a human-readable validation summary to stdout."""
    total_valid = sum(len(r.valid_rows) for r in reports.values())
    total_invalid = sum(len(r.invalid_rows) for r in reports.values())
    total_warnings = sum(len(r.warnings) for r in reports.values())

    print(f"\n{'='*60}")
    print("SAT-SA Ingestion Validation Report")
    print(f"{'='*60}")
    for report in reports.values():
        status = "✓" if not report.invalid_rows else "✗"
        print(f"  {status} {report.summary()}")
        for warn in report.warnings[:5]:   # Limit warning output
            print(f"      ⚠ {warn}")
        if len(report.warnings) > 5:
            print(f"      ⚠ ... and {len(report.warnings)-5} more warnings")
        for err in report.invalid_rows[:3]:  # Show first 3 errors
            print(f"      ✗ Row {err.row_index}: {err.error_message}")
        if len(report.invalid_rows) > 3:
            print(f"      ✗ ... and {len(report.invalid_rows)-3} more errors")

    print(f"{'='*60}")
    print(f"TOTAL: {total_valid} valid | {total_invalid} quarantined | {total_warnings} warnings")
    print(f"{'='*60}\n")
