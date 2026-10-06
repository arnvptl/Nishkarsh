"""
SAT-SA CLI Entry Point.

All commands call the engine directly (not through the API).
The API is only for the React frontend.

Commands:
    satsa gen       -- Generate synthetic data
    satsa gen-null  -- Generate null corpus for FPR computation
    satsa ingest    -- Ingest CSV data into DuckDB
    satsa run       -- Run all detectors for all entities
    satsa serve     -- Start the FastAPI + React UI server
    satsa verify-audit -- Verify audit log hash chain
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Optional

import typer

app = typer.Typer(
    name="satsa",
    help="SAT-SA: Supervisory Analytics Tool for SOC Assessment",
    add_completion=False,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


@app.command()
def gen(
    seed: int = typer.Option(42, help="RNG seed for full reproducibility"),
    entities: int = typer.Option(40, help="Number of entities (min 8)"),
    alerts: int = typer.Option(200_000, help="Target alert count"),
    out: Path = typer.Option(Path("data"), help="Output directory for CSV files"),
) -> None:
    """Generate synthetic demo data with injected anomalies."""
    from datagen.generator import generate

    typer.echo(f"Generating synthetic data: seed={seed}, entities={entities}, alerts={alerts}")
    stats = generate(seed=seed, n_entities=entities, n_alerts=alerts, out_dir=out)

    typer.echo("\n=== Generation Complete ===")
    for table, count in stats.items():
        if table not in ("anomaly_entities",):
            typer.echo(f"  {table}: {count:,}" if isinstance(count, int) else f"  {table}: {count}")
    typer.echo(f"\nAnomaly entities: {', '.join(stats.get('anomaly_entities', []))}")
    typer.echo(f"\nGround truth: {out}/ground_truth.json")
    typer.echo("\nNext: satsa ingest --data-dir data/ --db-path data/satsa.db --key-file data/demo.key")


@app.command("gen-null")
def gen_null(
    seed: int = typer.Option(100, help="RNG seed (use different from main gen)"),
    entities: int = typer.Option(20, help="Number of clean entities"),
    alerts: int = typer.Option(50_000, help="Target alert count"),
    out: Path = typer.Option(Path("data/null"), help="Output directory"),
) -> None:
    """Generate null corpus (no anomalies) for FPR computation."""
    from datagen.null_corpus import generate_null_corpus

    typer.echo(f"Generating null corpus: seed={seed}, entities={entities}, alerts={alerts}")
    stats = generate_null_corpus(seed=seed, n_entities=entities, n_alerts=alerts, out_dir=out)

    typer.echo("\n=== Null Corpus Complete ===")
    for table, count in stats.items():
        typer.echo(f"  {table}: {count:,}" if isinstance(count, int) else f"  {table}: {count}")


@app.command()
def ingest(
    data_dir: Path = typer.Option(Path("data"), help="Directory with CSV files"),
    db_path: Path = typer.Option(Path("data/satsa.db"), help="DuckDB database path"),
    key_file: Path = typer.Option(Path("data/demo.key"), help="AES-256 key file path"),
    generate_key: bool = typer.Option(False, help="Generate a new demo key if not found"),
    skip_validation: bool = typer.Option(False, help="Skip Pydantic schema validation"),
) -> None:
    """Ingest CSV data files into DuckDB (with AES-256-GCM key for production)."""
    from engine.ingestion.loader import open_connection, ingest_from_csv_dir
    from engine.ingestion.encryption import KeyProvider

    # Key management
    if generate_key or not key_file.exists():
        typer.echo(f"Generating new demo key at {key_file}")
        KeyProvider.generate_demo_key(key_file)

    typer.echo(f"Ingesting from {data_dir} → {db_path}")
    con = open_connection(db_path)

    try:
        counts = ingest_from_csv_dir(
            data_dir,
            con,
            validate=not skip_validation,
            abort_on_errors=False,
        )
    finally:
        con.close()

    typer.echo("\n=== Ingestion Complete ===")
    for table, count in counts.items():
        typer.echo(f"  {table}: {count:,} rows")

    typer.echo(f"\nNext: satsa run --db-path {db_path} --key-file {key_file} --cycle-id DEMO")


@app.command("run")
def run_detectors(
    db_path: Path = typer.Option(Path("data/satsa.db"), help="DuckDB database path"),
    key_file: Path = typer.Option(Path("data/demo.key"), help="AES-256 key file"),
    cycle_id: str = typer.Option("DEMO", help="Audit cycle identifier"),
    entity_id: Optional[str] = typer.Option(None, help="Run for specific entity only"),
    weights_path: Path = typer.Option(Path("config/weights.yaml"), help="Weights config"),
) -> None:
    """Run all detectors (G1-G6, L1) for all entities and compute risk scores."""
    from engine.ingestion.loader import open_connection
    from engine.detectors.g1_velocity import run_g1
    from engine.detectors.g2_severity import run_g2
    from engine.detectors.g3_temporal import run_g3
    from engine.detectors.g4_template import run_g4
    from engine.detectors.g5_workload import run_g5
    from engine.detectors.g6_silent_loop import run_g6
    from engine.layer1.sla import run_l1_sla
    from engine.layer1.negative_space import run_l1_negative_space
    from engine.scoring.risk_score import compute_risk_score
    from engine.scoring.sampling import generate_manifest
    from engine.audit.log import AuditLog
    import json, uuid
    from datetime import datetime

    audit_path = db_path.parent / "audit.db"
    audit = AuditLog(audit_path)

    con = open_connection(db_path)

    try:
        # Get entities to run
        if entity_id:
            entity_rows = con.execute(
                "SELECT entity_id FROM entities WHERE entity_id = ?", [entity_id]
            ).fetchall()
        else:
            entity_rows = con.execute("SELECT entity_id FROM entities").fetchall()

        entity_ids = [r[0] for r in entity_rows]
        typer.echo(f"Running detectors for {len(entity_ids)} entities, cycle: {cycle_id}")

        run_ts = datetime.utcnow()
        all_scores = []

        for eid in entity_ids:
            typer.echo(f"  Processing {eid}...", nl=False)

            results = []
            for detector_fn, args in [
                (run_g1, {"entity_id": eid, "run_ts": run_ts}),
                (run_g2, {"entity_id": eid, "run_ts": run_ts}),
                (run_g3, {"entity_id": eid, "run_ts": run_ts}),
                (run_g4, {"entity_id": eid, "run_ts": run_ts}),
                (run_g5, {"entity_id": eid, "run_ts": run_ts}),
                (run_g6, {"entity_id": eid, "run_ts": run_ts}),
                (run_l1_sla, {"entity_id": eid, "run_ts": run_ts}),
                (run_l1_negative_space, {"entity_id": eid, "run_ts": run_ts}),
            ]:
                try:
                    result = detector_fn(con, **args)
                    results.append(result)

                    # Store in DuckDB
                    result_dict = result.to_dict()
                    con.execute("""
                        INSERT OR REPLACE INTO detector_results
                        (id, detector_id, detector_name, entity_id, cycle_id, run_ts,
                         test_name, statistic, p_value, score, parameters, sample_size,
                         flag, threshold_tier, confidence_note, fi_value, result_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, [
                        f"{eid}-{result.detector_id}-{cycle_id}",
                        result.detector_id, result.detector_name, eid, cycle_id,
                        run_ts.isoformat(), result.test_name, result.statistic,
                        result.p_value, result.score,
                        json.dumps(result.parameters), result.sample_size,
                        result.flag, result.threshold_tier, result.confidence_note,
                        result.fi_value(), json.dumps(result_dict),
                    ])
                except Exception as exc:
                    typer.echo(f"\n    WARNING: {result.detector_id if 'result' in dir() else '?'} failed: {exc}")

            # Compute risk score
            risk = compute_risk_score(results, eid, cycle_id, weights_path=str(weights_path), run_ts=run_ts)
            all_scores.append(risk)

            con.execute("""
                INSERT OR REPLACE INTO risk_scores
                (id, entity_id, cycle_id, run_ts, score, band, weights_version, binary_mode, component_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                f"{eid}-{cycle_id}",
                eid, cycle_id, run_ts.isoformat(), risk.score, risk.band,
                risk.weights_version, risk.binary_mode,
                json.dumps(risk.component_scores),
            ])

            # Generate review manifest
            alert_rows = con.execute(
                "SELECT alert_id FROM alerts WHERE entity_id = ?", [eid]
            ).fetchall()
            all_alert_ids = [r[0] for r in alert_rows]
            manifest = generate_manifest(
                results, eid, cycle_id, all_alert_ids, seed=42, run_ts=run_ts
            )
            for row in manifest.rows:
                con.execute("""
                    INSERT OR REPLACE INTO review_manifests
                    (id, entity_id, cycle_id, run_ts, alert_id, stratum,
                     priority_rank, detector_score, sampled_by, seed)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, [
                    f"{eid}-{cycle_id}-{row.priority_rank}",
                    eid, cycle_id, run_ts.isoformat(), row.alert_id,
                    row.stratum, row.priority_rank, row.detector_score,
                    row.sampled_by, row.seed,
                ])

            n_flagged = sum(1 for r in results if r.flag)
            typer.echo(f" score={risk.score:.1f} [{risk.band}] flags={n_flagged}/8")
            audit.log_detector_run("CLI", cycle_id, eid, [r.detector_id for r in results])

        con.commit()

        typer.echo(f"\n=== Detector Run Complete ===")
        typer.echo(f"Entities processed: {len(entity_ids)}")
        if all_scores:
            scores_sorted = sorted(all_scores, key=lambda x: x.score, reverse=True)
            typer.echo(f"\nTop 5 Risk Entities:")
            for rs in scores_sorted[:5]:
                typer.echo(f"  {rs.entity_id}: {rs.score:.1f} [{rs.band}]")

        typer.echo(f"\nNext: satsa serve --db-path {db_path} --key-file {key_file}")

    finally:
        con.close()
        audit.close()


@app.command()
def serve(
    db_path: Path = typer.Option(Path("data/satsa.db"), help="DuckDB database path"),
    key_file: Path = typer.Option(Path("data/demo.key"), help="AES-256 key file"),
    host: str = typer.Option("127.0.0.1", help="Bind address (do not change for security)"),
    port: int = typer.Option(8000, help="Port"),
) -> None:
    """Start the SAT-SA API server and React UI."""
    import uvicorn

    typer.echo(f"Starting SAT-SA at http://{host}:{port}")
    typer.echo("Press Ctrl+C to stop.")

    # Set environment for the API to find the DB
    import os
    os.environ["SATSA_DB_PATH"] = str(db_path)
    os.environ["SATSA_KEY_FILE"] = str(key_file)

    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
    )


@app.command("verify-audit")
def verify_audit(
    audit_db: Path = typer.Option(Path("data/audit.db"), help="Audit SQLite database path"),
) -> None:
    """Verify the audit log hash chain integrity."""
    from engine.audit.log import AuditLog

    if not audit_db.exists():
        typer.echo(f"ERROR: Audit log not found at {audit_db}", err=True)
        raise typer.Exit(1)

    audit = AuditLog(audit_db)
    valid, message = audit.verify_chain()
    audit.close()

    if valid:
        typer.echo(f"✓ {message}")
    else:
        typer.echo(f"✗ CHAIN INTEGRITY FAILURE: {message}", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
