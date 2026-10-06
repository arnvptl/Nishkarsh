#!/usr/bin/env python3
"""
Demo E2E script:
  1. Generate synthetic dataset
  2. Encrypt CSVs
  3. Ingest -> DuckDB
  4. Run all detectors
  5. Compute risk scores + sampling
  6. Verify audit log
  7. Print summary report

Usage:
    python demo.py [--key-file KEY_FILE] [--data-dir DATA_DIR] [--cycle-id CYCLE]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is on sys.path
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))


def banner(msg: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print('='*60)


def run_demo(
    key_file: Path,
    data_dir: Path,
    cycle_id: str,
    n_entities: int,
    seed: int,
) -> None:
    banner("Phase 0 -- Generate Synthetic Dataset")
    from datagen.generator import generate
    t0 = time.time()
    records = generate(
        n_entities=n_entities,
        seed=seed,
        out_dir=data_dir,
        n_alerts=5000,
    )
    print(f"  Generated {sum(len(v) if isinstance(v, list) else int(v) for v in records.values()):,} records "
          f"across {len(records)} tables in {time.time()-t0:.1f}s")

    banner("Phase 1 -- Encrypt CSVs")
    from engine.ingestion.encryption import encrypt_file, FileKeyProvider

    # Generate or load key
    if not key_file.exists():
        key = os.urandom(32)
        key_file.write_bytes(key)
        try:
            key_file.chmod(0o600)
        except Exception:
            pass  # Windows may not support chmod
        print(f"  Key generated -> {key_file}")
    else:
        key = key_file.read_bytes()
        print(f"  Key loaded from {key_file}")

    key_provider = FileKeyProvider(key_file)
    KNOWN_TABLES = {"entities", "assets", "alerts", "cases", "escalations",
                   "severity_transitions", "workflow_effort", "ground_truth"}
    encrypted_files = []
    for csv_path in sorted(data_dir.glob("*.csv")):
        # Skip any stray temp files (stem won't match a known table name)
        if csv_path.stem not in KNOWN_TABLES:
            print(f"  Skipping non-table file: {csv_path.name}")
            continue
        enc_path = csv_path.with_suffix(".csv.enc")
        encrypt_file(csv_path, enc_path, key_provider)
        csv_path.unlink()   # Remove plaintext CSV after encryption
        encrypted_files.append(enc_path)
        print(f"  Encrypted: {enc_path.name}")

    banner("Phase 2 -- Ingest -> DuckDB")
    from engine.ingestion.loader import open_connection, ingest_from_csv_dir
    from engine.ingestion.encryption import decrypted_temp_file
    import contextlib

    db_path = data_dir / "satsa.db"
    if db_path.exists():
        db_path.unlink()
    con = open_connection(db_path)

    # Decrypt each encrypted CSV to a temp file and ingest
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_csv_dir = Path(tmpdir)
        for enc_path in encrypted_files:
            with decrypted_temp_file(enc_path, key_provider, suffix=".csv") as plain_path:
                import shutil
                shutil.copy(plain_path, tmp_csv_dir / enc_path.stem)  # e.g. alerts.csv
        ingest_from_csv_dir(tmp_csv_dir, con, validate=True, abort_on_errors=False)

    print(f"  DuckDB ready at: {db_path}")

    # Count tables
    for table in ["entities", "assets", "alerts", "severity_transitions", "cases",
                  "workflow_effort", "escalations"]:
        try:
            n = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            print(f"    {table}: {n:,} rows")
        except Exception:
            pass

    banner("Phase 3-4 -- Validate Schema + Run Detectors")
    # Note: validate_all_tables works on a directory of CSV files; schema already
    # validated during ingest_from_csv_dir. Just print row counts from DuckDB.
    for table in ["entities", "assets", "alerts", "severity_transitions", "cases",
                  "workflow_effort", "escalations"]:
        try:
            n = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            print(f"  {table}: {n:,} rows")
        except Exception:
            print(f"  {table}: not found")

    from engine.detectors.g1_velocity import run_g1
    from engine.detectors.g2_severity import run_g2
    from engine.detectors.g3_temporal import run_g3
    from engine.detectors.g4_template import run_g4
    from engine.detectors.g5_workload import run_g5
    from engine.detectors.g6_silent_loop import run_g6
    from engine.layer1.sla import run_l1_sla
    from engine.layer1.negative_space import run_l1_negative_space

    entities_list = con.execute("SELECT entity_id FROM entities LIMIT 50").fetchall()
    entities_list = [r[0] for r in entities_list]

    exemptions_path = str(ROOT / "config" / "known_noisy_exemptions.yaml")

    print(f"  Running detectors on {len(entities_list)} entities...")
    all_results: dict[str, list] = {}
    t0 = time.time()
    for eid in entities_list:
        results = []
        try: results.append(run_g1(con, eid))
        except Exception as e: print(f"    G1 error {eid}: {e}")
        try: results.append(run_g2(con, eid))
        except Exception as e: print(f"    G2 error {eid}: {e}")
        try: results.append(run_g3(con, eid))
        except Exception as e: print(f"    G3 error {eid}: {e}")
        try: results.append(run_g4(con, eid))
        except Exception as e: print(f"    G4 error {eid}: {e}")
        try: results.append(run_g5(con, eid))  # uses config/capacity.yaml default
        except Exception as e: print(f"    G5 error {eid}: {e}")
        try: results.append(run_g6(con, eid, lookback_days=1200, exemptions_path=exemptions_path))
        except Exception as e: print(f"    G6 error {eid}: {e}")
        try: results.append(run_l1_sla(con, eid))
        except Exception as e: print(f"    L1_SLA error {eid}: {e}")
        try: results.append(run_l1_negative_space(con, eid))
        except Exception as e: print(f"    L1_NS error {eid}: {e}")
        all_results[eid] = results

    n_flagged = sum(1 for res_list in all_results.values() for r in res_list if r.flag)
    print(f"  Detectors complete in {time.time()-t0:.1f}s. {n_flagged} total flags.")

    banner("Phase 5 -- Risk Scoring + Sampling")
    from engine.scoring.risk_score import compute_risk_score, persist_results
    from engine.scoring.sampling import generate_manifest

    weights_path = str(ROOT / "config" / "weights.yaml")
    all_alerts = [r[0] for r in con.execute("SELECT alert_id FROM alerts").fetchall()]

    scores = []
    manifests = []
    for eid, results in all_results.items():
        risk = compute_risk_score(results, eid, cycle_id, weights_path=weights_path)
        scores.append(risk)
        mf = generate_manifest(results, eid, cycle_id, all_alerts,
                               examiner_budget=50, seed=42)
        manifests.append(mf)
        persist_results(con, risk, results, mf)

    scores.sort(key=lambda r: r.score, reverse=True)
    print(f"  Top 5 entities by risk score:")
    for rs in scores[:5]:
        print(f"    {rs.entity_id}: {rs.score:.1f} [{rs.band}]")

    banner("Phase 6 -- Audit Log Verification")
    from engine.audit.log import AuditLog
    audit_path = data_dir / "audit.db"
    with AuditLog(audit_path) as audit:
        audit.log("DEMO_RUN", "system",
                  {"cycle_id": cycle_id, "n_entities": len(entities_list),
                   "n_flags": n_flagged, "ts": datetime.now(timezone.utc).isoformat()})
        valid, msg = audit.verify_chain()
        print(f"  Audit chain: {'VALID ✓' if valid else 'BROKEN ✗'} -- {msg}")

    banner("Phase 7 -- Summary")
    print(f"  Cycle ID:         {cycle_id}")
    print(f"  Entities scored:  {len(scores)}")
    print(f"  CRITICAL band:    {sum(1 for r in scores if r.band == 'CRITICAL')}")
    print(f"  HIGH band:        {sum(1 for r in scores if r.band == 'HIGH')}")
    print(f"  MEDIUM band:      {sum(1 for r in scores if r.band == 'MEDIUM')}")
    print(f"  LOW band:         {sum(1 for r in scores if r.band == 'LOW')}")
    print(f"  Total flags:      {n_flagged}")
    print(f"  DB path:          {db_path}")
    print(f"\n  ✓ Demo complete. Run: SATSA_DB_PATH={db_path} satsa serve")
    print()

    con.close()


def main():
    parser = argparse.ArgumentParser(description="SAT-SA Demo E2E Script")
    parser.add_argument("--key-file", default="demo_key.bin", type=Path)
    parser.add_argument("--data-dir", default="data", type=Path)
    parser.add_argument("--cycle-id", default="DEMO")
    parser.add_argument("--n-entities", default=25, type=int)
    parser.add_argument("--seed", default=42, type=int)
    args = parser.parse_args()

    args.data_dir.mkdir(parents=True, exist_ok=True)

    run_demo(
        key_file=args.key_file,
        data_dir=args.data_dir,
        cycle_id=args.cycle_id,
        n_entities=args.n_entities,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
