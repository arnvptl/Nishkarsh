# SAT-SA — Supervisory Analytics Tool for SOC Assessment

**Version 1.0.0 | NCIIPC | Air-gapped deployment**

SAT-SA is a risk-based sampling and prioritisation engine that detects statistical anomalies consistent with metric gaming (Goodhart's Law) in SOC operations. Rather than rigid compliance checklists, it identifies *execution gaps* and *negative space* in SOC data, and produces a prioritised **review manifest** for expert examiners.

---

## Quick Start

```bash
# 1. Install (Python 3.11+)
pip install -e ".[dev]"

# 2. Run the full demo (generates data, encrypts, ingests, runs detectors)
python demo.py --n-entities 25 --seed 42

# 3. Start the API + UI
$env:SATSA_DB_PATH="data/satsa.db"
uvicorn api.main:app --host 127.0.0.1 --port 8000

# 4. Open browser at http://localhost:8000
```

---

## Architecture

```
sat-sa/
├── engine/
│   ├── schema/          # Pydantic models + validator (quarantine on error)
│   ├── ingestion/       # AES-256-GCM file decryption + DuckDB loader
│   ├── detectors/       # G1-G6 detectors (returns DetectorResult)
│   ├── layer1/          # L1-SLA, L1-NegativeSpace
│   ├── scoring/         # Risk score aggregation + stratified sampling
│   ├── audit/           # SHA-256 hash-chained SQLite audit log
│   └── cli.py           # Typer CLI
├── api/                 # FastAPI REST API
│   └── routers/         # entities, detectors, sampling, audit, compliance
├── ui/                  # React + Vite frontend (dark mode, recharts)
│   └── dist/            # Production build (served by FastAPI)
├── datagen/             # Synthetic dataset generator with seeded anomalies
├── tests/unit/          # 106 passing unit tests
├── config/              # weights.yaml, capacity.yaml, exemptions.yaml
├── docs/security.md     # Encryption design & key management
├── demo.py              # E2E demo script
└── satsa.spec           # PyInstaller single-binary build spec
```

---

## Detectors

| ID | Name | Method | Weight |
|---|---|---|---|
| **G2** | Severity Laundering | Bowker's test (Monte Carlo for small cells) | 35 |
| **G1** | Velocity Distortion | KDE + bimodality test | 25 |
| **G3** | Temporal Clustering | Normalized Shannon entropy | 15 |
| **G4** | Template Collapse | MinHash Jaccard LSH (128 perm, 16×8) | 10 |
| **G5** | Workload Inconsistency | Active min / net shift capacity | 10 |
| **G6** | Silent Loop | Recurrent fast-close disposition recurrence | 10 |
| **L1-SLA** | SLA Violations | Breach rate vs configurable thresholds | 10 |
| **L1-NS** | Negative Space | Alert volume vs cohort P5 baseline | 10 |

**Score** = min(100, Σ w_i × F_i) where F_i ∈ [0, 1] (graded by p-value/effect size).

**Risk bands**: CRITICAL (>80) · HIGH (>60) · MEDIUM (>30) · LOW (≤30)

---

## Sampling

The review manifest uses **stratified sampling** (80/20 split):
- 80% of examiner budget from **flagged alerts** (sorted by detector score)
- 20% from **uniform random** (guarantees representation of non-flagged activity)

Seed is fixed per cycle for **full reproducibility** and audit traceability.

---

## Security

See [`docs/security.md`](docs/security.md) for full details.

| Property | Value |
|---|---|
| Encryption | AES-256-GCM (file-level) |
| Audit log | SHA-256 hash-chained SQLite |
| DuckDB | In-process (plaintext DB — OS disk encryption required) |
| Network | Binds to `127.0.0.1` by default (air-gapped) |

---

## Running Tests

```bash
pytest tests/unit/ -v          # 106 tests, ~12s
pytest tests/unit/ --cov=engine --cov-report=term-missing
```

---

## Building the Binary

```bash
# Build UI first
cd ui && npm run build && cd ..

# Install PyInstaller
pip install pyinstaller==6.11.1

# Build single-file executable
pyinstaller satsa.spec

# Output: dist/satsa.exe (Windows) or dist/satsa (Linux)
```

> **Note on diptest**: `diptest` is a compiled C extension used by G3 for bimodality testing.
> If not installed, G3 falls back to a pure-Python approximation with a `LOW_CONFIDENCE` note.
> Install with `pip install diptest` before building the binary to include the C extension.

---

## CLI Reference

```bash
satsa gen       --seed 42 --entities 25 --out data/   # Generate synthetic data
satsa ingest    --data-dir data/ --db data/satsa.db    # Ingest + validate
satsa run       --db data/satsa.db --cycle DEMO        # Run all detectors
satsa serve     --db data/satsa.db --port 8000         # Start API + UI
satsa verify    --db data/satsa.db                     # Verify audit chain
```

---

## Limitations and Disclaimers

- SAT-SA outputs are **probabilistic signals for supervisory prioritisation**, not findings of misconduct.
- All findings must be assessed by qualified examiners in context.
- Processing of analyst identifiers is authorised under Section 7 of DPDP Act 2023 (State functions). See [`docs/security.md`](docs/security.md).
- CERT-In compliance windows are tracked separately and are **not** incorporated into the SOC performance risk score.

---

## Citation

If using SAT-SA for research or policy development, please cite the technical report:
> *SAT-SA: Supervisory Analytics Tool for SOC Assessment — Risk-Based Sampling for Regulatory Oversight of Critical Information Infrastructure Protection Centres*, NCIIPC, 2024.
