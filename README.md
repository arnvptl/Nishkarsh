# SAT-SA — Supervisory Analytics Tool for SOC Assessment

**Version 1.0.0 | NCIIPC | Air-gapped deployment**

SAT-SA is a risk-based sampling and prioritisation engine designed to detect statistical anomalies consistent with "metric gaming" (Goodhart's Law) in SOC operations. Rather than relying on rigid compliance checklists, it highlights *execution gaps* and *negative space* in SOC data, automatically producing a prioritised **review manifest** for expert NCIIPC examiners.

---

## Table of Contents
1. [Features](#features)
2. [Architecture](#architecture)
3. [Setup & Installation Instructions](#setup--installation-instructions)
4. [Usage Guide](#usage-guide)
5. [Detectors Overview](#detectors-overview)
6. [Security & Compliance](#security--compliance)
7. [Building for Production (Air-Gapped)](#building-for-production-air-gapped)

---

## Features
* **AES-256-GCM Secure Ingestion:** Natively parses symmetrically encrypted `.csv.enc` archives, keeping intermediate temp files exclusively in restricted memory spaces.
* **DuckDB Analytics Engine:** Blazing fast, in-process analytical SQL processing capable of ingesting and querying millions of rows of SOC data instantly.
* **Cryptographic Audit Log:** All operations (detector runs, data loads, manifest exports) are recorded in an immutable SQLite SHA-256 hash-chain.
* **Modern Dashboard:** React (Vite) + Recharts frontend with a sleek, light-theme interface for data visualization and entity drill-downs.

---

## Setup & Installation Instructions

Follow these step-by-step instructions to get SAT-SA running on your local machine or a cloud virtual machine.

### Prerequisites
* **Python 3.11+** (64-bit required)
* **Node.js (v18+)** (for building the React UI)
* **Git** (for version control)
* **C++ Build Tools** (Optional but recommended for `diptest` and `datasketch` performance on Windows/Linux)

### 1. Clone the Repository
```bash
git clone https://github.com/arnvptl/Nishkarsh.git
cd Nishkarsh
```

### 2. Set up the Python Virtual Environment
We strongly recommend using a virtual environment to prevent dependency conflicts.
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python Dependencies
Install the engine and its dependencies in editable mode:
```bash
pip install -e ".[dev]"
```
*(Note: If you encounter an error with `diptest` failing to compile, ensure you have C++ build tools installed, or safely ignore it—the engine will fall back to a pure-Python approximation).*

### 4. Build the React Dashboard
The FastAPI backend serves the React application directly from the `ui/dist` folder. You must build this folder first:
```bash
cd ui
npm install
npm run build
cd ..
```

---

## Usage Guide

You can run the application either using the **Interactive Demo Script** (which handles everything automatically) or manually via the **CLI**.

### Option A: The Full E2E Demo (Recommended for Testing)
The repository includes a powerful data generator that creates realistic, synthetic SOC datasets mimicking severity laundering and SLA gaming.

Run the demo script from the root folder:
```bash
python demo.py --n-entities 15 --seed 42
```
**What this does:**
1. Generates synthetic data for 15 entities.
2. Encrypts the CSVs via AES-256-GCM.
3. Ingests them into DuckDB (`data/satsa.db`).
4. Runs the G1-G6 detectors and calculates risk scores.
5. Generates the final review manifests.

Once the demo completes, start the web server:
```bash
# Windows PowerShell
$env:SATSA_DB_PATH="data/satsa.db"
uvicorn api.main:app --host 127.0.0.1 --port 8000

# Linux / Mac
SATSA_DB_PATH="data/satsa.db" uvicorn api.main:app --host 127.0.0.1 --port 8000
```
Open **http://127.0.0.1:8000** in your web browser to view the Dashboard!

### Option B: Using the CLI
For production use where data is provided externally, use the python module directly:
```bash
python -m engine.cli ingest --data-dir data/ --db data/satsa.db    # Ingest + validate
python -m engine.cli run --db data/satsa.db --cycle DEMO           # Run all detectors
python -m engine.cli verify-audit --db data/satsa.db               # Verify the Audit Chain
python -m engine.cli serve --db data/satsa.db --port 8000          # Start the Dashboard
```

---

## Detectors Overview

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

## Security & Compliance
* **Data Privacy:** Processing of analyst identifiers is authorised under Section 7 of the DPDP Act 2023 (State functions). See `docs/security.md`.
* **Air-Gapped:** The application binds exclusively to `127.0.0.1` by default to prevent external network access on the examiner's machine.
* **Audit Trails:** Every action is securely hashed in an SQLite database using SHA-256 chaining.

---

## Building for Production (Air-Gapped)
To package SAT-SA into a **single, portable executable** that requires NO Python or Node installation on the target machine (perfect for air-gapped NCIIPC examiner laptops):

1. Ensure the UI is built (`npm run build` in the `ui` folder).
2. Install PyInstaller:
   ```bash
   pip install pyinstaller==6.11.1
   ```
3. Run the provided PyInstaller spec file:
   ```bash
   pyinstaller satsa.spec
   ```
4. The standalone binary will be generated at `dist/satsa.exe` (Windows) or `dist/satsa` (Linux). You can transfer this single file via a secure USB to the air-gapped environment.

---

## Tests
The engine includes a robust test suite covering edge cases and mathematical logic:
```bash
pytest tests/unit/ -v
pytest tests/unit/ --cov=engine --cov-report=term-missing
```

---

## Citation
If using SAT-SA for research or policy development, please cite the technical report:
> *SAT-SA: Supervisory Analytics Tool for SOC Assessment — Risk-Based Sampling for Regulatory Oversight of Critical Information Infrastructure Protection Centres*, NCIIPC, 2024.
