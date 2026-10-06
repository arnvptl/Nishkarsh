.PHONY: setup demo test build clean serve lint

PYTHON := python
PIP := pip
NPM := npm
SATSA := satsa

DATA_DIR := data
DB_PATH := $(DATA_DIR)/satsa.db
AUDIT_DB := $(DATA_DIR)/audit.db
KEY_FILE := $(DATA_DIR)/demo.key
SEED := 42
ENTITIES := 40
ALERTS := 200000

# ─── Setup ──────────────────────────────────────────────────────────────────

setup:
	@echo "==> Installing Python dependencies..."
	$(PIP) install -e ".[dev]" --quiet
	@echo "==> Installing frontend dependencies..."
	cd ui && $(NPM) install --prefer-offline
	@echo "==> Creating data directory..."
	mkdir -p $(DATA_DIR)
	@echo "==> Setup complete. Run 'make demo' to generate data and start."

# ─── Demo ───────────────────────────────────────────────────────────────────

demo: demo-data demo-run demo-serve

demo-data:
	@echo "==> Generating synthetic demo data (seed=$(SEED), entities=$(ENTITIES), alerts=$(ALERTS))..."
	mkdir -p $(DATA_DIR)
	$(SATSA) gen --seed $(SEED) --entities $(ENTITIES) --alerts $(ALERTS) --out $(DATA_DIR)
	@echo "==> Ingesting data..."
	$(SATSA) ingest --data-dir $(DATA_DIR) --db-path $(DB_PATH) --key-file $(KEY_FILE)

demo-run:
	@echo "==> Running all detectors..."
	$(SATSA) run --db-path $(DB_PATH) --key-file $(KEY_FILE) --cycle-id "DEMO-$(SEED)"

demo-serve:
	@echo "==> Starting SAT-SA at http://127.0.0.1:8000 ..."
	@echo "==> Press Ctrl+C to stop."
	$(SATSA) serve --db-path $(DB_PATH) --key-file $(KEY_FILE)

# ─── Tests ──────────────────────────────────────────────────────────────────

test:
	@echo "==> Running all tests..."
	$(PYTHON) -m pytest tests/ -v --tb=short --cov=engine --cov=datagen --cov-report=term-missing

test-unit:
	$(PYTHON) -m pytest tests/unit/ -v --tb=short

test-integration:
	$(PYTHON) -m pytest tests/integration/ -v --tb=short

test-validation:
	@echo "==> Running validation harness (generates charts in docs/validation/)..."
	$(PYTHON) -m pytest tests/validation/ -v --tb=short -s

test-benchmarks:
	@echo "==> Running scalability benchmarks (100k, 1M records)..."
	$(PYTHON) -m pytest tests/validation/test_scalability.py -v --tb=short -s --benchmark-only

# ─── Build ──────────────────────────────────────────────────────────────────

build: build-ui build-exe

build-ui:
	@echo "==> Building React frontend..."
	cd ui && $(NPM) run build

build-exe:
	@echo "==> Building standalone executable with PyInstaller..."
	$(PYTHON) -m PyInstaller \
		--onefile \
		--name satsa \
		--collect-all duckdb \
		--add-data "ui/dist:ui/dist" \
		--add-data "config:config" \
		engine/cli.py
	@echo "==> Executable at dist/satsa"

# ─── Utilities ──────────────────────────────────────────────────────────────

clean:
	rm -rf $(DATA_DIR) dist/ build/ __pycache__ .pytest_cache .coverage
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null; true

lint:
	$(PYTHON) -m ruff check engine/ api/ datagen/ tests/ --fix

verify-audit:
	$(SATSA) verify-audit --audit-db $(AUDIT_DB)
