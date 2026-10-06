"""
SAT-SA Engine Package.

Provides the complete analytics pipeline:
  - Schema validation (engine.schema)
  - Data ingestion with AES-256-GCM encryption (engine.ingestion)
  - Audit logging (engine.audit)
  - Layer 1 behavioral forensics (engine.layer1)
  - Integrity detectors G1-G6 (engine.detectors)
  - Risk scoring and stratified sampling (engine.scoring)
  - Two-tier thresholds and CERT-In tracker (engine.thresholds, engine.compliance)
"""
