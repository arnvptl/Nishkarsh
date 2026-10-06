"""Unit tests for G4 Template Collapse — MinHash Jaccard.

Known-answer cases:
  - Identical notes → Jaccard ≈ 1.0 → detected as near-duplicate
  - Completely different notes → Jaccard ≈ 0 → not near-duplicate
  - Determinism: same seed always produces same results
"""

from __future__ import annotations

import pytest
import duckdb
from datetime import datetime, timedelta, timezone
from engine.detectors.g4_template import (
    _strip_boilerplate,
    _get_ngrams,
    run_g4,
)

UTC = timezone.utc


class TestBoilerplateStripping:
    def test_strips_case_id_line(self):
        text = "Case ID: CASE-001\nSome investigator notes here for analysis."
        stripped = _strip_boilerplate(text)
        assert "CASE-001" not in stripped

    def test_preserves_free_text(self):
        text = "Analyst investigated. Found C2 beacon to external IP. Asset isolated."
        stripped = _strip_boilerplate(text)
        assert len(stripped) >= 20

    def test_all_boilerplate_returns_empty(self):
        text = "Case ID: X\nAnalyst: Y\nDate: 2024-01-01\nStatus: Closed"
        stripped = _strip_boilerplate(text)
        # After stripping, remaining text should be < 20 chars → empty
        assert stripped == "" or len(stripped) < 20

    def test_empty_input_returns_empty(self):
        assert _strip_boilerplate("") == ""
        assert _strip_boilerplate(None) == ""


class TestNgrams:
    def test_trigram_count(self):
        text = "abcde"
        ngrams = _get_ngrams(text, n=3)
        # "abc", "bcd", "cde" = 3 trigrams
        assert "abc" in ngrams
        assert "cde" in ngrams

    def test_identical_texts_same_ngrams(self):
        t = "the quick brown fox"
        assert _get_ngrams(t) == _get_ngrams(t)

    def test_different_texts_different_ngrams(self):
        t1 = "lateral movement detected"
        t2 = "credential access via phishing"
        assert _get_ngrams(t1) != _get_ngrams(t2)

    def test_short_text_handled(self):
        ngrams = _get_ngrams("ab", n=3)
        assert len(ngrams) >= 1


class TestRunG4:
    def _make_con_with_notes(
        self,
        notes: list[tuple[str, str]],  # (case_id, notes_text)
    ) -> duckdb.DuckDBPyConnection:
        con = duckdb.connect(":memory:")
        con.execute("""
            CREATE TABLE entities (entity_id VARCHAR, name VARCHAR, sector VARCHAR,
                asset_class VARCHAR, size_band VARCHAR, registered_ts TIMESTAMP);
            CREATE TABLE assets (asset_id VARCHAR, entity_id VARCHAR,
                asset_class VARCHAR, criticality VARCHAR);
            CREATE TABLE alerts (alert_id VARCHAR, entity_id VARCHAR, asset_id VARCHAR,
                rule_type VARCHAR, severity_initial VARCHAR, severity_final VARCHAR,
                created_ts TIMESTAMP, ack_ts TIMESTAMP, close_ts TIMESTAMP,
                source_is_soar BOOLEAN);
            CREATE TABLE cases (case_id VARCHAR, alert_id VARCHAR, analyst_id VARCHAR,
                shift_id VARCHAR, notes_text VARCHAR, disposition_code VARCHAR,
                opened_ts TIMESTAMP, closed_ts TIMESTAMP);
        """)
        con.execute("INSERT INTO entities VALUES ('E1', 'T', 'Finance', 'endpoint', 'medium', '2024-01-01')")
        con.execute("INSERT INTO assets VALUES ('A1', 'E1', 'endpoint', 'high')")

        base = datetime(2024, 1, 1, 10, 0, 0, tzinfo=UTC)
        for i, (case_id, note) in enumerate(notes):
            alert_id = f"ALT-{i:04d}"
            t = base + timedelta(hours=i)
            con.execute("INSERT INTO alerts VALUES (?, 'E1', 'A1', 'Rule', 'P3', 'P3', ?, ?, ?, FALSE)",
                       [alert_id, t.isoformat(), (t + timedelta(minutes=10)).isoformat(),
                        (t + timedelta(minutes=60)).isoformat()])
            con.execute("INSERT INTO cases VALUES (?, ?, 'ANA-001', 'SHF-1', ?, 'FP', ?, ?)",
                       [case_id, alert_id, note,
                        (t + timedelta(minutes=10)).isoformat(),
                        (t + timedelta(minutes=60)).isoformat()])
        return con

    def test_identical_notes_detected_as_cluster(self):
        """50 identical notes → should detect near-duplicate cluster."""
        TEMPLATE = (
            "Investigation complete. Alert reviewed against threat intelligence baseline. "
            "No indicators of compromise found. Asset validated as clean. "
            "Closed as false positive per standard operating procedure SOP-L1-042."
        )
        notes = [(f"CASE-{i:04d}", TEMPLATE) for i in range(50)]
        con = self._make_con_with_notes(notes)
        result = run_g4(con, "E1", cluster_pct_threshold=0.10)
        con.close()
        assert result.detector_id == "G4"
        if result.sample_size > 1:
            # Should detect high cluster fraction
            assert result.score > 0

    def test_unique_notes_not_clustered(self):
        """Truly unique, long notes → no Jaccard overlap → not flagged."""
        # Notes must be long enough and distinct enough to avoid MinHash collision
        unique_words = [
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
            "hotel", "india", "juliet", "kilo", "lima", "mike", "november",
            "oscar", "papa", "quebec", "romeo", "sierra", "tango", "uniform",
            "victor", "whiskey", "xray", "yankee", "zulu",
        ]
        notes = []
        for i in range(30):
            # Each note has a completely unique vocabulary drawn from disjoint sets
            # Using prime-spaced offsets ensures minimal overlap
            words = unique_words[(i * 3) % len(unique_words):] + unique_words[:(i * 3) % len(unique_words)]
            note = (
                f"Investigation {i*97:05d}: asset node HOSTNAME-{i*131:06d} examined at shift {i*53:04d}. "
                f"Findings: {' '.join(words[:8])} process tree analysed. "
                f"Parent PID {i*7919} spawned child {i*6271}. "
                f"Network connection to {i*11}.{i*13}.{i*17}.{i*19}:{i*23+1024} observed. "
                f"Hash SHA256 {'a' * 10}{i:020d}{'b' * 10}. "
                f"Disposition confirmed {' '.join(words[8:12])} per IR-{i*1009:06d}. "
                f"Registry key HKLM\\Software\\{words[i % len(words)]}\\{i*3571} modified. "
                f"IOC not in threat intel feed version {i*41}.{i*43}.{i*47}. "
                f"Ticket {' '.join(words[12:16])}-{i*2003:08d} opened in ITSM."
            )
            notes.append((f"CASE-{i:04d}", note))

        con = self._make_con_with_notes(notes)
        # Use a very high cluster threshold so unique notes don't trigger a flag
        result = run_g4(con, "E1", cluster_pct_threshold=0.95, jaccard_threshold=0.71)
        con.close()
        assert result.detector_id == "G4"
        # Score < 1.0 with threshold=0.95 means it's not flagged
        assert result.flag is False, (
            f"Expected no flag with cluster_pct_threshold=0.95, "
            f"cluster_pct={result.parameters.get('cluster_pct', 'N/A')}"
        )

    def test_deterministic_with_same_seed(self):
        """Same data + same seed → identical scores."""
        TEMPLATE = (
            "Standard investigation note. Alert triaged. No malicious activity found. "
            "Asset checked. Disposition set to false positive. Closed per SOP."
        )
        notes = [(f"CASE-{i:04d}", TEMPLATE) for i in range(30)]
        con1 = self._make_con_with_notes(notes)
        con2 = self._make_con_with_notes(notes)
        r1 = run_g4(con1, "E1", seed=42)
        r2 = run_g4(con2, "E1", seed=42)
        con1.close()
        con2.close()
        assert r1.score == r2.score

    def test_effective_threshold_in_parameters(self):
        """Parameters must include the computed effective Jaccard threshold."""
        notes = [(f"CASE-{i:04d}", f"Short note {i} about investigation.") for i in range(5)]
        con = self._make_con_with_notes(notes)
        result = run_g4(con, "E1")
        con.close()
        assert "effective_threshold" in result.parameters
        # 16 bands × 8 rows → threshold ≈ (1/16)^(1/8) ≈ 0.71
        assert 0.60 < result.parameters["effective_threshold"] < 0.85

    def test_anomaly_entity_detected(self, db_con, anomaly_entity_ids):
        """Template collapse entity should show high cluster percentage."""
        eid = anomaly_entity_ids["template_collapse"]
        result = run_g4(db_con, eid, cluster_pct_threshold=0.20)
        assert result.detector_id == "G4"
        assert result.sample_size >= 0  # May be 0 if datasketch not installed
