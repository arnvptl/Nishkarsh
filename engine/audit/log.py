"""
SAT-SA Append-Only, Hash-Chained Audit Log.

Maintains an immutable record of all examiner queries, detector runs,
and data exports. Each entry's SHA-256 hash includes the previous entry's
hash, creating a tamper-evident chain.

Storage: Append-only SQLite (not DuckDB — separate process, always writable).

Hash chain:
    entry_hash = SHA-256(prev_hash || timestamp || event_type || actor || details)

Verification:
    satsa verify-audit --audit-db audit.db
    Recomputes the full chain and reports the first broken link.

Legal note:
    The audit log records Analyst IDs (from case management data) and Examiner IDs.
    Processing Analyst IDs is authorized under Section 7, DPDP Act 2023
    (State functions and legal obligations). Examiner IDs are recorded for
    accountability of supervisory access.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    actor       TEXT NOT NULL,
    details     TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts);
CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log (event_type);
"""

# Genesis block: the hash "before" the first entry
_GENESIS_HASH = "0" * 64


class AuditLog:
    """
    Append-only, hash-chained audit log backed by SQLite.

    Thread-safety: NOT thread-safe. Use one instance per process.
    For multi-process environments, serialize writes through the FastAPI process.
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._con = sqlite3.connect(str(db_path))
        self._con.execute("PRAGMA journal_mode=WAL")  # Write-ahead logging for safety
        self._con.executescript(_SCHEMA)
        self._con.commit()
        logger.info(f"Audit log opened: {db_path}")

    def _get_last_hash(self) -> str:
        """Return the hash of the most recent entry, or genesis hash if empty."""
        row = self._con.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else _GENESIS_HASH

    @staticmethod
    def _compute_hash(
        prev_hash: str,
        ts: str,
        event_type: str,
        actor: str,
        details: str,
    ) -> str:
        """Compute SHA-256 hash for a new audit entry."""
        content = f"{prev_hash}|{ts}|{event_type}|{actor}|{details}"
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def log(
        self,
        event_type: str,
        actor: str,
        details: Any,
    ) -> int:
        """
        Append an entry to the audit log.

        Args:
            event_type: Category of event (e.g., "QUERY", "DETECTOR_RUN", "EXPORT").
            actor: Examiner or system identifier.
            details: Event details (dict or string; dicts are JSON-serialized).

        Returns:
            New audit log entry ID.
        """
        ts = datetime.utcnow().isoformat()
        if isinstance(details, dict):
            details_str = json.dumps(details, default=str)
        else:
            details_str = str(details)

        prev_hash = self._get_last_hash()
        entry_hash = self._compute_hash(prev_hash, ts, event_type, actor, details_str)

        self._con.execute(
            "INSERT INTO audit_log (ts, event_type, actor, details, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts, event_type, actor, details_str, prev_hash, entry_hash),
        )
        self._con.commit()

        row_id = self._con.execute(
            "SELECT last_insert_rowid()"
        ).fetchone()[0]
        logger.debug(f"Audit log entry {row_id}: {event_type} by {actor}")
        return row_id

    def log_query(self, actor: str, query_name: str, parameters: dict) -> int:
        """Log an examiner API query."""
        return self.log("QUERY", actor, {"query": query_name, "params": parameters})

    def log_detector_run(self, actor: str, cycle_id: str, entity_id: str, detectors: list[str]) -> int:
        """Log a detector run."""
        return self.log("DETECTOR_RUN", actor, {
            "cycle_id": cycle_id,
            "entity_id": entity_id,
            "detectors": detectors,
        })

    def log_export(self, actor: str, export_type: str, entity_id: str, n_rows: int) -> int:
        """Log a data export (manifest, report, etc.)."""
        return self.log("EXPORT", actor, {
            "export_type": export_type,
            "entity_id": entity_id,
            "n_rows": n_rows,
        })

    def verify_chain(self) -> tuple[bool, str]:
        """
        Verify the full audit log hash chain.

        Returns:
            (is_valid, message). If invalid, message includes the broken link ID.
        """
        rows = self._con.execute(
            "SELECT id, ts, event_type, actor, details, prev_hash, entry_hash "
            "FROM audit_log ORDER BY id ASC"
        ).fetchall()

        if not rows:
            return True, "Audit log is empty."

        expected_prev_hash = _GENESIS_HASH

        for row in rows:
            row_id, ts, event_type, actor, details, prev_hash, stored_hash = row

            # Verify prev_hash chain
            if prev_hash != expected_prev_hash:
                return False, (
                    f"Hash chain broken at entry ID={row_id}: "
                    f"expected prev_hash={expected_prev_hash[:16]}... "
                    f"got {prev_hash[:16]}..."
                )

            # Recompute entry hash
            expected_hash = self._compute_hash(prev_hash, ts, event_type, actor, details)
            if stored_hash != expected_hash:
                return False, (
                    f"Entry hash mismatch at ID={row_id}: "
                    f"stored={stored_hash[:16]}... computed={expected_hash[:16]}..."
                )

            expected_prev_hash = stored_hash

        return True, f"Audit log chain valid: {len(rows)} entries verified."

    def recent_entries(self, limit: int = 50) -> list[dict]:
        """Return the most recent audit log entries."""
        rows = self._con.execute(
            "SELECT id, ts, event_type, actor, details, entry_hash "
            "FROM audit_log ORDER BY id DESC LIMIT ?",
            [limit],
        ).fetchall()
        return [
            {
                "id": r[0],
                "ts": r[1],
                "event_type": r[2],
                "actor": r[3],
                "details": r[4],
                "entry_hash": r[5][:16] + "...",  # Truncated for display
            }
            for r in rows
        ]

    def close(self) -> None:
        """Close the SQLite connection."""
        self._con.close()

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
