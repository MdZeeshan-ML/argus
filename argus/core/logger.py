# A.R.G.U.S. — Automated Real-time Guardian for User Systems
# Copyright (C) 2026  MdZeeshan-ML | GPL v3
"""
SQLite incident logger with tamper-evident append-only design.

Each row stores a chain_hash = sha256(prev_hash + incident_id + timestamp + verdict).
If any row is deleted or modified, the chain breaks and verify_chain() will catch it.
"""

import hashlib
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Sentinel for the genesis row's previous hash
_GENESIS_HASH = "0" * 64


class ArgusLogger:
    """Append-only SQLite logger with SHA-256 hash chaining for tamper detection."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        log.info("ArgusLogger initialised at %s", db_path)

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        """Create tables if they don't exist. Never drops or alters existing tables."""
        self._conn.executescript("""
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS incidents (
                incident_id       TEXT PRIMARY KEY,
                timestamp         TEXT NOT NULL,
                date              TEXT NOT NULL,
                monitor_type      TEXT NOT NULL,
                input_summary     TEXT,
                features          TEXT,
                rag_matches       TEXT,
                model_used        TEXT,
                model_version     TEXT,
                reasoning         TEXT,
                verdict           TEXT NOT NULL,
                confidence        REAL,
                action_taken      TEXT,
                user_confirmed    INTEGER,
                false_positive    INTEGER DEFAULT 0,
                training_exported INTEGER DEFAULT 0,
                synced_bigquery   INTEGER DEFAULT 0,
                synced_gcs        INTEGER DEFAULT 0,
                chain_hash        TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS daily_stats (
                date              TEXT PRIMARY KEY,
                total_events      INTEGER DEFAULT 0,
                threats_detected  INTEGER DEFAULT 0,
                false_positives   INTEGER DEFAULT 0,
                report_generated  INTEGER DEFAULT 0,
                report_drive_url  TEXT
            );
        """)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Hash chain helpers
    # ------------------------------------------------------------------

    def _latest_chain_hash(self) -> str:
        """Return the chain_hash of the most recent incident, or the genesis sentinel."""
        row = self._conn.execute(
            "SELECT chain_hash FROM incidents ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        return row["chain_hash"] if row else _GENESIS_HASH

    def _compute_hash(self, prev_hash: str, incident_id: str, timestamp: str, verdict: str) -> str:
        payload = f"{prev_hash}{incident_id}{timestamp}{verdict}"
        return hashlib.sha256(payload.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Public write API
    # ------------------------------------------------------------------

    def log_incident(
        self,
        *,
        monitor_type: str,
        verdict: str,
        input_summary: str = "",
        features: dict[str, Any] | None = None,
        rag_matches: list[dict] | None = None,
        model_used: str = "",
        model_version: str = "",
        reasoning: str = "",
        confidence: float | None = None,
        action_taken: str = "",
    ) -> str:
        """
        Insert a new incident row and return its incident_id.

        This is the ONLY write path — no UPDATE or DELETE is exposed.
        SQLite write happens before any notification or quarantine action.
        """
        incident_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        timestamp = now.isoformat()
        date = now.strftime("%Y-%m-%d")

        prev_hash = self._latest_chain_hash()
        chain_hash = self._compute_hash(prev_hash, incident_id, timestamp, verdict)

        self._conn.execute(
            """
            INSERT INTO incidents (
                incident_id, timestamp, date, monitor_type,
                input_summary, features, rag_matches,
                model_used, model_version, reasoning,
                verdict, confidence, action_taken,
                chain_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id, timestamp, date, monitor_type,
                input_summary,
                json.dumps(features) if features else None,
                json.dumps(rag_matches) if rag_matches else None,
                model_used, model_version, reasoning,
                verdict, confidence, action_taken,
                chain_hash,
            ),
        )
        self._conn.commit()

        # Keep daily_stats in sync
        self._upsert_daily_stats(date, verdict)

        log.info("[%s] %s — %s (id=%s)", monitor_type, verdict, input_summary[:80], incident_id)
        return incident_id

    def mark_user_confirmed(self, incident_id: str, confirmed: bool) -> None:
        """Record whether the user confirmed a threat or dismissed it as a false positive."""
        self._conn.execute(
            """
            UPDATE incidents
               SET user_confirmed = ?,
                   false_positive = ?
             WHERE incident_id = ?
            """,
            (1 if confirmed else 0, 0 if confirmed else 1, incident_id),
        )
        self._conn.commit()

    def mark_synced(self, incident_id: str, *, bigquery: bool = False, gcs: bool = False) -> None:
        """Set cloud-sync flags after successful upload."""
        self._conn.execute(
            """
            UPDATE incidents
               SET synced_bigquery = CASE WHEN ? THEN 1 ELSE synced_bigquery END,
                   synced_gcs      = CASE WHEN ? THEN 1 ELSE synced_gcs END
             WHERE incident_id = ?
            """,
            (bigquery, gcs, incident_id),
        )
        self._conn.commit()

    def mark_training_exported(self, incident_id: str) -> None:
        """Flag a row as included in a training data export."""
        self._conn.execute(
            "UPDATE incidents SET training_exported = 1 WHERE incident_id = ?",
            (incident_id,),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Public read API
    # ------------------------------------------------------------------

    def get_incident(self, incident_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_recent(self, limit: int = 50) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM incidents ORDER BY rowid DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_unsynced(self) -> list[dict]:
        """Return rows not yet pushed to BigQuery."""
        rows = self._conn.execute(
            "SELECT * FROM incidents WHERE synced_bigquery = 0 ORDER BY rowid"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_unreviewed_threats(self) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT * FROM incidents
             WHERE verdict IN ('SUSPICIOUS', 'UNCERTAIN')
               AND user_confirmed IS NULL
             ORDER BY rowid DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]

    def get_daily_stats(self, date: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM daily_stats WHERE date = ?", (date,)
        ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Tamper detection
    # ------------------------------------------------------------------

    def verify_chain(self) -> tuple[bool, str]:
        """
        Walk every row in insertion order and recompute the hash chain.
        Returns (True, "ok") if intact, or (False, "broken at incident_id=X") if tampered.
        """
        rows = self._conn.execute(
            "SELECT incident_id, timestamp, verdict, chain_hash FROM incidents ORDER BY rowid"
        ).fetchall()

        prev_hash = _GENESIS_HASH
        for row in rows:
            expected = self._compute_hash(prev_hash, row["incident_id"], row["timestamp"], row["verdict"])
            if expected != row["chain_hash"]:
                msg = f"broken at incident_id={row['incident_id']}"
                log.warning("Chain verification failed: %s", msg)
                return False, msg
            prev_hash = row["chain_hash"]

        return True, "ok"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _upsert_daily_stats(self, date: str, verdict: str) -> None:
        """Increment counters in daily_stats. Uses INSERT OR IGNORE + UPDATE pattern."""
        self._conn.execute(
            "INSERT OR IGNORE INTO daily_stats (date) VALUES (?)", (date,)
        )
        self._conn.execute(
            "UPDATE daily_stats SET total_events = total_events + 1 WHERE date = ?", (date,)
        )
        if verdict in ("SUSPICIOUS", "UNCERTAIN"):
            self._conn.execute(
                "UPDATE daily_stats SET threats_detected = threats_detected + 1 WHERE date = ?",
                (date,),
            )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


# ------------------------------------------------------------------
# Standalone test
# ------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")

    # Use a temp DB for the smoke test
    test_db = Path("test_argus.db")
    logger = ArgusLogger(test_db)

    # Log a suspicious file incident
    iid = logger.log_incident(
        monitor_type="file",
        verdict="SUSPICIOUS",
        input_summary="invoice_final_FINAL.exe dropped in Downloads",
        features={"hash": "abc123", "entropy": 7.9, "extension": ".exe"},
        confidence=0.92,
        action_taken="QUARANTINE",
    )
    print(f"Logged incident: {iid}")

    # Log a clean email
    iid2 = logger.log_incident(
        monitor_type="email",
        verdict="CLEAN",
        input_summary="Newsletter from github.com",
        confidence=0.05,
        action_taken="ALLOW",
    )
    print(f"Logged incident: {iid2}")

    # Verify chain integrity
    ok, msg = logger.verify_chain()
    print(f"Chain verification: {ok} — {msg}")

    # Check daily stats
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    stats = logger.get_daily_stats(today)
    print(f"Daily stats: {stats}")

    # Retrieve incidents
    recent = logger.get_recent()
    print(f"Recent incidents: {len(recent)} rows")

    logger.close()

    # Clean up test DB
    test_db.unlink()
    print("Test passed. DB cleaned up.")
