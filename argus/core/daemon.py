# A.R.G.U.S. — Automated Real-time Guardian for User Systems
# Copyright (C) 2026  MdZeeshan-ML | GPL v3
"""
Core daemon — wires all subsystems, manages thread lifecycle, routes events.

This module is the Orchestration layer of the DOE framework.
It starts workers, routes events to the correct pipeline, and manages shutdown.
All analysis logic lives in gate_keeper, feature_extractor, and inference modules.

Threading model:
  Main thread      — blocks in wait_for_shutdown(); pystray takes this slot in Phase 4
  file-watcher     — watchdog Observer thread (managed by FileWatcher internally)
  email-scanner    — IMAP poll thread (managed by EmailScanner internally)
  event-processor  — reads event_queue, dispatches to gate_keeper or extractor+logger
  cloud-sync-stub  — drains sync_queue (Phase 7 will add real BigQuery/GCS writes)
"""

import logging
import logging.handlers
import os
import queue
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

from argus.analysis.feature_extractor import FeatureExtractor
from argus.core.gate_keeper import GateKeeper, heuristic_verdict
from argus.core.logger import ArgusLogger
from argus.monitors.email_scanner import EmailScanner
from argus.monitors.file_watcher import FileWatcher

log = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Logging setup
# ------------------------------------------------------------------

def _setup_logging() -> None:
    """Configure console + rotating file logging before anything else starts."""
    log_dir = Path.home() / ".argus" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(formatter)

    file_handler = logging.handlers.RotatingFileHandler(
        log_dir / "argus.log",
        maxBytes=5_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(console)
    root.addHandler(file_handler)


# ------------------------------------------------------------------
# Config loading
# ------------------------------------------------------------------

def _load_config() -> dict:
    """
    Load configuration from .env and environment variables.
    All paths have safe defaults under ~/.argus so the daemon can start
    even with a minimal .env. Optional features (email, VT) warn and skip.
    """
    load_dotenv()

    home = Path.home()
    argus_home = Path(os.getenv("ARGUS_HOME", str(home / ".argus")))

    return {
        "argus_home":       argus_home,
        "db_path":          Path(os.getenv("SQLITE_DB_PATH",  str(argus_home / "argus.db"))),
        "quarantine_dir":   Path(os.getenv("QUARANTINE_DIR",  str(argus_home / "quarantine"))),
        "chroma_db_dir":    Path(os.getenv("CHROMA_DB_DIR",   str(argus_home / "chroma_db"))),
        "staging_dir":      home / "Downloads",
        "cleared_dir":      home / "Downloads" / "Cleared",
        "email_state_path": argus_home / "email_state.json",

        # Email (optional — scanner disabled if blank)
        "imap_server":     os.getenv("IMAP_SERVER",                  "imap.gmail.com"),
        "imap_port":       int(os.getenv("IMAP_PORT",                "993")),
        "email_address":   os.getenv("EMAIL_ADDRESS",                ""),
        "email_password":  os.getenv("EMAIL_PASSWORD",               ""),
        "email_poll_mins": int(os.getenv("EMAIL_POLL_INTERVAL_MINUTES", "15")),

        # Inference (optional, Phase 2)
        "ollama_base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        "ollama_model":    os.getenv("OLLAMA_MODEL",    "qwen3:1.7b"),
        "nim_api_key":     os.getenv("NIM_API_KEY",     ""),
        "default_mode":    os.getenv("DEFAULT_MODE",    "local"),

        # Gate 1.5 (optional)
        "virustotal_key":  os.getenv("VIRUSTOTAL_API_KEY", ""),
    }


# ------------------------------------------------------------------
# Startup checks
# ------------------------------------------------------------------

def _check_ollama(base_url: str) -> bool:
    """Ping Ollama. Logs warning and returns False if unreachable — non-fatal."""
    try:
        # Strip /v1 suffix to reach the Ollama REST API
        api_url = base_url.rstrip("/").removesuffix("/v1")
        resp = httpx.get(f"{api_url}/api/version", timeout=3.0)
        if resp.status_code == 200:
            version = resp.json().get("version", "?")
            log.info("Ollama reachable: version=%s at %s", version, api_url)
            return True
    except Exception as e:
        log.warning(
            "Ollama unreachable at %s (%s) — inference will log as UNANALYZED until available",
            base_url, e,
        )
    return False


# ------------------------------------------------------------------
# Event routing helpers
# ------------------------------------------------------------------

def _build_summary(event: dict, features: dict) -> str:
    """One-line incident summary for SQLite input_summary column."""
    source = event.get("source", "")

    if source == "email_scanner":
        # email_scanner already builds a good summary string
        return event.get("summary", "email event")

    # file_watcher event
    name  = features.get("file_name", "unknown")
    size  = features.get("file_size_bytes")
    size_s = f"{size:,}B" if size else "?"
    zone  = "staged" if event.get("staged") else "desktop"
    return f"{name} ({size_s}, {zone})"


def _dispatch(
    event: dict,
    gate_keeper: GateKeeper,
    extractor: FeatureExtractor,
    logger: ArgusLogger,
    sync_queue: queue.Queue,
) -> None:
    """
    Route one event to the appropriate pipeline.

    staged file  → gate_keeper (handles its own SQLite write)
    desktop file → extractor → heuristics → logger
    email        → extractor → heuristics → logger
    """
    source = event.get("source", "")
    staged = event.get("staged", False)

    # ----- Downloads staging zone: four-gate pipeline -----
    if source == "file_watcher" and staged:
        result = gate_keeper.process(event)
        if result.incident_id:
            try:
                sync_queue.put_nowait(result.incident_id)
            except queue.Full:
                pass
        return

    # ----- Desktop file or email: direct pipeline -----
    monitor_type = "file" if source == "file_watcher" else "email"

    features = extractor.extract(event)

    # Apply heuristics (reuses gate_keeper logic, extended for email)
    verdict, confidence = heuristic_verdict(features, monitor_type=monitor_type)

    summary = _build_summary(event, features)
    action = "LOGGED" if verdict == "UNANALYZED" else "FLAGGED"

    try:
        incident_id = logger.log_incident(
            monitor_type=monitor_type,
            verdict=verdict,
            input_summary=summary,
            features=features,
            confidence=confidence,
            action_taken=action,
        )
        if incident_id:
            try:
                sync_queue.put_nowait(incident_id)
            except queue.Full:
                pass
        log.info("Logged %s event: verdict=%s  summary=%s", monitor_type, verdict, summary[:80])
    except Exception:
        log.exception("Logger failed for %s event: %s", monitor_type, summary[:80])


# ------------------------------------------------------------------
# Worker threads
# ------------------------------------------------------------------

def _event_processor(
    event_queue: queue.Queue,
    gate_keeper: GateKeeper,
    extractor: FeatureExtractor,
    logger: ArgusLogger,
    sync_queue: queue.Queue,
    shutdown_event: threading.Event,
) -> None:
    """
    Thread function: reads events from the shared queue and dispatches them.

    Drains the queue completely before exiting on shutdown — guarantees
    every event that entered the queue before stop() was called gets processed.
    One Defender scan can block this thread for up to 60s; that's expected.
    """
    log.info("Event processor started")

    while True:
        try:
            event = event_queue.get(timeout=0.5)
        except queue.Empty:
            # Nothing in queue — exit only if shutdown was requested
            if shutdown_event.is_set():
                break
            continue

        try:
            _dispatch(event, gate_keeper, extractor, logger, sync_queue)
        except Exception:
            log.exception(
                "Event processor: unhandled error (source=%s, path=%s)",
                event.get("source"),
                event.get("path", event.get("summary", "?")),
            )
        finally:
            event_queue.task_done()

    log.info("Event processor stopped (queue drained)")


def _sync_worker(sync_queue: queue.Queue, shutdown_event: threading.Event) -> None:
    """
    Thread function: cloud sync stub.
    Drains the sync_queue without doing anything — Phase 7 replaces this with
    real BigQuery streaming inserts and GCS log rotation.
    """
    log.info("Cloud sync stub started (Phase 7 will add real sync)")

    while True:
        try:
            incident_id = sync_queue.get(timeout=1.0)
            log.debug("Sync stub: queued for cloud sync: incident_id=%s", incident_id)
            sync_queue.task_done()
        except queue.Empty:
            if shutdown_event.is_set():
                break

    log.info("Cloud sync stub stopped")


# ------------------------------------------------------------------
# Daemon class
# ------------------------------------------------------------------

class ArgusDaemon:
    """
    Manages the full A.R.G.U.S. subsystem lifecycle.

    Usage:
        daemon = ArgusDaemon(config)
        daemon.start()
        daemon.wait_for_shutdown()   # blocks — KeyboardInterrupt exits
        daemon.stop()
    """

    def __init__(self, config: dict) -> None:
        self._cfg = config
        self._shutdown = threading.Event()
        self._event_queue: queue.Queue = queue.Queue()
        self._sync_queue: queue.Queue = queue.Queue()

        # All handles set in start()
        self._logger: ArgusLogger | None = None
        self._extractor: FeatureExtractor | None = None
        self._gate_keeper: GateKeeper | None = None
        self._file_watcher: FileWatcher | None = None
        self._email_scanner: EmailScanner | None = None
        self._processor_thread: threading.Thread | None = None
        self._sync_thread: threading.Thread | None = None

    def start(self) -> None:
        """Initialize all subsystems and launch background threads."""
        cfg = self._cfg

        # -- Directory structure --
        for d in [cfg["argus_home"], cfg["quarantine_dir"], cfg["chroma_db_dir"], cfg["cleared_dir"]]:
            d.mkdir(parents=True, exist_ok=True)

        # -- SQLite logger (must succeed — no daemon without logging) --
        self._logger = ArgusLogger(cfg["db_path"])
        self._logger.log_incident(
            monitor_type="system",
            verdict="CLEAN",
            input_summary="A.R.G.U.S. daemon started",
            action_taken="NONE",
        )

        # -- Feature extractor --
        self._extractor = FeatureExtractor()

        # -- Gate keeper (applies Downloads ACL) --
        self._gate_keeper = GateKeeper(
            staging_dir=cfg["staging_dir"],
            cleared_dir=cfg["cleared_dir"],
            quarantine_dir=cfg["quarantine_dir"],
            extractor=self._extractor,
            logger=self._logger,
            virustotal_api_key=cfg["virustotal_key"] or None,
        )
        self._gate_keeper.setup()

        # -- File watcher --
        self._file_watcher = FileWatcher(self._event_queue)
        self._file_watcher.start()

        # -- Email scanner (optional) --
        if cfg["email_address"] and cfg["email_password"]:
            self._email_scanner = EmailScanner(
                event_queue=self._event_queue,
                imap_server=cfg["imap_server"],
                imap_port=cfg["imap_port"],
                email_address=cfg["email_address"],
                password=cfg["email_password"],
                poll_interval_minutes=cfg["email_poll_mins"],
                state_path=cfg["email_state_path"],
            )
            self._email_scanner.start()
        else:
            log.warning(
                "EMAIL_ADDRESS or EMAIL_PASSWORD not set in .env — email scanner disabled"
            )

        # -- Background worker threads --
        self._processor_thread = threading.Thread(
            target=_event_processor,
            args=(
                self._event_queue,
                self._gate_keeper,
                self._extractor,
                self._logger,
                self._sync_queue,
                self._shutdown,
            ),
            name="event-processor",
            daemon=False,  # non-daemon so it can drain the queue before process exits
        )

        self._sync_thread = threading.Thread(
            target=_sync_worker,
            args=(self._sync_queue, self._shutdown),
            name="cloud-sync-stub",
            daemon=False,
        )

        self._processor_thread.start()
        self._sync_thread.start()

        log.info("A.R.G.U.S. is running — Ctrl+C to stop")

    def wait_for_shutdown(self) -> None:
        """
        Block the main thread until KeyboardInterrupt or external shutdown signal.
        pystray (Phase 4) will take over this main-thread slot.
        """
        try:
            while not self._shutdown.is_set():
                self._shutdown.wait(timeout=1.0)
        except KeyboardInterrupt:
            log.info("Keyboard interrupt — initiating graceful shutdown")

    def stop(self) -> None:
        """
        Graceful shutdown sequence:
        1. Signal shutdown
        2. Stop monitors (they stop writing to the queue)
        3. Processor drains the queue and exits
        4. Sync thread drains its queue and exits
        5. Close SQLite
        """
        log.info("A.R.G.U.S. shutting down...")
        self._shutdown.set()

        # Stop monitors first so no new events enter the queue
        if self._file_watcher:
            self._file_watcher.stop()

        if self._email_scanner:
            self._email_scanner.stop()

        # Wait for processor to drain (up to 90s: 60s Defender + 30s buffer)
        if self._processor_thread and self._processor_thread.is_alive():
            self._processor_thread.join(timeout=90)
            if self._processor_thread.is_alive():
                log.warning("Event processor did not exit within 90s — may have abandoned items")

        # Sync thread is fast once queue is empty
        if self._sync_thread and self._sync_thread.is_alive():
            self._sync_thread.join(timeout=10)
            if self._sync_thread.is_alive():
                log.warning("Sync thread did not exit cleanly")

        # Close DB last — processor must be done writing before we close
        if self._logger:
            self._logger.log_incident(
                monitor_type="system",
                verdict="CLEAN",
                input_summary="A.R.G.U.S. daemon stopped cleanly",
                action_taken="NONE",
            )
            self._logger.close()

        log.info("A.R.G.U.S. stopped")

    def inject_event(self, event: dict) -> None:
        """
        Inject a synthetic event directly into the processing queue.
        Used only in testing — not part of normal operation.
        """
        self._event_queue.put(event)

    def wait_for_queue_drain(self, timeout: float = 10.0) -> bool:
        """Block until event_queue is fully processed. Test helper."""
        try:
            self._event_queue.join()
            return True
        except Exception:
            return False


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def main() -> None:
    """CLI entry point — called by `argus` command (pyproject.toml scripts)."""
    _setup_logging()
    log.info("A.R.G.U.S. — Automated Real-time Guardian for User Systems")
    log.info("Starting up at %s", datetime.now(timezone.utc).isoformat())

    config = _load_config()
    _check_ollama(config["ollama_base_url"])

    daemon = ArgusDaemon(config)
    daemon.start()
    daemon.wait_for_shutdown()
    daemon.stop()


# ------------------------------------------------------------------
# Standalone test
# ------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile
    import time

    _setup_logging()
    print("=== A.R.G.U.S. Daemon Smoke Test ===\n")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        staging  = tmp_path / "staging"
        cleared  = tmp_path / "Cleared"
        quarantine = tmp_path / "quarantine"
        staging.mkdir()

        config = {
            "argus_home":       tmp_path / ".argus",
            "db_path":          tmp_path / ".argus" / "test.db",
            "quarantine_dir":   quarantine,
            "chroma_db_dir":    tmp_path / "chroma",
            "staging_dir":      staging,
            "cleared_dir":      cleared,
            "email_state_path": tmp_path / "email_state.json",
            "imap_server":      "imap.gmail.com",
            "imap_port":        993,
            "email_address":    "",   # no email credentials → scanner disabled
            "email_password":   "",
            "email_poll_mins":  15,
            "ollama_base_url":  "http://localhost:11434/v1",
            "ollama_model":     "qwen3:1.7b",
            "nim_api_key":      "",
            "default_mode":     "local",
            "virustotal_key":   "",   # no VT key → Gate 1.5 skipped
        }

        daemon = ArgusDaemon(config)
        daemon.start()
        print("Test 1: daemon started — PASSED")

        # --- Test 2: inject a synthetic Desktop file event ---
        pdf_data = b'\x25\x50\x44\x46\x2d'  # %PDF-
        pdf_path = tmp_path / "test_document.pdf"
        pdf_path.write_bytes(pdf_data)

        desktop_event = {
            "source": "file_watcher",
            "path": str(pdf_path),
            "event_type": "created",
            "staged": False,  # Desktop → direct pipeline
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        daemon.inject_event(desktop_event)

        # --- Test 3: inject a synthetic email event ---
        email_event = {
            "source": "email_scanner",
            "event_type": "new_email",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": "from=suspicious.ru | reply_to=evil.ru [MISMATCH] | spf=fail",
            "metadata": {
                "from_domain": "suspicious.ru",
                "reply_to_domain": "evil.ru",
                "reply_to_mismatch": True,
                "spf": "fail",
                "dkim": "fail",
                "dmarc": "fail",
                "html_only": True,
                "has_external_links": True,
                "links": ["http://paypal-login.evil.ru/steal"],
                "has_attachments": False,
                "_sensitive_fields": ["subject"],
            },
        }
        daemon.inject_event(email_event)

        # --- Test 4: inject a staged file event (goes through gate_keeper) ---
        staged_path = staging / "invoice.pdf"
        # MZ header in .pdf extension — should be flagged by heuristic
        staged_path.write_bytes(b'\x4d\x5a\x90\x00' + b'\x00' * 50)

        staged_event = {
            "source": "file_watcher",
            "path": str(staged_path),
            "event_type": "created",
            "staged": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        daemon.inject_event(staged_event)

        # Wait for all three events to be processed
        drained = daemon.wait_for_queue_drain(timeout=90)
        print(f"Test 2/3/4: queue drained={drained} — ", end="")

        # Verify SQLite entries (skip startup/shutdown system rows)
        rows = daemon._logger.get_recent(limit=10)
        non_system = [r for r in rows if r["monitor_type"] != "system"]
        print(f"non-system rows in DB: {len(non_system)}")

        for r in non_system:
            print(f"  [{r['monitor_type']}] verdict={r['verdict']}  summary={r['input_summary'][:60]}")

        assert len(non_system) >= 3, f"Expected at least 3 non-system rows, got {len(non_system)}"
        print("Test 2/3/4: PASSED")

        # --- Test 5: graceful shutdown ---
        daemon.stop()
        time.sleep(0.5)

        processor_alive = daemon._processor_thread.is_alive() if daemon._processor_thread else False
        sync_alive      = daemon._sync_thread.is_alive()      if daemon._sync_thread      else False
        print(f"Test 5: processor alive={processor_alive}, sync alive={sync_alive}")
        assert not processor_alive, "Processor thread should have stopped"
        assert not sync_alive,      "Sync thread should have stopped"
        print("Test 5: PASSED")

    print("\n=== All tests passed ===")
