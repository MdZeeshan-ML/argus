# A.R.G.U.S. — Automated Real-time Guardian for User Systems
# Copyright (C) 2026  MdZeeshan-ML | GPL v3
"""
Watchdog-based file monitor for Downloads and Desktop directories.

Puts a structured event dict into a queue.Queue on every new file creation.
The daemon (core/daemon.py) owns that queue and dispatches events to the extractor.
"""

import logging
import queue
import time
from datetime import datetime, timezone
from pathlib import Path

from watchdog.events import FileCreatedEvent, FileSystemEventHandler
from watchdog.observers import Observer

log = logging.getLogger(__name__)

# Extensions that indicate a file is still being written — skip until final rename
_TEMP_SUFFIXES = {".tmp", ".crdownload", ".part", ".partial", ".download", ".!ut"}

# Windows lock-file prefix (Office, etc.)
_TEMP_PREFIXES = ("~$",)


def _is_temp_file(path: Path) -> bool:
    """Return True if this looks like an in-progress download or lock file."""
    if path.suffix.lower() in _TEMP_SUFFIXES:
        return True
    if any(path.name.startswith(p) for p in _TEMP_PREFIXES):
        return True
    return False


class _FileCreatedHandler(FileSystemEventHandler):
    """Internal watchdog handler — converts OS events into queue entries."""

    def __init__(self, event_queue: queue.Queue) -> None:
        super().__init__()
        self._queue = event_queue

    def on_created(self, event: FileCreatedEvent) -> None:
        if event.is_directory:
            return

        path = Path(event.src_path)

        if _is_temp_file(path):
            log.debug("Skipping temp file: %s", path.name)
            return

        entry = {
            "source": "file_watcher",
            "path": str(path),
            "event_type": "created",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._queue.put(entry)
        log.info("New file detected: %s", path)

    def on_moved(self, event) -> None:
        """
        Browsers rename .crdownload → real filename when download completes.
        We catch that final rename here so we don't miss completed downloads.
        """
        if event.is_directory:
            return

        dest = Path(event.dest_path)

        if _is_temp_file(dest):
            return

        entry = {
            "source": "file_watcher",
            "path": str(dest),
            "event_type": "download_complete",  # rename from temp → real
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._queue.put(entry)
        log.info("Download complete (rename): %s", dest)


class FileWatcher:
    """
    Monitors one or more directories for new files.

    Usage:
        q = queue.Queue()
        watcher = FileWatcher(q, watch_dirs=[Path("C:/Users/me/Downloads")])
        watcher.start()
        ...
        watcher.stop()
    """

    def __init__(
        self,
        event_queue: queue.Queue,
        watch_dirs: list[Path] | None = None,
    ) -> None:
        self._queue = event_queue
        self._dirs = watch_dirs or _default_watch_dirs()
        self._observer = Observer()
        self._handler = _FileCreatedHandler(event_queue)

    def start(self) -> None:
        """Schedule all watch directories and start the observer thread."""
        scheduled = 0
        for d in self._dirs:
            if not d.exists():
                log.warning("Watch dir does not exist, skipping: %s", d)
                continue
            self._observer.schedule(self._handler, str(d), recursive=False)
            log.info("Watching: %s", d)
            scheduled += 1

        if scheduled == 0:
            log.error("No valid watch directories found — file watcher idle")
            return

        self._observer.start()
        log.info("FileWatcher started (%d dir(s))", scheduled)

    def stop(self) -> None:
        """Stop the observer thread cleanly."""
        self._observer.stop()
        self._observer.join()
        log.info("FileWatcher stopped")


def _default_watch_dirs() -> list[Path]:
    """Resolve Downloads and Desktop from the current user's home directory."""
    home = Path.home()
    return [
        home / "Downloads",
        home / "Desktop",
    ]


# ------------------------------------------------------------------
# Standalone test
# ------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(levelname)s %(name)s: %(message)s",
    )

    event_q: queue.Queue = queue.Queue()

    # Use a temp dir so the test is self-contained and reproducible
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        watcher = FileWatcher(event_q, watch_dirs=[tmp_path])
        watcher.start()

        # Give the observer thread a moment to initialise
        time.sleep(0.5)

        # Drop a test file — simulates a file arriving in Downloads
        test_file = tmp_path / "invoice_FINAL.exe"
        test_file.write_text("fake payload")
        print(f"Created: {test_file}")

        # Drop a temp file — should be silently ignored
        temp_file = tmp_path / "partial.crdownload"
        temp_file.write_text("in progress")
        print(f"Created (temp, expect no event): {temp_file}")

        # Wait for the handler to fire
        time.sleep(1.0)

        watcher.stop()

    # Drain the queue
    events = []
    while not event_q.empty():
        events.append(event_q.get_nowait())

    print(f"\nEvents captured: {len(events)}")
    for e in events:
        print(f"  {e}")

    assert len(events) == 1, f"Expected 1 event, got {len(events)}"
    assert events[0]["source"] == "file_watcher"
    assert events[0]["path"].endswith("invoice_FINAL.exe")
    assert events[0]["event_type"] == "created"

    print("\nTest passed.")
