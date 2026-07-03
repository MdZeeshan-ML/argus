# A.R.G.U.S. — Automated Real-time Guardian for User Systems
# Copyright (C) 2026  MdZeeshan-ML | GPL v3
"""
Watchdog-based file monitor for Downloads (staging zone) and Desktop.

Architecture note:
  Downloads is the gate pipeline staging zone — files arriving there are
  processed through gate_keeper.py (Defender → VirusTotal → Static → Dynamic)
  before being moved to Downloads/Cleared/ with normal permissions.

  Desktop is monitored on the original pipeline (direct extractor → inference).

Events carry a 'staged' flag so the daemon routes them correctly:
  staged=True  → gate_keeper.process(event)
  staged=False → extractor.extract(event) → inference → logger
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
# FW-8: .opdownload (Opera), .crswap (Chrome swap file) added to cover common gaps
_TEMP_SUFFIXES = {
    ".tmp", ".crdownload", ".part", ".partial", ".download", ".!ut",
    ".opdownload", ".crswap",
}

# Windows lock-file prefix (Office, etc.)
_TEMP_PREFIXES = ("~$",)


def _is_temp_file(path: Path) -> bool:
    """Return True if this looks like an in-progress download or lock file."""
    if path.suffix.lower() in _TEMP_SUFFIXES:
        return True
    if any(path.name.startswith(p) for p in _TEMP_PREFIXES):
        return True
    return False


def _is_staged(path: Path, staging_dir: Path) -> bool:
    """True if path sits directly in the staging zone root (not a subdirectory)."""
    try:
        # Only the root of Downloads is staged — Cleared/ subdirectory is not.
        # If resolve() fails, fail closed: over-gating is safe; under-gating is a hole.
        return path.parent.resolve() == staging_dir.resolve()
    except OSError:
        return True


class _FileCreatedHandler(FileSystemEventHandler):
    """Internal watchdog handler — converts OS events into queue entries."""

    def __init__(self, event_queue: queue.Queue, staging_dir: Path) -> None:
        super().__init__()
        self._queue = event_queue
        self._staging_dir = staging_dir
        self._seen: dict[str, float] = {}

    def on_created(self, event: FileCreatedEvent) -> None:
        if event.is_directory:
            return

        path = Path(event.src_path)

        if _is_temp_file(path):
            log.debug("Skipping temp file: %s", path.name)
            return

        now = time.time()
        if str(path) in self._seen and now - self._seen[str(path)] < 1.0:
            return
        self._seen[str(path)] = now

        entry = {
            "source": "file_watcher",
            "path": str(path),
            "event_type": "created",
            "staged": _is_staged(path, self._staging_dir),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            self._queue.put_nowait(entry)
            log.info("File detected (%s): %s", "staged" if entry["staged"] else "direct", path)
        except queue.Full:
            log.warning("Queue full, event dropped, file: %s", path.name)

    def on_moved(self, event) -> None:
        """
        Browsers rename .crdownload → real filename when download completes.
        We catch the final rename here so we don't miss completed downloads.

        FW-9: Drop events where the SOURCE is inside Cleared/ — those files already
        passed all gates. We check src (not just dest) because a move FROM Cleared/
        back into the staging root would otherwise be incorrectly re-gated.
        """
        if event.is_directory:
            return

        src = Path(event.src_path)
        dest = Path(event.dest_path)

        if _is_temp_file(dest):
            return

        # FW-9: if the move originates from Cleared/, it already cleared all gates — drop it
        cleared_dir = self._staging_dir / "Cleared"
        try:
            if src.parent.resolve() == cleared_dir.resolve():
                log.debug("on_moved: src from Cleared/, dropping: %s", src.name)
                return
        except OSError:
            pass

        staged = _is_staged(dest, self._staging_dir)

        entry = {
            "source": "file_watcher",
            "path": str(dest),
            "event_type": "download_complete",
            "staged": staged,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            self._queue.put_nowait(entry)
            log.info("Download complete (%s): %s", "staged" if staged else "direct", dest)
        except queue.Full:
            log.warning("Queue full, event dropped, file: %s", dest.name)

        


class FileWatcher:
    """
    Monitors Downloads (gate pipeline staging zone) and Desktop (direct pipeline).

    Usage:
        q = queue.Queue()
        watcher = FileWatcher(q, staging_dir=Path.home() / "Downloads")
        watcher.start()
        ...
        watcher.stop()
    """

    def __init__(
        self,
        event_queue: queue.Queue,
        watch_dirs: list[Path] | None = None,
        staging_dir: Path | None = None,
    ) -> None:
        # FW-5: staging_dir from config so _is_staged agrees with gate_keeper's path
        self._staging_dir = staging_dir or (Path.home() / "Downloads")
        self._queue = event_queue
        self._dirs = watch_dirs or _default_watch_dirs()
        self._observer = Observer()
        self._handler = _FileCreatedHandler(event_queue, self._staging_dir)

    def start(self) -> None:
        """Schedule all watch directories and start the observer thread.

        FW-7: raises RuntimeError when no valid watch directory exists so the
        daemon fails loudly rather than running silently idle.
        """
        scheduled = 0
        for d in self._dirs:
            if not d.exists():
                log.warning("Watch dir does not exist, skipping: %s", d)
                continue
            # recursive=False: Downloads/Cleared/ files are already clean — don't re-process
            self._observer.schedule(self._handler, str(d), recursive=False)
            log.info("Watching: %s", d)
            scheduled += 1

        if scheduled == 0:
            raise RuntimeError(
                "No valid watch directories found — file watcher cannot start. "
                f"Check that at least one of these paths exists: {self._dirs}"
            )

        self._observer.start()
        log.info("FileWatcher started (%d dir(s))", scheduled)

    def stop(self) -> None:
        """Stop the observer thread cleanly.

        FW-6: join() has a 5s timeout so a hung observer never stalls shutdown.
        """
        self._observer.stop()
        self._observer.join(timeout=5)
        if self._observer.is_alive():
            log.warning("FileWatcher observer thread did not stop within 5s — may be hung")
        log.info("FileWatcher stopped")


def _default_watch_dirs() -> list[Path]:
    """Staging zone (Downloads) + direct pipeline (Desktop)."""
    home = Path.home()
    return [
        home / "Downloads",  # staged=True  → gate pipeline
        home / "Desktop",    # staged=False → direct pipeline
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
