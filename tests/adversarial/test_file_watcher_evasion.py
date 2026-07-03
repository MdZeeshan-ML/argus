# A.R.G.U.S. — Automated Real-time Guardian for User Systems
# Copyright (C) 2026  MdZeeshan-ML | GPL v3
"""
Adversary POV: don't fight gate_keeper's scoring at all — arrange for file_watcher to
never generate an event in the first place. If nothing gets queued, nothing gets
scanned, and the rest of the pipeline (however good) never runs. file_watcher.py is
fully built and cross-platform (CLAUDE.local.md: "Portable — dev + test on Linux"), so
this uses the real watchdog Observer, not a mock of it.
"""

from __future__ import annotations

import queue
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from argus.monitors.file_watcher import FileWatcher, _is_temp_file


def _drain(q: "queue.Queue") -> list[dict]:
    events = []
    while not q.empty():
        events.append(q.get_nowait())
    return events


def test_tmp_suffix_permanently_evades_created_event():
    """REAL FINDING: _is_temp_file treats any '.tmp'-suffixed file as an in-progress
    browser download and on_created skips it outright — no event, ever. Nothing
    requires the file to actually BE a partial download. A payload delivered directly
    as 'invoice_receipt.tmp' (e.g. a direct download link, not a browser's
    partial-then-rename flow) and never renamed sits in Downloads, complete and
    malicious, completely invisible to file_watcher for as long as it keeps that name.
    See FINDINGS.md #3.
    """
    event_q: "queue.Queue" = queue.Queue()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        watcher = FileWatcher(event_q, watch_dirs=[tmp_path])
        watcher.start()
        time.sleep(0.3)

        # Final, complete, fully-malicious-in-a-real-scenario payload — just named
        # like an in-progress download. Never touched/renamed after this.
        payload = tmp_path / "invoice_receipt.tmp"
        payload.write_bytes(b"\x4d\x5a\x90\x00" + b"\x00" * 200)  # MZ/PE bytes

        time.sleep(1.0)
        watcher.stop()

    events = _drain(event_q)
    assert events == [], (
        f"expected zero events for a '.tmp'-named payload that is never renamed, "
        f"got {events!r} — if this now fails, the evasion gap has been closed, "
        f"update FINDINGS.md #3"
    )
    assert _is_temp_file(payload) is True  # confirms *why*: it matched the ignore-list


def test_recursive_false_misses_files_in_extracted_subdirectory():
    """CONFIRMS FW-1 (CRITICAL, already tracked in HANDOFF.md, parked — not a new
    discovery). FileWatcher.start() schedules watch_dirs with recursive=False. A file
    created inside a NEW subdirectory of Downloads — exactly what happens when a
    victim extracts a downloaded 'portfolio_samples.zip' — is invisible to the watcher
    entirely, the same way a '.tmp' name is: zero events, not a filtered event. This
    test exists as a reproducible regression-guard for when FW-1 is reopened.
    See FINDINGS.md #4.
    """
    event_q: "queue.Queue" = queue.Queue()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        watcher = FileWatcher(event_q, watch_dirs=[tmp_path])
        watcher.start()
        time.sleep(0.3)

        # Simulates "victim extracted the zip we sent them" — a fresh subdirectory
        # appearing under the watched root, with the real payload inside it.
        extracted = tmp_path / "portfolio_samples"
        extracted.mkdir()
        payload = extracted / "resume_cover_letter.exe"
        payload.write_bytes(b"\x4d\x5a\x90\x00" + b"\x00" * 200)

        time.sleep(1.0)
        watcher.stop()

    events = _drain(event_q)
    assert events == [], (
        f"expected zero events for a file inside a newly-created subdirectory "
        f"(recursive=False) — got {events!r}. If this now fails, FW-1 has been fixed; "
        f"update FINDINGS.md #4 and HANDOFF.md"
    )


def test_debounce_collapses_rapid_duplicate_create_events_for_the_same_path():
    """Not an evasion of detection — a check that a burst of duplicate OS-level
    'created' events for the identical path (flaky filesystem notifications, or an
    attacker deliberately re-triggering the same path to try to double up entries in
    the bounded queue faster than one slot per real file) collapses to one queued
    event, not N. _FileCreatedHandler's 1-second '_seen' debounce is the mitigation;
    confirms it actually fires under a rapid repeat, not just in theory.
    """
    event_q: "queue.Queue" = queue.Queue()
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        watcher = FileWatcher(event_q, watch_dirs=[tmp_path])
        watcher.start()
        time.sleep(0.3)

        payload = tmp_path / "contract.pdf"
        payload.write_bytes(b"%PDF-1.4\n")
        # Immediately touch it again (mtime bump) to try to provoke a second
        # watchdog 'created'-shaped notification for the same path within the
        # 1-second debounce window.
        payload.write_bytes(b"%PDF-1.4\nmore\n")

        time.sleep(1.2)
        watcher.stop()

    events = _drain(event_q)
    paths = [e["path"] for e in events]
    assert paths.count(str(payload)) <= 1, (
        f"debounce should collapse rapid duplicate events for the same path into at "
        f"most one queue entry, got {paths.count(str(payload))}: {events!r}"
    )


if __name__ == "__main__":
    from _runner import run_tests

    sys.exit(run_tests(globals(), module_name=__file__))
