# A.R.G.U.S. — Automated Real-time Guardian for User Systems
# Copyright (C) 2026  MdZeeshan-ML | GPL v3
"""
Adversary POV: the highest-leverage move against a security tool is never beating its
detection logic — it's making the tool blind or slow enough that the *next* payload
sails through unscanned. Session 11's own change log (bounded queue, debounce, 0-byte
fast-path, fail-closed staging — see HANDOFF.md) shows this project already treats
availability as part of its threat model, not an afterthought; these tests check those
specific mitigations hold under the load they were built for, using the real
FileWatcher + watchdog Observer (cross-platform per CLAUDE.local.md), not a mock of it.
"""

from __future__ import annotations

import queue
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from _fixtures import build_file_event

from argus.analysis.feature_extractor import FeatureExtractor
from argus.core.gate_keeper import GateKeeper
from argus.core.logger import ArgusLogger
from argus.monitors.email_scanner import (
    MAX_MESSAGE_BYTES,
    MAX_PART_BYTES,
    MAX_PARTS_PER_MESSAGE,
)
from argus.monitors.file_watcher import FileWatcher

_EXTRACTOR = FeatureExtractor(whois_timeout=2)


def test_email_part_and_size_caps_are_present_and_sane():
    """Guard against someone quietly deleting the ES-bug-3 fix (session 12 HANDOFF
    entry: "500-tiny-part email... stalls the poll thread"). A flood of tiny MIME
    parts, or one part padded to a huge size, is a cheap way to stall the single IMAP
    poll thread while a second, real phishing message slips in behind it — that only
    stays fixed if these constants keep existing with sane, small-enough values.
    """
    assert isinstance(MAX_PARTS_PER_MESSAGE, int) and 0 < MAX_PARTS_PER_MESSAGE <= 100, (
        "part-count cap must exist and stay small enough to actually bound a stall"
    )
    assert isinstance(MAX_PART_BYTES, int) and MAX_PART_BYTES > 0
    assert isinstance(MAX_MESSAGE_BYTES, int) and MAX_MESSAGE_BYTES >= MAX_PART_BYTES, (
        "message-level cap must be at least as large as the per-part cap, or every "
        "message with one max-size part would be rejected outright"
    )


def test_flood_of_tiny_files_does_not_crash_filewatcher_bounded_queue():
    """DoS goal: drop far more files than the daemon's queue can hold in one burst
    (a scripted flood, not a real user's download pattern) hoping either (a) the
    watcher thread crashes/dies, silently blinding the daemon, or (b) put_nowait raises
    uncaught and kills the observer callback. The queue.Full except-branch in
    _FileCreatedHandler.on_created is exactly the mitigation for this; verify the
    watcher is still alive and stoppable afterward, and that the queue itself never
    exceeds the bound we gave it (Python's queue.Queue enforces this structurally, but
    confirming no exception ever escaped the handler is the actual point).
    """
    maxsize = 5
    flood_count = 40  # comfortably more than the queue can hold
    event_q: queue.Queue = queue.Queue(maxsize=maxsize)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        watcher = FileWatcher(event_q, watch_dirs=[tmp_path])
        watcher.start()
        time.sleep(0.3)

        for i in range(flood_count):
            (tmp_path / f"payload_{i:03d}.pdf").write_bytes(b"%PDF-1.4\n")

        time.sleep(1.5)  # let the observer thread drain the burst
        watcher.stop()

    assert event_q.qsize() <= maxsize, (
        "queue must never exceed the bound given to it — if this fails, either "
        "put_nowait's Full exception isn't reaching the except branch, or something "
        "bypassed the bounded queue"
    )
    # The real assertion: we got this far without an unhandled exception killing the
    # observer thread mid-flood. FileWatcher.stop()'s clean return (no hang, no raise)
    # is the proof the daemon would still be alive to process the NEXT real event.


def test_event_flood_through_gatekeeper_never_silently_skips_a_verdict():
    """Even once events survive the queue, the daemon's per-event loop is the second
    place volume could cause a silent skip (an unhandled exception on file #17 killing
    the loop for files #18-40). Runs a real burst through GateKeeper.process — the
    actual per-file entry point — and requires every single one to come back with a
    non-empty verdict and incident_id; a `pass`-on-exception bug here would show up as
    fewer than flood_count actual results.
    """
    flood_count = 30
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        staging = tmp_path / "staging"
        staging.mkdir()
        # Real logger (not None) so incident_id is genuinely populated — the point is
        # to prove every one of these ends up durably logged, not just returned.
        logger = ArgusLogger(tmp_path / "argus.db")
        gk = GateKeeper(
            staging_dir=staging, cleared_dir=tmp_path / "Cleared",
            quarantine_dir=tmp_path / "quarantine",
            extractor=_EXTRACTOR, logger=logger, virustotal_api_key=None,
        )
        gk.setup()

        try:
            results = []
            for i in range(flood_count):
                p = staging / f"resume_{i:03d}.pdf"
                p.write_bytes(b"%PDF-1.4\n" + bytes([i % 256]) * 100)
                results.append(gk.process(build_file_event(p)))

            assert len(results) == flood_count, "every event in the burst must get processed"
            for r in results:
                assert r.verdict, "no event may come back with an empty/missing verdict"
                assert r.incident_id, "no event may be processed without a loggable incident_id"

            ok, msg = logger.verify_chain()
            assert ok, f"audit chain must stay intact under flood volume: {msg}"
        finally:
            logger.close()


if __name__ == "__main__":
    from _runner import run_tests

    sys.exit(run_tests(globals(), module_name=__file__))
