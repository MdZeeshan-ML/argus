# A.R.G.U.S. — Automated Real-time Guardian for User Systems
# Copyright (C) 2026  MdZeeshan-ML | GPL v3
"""
Adversary POV: we already have code execution (some payload got through, or the
victim ran something dumb on their own). Now our goal shifts from "get past the
guardian" to "make the guardian lie" — erase or corrupt the evidence, or make it
blind. This is the group that specifically wants ARGUS's own audit trail broken,
because a freelancer who trusts a clean incident log won't go looking for us.
"""

from __future__ import annotations

import inspect
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from argus.analysis.feature_extractor import FeatureExtractor
from argus.core.gate_keeper import GateKeeper
from argus.core.logger import ArgusLogger
from argus.monitors.file_watcher import _is_staged

_EXTRACTOR = FeatureExtractor(whois_timeout=2)


def _new_logger(tmp_path: Path) -> ArgusLogger:
    return ArgusLogger(tmp_path / "argus.db")


def _new_gatekeeper(tmp_path: Path, logger: ArgusLogger | None) -> GateKeeper:
    staging = tmp_path / "staging"
    staging.mkdir()
    gk = GateKeeper(
        staging_dir=staging, cleared_dir=tmp_path / "Cleared",
        quarantine_dir=tmp_path / "quarantine",
        extractor=_EXTRACTOR, logger=logger, virustotal_api_key=None,
    )
    gk.setup()
    return gk


def test_log_tamper_detected_by_hash_chain_update():
    """We got write access to argus.db (it's just a SQLite file on disk) after the
    fact and want to flip a SUSPICIOUS row to CLEAN so a manual review never flags it.
    A raw UPDATE breaks the sha256(prev_hash+id+ts+verdict) chain — verify_chain must
    catch it, because catching this is the entire stated purpose of the chain design.
    """
    with tempfile.TemporaryDirectory() as tmp:
        logger = _new_logger(Path(tmp))
        try:
            iid1 = logger.log_incident(
                monitor_type="file", verdict="SUSPICIOUS",
                input_summary="invoice_FINAL_v3.exe", confidence=0.9,
            )
            logger.log_incident(monitor_type="file", verdict="CLEARED",
                                 input_summary="resume.pdf", confidence=0.02)
            ok, msg = logger.verify_chain()
            assert ok, f"chain must be intact before tampering: {msg}"

            # Attacker: rewrite the verdict directly via SQL, bypassing log_incident
            # entirely (log_incident is documented as "the ONLY write path" — we're
            # deliberately going around it, since that's what disk-level access buys).
            logger._conn.execute(
                "UPDATE incidents SET verdict = 'CLEARED' WHERE incident_id = ?", (iid1,)
            )
            logger._conn.commit()

            ok2, msg2 = logger.verify_chain()
            assert ok2 is False, "hash chain must detect a tampered verdict"
            assert iid1 in msg2, f"break must be attributable to the tampered row: {msg2}"
        finally:
            logger.close()


def test_log_row_deletion_detected():
    """Same goal, blunter tool: DELETE the incriminating row outright instead of
    editing it, hoping a gap in the log is less suspicious than a contradiction. The
    chain links each row to the previous row's hash, so removing a row from the middle
    must still break verification for everything after it — deletion isn't a safer
    tamper than modification.
    """
    with tempfile.TemporaryDirectory() as tmp:
        logger = _new_logger(Path(tmp))
        try:
            logger.log_incident(monitor_type="file", verdict="CLEARED", input_summary="a")
            iid2 = logger.log_incident(monitor_type="file", verdict="SUSPICIOUS", input_summary="b")
            logger.log_incident(monitor_type="file", verdict="CLEARED", input_summary="c")

            logger._conn.execute("DELETE FROM incidents WHERE incident_id = ?", (iid2,))
            logger._conn.commit()

            ok, msg = logger.verify_chain()
            assert ok is False, "deleting a row must break chain verification"
        finally:
            logger.close()


def test_write_path_is_append_only_no_update_delete_exposed():
    """Structural contract check, not a runtime attack: log_incident's own docstring
    claims "This is the ONLY write path — no UPDATE or DELETE is exposed." That's a
    security property (an attacker with normal API access, not raw disk/SQL access,
    should have no legitimate way to rewrite history) worth enforcing so a future
    change doesn't quietly add an update_incident()/delete_incident() method without
    someone noticing the invariant broke.
    """
    public_methods = {
        name for name, _ in inspect.getmembers(ArgusLogger, predicate=inspect.isfunction)
        if not name.startswith("_")
    }
    forbidden = {"update_incident", "delete_incident", "edit_incident", "remove_incident"}
    hit = public_methods & forbidden
    assert not hit, f"ArgusLogger exposes a mutate/delete method it shouldn't: {hit}"


def test_log_incident_survives_control_character_and_oversized_payload_injection():
    """We can't rewrite the log directly (no disk access this time), but we DO control
    some of what ends up inside incident rows indirectly — e.g. a crafted filename or
    email subject that becomes part of input_summary/features. Goal: crash the logger
    (denial of the audit trail itself) with null bytes, control characters, or a huge
    string, so nothing gets recorded for the real payload that follows in the same
    session. log_incident must swallow adversarial *content* without raising — it's a
    data value, not a code path.
    """
    with tempfile.TemporaryDirectory() as tmp:
        logger = _new_logger(Path(tmp))
        try:
            hostile_summary = "invoice\x00.exe " + ("A" * 200_000) + "\x1b[31mFAKE-ADMIN-ALERT\x1b[0m"
            hostile_features = {
                "file_name": "a\x00b.exe",
                "nested": {"payload": "x" * 50_000},
                "unicode_bomb": "\U0001f4a3" * 1000,
            }
            iid = logger.log_incident(
                monitor_type="file", verdict="SUSPICIOUS",
                input_summary=hostile_summary, features=hostile_features,
                confidence=0.8,
            )
            row = logger.get_incident(iid)
            assert row is not None, "hostile-but-well-typed content must still be logged"
            ok, msg = logger.verify_chain()
            assert ok, f"hash chain must remain valid even with adversarial content: {msg}"
        finally:
            logger.close()


def test_path_string_classification_cannot_distinguish_a_post_check_symlink_swap():
    """TOCTOU shape, tested at the one layer available without a Windows boot: classify
    a path, THEN replace what's actually at that path with a symlink to somewhere
    sensitive, and show that pure path-string classifiers (_is_staged — 'is this path
    under staging_dir') give the identical answer before and after, because they never
    re-check what the path currently resolves to. The real mitigation for this race
    lives in gate_keeper's Windows-only ACL/move code (icacls deny-execute on staging,
    tested only on the Windows boot per CLAUDE.local.md's platform-coupling rule) — not
    exercised here. This proves the *shape* of the gap at the primitive that IS
    testable cross-platform, honestly scoped to that.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        staging = tmp_path / "staging"
        staging.mkdir()
        outside_secret = tmp_path / "outside" / "ssh_key_or_whatever"
        outside_secret.parent.mkdir()
        outside_secret.write_text("sensitive")

        victim_path = staging / "invoice.pdf"
        victim_path.write_bytes(b"%PDF-1.4\n")

        before = _is_staged(victim_path, staging)
        assert before is True, "sanity: real staged file must classify as staged"

        # Attacker races: swap the staged file for a symlink to something outside
        # staging, at the exact same path a mover would act on next.
        victim_path.unlink()
        victim_path.symlink_to(outside_secret)

        after = _is_staged(victim_path, staging)
        assert after is True, (
            "_is_staged gives the same answer for the swapped symlink as for the "
            "original file — path-string classification alone cannot detect a "
            "post-check target swap; this is why the mover step needs its own "
            "content/identity check, not just a re-use of the earlier classification"
        )


def test_vanished_file_still_logs_an_incident():
    """Goal: execute a dropper, have it self-delete immediately, and leave zero trace
    in the audit log — "nothing was ever here." gate_keeper.process() calls
    _wait_for_stable() first; if the file is gone by the time it's stat()'d, the code
    comment says this is a deliberate audit fix ("previously returned without any
    SQLite record — silent gap in the audit trail"). Confirms that holds: even a file
    that's already gone before analysis starts gets a logged incident, not silence.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        logger = _new_logger(tmp_path)
        try:
            gk = _new_gatekeeper(tmp_path, logger)
            never_existed = gk.staging_dir / "self_deleting_dropper.exe"
            # Deliberately never created — same observable state as "existed for an
            # instant, then deleted itself before the stability check ran."
            result = gk.process({
                "source": "file_watcher", "path": str(never_existed),
                "event_type": "created", "staged": True,
                "timestamp": "2026-01-01T00:00:00+00:00",
            })
            assert result.verdict == "UNANALYZED"
            assert result.incident_id, "a vanished file must still produce a loggable incident"
            row = logger.get_incident(result.incident_id)
            assert row is not None, "the incident must actually be durably logged, not just returned"
        finally:
            logger.close()


def test_zero_byte_file_is_held_not_cleared():
    """Goal: drop a 0-byte placeholder (or a file truncated to 0 bytes) hoping an
    empty-file fast-path either ignores it or waves it through as trivially harmless.
    gate_keeper's stability check returns 'empty' immediately for a 0-byte file
    (skipping the full stability-wait budget) but routes it to HOLD_FOR_HUMAN, not
    CLEARED and not silently skipped.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        gk = _new_gatekeeper(tmp_path, None)
        empty = gk.staging_dir / "placeholder.exe"
        empty.touch()  # 0 bytes
        result = gk.process({
            "source": "file_watcher", "path": str(empty),
            "event_type": "created", "staged": True,
            "timestamp": "2026-01-01T00:00:00+00:00",
        })
        assert result.verdict != "CLEARED"
        assert result.action_taken == "HOLD_FOR_HUMAN"


def test_still_growing_file_past_stability_window_is_held_not_cleared():
    """Goal: keep a file permanently 'still being written' (trickle bytes in slowly,
    forever) past the stability wait window, hoping a timeout defaults to trusting
    partial content as CLEAN. Calls _wait_for_stable directly with a short max_wait
    (the real process() path uses a 60s default — too slow for a test — but the
    method's own logic is identical) against a file whose size keeps changing.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        gk = _new_gatekeeper(tmp_path, None)
        growing = gk.staging_dir / "still_downloading.exe"
        growing.write_bytes(b"A")

        stop = threading.Event()

        def _keep_growing():
            while not stop.is_set():
                with open(growing, "ab") as f:
                    f.write(b"A" * 10)
                time.sleep(0.15)

        t = threading.Thread(target=_keep_growing, daemon=True)
        t.start()
        try:
            outcome = gk._wait_for_stable(growing, max_wait=1.0)
        finally:
            stop.set()
            t.join(timeout=2)

        assert outcome == "unstable", (
            f"a file whose size never stops changing within the wait window must "
            f"report 'unstable' (held, execute-denied), not treated as done, got {outcome!r}"
        )


if __name__ == "__main__":
    from _runner import run_tests

    sys.exit(run_tests(globals(), module_name=__file__))
