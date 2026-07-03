# A.R.G.U.S. — Automated Real-time Guardian for User Systems
# Copyright (C) 2026  MdZeeshan-ML | GPL v3
"""
Adversary POV: getting a payload from "downloaded" to "double-clicked".

Target: the same freelancer, but this time we already got them to click 'download
attachment' — the browser drops the file into Downloads (ARGUS's staging zone). Now
the goal is to survive gate_keeper's pipeline: pass as a document long enough that
either the victim opens it directly, or a static/heuristic check waves it through to
Cleared/. We test against the real FeatureExtractor + heuristic_verdict + GateKeeper
running on this Linux dev box — gate_keeper is written to degrade gracefully without
Defender/icacls/Sandbox (confirmed empirically: its own __main__ self-test passes
here), so the cross-platform gate logic these tests exercise is real, not a mock of it.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from _fixtures import (
    build_double_extension_lure,
    build_file_event,
    build_macro_docm_as_doc,
    build_pe_masquerade,
    build_polyglot_pdf_with_trailing_pe,
    build_url_shortcut,
    build_zip_bomb,
)

from argus.analysis.feature_extractor import FeatureExtractor
from argus.core.gate_keeper import GateKeeper, heuristic_verdict
from argus.monitors.email_scanner import _double_extension

_EXTRACTOR = FeatureExtractor(whois_timeout=2)


def _new_gatekeeper(tmp_path: Path) -> GateKeeper:
    """One fresh GateKeeper per test, isolated temp dirs — same pattern gate_keeper.py's
    own __main__ self-test uses, so behaviour matches what Zeeshan already validated.
    """
    staging = tmp_path / "staging"
    cleared = tmp_path / "Cleared"
    quarantine = tmp_path / "quarantine"
    staging.mkdir()
    gk = GateKeeper(
        staging_dir=staging, cleared_dir=cleared, quarantine_dir=quarantine,
        extractor=_EXTRACTOR, logger=None, virustotal_api_key=None,
    )
    gk.setup()
    return gk


def test_mz_header_in_pdf_extension_scores_suspicious():
    """Payload: raw MZ/PE bytes saved as 'invoice.pdf'. This is the single strongest
    heuristic rule in gate_keeper (+0.75, unambiguous masquerade) — if this doesn't
    fire, nothing else in this file matters.
    """
    with tempfile.TemporaryDirectory() as tmp:
        p = build_pe_masquerade(Path(tmp), "invoice.pdf")
        features = _EXTRACTOR.extract(build_file_event(p))
        verdict, confidence = heuristic_verdict(features, monitor_type="file")
        assert verdict == "SUSPICIOUS", f"got {verdict}/{confidence}"
        assert confidence is not None and confidence >= 0.6


def test_double_extension_never_reaches_cleared_via_gatekeeper():
    """Payload: 'Contract_Signed.pdf.exe' — the real security invariant we care about
    isn't the exact verdict label (heuristic thresholds are tunable and not something
    this suite should pin down without reading the scoring internals), it's that a
    disguised executable is never silently moved to Cleared/ with normal permissions.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        gk = _new_gatekeeper(tmp_path)
        lure = build_double_extension_lure(gk.staging_dir, "Contract_Signed", ".exe")
        result = gk.process(build_file_event(lure))
        assert result.verdict != "CLEARED", (
            f"double-extension executable must never auto-clear, got {result.verdict} "
            f"({result.reason})"
        )
        assert _double_extension(lure.name) is True


def test_macro_payload_detected_when_extension_is_in_the_checked_set():
    """Boundary control for the finding below: prove macro detection genuinely works
    on content it's built to look at, e.g. via the real .docm extension. Needed so the
    next test's failure reads as a scope gap, not a broken detector.
    """
    with tempfile.TemporaryDirectory() as tmp:
        p = build_macro_docm_as_doc(Path(tmp), "New_Client_Brief.docm")
        features = _EXTRACTOR.extract(build_file_event(p))
        assert features["has_macros"] is True


def test_macro_payload_renamed_to_doc_is_never_even_inspected():
    """REAL FINDING (confirmed by running this, not assumed): _extract_file only calls
    _check_office_macros when ext is in {'.docm','.xlsm','.pptm','.xll','.iqy','.slk'}
    (feature_extractor.py, is_office_macro_ext). '.doc' — and '.docx', '.xls', '.xlsx',
    '.ppt', '.pptx', all still legitimately openable by Office regardless of extension,
    since Office sniffs actual format, not the filename — is not in that set. So the
    exact lure named in CLAUDE.local.md ("fake client briefs — malicious PDF/DOCX")
    saved with a macro-laden OOXML body under a plain '.docx'/'.doc' name gets
    has_macros=None: the zip is never even opened to check. This asserts the current
    (gap) behavior rather than papering over it — see the companion test above for
    proof the underlying content-scanner is fine; this is a scope/allowlist gap, not a
    parser bug.
    """
    with tempfile.TemporaryDirectory() as tmp:
        p = build_macro_docm_as_doc(Path(tmp), "New_Client_Brief.doc")
        features = _EXTRACTOR.extract(build_file_event(p))
        assert features["has_macros"] is None, (
            "if this starts returning True/False, the extension allowlist in "
            "_extract_file was widened and this test (and the gap) is stale — update it"
        )
        print(
            "  [FINDING] macro-laden OOXML saved as '.doc' is never inspected for "
            "macros (has_macros stays None) — extension allowlist gap, recommend "
            "content-sniffing (zip magic bytes) instead of/alongside extension gating"
        )


def test_polyglot_pdf_with_trailing_pe_is_a_documented_blind_spot():
    """KNOWN GAP, not asserted as pass/fail against internals we haven't read: a file
    that starts with a fully valid '%PDF-1.4' header (what any offset-0/header-only
    magic check sees) and carries a complete MZ/PE blob appended after %%EOF. Any PDF
    reader ignores trailing bytes; a second-stage tool (or a renamed copy of the exact
    same bytes) would happily run the appended PE. We don't know from the interface
    alone whether magic-byte identification here scans past EOF, so we don't assert a
    verdict — we just prove the artifact is constructed correctly and flag it for
    human review, which is honest given the "no line-by-line audit" constraint on this
    suite.
    """
    with tempfile.TemporaryDirectory() as tmp:
        p = build_polyglot_pdf_with_trailing_pe(Path(tmp), "final_invoice.pdf")
        raw = p.read_bytes()
        assert raw.startswith(b"%PDF-1.4"), "sanity: must present as a valid PDF header"
        assert b"\x4d\x5a\x90\x00" in raw, "sanity: must actually carry the PE payload"
        features = _EXTRACTOR.extract(build_file_event(p))
        verdict, confidence = heuristic_verdict(features, monitor_type="file")
        print(
            f"  [heads-up for Zeeshan] polyglot PDF+PE -> verdict={verdict} "
            f"confidence={confidence} magic={features.get('magic_bytes_desc')!r} — "
            f"if magic detection is header-only, this masquerade is currently unflagged"
        )


def test_url_shortcut_never_reaches_cleared_via_gatekeeper():
    """Payload: a plain-text .url Internet Shortcut pointing at a remote exploit page —
    no PE header, no macro, nothing for content-based file heuristics to key on at all.
    This is the cheapest possible bypass of every file-content check in this suite.
    Same invariant as the double-extension test: must not be silently auto-cleared,
    it must be routed to a human/inference decision.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        gk = _new_gatekeeper(tmp_path)
        shortcut = build_url_shortcut(gk.staging_dir, "Payment_Receipt.url",
                                       "http://razorpay-verify.ru/payload.exe")
        result = gk.process(build_file_event(shortcut))
        assert result.verdict != "CLEARED", (
            f".url shortcut to a remote payload must never auto-clear, got "
            f"{result.verdict} ({result.reason})"
        )
        features = result.features
        assert features.get("url_target") == "http://razorpay-verify.ru/payload.exe"
        assert features.get("requires_gate3") is True, (
            ".url is in GATE3_EXTENSIONS — must be routed for deeper analysis, not "
            "cleared on file-structure grounds alone"
        )


def test_zip_bomb_entropy_extraction_is_time_bounded():
    """DoS goal, not evasion: stall the single scanning thread long enough to open a
    window for a second, real payload. FeatureExtractor caps entropy sampling at
    entropy_sample_bytes (1 MB default) regardless of on-disk file size, so a scaled-
    down bomb (a few hundred KB compressed) must not make extraction noticeably slower
    than a normal small file — proving the cap actually bounds the work, not just the
    intent to bound it.
    """
    with tempfile.TemporaryDirectory() as tmp:
        bomb = build_zip_bomb(Path(tmp), "portfolio_samples.zip",
                               inner_files=20, inner_size=200_000)
        start = time.monotonic()
        features = _EXTRACTOR.extract(build_file_event(bomb))
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, (
            f"zip-bomb-shaped file took {elapsed:.2f}s to extract features from — "
            f"a scanning thread stall of this shape is exactly the DoS window an "
            f"attacker wants to buy for a second real payload"
        )
        assert features.get("sha256"), "extraction must still complete, not just be fast"


def test_giant_high_entropy_file_extraction_is_time_bounded():
    """Same DoS goal, different shape: one large (not nested) high-entropy file to make
    hashing+entropy computation slow. Kept to 3 MB (not GB) to stay CI-safe while still
    exceeding the 1 MB entropy_sample_bytes cap, so this genuinely exercises the cap
    rather than just reading a file that happens to be small.
    """
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "portfolio_export.zip"
        # Pseudo-random-looking, cheap to generate: repeating full-byte-range block,
        # ~3 MB total — exceeds the 1 MB entropy_sample_bytes cap without needing GBs.
        p.write_bytes(bytes(range(256)) * 4093 * 3)
        start = time.monotonic()
        features = _EXTRACTOR.extract(build_file_event(p))
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"3MB file took {elapsed:.2f}s — scanning thread stall risk"
        assert features.get("entropy") is not None


def test_iso_disk_image_container_never_reaches_cleared():
    """Container-smuggling lure: deliver the payload inside a mountable disk image
    ('portfolio_samples.iso') instead of a raw executable, hoping it reads as an inert
    'disk image' file type rather than triggering executable-focused heuristics —
    Windows will happily auto-mount a double-clicked .iso as a new drive letter.
    CONFIRMED DEFENDED: gate3_category=='archive_image' is routed to
    HUMAN_DECISION_REQUIRED unconditionally in _gate3_route, regardless of what static
    heuristics say about the container file itself. See FINDINGS.md #6.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        gk = _new_gatekeeper(tmp_path)
        # Contents don't need to be a real bootable ISO — routing is extension/category
        # based at this gate, not content-parsed.
        iso = gk.staging_dir / "portfolio_samples.iso"
        iso.write_bytes(b"\x00" * 1024)
        result = gk.process(build_file_event(iso))
        assert result.verdict != "CLEARED", (
            f"a .iso container must never auto-clear, got {result.verdict}"
        )
        assert result.features.get("gate3_category") == "archive_image"
        assert result.action_taken == "HOLD_FOR_HUMAN"


if __name__ == "__main__":
    import sys
    from _runner import run_tests

    sys.exit(run_tests(globals(), module_name=__file__))
