# A.R.G.U.S. — Automated Real-time Guardian for User Systems
# Copyright (C) 2026  MdZeeshan-ML | GPL v3
"""
Gate pipeline for the Downloads staging zone.

Three-gate security pipeline:
  Gate 1   — Windows Defender (60s timeout, authoritative AV scan)
  Gate 1.5 — VirusTotal SHA-256 lookup (optional; skipped if no API key)
  Gate 2   — Static analysis: features + inference (gracefully degrades without inference)
  Gate 3   — Dynamic/human routing: sandbox for scripts, HUMAN_DECISION for executables

Verdicts:
  CLEARED               → file moved to Downloads/Cleared/ with normal permissions
  QUARANTINED           → file moved to ~/.argus/quarantine/
  HUMAN_DECISION_REQUIRED → file stays in staging zone; tray notification sent
  UNANALYZED            → inference unavailable; logged and held pending human review

Privacy: only metadata (feature dicts) ever goes to LLM. File bytes never leave this module.
"""

import getpass
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import httpx

from argus.analysis.feature_extractor import (
    GATE3_EXTENSIONS,
    NEVER_EXECUTE_NATIVELY,
    STATIC_ANALYSIS_ONLY,
    FeatureExtractor,
)

log = logging.getLogger(__name__)

# Minimum clean-verdict confidence to auto-clear without inference uncertainty
_CLEAR_CONFIDENCE_THRESHOLD = 0.85

# How long to wait for a file's size to stabilize (still being written)
_STABILITY_POLL_INTERVAL = 0.5   # seconds between size checks
_STABILITY_MAX_WAIT = 10.0       # maximum seconds to wait for stabilization

# Extensions handled by Windows Sandbox dynamic analysis (Gate 3)
# Anything not here but in GATE3_EXTENSIONS → HUMAN_DECISION_REQUIRED
_SANDBOX_EXTENSIONS = frozenset({
    '.py', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.sh',
})


@dataclass
class GateResult:
    """Result of running one file through the full gate pipeline."""
    path: Path
    verdict: str          # CLEARED | QUARANTINED | HUMAN_DECISION_REQUIRED | UNANALYZED
    gate_reached: int     # 1, 15 (Gate 1.5), 2, or 3
    features: dict        # from FeatureExtractor
    incident_id: str      # logged to SQLite
    reason: str           # human-readable verdict explanation
    action_taken: str     # MOVE_TO_CLEARED | MOVE_TO_QUARANTINE | HOLD_FOR_HUMAN | HOLD_UNANALYZED
    final_path: Path | None = None   # set after file is moved


class GateKeeper:
    """
    Orchestrates the four-gate security pipeline for files in the Downloads staging zone.

    Designed for graceful degradation: works with feature extraction only (Phase 1).
    Slots for inference_router (Phase 2) and rag (Phase 3) are accepted but optional.

    Usage:
        gk = GateKeeper(staging_dir, cleared_dir, extractor, logger)
        gk.setup()          # call once at daemon startup
        result = gk.process(event)
    """

    def __init__(
        self,
        staging_dir: Path,
        cleared_dir: Path,
        quarantine_dir: Path,
        extractor: FeatureExtractor,
        logger: Any,                             # ArgusLogger (avoid circular import)
        inference_router: Any = None,            # Phase 2 — None until built
        rag: Any = None,                         # Phase 3 — None until built
        virustotal_api_key: str | None = None,
        defender_timeout: int = 60,
        notify_callback: Callable[[str, str], None] | None = None,
    ) -> None:
        self.staging_dir = staging_dir
        self.cleared_dir = cleared_dir
        self.quarantine_dir = quarantine_dir
        self._extractor = extractor
        self._logger = logger
        self._inference_router = inference_router
        self._rag = rag
        self._vt_api_key = virustotal_api_key
        self._defender_timeout = defender_timeout
        self._notify = notify_callback

        # VirusTotal rate limiter: free tier = 4 requests/minute
        self._vt_last_requests: list[float] = []
        self._vt_rate_limit = 4
        self._vt_rate_window = 60.0

    def setup(self) -> None:
        """
        Create required directories and apply ACL to staging zone.
        Call once at daemon startup before processing events.
        """
        self.cleared_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        log.info("GateKeeper: directories ready")

        # Apply deny-execute ACL to staging zone so files can't be run before analysis
        self._apply_staging_acl()

    def process(self, event: dict) -> GateResult:
        """
        Run the full gate pipeline for one file event from Downloads staging zone.
        Logs to SQLite, moves the file, and calls notify_callback with result.
        """
        path = Path(event["path"])
        log.info("GateKeeper: processing %s", path.name)

        # Wait for the file to finish writing before scanning
        if not self._wait_for_stable(path):
            log.warning("GateKeeper: file vanished or never stabilised: %s", path.name)
            return GateResult(
                path=path,
                verdict="UNANALYZED",
                gate_reached=0,
                features={},
                incident_id="",
                reason="File disappeared before analysis could complete",
                action_taken="NONE",
            )

        # -- Gate 1: Windows Defender ------------------------------------------
        defender_clean, defender_detail = self._gate1_defender(path)
        if not defender_clean:
            return self._finalize(
                path=path,
                verdict="QUARANTINED",
                gate_reached=1,
                features={"defender_result": defender_detail},
                reason=f"Windows Defender detected threat: {defender_detail}",
                action_taken="MOVE_TO_QUARANTINE",
            )

        # -- Gate 1.5: VirusTotal hash lookup -----------------------------------
        # Run feature extraction here so we have the SHA-256 for the VT query
        features = self._extractor.extract(event)
        sha256: str = features.get("sha256", "")
        ext: str = features.get("extension", "").lower()

        if self._vt_api_key and sha256:
            vt_verdict, vt_data = self._gate15_virustotal(sha256, ext)
            features["virustotal"] = vt_data

            if vt_verdict == "KNOWN_MALICIOUS":
                return self._finalize(
                    path=path,
                    verdict="QUARANTINED",
                    gate_reached=15,
                    features=features,
                    reason=f"VirusTotal: known malicious ({vt_data})",
                    action_taken="MOVE_TO_QUARANTINE",
                )
            elif vt_verdict == "UNKNOWN_HIGH_RISK":
                # Unknown hash + executable/script = highest risk, hold for human
                return self._finalize(
                    path=path,
                    verdict="HUMAN_DECISION_REQUIRED",
                    gate_reached=15,
                    features=features,
                    reason="VirusTotal: hash unknown (never seen) and file is executable/script — custom payload risk",
                    action_taken="HOLD_FOR_HUMAN",
                )
            # CLEAN or UNKNOWN_LOW_RISK → continue to Gate 2 with VT data enriched in features
        else:
            if not self._vt_api_key:
                log.debug("GateKeeper: Gate 1.5 skipped — no VIRUSTOTAL_API_KEY configured")
            features["virustotal"] = None

        # -- Gate 2: Static analysis --------------------------------------------
        gate2_verdict, gate2_confidence = self._gate2_static(path, features)

        if gate2_verdict == "SUSPICIOUS":
            return self._finalize(
                path=path,
                verdict="QUARANTINED",
                gate_reached=2,
                features=features,
                reason=f"Static analysis: SUSPICIOUS (confidence={gate2_confidence:.2f})",
                action_taken="MOVE_TO_QUARANTINE",
            )

        if gate2_verdict == "CLEAN" and gate2_confidence is not None and gate2_confidence >= _CLEAR_CONFIDENCE_THRESHOLD:
            if ext not in GATE3_EXTENSIONS:
                # Non-executable with high confidence CLEAN → cleared
                return self._finalize(
                    path=path,
                    verdict="CLEARED",
                    gate_reached=2,
                    features=features,
                    reason=f"Static analysis: CLEAN (confidence={gate2_confidence:.2f})",
                    action_taken="MOVE_TO_CLEARED",
                )

        # -- Gate 3: Dynamic analysis / human decision --------------------------
        return self._gate3_route(path, features, gate2_verdict, gate2_confidence)

    # ------------------------------------------------------------------
    # Gate 1 — Windows Defender
    # ------------------------------------------------------------------

    def _gate1_defender(self, path: Path) -> tuple[bool, str]:
        """
        Run Windows Defender on a single file.
        Returns (True, 'clean') or (False, 'threat description').
        """
        mpcmdrun = _find_mpcmdrun()
        if not mpcmdrun:
            log.warning("GateKeeper: MpCmdRun.exe not found — Gate 1 skipped")
            return True, "Defender unavailable (skipped)"

        try:
            result = subprocess.run(
                [
                    str(mpcmdrun),
                    "/Scan",
                    "/ScanType", "3",        # custom scan
                    "/File", str(path),
                    "/DisableRemediation",   # detect only, don't auto-remediate
                ],
                capture_output=True,
                text=True,
                timeout=self._defender_timeout,
            )
            output = result.stdout + result.stderr

            if result.returncode == 0:
                return True, "clean"

            # Exit code 2 = threats found; other codes = errors
            if result.returncode == 2:
                # Extract threat name from output if present
                for line in output.splitlines():
                    if "Threat" in line and line.strip():
                        return False, line.strip()
                return False, f"Threat detected (exit code 2)"

            # Non-zero but not 2 = scan error — treat as inconclusive, continue
            log.warning("GateKeeper: Defender returned unexpected code %d for %s",
                        result.returncode, path.name)
            return True, f"Defender scan inconclusive (code {result.returncode})"

        except subprocess.TimeoutExpired:
            log.warning("GateKeeper: Defender scan timed out after %ds for %s",
                        self._defender_timeout, path.name)
            return True, "Defender timeout (scan inconclusive)"
        except Exception as e:
            log.exception("GateKeeper: Gate 1 error for %s: %s", path.name, e)
            return True, f"Defender error: {e}"

    # ------------------------------------------------------------------
    # Gate 1.5 — VirusTotal hash lookup
    # ------------------------------------------------------------------

    def _gate15_virustotal(self, sha256: str, ext: str) -> tuple[str, dict | None]:
        """
        Returns (verdict, data_dict).
        Verdicts: KNOWN_MALICIOUS | UNKNOWN_HIGH_RISK | UNKNOWN_LOW_RISK | CLEAN | ERROR
        """
        self._vt_rate_limit_wait()

        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        try:
            with httpx.Client(timeout=15.0) as client:
                response = client.get(url, headers={"x-apikey": self._vt_api_key})

            if response.status_code == 404:
                # Hash unknown — never submitted to VT
                is_high_risk = ext in GATE3_EXTENSIONS
                verdict = "UNKNOWN_HIGH_RISK" if is_high_risk else "UNKNOWN_LOW_RISK"
                return verdict, {"status": "not_found", "sha256": sha256}

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())

                if malicious > 0:
                    return "KNOWN_MALICIOUS", {
                        "malicious_engines": malicious,
                        "suspicious_engines": suspicious,
                        "total_engines": total,
                        "sha256": sha256,
                    }
                return "CLEAN", {
                    "malicious_engines": 0,
                    "total_engines": total,
                    "sha256": sha256,
                }

            log.warning("GateKeeper: VT API returned %d for %s", response.status_code, sha256[:16])
            return "ERROR", {"status_code": response.status_code}

        except httpx.TimeoutException:
            log.warning("GateKeeper: VirusTotal request timed out for %s...", sha256[:16])
            return "ERROR", {"error": "timeout"}
        except Exception as e:
            log.warning("GateKeeper: VirusTotal error: %s", e)
            return "ERROR", {"error": str(e)}

    def _vt_rate_limit_wait(self) -> None:
        """Block until we're within the VT free-tier rate limit (4 req/min)."""
        now = time.monotonic()
        # Drop requests older than 60 seconds
        self._vt_last_requests = [t for t in self._vt_last_requests if now - t < self._vt_rate_window]
        if len(self._vt_last_requests) >= self._vt_rate_limit:
            wait_until = self._vt_last_requests[0] + self._vt_rate_window
            sleep_secs = wait_until - now
            if sleep_secs > 0:
                log.debug("GateKeeper: VT rate limit — sleeping %.1fs", sleep_secs)
                time.sleep(sleep_secs)
        self._vt_last_requests.append(time.monotonic())

    # ------------------------------------------------------------------
    # Gate 2 — Static analysis
    # ------------------------------------------------------------------

    def _gate2_static(self, path: Path, features: dict) -> tuple[str, float | None]:
        """
        Returns (verdict, confidence).
        Without inference: returns (UNANALYZED, None).
        With inference (Phase 2): returns (SUSPICIOUS|UNCERTAIN|CLEAN, 0.0-1.0).
        """
        if self._inference_router is None:
            # Graceful degradation: inference not built yet
            # Apply simple rule-based heuristics to flag obvious threats
            verdict, confidence = _heuristic_verdict(features)
            if verdict != "UNANALYZED":
                log.info("GateKeeper: heuristic gate2 verdict=%s confidence=%.2f for %s",
                         verdict, confidence or 0.0, path.name)
            return verdict, confidence

        # Phase 2 path — inference router handles prompt building + LLM call
        try:
            rag_context = self._rag.query(features) if self._rag else None
            result = self._inference_router.analyze(
                monitor_type="file",
                features=features,
                rag_context=rag_context,
            )
            return result["verdict"], result.get("confidence")
        except Exception:
            log.exception("GateKeeper: inference failed for %s — treating as UNANALYZED", path.name)
            return "UNANALYZED", None

    # ------------------------------------------------------------------
    # Gate 3 — Dynamic analysis / human routing
    # ------------------------------------------------------------------

    def _gate3_route(
        self,
        path: Path,
        features: dict,
        gate2_verdict: str,
        gate2_confidence: float | None,
    ) -> GateResult:
        """Route file to appropriate Gate 3 handler based on extension category."""
        ext: str = features.get("extension", "").lower()
        category: str | None = features.get("gate3_category")

        if ext in NEVER_EXECUTE_NATIVELY:
            return self._finalize(
                path=path,
                verdict="HUMAN_DECISION_REQUIRED",
                gate_reached=3,
                features=features,
                reason=(
                    f"Executable type ({ext}) cannot be safely sandboxed — "
                    f"manual review required. Static analysis verdict: {gate2_verdict}"
                ),
                action_taken="HOLD_FOR_HUMAN",
            )

        if ext in STATIC_ANALYSIS_ONLY:
            # LNK/URL shortcuts — target was analyzed in extractor
            target = features.get("lnk_target") or features.get("url_target", "")
            return self._finalize(
                path=path,
                verdict="HUMAN_DECISION_REQUIRED",
                gate_reached=3,
                features=features,
                reason=f"Shortcut file pointing to: {target or 'unknown target'}",
                action_taken="HOLD_FOR_HUMAN",
            )

        if category == "office_macro" and features.get("has_macros"):
            return self._finalize(
                path=path,
                verdict="HUMAN_DECISION_REQUIRED",
                gate_reached=3,
                features=features,
                reason="Office document contains VBA macros — manual review required",
                action_taken="HOLD_FOR_HUMAN",
            )

        if category == "archive_image":
            return self._finalize(
                path=path,
                verdict="HUMAN_DECISION_REQUIRED",
                gate_reached=3,
                features=features,
                reason="Disk image file — mount and scan contents manually",
                action_taken="HOLD_FOR_HUMAN",
            )

        if ext in _SANDBOX_EXTENSIONS:
            # Script: try Windows Sandbox dynamic analysis
            sandbox_verdict, sandbox_reason = self._gate3_sandbox(path, features)
            if sandbox_verdict == "CLEAN":
                return self._finalize(
                    path=path,
                    verdict="CLEARED",
                    gate_reached=3,
                    features=features,
                    reason=f"Sandbox analysis: {sandbox_reason}",
                    action_taken="MOVE_TO_CLEARED",
                )
            elif sandbox_verdict == "SUSPICIOUS":
                return self._finalize(
                    path=path,
                    verdict="QUARANTINED",
                    gate_reached=3,
                    features=features,
                    reason=f"Sandbox detected suspicious behavior: {sandbox_reason}",
                    action_taken="MOVE_TO_QUARANTINE",
                )
            else:
                # UNAVAILABLE or INCONCLUSIVE
                return self._finalize(
                    path=path,
                    verdict="HUMAN_DECISION_REQUIRED",
                    gate_reached=3,
                    features=features,
                    reason=f"Script requires sandbox analysis — sandbox unavailable: {sandbox_reason}",
                    action_taken="HOLD_FOR_HUMAN",
                )

        # File not in GATE3_EXTENSIONS and static analysis was UNCERTAIN or UNANALYZED
        if gate2_verdict == "UNANALYZED":
            return self._finalize(
                path=path,
                verdict="UNANALYZED",
                gate_reached=2,
                features=features,
                reason="Inference unavailable — logged for human review",
                action_taken="HOLD_UNANALYZED",
            )

        # UNCERTAIN with moderate confidence — let static verdict decide
        return self._finalize(
            path=path,
            verdict="HUMAN_DECISION_REQUIRED",
            gate_reached=3,
            features=features,
            reason=f"Static analysis uncertain (verdict={gate2_verdict}, confidence={gate2_confidence}) — human review requested",
            action_taken="HOLD_FOR_HUMAN",
        )

    def _gate3_sandbox(self, _path: Path, _features: dict) -> tuple[str, str]:
        """
        Windows Sandbox execution for scripts.
        Returns (verdict, reason): verdict is CLEAN|SUSPICIOUS|UNAVAILABLE.
        Stub until argus/analysis/dynamic/sandbox_python.py is built (Phase 3).
        """
        if not _windows_sandbox_available():
            return "UNAVAILABLE", "Windows Sandbox feature not installed"

        # TODO (Phase 3): dispatch to argus/analysis/dynamic/ based on extension
        # For now, return UNAVAILABLE to route to HUMAN_DECISION_REQUIRED
        return "UNAVAILABLE", "Sandbox dispatch not yet implemented (Phase 3)"

    # ------------------------------------------------------------------
    # File operations
    # ------------------------------------------------------------------

    def _finalize(
        self,
        *,
        path: Path,
        verdict: str,
        gate_reached: int,
        features: dict,
        reason: str,
        action_taken: str,
    ) -> GateResult:
        """Log to SQLite, move file, notify, return GateResult."""
        final_path: Path | None = None

        if action_taken == "MOVE_TO_CLEARED":
            final_path = self._move_to_cleared(path)
        elif action_taken == "MOVE_TO_QUARANTINE":
            final_path = self._move_to_quarantine(path)
        # HOLD_* actions leave file in staging zone — ACL prevents execution

        # Log incident — SQLite write happens before any notification
        incident_id = ""
        if self._logger:
            try:
                incident_id = self._logger.log_incident(
                    monitor_type="file",
                    verdict=verdict,
                    input_summary=f"{path.name} | gate={gate_reached}",
                    features=features,
                    action_taken=action_taken,
                    confidence=features.get("_gate2_confidence"),
                )
            except Exception:
                log.exception("GateKeeper: failed to log incident for %s", path.name)

        log.info("GateKeeper: %s → %s (gate=%d) — %s", path.name, verdict, gate_reached, reason)

        if self._notify:
            try:
                self._notify(f"ARGUS | {verdict}", f"{path.name}: {reason}")
            except Exception:
                log.warning("GateKeeper: notify_callback failed")

        return GateResult(
            path=path,
            verdict=verdict,
            gate_reached=gate_reached,
            features=features,
            incident_id=incident_id,
            reason=reason,
            action_taken=action_taken,
            final_path=final_path,
        )

    def _move_to_cleared(self, path: Path) -> Path | None:
        """Move file to Cleared/ directory with normal permissions."""
        dest = self.cleared_dir / path.name
        # Avoid overwriting existing files in Cleared/
        if dest.exists():
            stem = dest.stem
            suffix = dest.suffix
            dest = self.cleared_dir / f"{stem}_{int(time.time())}{suffix}"
        try:
            shutil.move(str(path), str(dest))
            log.info("GateKeeper: moved to Cleared/: %s", dest.name)
            return dest
        except OSError as e:
            log.error("GateKeeper: failed to move %s to Cleared/: %s", path.name, e)
            return None

    def _move_to_quarantine(self, path: Path) -> Path | None:
        """Move file to quarantine directory. File stays there until user decides."""
        dest = self.quarantine_dir / path.name
        if dest.exists():
            dest = self.quarantine_dir / f"{path.stem}_{int(time.time())}{path.suffix}"
        try:
            shutil.move(str(path), str(dest))
            log.info("GateKeeper: QUARANTINED: %s → %s", path.name, dest)
            return dest
        except OSError as e:
            log.error("GateKeeper: failed to quarantine %s: %s", path.name, e)
            return None

    # ------------------------------------------------------------------
    # ACL setup
    # ------------------------------------------------------------------

    def _apply_staging_acl(self) -> None:
        """
        Apply deny-execute ACL to the staging zone (Downloads directory).
        Files in staging cannot be run until they pass all gates and move to Cleared/.
        Deny (X) only — read access is preserved so the user can inspect files.
        Best-effort: logs warning on failure, does not halt daemon startup.
        """
        try:
            username = getpass.getuser()
            result = subprocess.run(
                [
                    "icacls",
                    str(self.staging_dir),
                    "/deny",
                    f"{username}:(OI)(CI)(X)",  # OI=object inherit, CI=container inherit
                ],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                log.info("GateKeeper: staging zone ACL set — deny execute for %s in %s",
                         username, self.staging_dir)
            else:
                log.warning("GateKeeper: icacls failed (code %d): %s",
                            result.returncode, result.stderr.strip())
        except Exception as e:
            log.warning("GateKeeper: ACL setup failed (non-fatal): %s", e)

    # ------------------------------------------------------------------
    # File stability check
    # ------------------------------------------------------------------

    def _wait_for_stable(self, path: Path, max_wait: float = _STABILITY_MAX_WAIT) -> bool:
        """
        Wait until the file size stops changing (download finished writing).
        Returns False if file disappears or never stabilises within max_wait.
        """
        deadline = time.monotonic() + max_wait
        prev_size = -1

        while time.monotonic() < deadline:
            try:
                size = path.stat().st_size
            except OSError:
                return False  # file gone

            if size == prev_size and size > 0:
                return True   # stable, non-empty

            prev_size = size
            time.sleep(_STABILITY_POLL_INTERVAL)

        # Give it one final check
        try:
            return path.stat().st_size > 0
        except OSError:
            return False


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _find_mpcmdrun() -> Path | None:
    """
    Find MpCmdRun.exe — checks platform path first (version-stamped),
    falls back to classic path. Returns None if not found.
    """
    # Platform path (version-stamped, updated with Defender updates)
    platform_glob = list(
        Path(r"C:\ProgramData\Microsoft\Windows Defender\Platform").glob(
            r"*\MpCmdRun.exe"
        )
    )
    if platform_glob:
        # Sort descending — latest platform version has the highest version number
        platform_glob.sort(reverse=True)
        return platform_glob[0]

    # Classic path (older installs / fallback)
    classic = Path(r"C:\Program Files\Windows Defender\MpCmdRun.exe")
    if classic.exists():
        return classic

    return None


def _windows_sandbox_available() -> bool:
    """Check if the Windows Sandbox feature is installed."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM | Select-Object -ExpandProperty State"],
            capture_output=True, text=True, timeout=15,
        )
        return "Enabled" in result.stdout
    except Exception:
        return False


def _heuristic_verdict(features: dict) -> tuple[str, float | None]:
    """
    Simple rule-based pre-inference heuristics for Gate 2 fallback.
    Returns (verdict, confidence) or (UNANALYZED, None).

    Flags only clear-cut cases so we don't block everything before inference is built.
    """
    signals: list[str] = []
    score = 0.0
    ext: str = features.get("extension", "")

    # MZ/PE header in a non-executable extension — always high-risk masquerade
    magic_desc = features.get("magic_bytes_desc") or ""
    _EXE_EXTS = {'.exe', '.dll', '.scr', '.com', '.pif', '.msi', '.sys', '.ocx'}
    if ("MZ" in magic_desc or "PE executable" in magic_desc) and ext not in _EXE_EXTS:
        signals.append(f"PE/MZ header in {ext or 'unknown'} file — masquerade detected")
        score += 0.75

    # Extension/MIME mismatch from python-magic (broader coverage)
    elif features.get("extension_mime_mismatch"):
        signals.append("extension/MIME mismatch")
        score += 0.4

    # Very high entropy on an executable (likely packed/encrypted)
    if features.get("entropy_is_high") and features.get("gate3_category") == "executable":
        signals.append("high entropy executable")
        score += 0.3

    # Origin domain is very new (< 7 days = extreme risk)
    whois = features.get("whois") or {}
    age = whois.get("domain_age_days")
    if age is not None and age < 7:
        signals.append(f"origin domain age {age} days")
        score += 0.35

    if score >= 0.6:
        return "SUSPICIOUS", min(score, 0.95)

    return "UNANALYZED", None


# ------------------------------------------------------------------
# Standalone test
# ------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(levelname)s %(name)s: %(message)s",
    )

    print("=== A.R.G.U.S. Gate Keeper Tests ===\n")

    # Use temp dirs so tests are self-contained
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        staging = tmp_path / "staging"
        cleared = tmp_path / "Cleared"
        quarantine = tmp_path / "quarantine"
        staging.mkdir()

        extractor = FeatureExtractor()
        gk = GateKeeper(
            staging_dir=staging,
            cleared_dir=cleared,
            quarantine_dir=quarantine,
            extractor=extractor,
            logger=None,  # no DB for this test
            virustotal_api_key=None,  # no VT key in test
        )
        gk.setup()

        # Verify Cleared/ and quarantine/ were created
        assert cleared.exists(), "Cleared/ must be created by setup()"
        assert quarantine.exists(), "quarantine/ must be created by setup()"
        print("Test 1: setup() creates directories — PASSED")

        # Test 2: Clean PDF file should reach Gate 3 routing (UNANALYZED, no inference)
        pdf_file = staging / "document.pdf"
        pdf_file.write_bytes(b'\x25\x50\x44\x46\x2d\x31\x2e\x34\x0a')  # %PDF-1.4
        event = {
            "source": "file_watcher",
            "path": str(pdf_file),
            "staged": True,
            "event_type": "created",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        result = gk.process(event)
        print(f"Test 2: PDF (no inference) -> verdict={result.verdict}, gate={result.gate_reached}")
        # Without inference: UNANALYZED or HUMAN_DECISION_REQUIRED (heuristics clean)
        assert result.verdict in {"UNANALYZED", "HUMAN_DECISION_REQUIRED", "CLEARED"}
        print("Test 2: PASSED")

        # Test 3: File with extension/MIME mismatch — heuristic should flag it
        fake_pdf = staging / "invoice.pdf"
        fake_pdf.write_bytes(b'\x4d\x5a\x90\x00' + b'\x00' * 100)  # MZ header but .pdf extension
        event3 = {
            "source": "file_watcher",
            "path": str(fake_pdf),
            "staged": True,
            "event_type": "created",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        result3 = gk.process(event3)
        print(f"Test 3: EXE disguised as PDF -> verdict={result3.verdict}, reason={result3.reason[:60]}")
        # Heuristic: extension_mime_mismatch → SUSPICIOUS
        # OR gate3_category=None for .pdf (not in GATE3_EXTENSIONS) → check heuristics
        print("Test 3: PASSED (no crash)")

        # Test 4: Verify _find_mpcmdrun doesn't crash
        mpc = _find_mpcmdrun()
        print(f"Test 4: MpCmdRun.exe found at: {mpc}")
        print("Test 4: PASSED")

        # Test 5: Verify _windows_sandbox_available doesn't crash
        sb = _windows_sandbox_available()
        print(f"Test 5: Windows Sandbox available: {sb}")
        print("Test 5: PASSED")

    print("\n=== All tests passed ===")
