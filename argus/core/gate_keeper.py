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
# Audit fix: 10s was shorter than many real downloads; an unstable file was
# then treated as stable and analyzed mid-write (partial hash, partial scan).
_STABILITY_MAX_WAIT = 60.0       # maximum seconds to wait for stabilization

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

        # Wait for the file to finish writing before scanning.
        # Audit fix: both failure paths now log an incident — previously these
        # returned without any SQLite record (silent gap in the audit trail).
        stability = self._wait_for_stable(path)
        if stability == "vanished":
            return self._finalize(
                path=path,
                verdict="UNANALYZED",
                gate_reached=0,
                features={"file_name": path.name},
                reason="File disappeared before analysis could complete (deleted, or removed by Defender real-time protection)",
                action_taken="NONE",
            )
        if stability == "unstable":
            return self._finalize(
                path=path,
                verdict="UNANALYZED",
                gate_reached=0,
                features={"file_name": path.name},
                reason=f"File still being written after {_STABILITY_MAX_WAIT:.0f}s — held in staging zone (execute denied)",
                action_taken="HOLD_UNANALYZED",
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
        # Audit fix: _finalize reads this key for the SQLite confidence column —
        # it was never set, so every gate incident logged confidence=NULL.
        features["_gate2_confidence"] = gate2_confidence
        # Confidence may be None (Phase 2 inference without a score) — never crash on format
        conf_s = f"{gate2_confidence:.2f}" if gate2_confidence is not None else "n/a"

        if gate2_verdict == "SUSPICIOUS":
            return self._finalize(
                path=path,
                verdict="QUARANTINED",
                gate_reached=2,
                features=features,
                reason=f"Static analysis: SUSPICIOUS (confidence={conf_s})",
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
                    reason=f"Static analysis: CLEAN (confidence={conf_s})",
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

        import httpx  # lazy — only needed when VT key is configured
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
                # Audit fix: suspicious_engines was dropped from the CLEAN payload —
                # a file 20 engines call suspicious looked identical to a true clean
                # in features, which would mislead Phase 2 inference toward CLEAN.
                return "CLEAN", {
                    "malicious_engines": 0,
                    "suspicious_engines": suspicious,
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
            verdict, confidence = heuristic_verdict(features, monitor_type="file")
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

        # Audit fix: a failed move must not be logged as if it succeeded —
        # the record claimed containment while the file was still in staging.
        if action_taken in ("MOVE_TO_CLEARED", "MOVE_TO_QUARANTINE") and final_path is None:
            action_taken = f"{action_taken}_FAILED"
            reason += " | MOVE FAILED — file remains in staging zone (execute denied by ACL)"

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
                    # Audit fix: the WHY of every gate decision was never persisted —
                    # only the rotating log file had it. Goes to the local-only column.
                    reasoning=reason,
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
            # Audit fix: an NTFS same-volume move keeps the source DACL, so the
            # file still carried the staging deny-X ACE. /reset re-inherits from
            # Cleared/ (which has no deny) — the file becomes normally usable.
            self._icacls(dest, "/reset")
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
            # Audit fix: belt-and-braces — explicitly deny execute on the
            # quarantined file itself (moved files keep their old DACL).
            try:
                self._icacls(dest, "/deny", f"{getpass.getuser()}:(X)")
            except Exception:
                log.warning("GateKeeper: per-file quarantine ACL failed for %s", dest.name)
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

            # Remove any stale deny first — repeated /deny calls stack duplicate ACEs
            self._icacls(self.staging_dir, "/remove:d", username)
            if self._icacls(self.staging_dir, "/deny", f"{username}:(OI)(CI)(X)"):
                log.info("GateKeeper: staging zone ACL set — deny execute for %s in %s",
                         username, self.staging_dir)

            # Audit fix: Cleared/ lives INSIDE Downloads, so (OI)(CI) inheritance
            # propagated the deny-X onto it — "cleared" files could never run,
            # silently breaking the pipeline's core promise. Break inheritance
            # (keeping copies of inherited ACEs), then strip the deny.
            self._icacls(self.cleared_dir, "/inheritance:d")
            self._icacls(self.cleared_dir, "/remove:d", username)

            # Audit fix: quarantine had NORMAL permissions — a quarantined
            # executable was one double-click from running. Deny execute there too.
            self._icacls(self.quarantine_dir, "/remove:d", username)
            self._icacls(self.quarantine_dir, "/deny", f"{username}:(OI)(CI)(X)")
        except Exception as e:
            log.warning("GateKeeper: ACL setup failed (non-fatal): %s", e)

    def _icacls(self, target: Path, *args: str) -> bool:
        """Run one icacls command best-effort. Returns True on exit code 0."""
        try:
            result = subprocess.run(
                ["icacls", str(target), *args],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0:
                log.warning("GateKeeper: icacls %s %s failed (code %d): %s",
                            target, " ".join(args), result.returncode, result.stderr.strip())
            return result.returncode == 0
        except Exception as e:
            log.warning("GateKeeper: icacls %s failed: %s", target, e)
            return False

    # ------------------------------------------------------------------
    # File stability check
    # ------------------------------------------------------------------

    def _wait_for_stable(self, path: Path, max_wait: float = _STABILITY_MAX_WAIT) -> str:
        """
        Wait until the file size stops changing (download finished writing).
        Returns "stable", "vanished" (file gone), or "unstable" (still growing).
        """
        deadline = time.monotonic() + max_wait
        prev_size = -1

        while time.monotonic() < deadline:
            try:
                size = path.stat().st_size
            except OSError:
                return "vanished"  # file gone

            if size == prev_size and size > 0:
                return "stable"   # stable, non-empty

            prev_size = size
            time.sleep(_STABILITY_POLL_INTERVAL)

        # Audit fix: previously returned True here if size > 0 — a file still
        # being written was analyzed on partial content (wrong hash, wrong scan,
        # and in Phase 2 a possible CLEAN verdict for bytes that don't exist yet).
        try:
            path.stat()
            return "unstable"
        except OSError:
            return "vanished"


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


# ------------------------------------------------------------------
# C1 — Exact intel hard-override interface (Phase 3 populates the sets)
# ------------------------------------------------------------------

@dataclass
class ExactIntelResult:
    """Return type of exact_intel_check — a hit locks verdict before any neural path."""
    hit: bool
    matched_indicator: str = ""
    feed_source: str = ""        # openphish | urlhaus | abuseipdb | malwarebazaar
    indicator_type: str = ""     # url | domain | ip | hash

# Phase 3 / threat_feeds.py will populate these via exact_intel_load().
# Membership test is O(1). DO NOT collapse into ChromaDB — exact match ≠ similarity score.
_EXACT_URL_INDICATORS: set[str] = set()
_EXACT_DOMAIN_INDICATORS: set[str] = set()
_EXACT_IP_INDICATORS: set[str] = set()
_EXACT_HASH_INDICATORS: set[str] = set()


def exact_intel_check(
    link_urls: list[str] | None = None,
    link_domains: list[str] | None = None,
    sender_ip: str | None = None,       # C3: only pass when originating_ip_trusted=True
    attachment_sha256: list[str] | None = None,
) -> ExactIntelResult:
    """
    Symbolic exact-match indicator lookup.  Called BEFORE classifier/LLM (C1 contract).

    Any hit → verdict=SUSPICIOUS, confidence=0.95.  Classifier and LLM are skipped.
    Stub: all sets empty until Phase 3 threat_feeds.py calls exact_intel_load().

    Fuzzy/semantic matches belong in ChromaDB → LLM prompt (separate channel).
    """
    for url in (link_urls or []):
        if url in _EXACT_URL_INDICATORS:
            return ExactIntelResult(hit=True, matched_indicator=url,
                                    feed_source="openphish", indicator_type="url")
    for domain in (link_domains or []):
        if domain in _EXACT_DOMAIN_INDICATORS:
            return ExactIntelResult(hit=True, matched_indicator=domain,
                                    feed_source="urlhaus", indicator_type="domain")
    if sender_ip and sender_ip in _EXACT_IP_INDICATORS:
        return ExactIntelResult(hit=True, matched_indicator=sender_ip,
                                feed_source="abuseipdb", indicator_type="ip")
    for sha256 in (attachment_sha256 or []):
        if sha256 in _EXACT_HASH_INDICATORS:
            return ExactIntelResult(hit=True, matched_indicator=sha256,
                                    feed_source="malwarebazaar", indicator_type="hash")
    return ExactIntelResult(hit=False)


def exact_intel_load(
    urls: set[str] | None = None,
    domains: set[str] | None = None,
    ips: set[str] | None = None,
    hashes: set[str] | None = None,
) -> None:
    """Replace indicator sets atomically. Called by threat_feeds.py after each refresh."""
    global _EXACT_URL_INDICATORS, _EXACT_DOMAIN_INDICATORS
    global _EXACT_IP_INDICATORS, _EXACT_HASH_INDICATORS
    if urls is not None:
        _EXACT_URL_INDICATORS = urls
    if domains is not None:
        _EXACT_DOMAIN_INDICATORS = domains
    if ips is not None:
        _EXACT_IP_INDICATORS = ips
    if hashes is not None:
        _EXACT_HASH_INDICATORS = hashes
    log.info(
        "Exact intel loaded: %d URLs  %d domains  %d IPs  %d hashes",
        len(_EXACT_URL_INDICATORS), len(_EXACT_DOMAIN_INDICATORS),
        len(_EXACT_IP_INDICATORS), len(_EXACT_HASH_INDICATORS),
    )


def heuristic_verdict(
    features: dict, monitor_type: str = "file"
) -> tuple[str, float | None]:
    """
    Rule-based pre-inference heuristics for Gate 2 fallback and daemon direct pipeline.
    Returns (verdict, confidence) or (UNANALYZED, None).

    Called by gate_keeper (file events only) and daemon (file + email events).
    For email: C1 exact-intel override runs first; C2 independent per-signal scoring;
    C3 IP is only passed to intel queries when originating_ip_trusted=True.
    """
    score = 0.0

    if monitor_type == "file":
        ext: str = features.get("extension", "")

        # MZ/PE header in a non-executable extension — unambiguous masquerade
        magic_desc = features.get("magic_bytes_desc") or ""
        _EXE_EXTS = {'.exe', '.dll', '.scr', '.com', '.pif', '.msi', '.sys', '.ocx'}
        if ("MZ" in magic_desc or "PE executable" in magic_desc) and ext not in _EXE_EXTS:
            score += 0.75

        # Extension/MIME mismatch from python-magic (broader coverage)
        elif features.get("extension_mime_mismatch"):
            score += 0.4

        # Very high entropy on an executable (likely packed/encrypted)
        if features.get("entropy_is_high") and features.get("gate3_category") == "executable":
            score += 0.3

        # Origin domain registered < 7 days ago (brand-new = extreme risk)
        whois = features.get("whois") or {}
        age = whois.get("domain_age_days")
        if age is not None and age < 7:
            score += 0.35

    elif monitor_type == "email":
        # C1: Exact intel hard-override — checked BEFORE any scoring.
        # C3: sender_ip passed only when trusted — forged IP must not steer intel.
        trusted_ip: str | None = (
            features.get("originating_ip") or None
        ) if features.get("originating_ip_trusted") else None

        intel = exact_intel_check(
            link_urls=[lk["href"] for lk in features.get("links", []) if isinstance(lk, dict)],
            link_domains=features.get("link_domains") or [],
            sender_ip=trusted_ip,
            attachment_sha256=[],  # Part D populates attachment manifests
        )
        if intel.hit:
            log.warning(
                "Exact intel hit: %s [%s / %s] — verdict locked SUSPICIOUS",
                intel.matched_indicator, intel.feed_source, intel.indicator_type,
            )
            return "SUSPICIOUS", 0.95

        # C2: Score each signal independently — no auth_fails >= 2 floor.
        # Weights ordered by signal strength (tune against labeled data in Phase 8).

        # --- sender identity ---
        if features.get("reply_to_mismatch"):
            score += 0.30

        # --- auth failures (each scored independently) ---
        spf = (features.get("spf") or "").lower()
        dkim = (features.get("dkim") or "").lower()
        dmarc = (features.get("dmarc") or "").lower()

        # dmarc=fail means both SPF-alignment AND DKIM-alignment failed — strongest auth signal
        if dmarc == "fail":
            score += 0.35
        elif dmarc == "softfail":
            score += 0.15

        if spf == "fail":
            score += 0.25
        elif spf == "softfail":
            score += 0.10

        # dkim_aligned=False when dkim=pass but d= != from_domain (B3) — authenticated spoof
        if dkim == "pass" and not features.get("dkim_aligned", True):
            score += 0.25
        elif dkim == "fail":
            score += 0.15

        # --- behavioral flags from B1/B2 (catch auth-passing lookalikes) ---
        if features.get("any_link_lookalike"):
            score += 0.35
        if features.get("sender_lookalike"):
            score += 0.30
        if features.get("any_text_href_mismatch"):
            score += 0.30
        if features.get("reply_to_lookalike"):
            score += 0.20
        if features.get("any_link_raw_ip"):
            score += 0.20

        # --- structure ---
        if features.get("html_only"):
            score += 0.15

        # --- domain age ---
        whois_from = features.get("whois_from") or {}
        age = whois_from.get("domain_age_days")
        if age is not None and age < 7:
            score += 0.35
        elif age is not None and age < 30:
            score += 0.15

        whois_reply = features.get("whois_reply_to") or {}
        reply_age = whois_reply.get("domain_age_days")
        if reply_age is not None and reply_age < 30:
            score += 0.20

        # NOTE: Phase 3 AbuseIPDB scoring MUST gate on originating_ip_trusted (C3).
        # Use trusted_ip (already gated above) — never features["originating_ip"] directly.

    if score >= 0.6:
        return "SUSPICIOUS", min(round(score, 4), 0.95)

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

    # Test 6: C1 exact-intel override
    print("\nTest 6: C1 exact intel hard-override")
    # 6a: stub always returns hit=False
    r = exact_intel_check(link_urls=["http://evil.ru/steal"], link_domains=["evil.ru"])
    assert r.hit is False, "Stub must return hit=False"
    print("  6a: stub returns hit=False  PASSED")
    # 6b: populate a URL, verify hit
    exact_intel_load(urls={"http://known-phish.ru/login"})
    r2 = exact_intel_check(link_urls=["http://known-phish.ru/login"])
    assert r2.hit is True and r2.feed_source == "openphish"
    print("  6b: exact URL hit → hit=True, source=openphish  PASSED")
    # 6c: clean URL not in set → no hit
    r3 = exact_intel_check(link_urls=["https://fiverr.com/"])
    assert r3.hit is False
    print("  6c: unknown URL → hit=False  PASSED")
    # reset for subsequent tests
    exact_intel_load(urls=set())
    print("Test 6: PASSED")

    # Test 7: C2 email scoring — independent per-signal weights
    print("\nTest 7: C2 email auth scoring")
    # 7a: dmarc=fail must contribute independently — old floor (auth_fails>=2) blocked it
    # dmarc=fail(0.35) + reply_to_mismatch(0.30) = 0.65 → SUSPICIOUS
    # Old code: dmarc=fail is 1 fail < floor of 2, so score=0+0.30=0.30 → UNANALYZED
    v, conf = heuristic_verdict({"dmarc": "fail", "spf": "none", "dkim": "none",
                                  "html_only": False, "reply_to_mismatch": True}, "email")
    assert v == "SUSPICIOUS", f"dmarc=fail + reply_to_mismatch must now be SUSPICIOUS, got {v}"
    print(f"  7a: dmarc=fail + reply_to_mismatch → SUSPICIOUS (conf={conf})  PASSED")
    # 7b: authenticated lookalike + text_href_mismatch must cross threshold even with all-pass auth
    v2, conf2 = heuristic_verdict({
        "spf": "pass", "dkim": "pass", "dmarc": "pass",
        "dkim_aligned": True,
        "any_link_lookalike": True, "any_text_href_mismatch": True,
        "any_link_raw_ip": False, "sender_lookalike": False,
        "reply_to_mismatch": False, "reply_to_lookalike": False,
        "html_only": False,
    }, "email")
    assert v2 == "SUSPICIOUS", f"auth-passing lookalike + mismatch must be SUSPICIOUS, got {v2}"
    print(f"  7b: all-pass + lookalike + mismatch → SUSPICIOUS (conf={conf2})  PASSED")
    # 7c: C3 trust gate — forged IP must not reach exact_intel_check
    features_forged = {
        "originating_ip": "1.2.3.4", "originating_ip_trusted": False,
        "spf": "none", "dkim": "none", "dmarc": "none",
        "links": [], "link_domains": [], "html_only": False, "reply_to_mismatch": False,
    }
    exact_intel_load(ips={"1.2.3.4"})  # pretend this IP is known-bad
    v3, _ = heuristic_verdict(features_forged, "email")
    # Forged IP should NOT trigger the intel hit because originating_ip_trusted=False
    assert v3 == "UNANALYZED", f"Forged IP must not trigger intel hit, got {v3}"
    exact_intel_load(ips=set())
    print("  7c: forged IP (trusted=False) not scored by exact_intel  PASSED")
    print("Test 7: PASSED")

    print("\n=== All tests passed ===")
