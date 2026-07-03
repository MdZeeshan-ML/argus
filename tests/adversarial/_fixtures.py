# A.R.G.U.S. — Automated Real-time Guardian for User Systems
# Copyright (C) 2026  MdZeeshan-ML | GPL v3
"""
Adversarial test schema for A.R.G.U.S. — shared malicious-sample builders.

FRAMING
-------
Every file in tests/adversarial/ is written from the other side of the fence: a small
crew that scams freelancers and ships commodity malware, picking A.R.G.U.S.'s specific
protected user (a Fiverr/Upwork freelancer on Razorpay/PayU/UPI, running IIT Madras
coursework, installing requests/pandas/fastapi/etc. — see CLAUDE.local.md) and asking
"how do we get past this guardian and reach that person." Per instruction, this was
built by reasoning about a *finished* product from its documented architecture
(CLAUDE.md invariants + module docstrings + each module's own __main__ self-test) —
not by auditing gate_keeper/daemon/email_scanner line-by-line for implementation bugs.
The two things converge less than you'd think: an interface contract ("hard fact
overrides neural output", "exact match ≠ similarity score") already implies exactly
where an attacker would push (polymorphism to dodge the hash, freemail display-name
spoofing to dodge the domain check) without ever reading a function body.

SCOPE / HONESTY RULES
----------------------
- Every test_* function calls real, currently-built ARGUS code and asserts a real
  property against it. On a second pass (Zeeshan's explicit call, in-session), this
  suite dropped its earlier spec_*/NotImplementedError stubs for Phase 2 (inference),
  Phase 3 (RAG/threat_feeds), and Phase 9 (supply-chain guard) — none of that exists
  yet, and testing code that doesn't exist yet was judged not worth the shelf space
  next to the layers that ARE built. Every remaining test here exercises file_watcher,
  feature_extractor, gate_keeper (the symbolic/heuristic layer — built ahead of any
  neural layer), email_scanner, or logger — the actual Phase-1 surface.
- FINDINGS.md in this directory catalogs every real gap/vulnerability this suite
  surfaced, in plain language, cross-referenced to the test that proves it. Read that
  first if you want the "so what," not the test code.
- Known gaps the suite deliberately does NOT assert pass/fail on (documented instead,
  because I can't verify the internals without the line-by-line audit I was told to
  skip): true TOCTOU on gate_keeper._move_to_quarantine/icacls timing, real .lnk binary
  parsing, anything requiring the Windows boot (icacls, MpCmdRun, Windows Sandbox — see
  CLAUDE.local.md "Platform Coupling"). These run happily on Linux because gate_keeper
  is written to degrade gracefully when those are absent (verified empirically: its own
  __main__ self-test passes on this Linux dev box), which is enough surface for the
  cross-platform gate logic these tests target.

> **Contradiction:** CLAUDE.md Hard Rule 10 says "Never write tests before the module
> being tested is complete." Several modules here (Phase 2 inference, Phase 3 intel
> feeds, Phase 9 supply-chain) are not complete — some are empty packages. Writing this
> suite anyway was an explicit, direct instruction for this task ("ignoring the fact
> that the project is yet to be complete"), so Rule 10 was overridden for this session
> rather than silently followed or silently ignored. Flagging per Hard Rule 12.

HOW TO RUN
----------
Each test_*.py is self-executing as a plain script (no pytest installed/approved —
see _runner.py), matching how every argus/*.py module runs its own __main__ self-test:
    python tests/adversarial/test_email_social_engineering.py
    ... or all of them in one pass:
    python tests/adversarial/run_all.py
Run as a script (not `-m`) so Python's automatic sys.path[0]=script-dir makes the
bare `import _fixtures` / `import _runner` sibling imports resolve.
"""

from __future__ import annotations

import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# Repo root on sys.path so `import argus...` works regardless of CWD/PYTHONPATH,
# matching how every module's own __main__ self-test is invoked (`python -m argus.X`).
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------------------
# File-side malicious samples
# ------------------------------------------------------------------

def build_pe_masquerade(dir_: Path, filename: str) -> Path:
    """MZ/PE header wrapped in a non-executable extension — 'invoice.pdf' that's an .exe.

    Why: the fastest way past a human ("does this file look dangerous?") and past any
    extension-allowlist filter that never opens the file to check. Real ransomware
    droppers use exactly this — rename the payload, let Explorer's icon lie for you.
    """
    p = dir_ / filename
    p.write_bytes(b"\x4d\x5a\x90\x00" + bytes(range(256)) * 64)  # MZ header + filler
    return p


def build_double_extension_lure(dir_: Path, lure_name: str, real_ext: str) -> Path:
    """'Contract_Signed.pdf.exe' — Windows hides known extensions by default, so the
    victim sees 'Contract_Signed.pdf' in Explorer and double-clicks a PE.
    """
    p = dir_ / f"{lure_name}.pdf{real_ext}"
    p.write_bytes(b"\x4d\x5a\x90\x00" + b"\x00" * 200)
    return p


def build_macro_docm_as_doc(dir_: Path, filename: str) -> Path:
    """OOXML zip carrying vbaProject.bin, saved under a '.doc' name.

    Why: macro payloads are still the #1 delivery vector for freelance-platform 'client
    brief' lures (CLAUDE.local.md names this exact threat). Forcing the extension to
    .doc instead of .docm is a cheap trick against any extension-based macro filter —
    the payload only reveals itself once something actually opens the zip.
    """
    p = dir_ / filename
    with zipfile.ZipFile(str(p), "w") as zf:
        zf.writestr("word/document.xml", "<w:document/>")
        zf.writestr("word/vbaProject.bin", b"\x00" * 64)
    return p


def build_polyglot_pdf_with_trailing_pe(dir_: Path, filename: str) -> Path:
    """Valid '%PDF-1.4' header (what any header-only magic check sees) with a complete
    MZ/PE blob appended after %%EOF (what a second-stage tool, or a renamed copy of this
    same file, would execute).

    Why: PDF readers ignore trailing bytes after %%EOF; a header-only or offset-0-only
    magic check sees a clean PDF and stops looking. This is the textbook polyglot
    technique (see: GIFAR-style attacks) — cheap to build, expensive to detect without
    scanning the whole file for a second signature.
    """
    p = dir_ / filename
    payload = (
        b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
        b"1 0 obj<</Type/Catalog>>endobj\n"
        b"trailer<</Root 1 0 R>>\n%%EOF\n"
        b"\x4d\x5a\x90\x00" + bytes(range(256)) * 16  # appended PE payload
    )
    p.write_bytes(payload)
    return p


def build_url_shortcut(dir_: Path, filename: str, target_url: str) -> Path:
    """Windows Internet Shortcut (.url) — plain text, no PE header, no macro. Delivers
    a browser navigation to an exploit kit / credential-harvest page instead of a file
    payload, sidestepping every file-content-based check entirely.
    """
    p = dir_ / filename
    p.write_text(f"[InternetShortcut]\nURL={target_url}\n")
    return p


def build_zip_bomb(dir_: Path, filename: str, *, inner_files: int = 20,
                    inner_size: int = 200_000) -> Path:
    """Nested-archive resource-exhaustion sample, deliberately scaled down (a few
    hundred KB on disk, a few MB decompressed) so the test suite stays fast and CI-safe
    — the point is to prove the *shape* of the DoS (small compressed, large/expensive
    to fully expand), not to actually launch a multi-GB bomb at a dev laptop.

    Why: if a scanner naively decompresses everything before hashing/entropy-checking,
    a malware author can stall or crash the single scanning thread for free, buying a
    window to drop a second, real payload while the guardian is blind.
    """
    p = dir_ / filename
    highly_compressible = b"\x00" * inner_size
    with zipfile.ZipFile(str(p), "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for i in range(inner_files):
            zf.writestr(f"payload_{i}.bin", highly_compressible)
    return p


# ------------------------------------------------------------------
# Email-side malicious event builders
# ------------------------------------------------------------------

def build_email_event(
    *,
    from_domain: str,
    reply_to_domain: str | None = None,
    reply_to_mismatch: bool = False,
    spf: str = "pass",
    dkim: str = "pass",
    dkim_d: str | None = None,
    dmarc: str = "pass",
    links: list[dict] | None = None,
    html_only: bool = True,
    has_attachments: bool = False,
    originating_ip: str | None = None,
    originating_ip_trusted: bool = False,
) -> dict:
    """Build an event dict matching the shape FeatureExtractor._extract_email expects
    (mirrors argus/analysis/feature_extractor.py's own __main__ self-test event).
    """
    reply_to_domain = reply_to_domain if reply_to_domain is not None else from_domain
    metadata: dict = {
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "reply_to_mismatch": reply_to_mismatch,
        "spf": spf,
        "dkim": dkim,
        "dkim_d": dkim_d if dkim_d is not None else from_domain,
        "dmarc": dmarc,
        "has_external_links": bool(links),
        "links": links or [],
        "has_attachments": has_attachments,
        "html_only": html_only,
        "subject": "[SENSITIVE — stripped before cloud inference]",
        "_sensitive_fields": ["subject"],
    }
    if originating_ip is not None:
        metadata["originating_ip"] = originating_ip
        metadata["originating_ip_trusted"] = originating_ip_trusted
    return {
        "source": "email_scanner",
        "event_type": "new_email",
        "timestamp": now_iso(),
        "metadata": metadata,
    }


def build_file_event(path: Path, *, staged: bool = True) -> dict:
    """Event dict matching file_watcher's real output shape (on_created/on_moved)."""
    return {
        "source": "file_watcher",
        "path": str(path),
        "event_type": "created",
        "staged": staged,
        "timestamp": now_iso(),
    }
