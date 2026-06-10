# A.R.G.U.S. — Automated Real-time Guardian for User Systems
# Copyright (C) 2026  MdZeeshan-ML | GPL v3
"""
IMAP email scanner — polls for new messages and extracts metadata + links.

Privacy rules enforced here:
  - BODY.PEEK[] is used throughout — emails are NEVER marked as read in Gmail.
  - SELECT is readonly=True — server rejects any accidental flag mutations.
  - Body is read ONLY to extract URL strings. The body text itself is never
    stored, logged, or passed to any LLM.
  - Subject is tagged _sensitive so the inference router strips it before
    cloud calls (local inference sees the full subject).
  - UID state is persisted to ~/.argus/email_state.json. On first run,
    existing emails are skipped — Argus watches new arrivals only.

Attachment downloading and Windows Defender scanning live in the
quarantine/response layer (Phase 4). This module only extracts metadata.
"""

import contextlib
import email
import email.header
import email.message
import imaplib
import json
import logging
import os
import queue
import re
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Cap to avoid flooding the queue on a busy inbox
_MAX_PER_POLL = 20

# URL extraction patterns
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)

# IP extraction from Received headers: matches [1.2.3.4] notation
_RECEIVED_IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")

# Private ranges to skip when looking for the true originating IP
_PRIVATE_PREFIXES = (
    "10.", "192.168.", "127.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)


# ---------------------------------------------------------------------------
# Pure helper functions — all testable without a live connection
# ---------------------------------------------------------------------------

def _decode_header(raw: str | bytes | None) -> str:
    """Decode RFC 2047-encoded header values (e.g. '=?UTF-8?Q?..?=')."""
    if not raw:
        return ""
    # Audit fix: an attacker-supplied bogus charset ('=?evil?Q?x?=') raised
    # LookupError here, aborting the entire poll cycle on one crafted email.
    try:
        parts = email.header.decode_header(str(raw))
    except Exception:
        return str(raw)
    decoded = []
    for chunk, charset in parts:
        if isinstance(chunk, bytes):
            try:
                decoded.append(chunk.decode(charset or "utf-8", errors="replace"))
            except (LookupError, UnicodeError):
                decoded.append(chunk.decode("utf-8", errors="replace"))
        else:
            decoded.append(chunk)
    return "".join(decoded)


def _extract_domain(addr: str) -> str:
    """Pull domain from 'Name <user@domain.com>' or 'user@domain.com'."""
    m = re.search(r"@([\w.\-]+)", addr)
    return m.group(1).lower() if m else ""


def _parse_auth_results(header_val: str) -> dict[str, str]:
    """
    Parse the Authentication-Results header for SPF, DKIM, DMARC verdicts.
    Gmail sets this on every inbound message — it's the authoritative auth record.
    """
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for proto in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{proto}=(\w+)", header_val, re.IGNORECASE)
        if m:
            results[proto] = m.group(1).lower()
    return results


def _extract_originating_ip(msg: email.message.Message) -> str:
    """
    Best-effort extraction of the true sender IP.
    Checks X-Originating-IP first; falls back to the last external IP
    found in the Received chain (last header = closest to origin).
    """
    xip = msg.get("X-Originating-IP", "").strip()
    if xip and not any(xip.startswith(p) for p in _PRIVATE_PREFIXES):
        return xip

    # Walk Received headers in reverse — last added is closest to the sending server
    received_headers = msg.get_all("Received") or []
    for received in reversed(received_headers):
        for m in _RECEIVED_IP_RE.finditer(received):
            ip = m.group(1)
            if not any(ip.startswith(p) for p in _PRIVATE_PREFIXES):
                return ip
    return ""


def _extract_links(msg: email.message.Message) -> list[str]:
    """
    Walk MIME parts and extract up to 10 unique external URLs.

    HTML parts: extracts <a href="..."> values.
    Plain text parts: extracts bare URLs via regex.
    The raw body text is read temporarily and immediately discarded —
    only the URL strings themselves are returned.
    """
    raw_urls: list[str] = []

    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype not in ("text/html", "text/plain"):
            continue
        try:
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace")
        except Exception:
            continue

        if ctype == "text/html":
            raw_urls.extend(_HREF_RE.findall(text))
        else:
            raw_urls.extend(_URL_RE.findall(text))

    # Deduplicate, keep only http(s), strip trailing punctuation, cap at 10
    seen: set[str] = set()
    clean: list[str] = []
    for url in raw_urls:
        url = url.strip().rstrip(".,;)>\"'")
        if not url.startswith(("http://", "https://")):
            continue
        if len(url) < 10 or url in seen:
            continue
        seen.add(url)
        clean.append(url)
        if len(clean) >= 10:
            break
    return clean


def extract_metadata(msg: email.message.Message) -> dict[str, Any]:
    """
    Extract all threat-relevant metadata from a parsed email.Message.

    Pure function — no network calls, no file I/O.
    Returns a dict suitable for the 'features' field in the incidents table.
    Subject is flagged in _sensitive_fields so the router can strip it
    before cloud inference while keeping it for local inference.
    """
    from_raw = msg.get("From", "")
    reply_to_raw = msg.get("Reply-To", "")
    auth_raw = msg.get("Authentication-Results", "")

    from_domain = _extract_domain(from_raw)
    reply_to_domain = _extract_domain(reply_to_raw) if reply_to_raw else from_domain
    auth = _parse_auth_results(auth_raw)

    # MIME structure scan — determines attachments and content types
    attachment_names: list[str] = []
    attachment_mimes: list[str] = []
    content_types: set[str] = set()
    has_attachments = False

    for part in msg.walk():
        ctype = part.get_content_type()
        content_types.add(ctype)
        disposition = part.get_content_disposition() or ""
        if "attachment" in disposition.lower():
            has_attachments = True
            filename = part.get_filename()
            if filename:
                attachment_names.append(_decode_header(filename))
            attachment_mimes.append(ctype)

    # Legitimate newsletters have text/plain + text/html; phishing is HTML-only
    html_only = (
        "text/html" in content_types and "text/plain" not in content_types
    )

    links = _extract_links(msg)

    return {
        "message_id": msg.get("Message-ID", "").strip(),
        "from_addr": from_raw,
        "from_domain": from_domain,
        "reply_to": reply_to_raw,
        "reply_to_domain": reply_to_domain,
        # Differs from From domain = spoofed reply-path, a strong phishing signal
        "reply_to_mismatch": bool(reply_to_raw) and (reply_to_domain != from_domain),
        "subject": _decode_header(msg.get("Subject", "")),
        "date": msg.get("Date", ""),
        "spf": auth["spf"],
        "dkim": auth["dkim"],
        "dmarc": auth["dmarc"],
        "originating_ip": _extract_originating_ip(msg),
        "has_attachments": has_attachments,
        "attachment_names": attachment_names,
        "attachment_mimes": attachment_mimes,
        "has_external_links": bool(links),
        "links": links,
        "html_only": html_only,
        # Router reads this list and redacts matching keys before cloud inference
        "_sensitive_fields": ["subject"],
    }


# ---------------------------------------------------------------------------
# State management — persists last-processed UID per folder
# ---------------------------------------------------------------------------

def _load_state(state_path: Path) -> dict:
    """Load UID tracking state. Returns empty dict on missing or corrupt file."""
    if not state_path.exists():
        return {}
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        log.warning("Corrupted email state — resetting: %s", state_path)
        return {}


def _save_state(state: dict, state_path: Path) -> None:
    """Atomically write state. Temp file + os.replace() prevents partial writes."""
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=state_path.parent, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp_path, state_path)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------

class EmailScanner:
    """
    Polls an IMAP inbox for new messages on a configurable interval.

    Key guarantees:
      - Gmail read/unread state is never touched (BODY.PEEK + readonly SELECT).
      - Restarts resume from the last processed UID — no re-processing.
      - First run skips all existing emails and watches only new arrivals.
      - Connection is opened fresh per poll and closed in a finally block.
    """

    def __init__(
        self,
        event_queue: queue.Queue,
        imap_server: str,
        imap_port: int,
        email_address: str,
        password: str,
        poll_interval_minutes: int = 15,
        folders: list[str] | None = None,
        state_path: Path | None = None,
    ) -> None:
        self._queue = event_queue
        self._server = imap_server
        self._port = imap_port
        self._address = email_address
        self._password = password
        self._interval = poll_interval_minutes * 60
        self._folders = folders or ["INBOX"]
        self._state_path = state_path or (Path.home() / ".argus" / "email_state.json")
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Spawn the polling thread."""
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="email-scanner"
        )
        self._thread.start()
        log.info(
            "EmailScanner started — folders=%s, poll every %d min",
            self._folders,
            self._interval // 60,
        )

    def stop(self) -> None:
        """Signal stop and wait for the thread to exit (wakes immediately)."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        log.info("EmailScanner stopped")

    # ------------------------------------------------------------------
    # Polling loop
    # ------------------------------------------------------------------

    def _run(self) -> None:
        """Poll immediately on start, then wait for interval or stop signal."""
        while not self._stop.is_set():
            try:
                self._poll()
            except Exception:
                log.exception("EmailScanner poll cycle failed")
            self._stop.wait(timeout=self._interval)

    def _poll(self) -> None:
        """Open a connection, scan all configured folders, save state."""
        conn = self._connect()
        if conn is None:
            return

        state = _load_state(self._state_path)
        try:
            for folder in self._folders:
                # Audit fix: one folder failing must not skip the rest,
                # and partial progress must persist (state saved in finally).
                try:
                    self._poll_folder(conn, folder, state)
                except Exception:
                    log.exception("Poll failed for folder %s — continuing", folder)
        finally:
            with contextlib.suppress(Exception):
                conn.logout()
            _save_state(state, self._state_path)

    def _poll_folder(
        self, conn: imaplib.IMAP4_SSL, folder: str, state: dict
    ) -> None:
        """Fetch new UIDs in one folder and process them. Mutates state in-place."""
        status, _ = conn.select(folder, readonly=True)
        if status != "OK":
            log.warning("SELECT failed for folder %s: %s", folder, status)
            return
        folder_state = state.setdefault(folder, {})

        # First run: record the current high-water UID and exit.
        # All existing emails are skipped; only future arrivals are scanned.
        if not folder_state.get("initialized"):
            status, data = conn.uid("search", None, "ALL")
            existing = data[0].split() if status == "OK" and data[0] else []
            last_uid = int(existing[-1]) if existing else 0
            folder_state["last_uid"] = last_uid
            folder_state["initialized"] = True
            log.info(
                "First run: folder=%s last_uid=%d (skipping %d existing emails)",
                folder, last_uid, len(existing),
            )
            return

        last_uid: int = folder_state.get("last_uid", 0)

        # UID last+1:* means "all UIDs from last+1 to the highest in the folder"
        status, data = conn.uid("search", None, f"UID {last_uid + 1}:*")
        if status != "OK":
            log.warning("UID SEARCH failed on %s: %s", folder, status)
            return

        # Filter strictly: the server may return last_uid itself if it's the max
        new_uids = [u for u in data[0].split() if int(u) > last_uid]
        if not new_uids:
            log.debug("No new emails in %s", folder)
            return

        # Audit fix: was [-_MAX_PER_POLL:] (newest 20) — older emails in a burst
        # were skipped FOREVER because last_uid jumped past them. Oldest-first
        # means the remainder is picked up on the next poll. No email is missed.
        to_process = new_uids[:_MAX_PER_POLL]
        log.info(
            "Found %d new email(s) in %s, processing %d",
            len(new_uids), folder, len(to_process),
        )
        if len(new_uids) > _MAX_PER_POLL:
            log.info("Remaining %d email(s) deferred to next poll", len(new_uids) - _MAX_PER_POLL)

        max_uid = last_uid
        for uid in to_process:
            # Audit fix: per-message isolation — a single malformed (or crafted)
            # message must not abort the poll or block emails behind it.
            try:
                self._process_message(conn, uid, folder)
            except Exception:
                log.exception("Failed to process UID %s in %s — skipped", uid, folder)
            max_uid = max(max_uid, int(uid))
            # Advance high-water mark per message so a later crash never re-serves
            # an already-handled (or poison) UID.
            folder_state["last_uid"] = max_uid

        folder_state["last_poll"] = datetime.now(timezone.utc).isoformat()

    def _process_message(
        self, conn: imaplib.IMAP4_SSL, uid: bytes, folder: str
    ) -> None:
        """Fetch full message (no read-flag set), extract metadata, enqueue event."""
        status, data = conn.uid("fetch", uid, "(BODY.PEEK[])")
        if status != "OK":
            log.warning("FETCH failed for UID %s in %s", uid, folder)
            return

        # data is [(b'UID ... {size}', b'<raw bytes>'), b')']
        raw_bytes = next(
            (item[1] for item in data if isinstance(item, tuple) and len(item) >= 2),
            None,
        )
        if not raw_bytes:
            log.warning("Empty message body for UID %s in %s", uid, folder)
            return

        msg = email.message_from_bytes(raw_bytes)
        metadata = extract_metadata(msg)

        # Build a compact human-readable summary for logging + SQLite input_summary
        parts = [f"from={metadata['from_domain']}"]
        if metadata["reply_to_mismatch"]:
            parts.append(f"reply_to={metadata['reply_to_domain']} [MISMATCH]")
        if metadata["attachment_names"]:
            parts.append(f"attach={metadata['attachment_names']}")
        if metadata["links"]:
            parts.append(f"links={len(metadata['links'])}")
        summary = " | ".join(parts)

        entry = {
            "source": "email_scanner",
            "event_type": "new_email",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "metadata": metadata,
        }
        self._queue.put(entry)

        log.info(
            "Queued: %s | spf=%s dkim=%s dmarc=%s | subj=%r",
            summary,
            metadata["spf"],
            metadata["dkim"],
            metadata["dmarc"],
            metadata["subject"][:60],
        )

    def _connect(self) -> imaplib.IMAP4_SSL | None:
        """Open and authenticate an IMAP SSL connection. Returns None on failure."""
        try:
            conn = imaplib.IMAP4_SSL(self._server, self._port)
            conn.login(self._address, self._password)
            return conn
        except imaplib.IMAP4.error as exc:
            log.error("IMAP login failed: %s", exc)
            return None
        except OSError as exc:
            log.error("IMAP connection error: %s", exc)
            return None


# ---------------------------------------------------------------------------
# Standalone test — no live IMAP connection required
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import textwrap

    logging.basicConfig(
        level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s"
    )

    print("=" * 60)
    print("Test 1: Clean email from a legitimate sender")
    print("=" * 60)

    raw_clean = textwrap.dedent("""\
        From: Fiverr Notifications <no-reply@fiverr.com>
        Reply-To: no-reply@fiverr.com
        To: zeeshan@example.com
        Subject: You have a new order!
        Date: Sun, 08 Jun 2026 10:00:00 +0000
        Message-ID: <abc123@mail.fiverr.com>
        Authentication-Results: mx.google.com;
               spf=pass smtp.mailfrom=no-reply@fiverr.com;
               dkim=pass header.i=@fiverr.com;
               dmarc=pass header.from=fiverr.com
        Received: from mail.fiverr.com (mail.fiverr.com [104.18.22.45])
               by mx.google.com; Sun, 08 Jun 2026 10:00:00 +0000
        Content-Type: text/plain

        You have received a new order. Visit fiverr.com to manage it.
    """)
    msg_clean = email.message_from_string(raw_clean)
    m = extract_metadata(msg_clean)
    for k, v in m.items():
        print(f"  {k}: {v}")
    assert m["from_domain"] == "fiverr.com"
    assert m["spf"] == "pass"
    assert m["dkim"] == "pass"
    assert m["dmarc"] == "pass"
    assert m["reply_to_mismatch"] is False
    assert m["has_attachments"] is False
    assert m["originating_ip"] == "104.18.22.45"
    print("  PASSED\n")

    print("=" * 60)
    print("Test 2: Phishing email -- Reply-To mismatch + SPF fail + HTML links")
    print("=" * 60)

    raw_phish = textwrap.dedent("""\
        From: PayPal Security <security@paypal.com>
        Reply-To: harvest@evil-domain.ru
        To: zeeshan@example.com
        Subject: =?UTF-8?Q?Your_account_has_been_limited_=E2=80=94_verify_now?=
        Date: Sun, 08 Jun 2026 09:55:00 +0000
        Message-ID: <xyz789@evil-domain.ru>
        Authentication-Results: mx.google.com;
               spf=fail smtp.mailfrom=paypal.com;
               dkim=fail header.i=@paypal.com;
               dmarc=fail
        Received: from evil-domain.ru (evil-domain.ru [185.220.101.34])
               by mx.google.com; Sun, 08 Jun 2026 09:55:00 +0000
        Content-Type: multipart/mixed; boundary="bound"

        --bound
        Content-Type: text/html; charset=utf-8

        <html><body>
        <p>Your account is limited. <a href="http://paypa1-secure.ru/login?t=abc">Verify now</a></p>
        <a href="https://bit.ly/3xK9mPQ">Click here</a>
        </body></html>

        --bound
        Content-Type: application/octet-stream
        Content-Disposition: attachment; filename="invoice_overdue.exe"

        FAKEPAYLOAD

        --bound--
    """)
    msg_phish = email.message_from_string(raw_phish)
    m = extract_metadata(msg_phish)
    for k, v in m.items():
        print(f"  {k}: {v}")
    assert m["from_domain"] == "paypal.com"
    assert m["reply_to_domain"] == "evil-domain.ru"
    assert m["reply_to_mismatch"] is True
    assert m["spf"] == "fail"
    assert m["dkim"] == "fail"
    assert m["dmarc"] == "fail"
    assert m["originating_ip"] == "185.220.101.34"
    assert m["has_attachments"] is True
    assert "invoice_overdue.exe" in m["attachment_names"]
    assert m["has_external_links"] is True
    assert any("paypa1-secure.ru" in link for link in m["links"])
    assert "verify now" in m["subject"].lower()  # RFC 2047 decoded
    print("  PASSED\n")

    print("=" * 60)
    print("Test 3: HTML-only email (no text/plain) — phishing structure signal")
    print("=" * 60)

    raw_html_only = textwrap.dedent("""\
        From: Upwork <noreply@upwork.com>
        To: zeeshan@example.com
        Subject: Action required on your account
        Date: Sun, 08 Jun 2026 11:00:00 +0000
        Message-ID: <html1@upwork.com>
        Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
        Content-Type: text/html; charset=utf-8

        <html><body>Click <a href="https://upw0rk-verify.tk/confirm">here</a></body></html>
    """)
    msg_html = email.message_from_string(raw_html_only)
    m = extract_metadata(msg_html)
    assert m["html_only"] is True
    assert any("upw0rk-verify.tk" in link for link in m["links"])
    print(f"  html_only={m['html_only']}  links={m['links']}")
    print("  PASSED\n")

    print("=" * 60)
    print("Test 4: State file save/load round-trip")
    print("=" * 60)

    import tempfile as _tmpmod
    with _tmpmod.TemporaryDirectory() as tmp:
        sp = Path(tmp) / "email_state.json"
        initial = _load_state(sp)
        assert initial == {}
        state = {"INBOX": {"last_uid": 12345, "initialized": True}}
        _save_state(state, sp)
        loaded = _load_state(sp)
        assert loaded["INBOX"]["last_uid"] == 12345
        assert loaded["INBOX"]["initialized"] is True
        print(f"  Saved and loaded: {loaded}")
        print("  PASSED\n")

    print("All tests passed.")
    print("(Live IMAP test: run with real .env credentials in integration test)")
