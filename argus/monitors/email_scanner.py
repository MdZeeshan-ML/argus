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

Attachment bytes are never fetched by this module. Filename metadata
(double_extension, dangerous_ext, size_bytes) is recorded from BODYSTRUCTURE.
When the user downloads an attachment naturally, file_watcher catches it
in ~/Downloads and the existing gate pipeline runs. Email and file incidents
are linked via correlation_id.
"""

import contextlib
import email
import email.header
import email.message
import html.parser
import imaplib
import json
import logging
import os
import queue
import random
import re
import tempfile
import threading
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Cap to avoid flooding the queue on a busy inbox
_MAX_PER_POLL = 20

# Exponential backoff for connect failures (Gap 13)
_BACKOFF_BASE_SECONDS = 30    # first retry after ~30 s
_BACKOFF_MAX_SECONDS = 900    # cap at 15 minutes
_AUTH_INCIDENT_THRESHOLD = 3  # consecutive auth failures before emitting an incident

# URL extraction pattern — used for text/plain parts only
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)

# Per-part and per-message size caps used by the two-phase IMAP fetch (A5)
MAX_PART_BYTES = 5 * 1024 * 1024      # 5 MB — skip any single MIME part above this
MAX_MESSAGE_BYTES = 25 * 1024 * 1024  # 25 MB — stop fetching further parts beyond this total

_DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".psd1", ".psm1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msi",
    ".msp", ".hta", ".lnk", ".iso", ".img", ".dll", ".sys",
    ".jar", ".reg", ".com", ".pif", ".cpl", ".msc", ".inf",
})


def _double_extension(filename: str) -> bool:
    """Return True when a dangerous outer extension hides an inner one (invoice.pdf.exe)."""
    p = Path(filename)
    if not p.suffix or p.suffix.lower() not in _DANGEROUS_EXTENSIONS:
        return False
    return bool(Path(p.stem).suffix)

class _AnchorParser(html.parser.HTMLParser):
    """
    Collect (href, anchor_text) pairs from <a href="..."> elements.

    convert_charrefs=True decodes HTML entities in both text nodes and
    attribute values, so &#x70;&#x61;&#x79;&#x70;&#x61;&#x6c; in an href
    is returned as the decoded string, not the raw entity sequence.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        if self._current_href is not None:
            # Malformed nested <a> — flush the open anchor before starting new one
            self.links.append((self._current_href, "".join(self._text_parts).strip()))
        href = dict(attrs).get("href") or ""
        self._current_href = href.strip()
        self._text_parts = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_href is not None:
            self.links.append((self._current_href, "".join(self._text_parts).strip()))
            self._current_href = None
            self._text_parts = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._text_parts.append(data)

# IP extraction from Received headers: matches [1.2.3.4] notation
_RECEIVED_IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")

# Extracts the hostname from the 'by <host>' clause of a Received header
_RECEIVED_BY_RE = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)

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

def _parse_int_response(responses: list | None) -> int | None:
    """Parse the first value from an imaplib untagged_responses list to int."""
    if not responses:
        return None
    try:
        val = responses[0]
        return int(val.decode() if isinstance(val, bytes) else val)
    except (TypeError, ValueError, AttributeError):
        return None


def _extract_literal(data: list) -> bytes | None:
    """Return the first literal payload from an imaplib FETCH response data list."""
    return next(
        (
            item[1]
            for item in data
            if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes)
        ),
        None,
    )


def _extract_balanced_paren(s: str, start: int) -> str | None:
    """Return the balanced parenthesized substring of s starting at s[start]."""
    if start >= len(s) or s[start] != "(":
        return None
    depth = 0
    i = start
    in_quote = False
    while i < len(s):
        c = s[i]
        if in_quote:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_quote = False
        else:
            if c == '"':
                in_quote = True
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return s[start : i + 1]
        i += 1
    return None


def _find_bodystructure_str(data: list) -> str | None:
    """
    Locate the BODYSTRUCTURE keyword in an imaplib FETCH response and return
    the balanced parenthesized expression that follows it, or None.
    """
    for item in data:
        raw = item[0] if isinstance(item, tuple) else item
        if not isinstance(raw, bytes):
            continue
        try:
            s = raw.decode("ascii", errors="replace")
        except Exception:
            continue
        m = re.search(r"\bBODYSTRUCTURE\s+", s, re.IGNORECASE)
        if not m:
            continue
        paren_start = s.find("(", m.end())
        if paren_start == -1:
            continue
        result = _extract_balanced_paren(s, paren_start)
        if result:
            return result
    return None


def _tokenize_bs(s: str) -> list:
    """
    Tokenize an IMAP BODYSTRUCTURE S-expression string into a nested Python list.

    Quoted strings → str.  NIL → None.  Integers → int.
    Parenthesized groups → list (recursed).
    """
    tokens: list = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c in (" ", "\t", "\r", "\n"):
            i += 1
        elif c == "(":
            # Find matching ')' while tracking depth and quoted strings
            depth = 1
            j = i + 1
            in_q = False
            while j < n and depth > 0:
                if in_q:
                    if s[j] == "\\":
                        j += 1  # skip escaped char
                    elif s[j] == '"':
                        in_q = False
                elif s[j] == '"':
                    in_q = True
                elif s[j] == "(":
                    depth += 1
                elif s[j] == ")":
                    depth -= 1
                j += 1
            tokens.append(_tokenize_bs(s[i + 1 : j - 1]))
            i = j
        elif c == '"':
            j = i + 1
            while j < n:
                if s[j] == "\\":
                    j += 2
                    continue
                if s[j] == '"':
                    break
                j += 1
            tokens.append(s[i + 1 : j])
            i = j + 1
        else:
            j = i
            while j < n and s[j] not in (" ", "\t", "\r", "\n", "(", ")", '"'):
                j += 1
            atom = s[i:j]
            if atom.upper() == "NIL":
                tokens.append(None)
            else:
                try:
                    tokens.append(int(atom))
                except ValueError:
                    tokens.append(atom)
            i = j
    return tokens


def _walk_bs_parts(tree: list, prefix: str = "") -> list[dict]:
    """
    Recursively walk a tokenized BODYSTRUCTURE tree and return a flat list of
    MIME parts.  Each entry has: part_num, type, subtype, size, filename,
    disposition.

    Part numbering follows RFC 3501: simple messages have part "1"; multipart
    sub-parts are numbered by position with dot-separated nesting for depth > 1.
    """
    if not tree:
        return []
    # Multipart: first element is itself a list (a child part token list)
    if isinstance(tree[0], list):
        parts: list[dict] = []
        idx = 0
        while idx < len(tree) and isinstance(tree[idx], list):
            child_prefix = f"{prefix}.{idx + 1}" if prefix else str(idx + 1)
            parts.extend(_walk_bs_parts(tree[idx], child_prefix))
            idx += 1
        return parts
    # Single-part: tree[0] is the media-type string
    type_ = (tree[0] or "").lower()
    subtype = (tree[1] or "").lower() if len(tree) > 1 else ""
    # Body params (tree[2]) — flat alternating key/value list
    filename: str | None = None
    if len(tree) > 2 and isinstance(tree[2], list):
        params = tree[2]
        for ki in range(0, len(params) - 1, 2):
            k, v = params[ki], params[ki + 1]
            if isinstance(k, str) and k.upper() in ("NAME", "FILENAME") and isinstance(v, str):
                filename = v
                break
    # Octet count at index 6 for both text and non-text parts (RFC 3501 §7.4.2)
    size = tree[6] if len(tree) > 6 and isinstance(tree[6], int) else 0
    # Content-Disposition lives in body-ext-1part: index 8 for text parts
    # (which have a "lines" field at index 7), index 7 for all others.
    # Verify the first element names a real disposition type before trusting it.
    disposition: str | None = None
    for disp_idx in (8, 7):
        if len(tree) > disp_idx and isinstance(tree[disp_idx], list) and tree[disp_idx]:
            disp_raw = tree[disp_idx]
            if isinstance(disp_raw[0], str) and disp_raw[0].upper() in ("ATTACHMENT", "INLINE"):
                disposition = disp_raw[0].lower()
                if not filename and len(disp_raw) > 1 and isinstance(disp_raw[1], list):
                    dparams = disp_raw[1]
                    for ki in range(0, len(dparams) - 1, 2):
                        k, v = dparams[ki], dparams[ki + 1]
                        if isinstance(k, str) and k.upper() == "FILENAME" and isinstance(v, str):
                            filename = v
                            break
                break
    part_num = prefix if prefix else "1"
    return [{"part_num": part_num, "type": type_, "subtype": subtype,
              "size": size, "filename": filename, "disposition": disposition}]


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


def _parse_auth_results(
    msg: email.message.Message,
    provider_authserv_id: str = "mx.google.com",
) -> dict:
    """
    Select the trusted Authentication-Results header using two conditions
    that must BOTH be satisfied (RFC 7601 §7.1, §7.2):

    1. authserv-id must exactly match provider_authserv_id.
       Rejects headers stamped by any foreign or attacker-controlled identity.

    2. Among headers that satisfy condition 1, only the topmost (document-order)
       is trusted.  The receiving MTA prepends its stamp, so the topmost matching
       header is the genuine provider verdict.  Any subsequent header with the
       same authserv-id was added by an earlier relay and is forged.

    Neither condition alone is sufficient:
    - Condition 1 alone: an attacker below the provider can forge `mx.google.com`
      in a header that appears above the real one (unusual but possible with
      misconfigured relays).
    - Condition 2 alone (topmost overall): allows a foreign stamp that lands first.

    Tokenizes by splitting on ';' and anchoring ^method=result at each segment
    boundary, so property values (smtp.mailfrom=, header.from=) cannot produce
    false verdict matches regardless of their content.

    Returns spf/dkim/dmarc as str verdicts plus auth_results_unverified=True
    when no provider-stamped header is present.
    """
    target_id = provider_authserv_id.lower().rstrip(".")

    # Iterate in document order (top-down). The first header that satisfies
    # condition 1 is also the topmost surviving match (condition 2). We return
    # immediately — every subsequent match with the same authserv-id is forged.
    for header in (msg.get_all("Authentication-Results") or []):
        # authserv-id is the leading token before the first ';'
        semi_pos = header.find(";")
        raw_id = (header[:semi_pos] if semi_pos != -1 else header).strip()
        # RFC 7601 allows an optional version after the hostname ("mx.google.com 1")
        authserv_token = raw_id.split()[0].rstrip(".").lower() if raw_id else ""

        if authserv_token != target_id:
            continue

        # Topmost provider-stamped header — extract verdicts and stop.
        # Anchoring at ^(method)= prevents property values from matching as verdicts.
        result: dict = {"spf": "none", "dkim": "none", "dmarc": "none",
                        "dkim_d": "", "auth_results_unverified": False}
        segments_str = header[semi_pos + 1:] if semi_pos != -1 else ""
        for seg in segments_str.split(";"):
            seg = seg.strip()
            if not seg:
                continue
            m = re.match(r"^(spf|dkim|dmarc)=(\w+)", seg, re.IGNORECASE)
            if m:
                method = m.group(1).lower()
                result[method] = m.group(2).lower()
                if method == "dkim":
                    # header.d= is the DKIM signing domain (B3 alignment check reads it)
                    d_m = re.search(r"\bheader\.d=([^\s;]+)", seg, re.IGNORECASE)
                    if d_m:
                        result["dkim_d"] = d_m.group(1).lower()
        return result

    # No provider-stamped header — all present Authentication-Results are untrusted
    return {"spf": "none", "dkim": "none", "dmarc": "none",
            "dkim_d": "", "auth_results_unverified": True}


def _extract_originating_ip(
    msg: email.message.Message,
    provider_authserv_id: str = "mx.google.com",
) -> tuple[str, bool]:
    """
    Return (ip, trusted) by walking Received headers in document order (top-down).

    Only the header whose 'by' clause matches provider_authserv_id is trusted —
    it was written by the receiving MX, so the 'from [IP]' it records cannot be
    forged. All headers below it are sender-controlled and are never read.
    X-Originating-IP is also sender-settable and is never consulted.

    Returns ("", False) when no provider-stamped header is present.
    """
    received_headers = msg.get_all("Received") or []
    # Index 0 = most recent hop (your provider's inbound MX); index -1 = sender-side.
    for header in received_headers:
        by_m = _RECEIVED_BY_RE.search(header)
        if not by_m:
            continue
        by_host = by_m.group(1).lower().rstrip(";,")
        if provider_authserv_id.lower() not in by_host:
            continue
        # This header was stamped by our provider; extract IP from the 'from' region
        # (everything before the 'by' keyword — the 'from [IP]' always precedes it).
        from_region = header[: by_m.start()]
        for ip_m in _RECEIVED_IP_RE.finditer(from_region):
            ip = ip_m.group(1)
            if not any(ip.startswith(p) for p in _PRIVATE_PREFIXES):
                return ip, True
        # Provider header found but no public IP in 'from' (e.g. internal relay).
        return "", True
    return "", False


def _collect_raw_links(body: str, ctype: str) -> list[tuple[str, str]]:
    """Extract (href, anchor_text) pairs from one decoded body string."""
    if ctype == "text/html":
        parser = _AnchorParser()
        try:
            parser.feed(body)
        except Exception:
            return []
        return list(parser.links)
    if ctype == "text/plain":
        return [(url, "") for url in _URL_RE.findall(body)]
    return []


def _links_from_raw(raw: list[tuple[str, str]]) -> list[dict]:
    """Deduplicate, filter, and cap a (href, text) list into link dicts."""
    seen: set[str] = set()
    clean: list[dict] = []
    for href, text in raw:
        href = href.strip().rstrip(".,;)>\"'")
        if not href.startswith(("http://", "https://")):
            continue
        if len(href) < 10 or href in seen:
            continue
        seen.add(href)
        clean.append({"href": href, "text": text.strip()})
        if len(clean) >= 10:
            break
    return clean


def _extract_links(msg: email.message.Message) -> list[dict]:
    """
    Walk MIME parts and return up to 10 unique HTTP(S) links with anchor text.

    HTML parts: parsed with _AnchorParser — handles entities, multi-tag anchors,
    and captures the visible anchor text alongside the href.
    Plain-text parts: bare URL regex; text field is empty string.

    Each item: {"href": str, "text": str}
    Anchor text lets callers detect the canonical phishing tell:
    displayed text implies one domain, href points to another.
    """
    raw: list[tuple[str, str]] = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype not in ("text/html", "text/plain"):
            continue
        try:
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            body = payload.decode(charset, errors="replace")
        except Exception:
            continue
        raw.extend(_collect_raw_links(body, ctype))
    return _links_from_raw(raw)


def _extract_links_from_parts(parts: list[tuple[bytes, str]]) -> list[dict]:
    """
    Extract links from pre-fetched (content_bytes, content_type) pairs.

    Used by the two-phase IMAP fetch path so link extraction can run on
    individually fetched MIME parts rather than a fully loaded email.Message.
    """
    raw: list[tuple[str, str]] = []
    for content_bytes, ctype in parts:
        try:
            body = content_bytes.decode("utf-8", errors="replace")
        except Exception:
            continue
        raw.extend(_collect_raw_links(body, ctype))
    return _links_from_raw(raw)


def extract_metadata(
    msg: email.message.Message,
    provider_authserv_id: str = "mx.google.com",
    *,
    _injected_links: list[dict] | None = None,
    _injected_attachments: dict | None = None,
    oversized_part_skipped: bool = False,
) -> dict[str, Any]:
    """
    Extract all threat-relevant metadata from a parsed email.Message.

    Pure function — no network calls, no file I/O.
    Returns a dict suitable for the 'features' field in the incidents table.
    Subject is flagged in _sensitive_fields so the router can strip it
    before cloud inference while keeping it for local inference.

    When called from the two-phase IMAP fetch path (A5), pass the
    pre-fetched data via _injected_links and _injected_attachments to skip
    the MIME walk (msg only has headers in that path).
    """
    from_raw = msg.get("From", "")
    reply_to_raw = msg.get("Reply-To", "")

    from_domain = _extract_domain(from_raw)
    reply_to_domain = _extract_domain(reply_to_raw) if reply_to_raw else from_domain
    auth = _parse_auth_results(msg, provider_authserv_id)

    if _injected_attachments is not None:
        # Two-phase fetch path: attachment info + html_only come from BODYSTRUCTURE;
        # links come from individually fetched parts.
        has_attachments = _injected_attachments["has_attachments"]
        attachment_names = _injected_attachments["attachment_names"]
        attachment_mimes = _injected_attachments["attachment_mimes"]
        attachment_manifest: list[dict] = _injected_attachments.get("attachment_manifest", [])
        html_only = _injected_attachments["html_only"]
        links = _injected_links if _injected_links is not None else []
    else:
        # Backward-compatible path: full MIME walk (used by tests 1–8 and
        # any caller that passes a complete email.Message).
        attachment_names: list[str] = []
        attachment_mimes: list[str] = []
        attachment_manifest = []
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

    _originating_ip, _originating_ip_trusted = _extract_originating_ip(
        msg, provider_authserv_id
    )

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
        "dkim_d": auth["dkim_d"],
        "dmarc": auth["dmarc"],
        # True when no Authentication-Results with our provider's authserv-id was found.
        "auth_results_unverified": auth["auth_results_unverified"],
        "originating_ip": _originating_ip,
        # False when no provider-stamped Received header was found; treat IP as unverified.
        "originating_ip_trusted": _originating_ip_trusted,
        "has_attachments": has_attachments,
        "attachment_names": attachment_names,
        "attachment_mimes": attachment_mimes,
        # D1: per-attachment metadata (filename, declared_mime, size_bytes,
        # double_extension, dangerous_ext, oversized). No bytes fetched.
        "attachment_manifest": attachment_manifest,
        "has_external_links": bool(links),
        "links": links,
        "html_only": html_only,
        # True if any MIME part exceeded the per-part or per-message size cap.
        "oversized_part_skipped": oversized_part_skipped,
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
        provider_authserv_id: str = "mx.google.com",
        first_run_scan_unread_days: int = 0,
        attachment_correlation_cache: dict | None = None,
    ) -> None:
        self._queue = event_queue
        self._server = imap_server
        self._port = imap_port
        self._address = email_address
        self._password = password
        self._interval = poll_interval_minutes * 60
        # Gap 14: default to INBOX + Spam — a user fishing out a message is high-risk
        self._folders = folders or ["INBOX", "[Gmail]/Spam"]
        self._state_path = state_path or (Path.home() / ".argus" / "email_state.json")
        self._provider_authserv_id = provider_authserv_id
        # Gap 12: 0 = skip all history on first run (legacy default)
        self._first_run_scan_days = first_run_scan_unread_days
        # Gap 13: backoff counters — manipulated only on the poll thread
        self._connect_fail_streak = 0
        self._auth_fail_streak = 0
        self._auth_incident_sent = False
        self._stop = threading.Event()
        # D3: shared dict {filename: (correlation_id, monotonic_ts)} owned by daemon
        self._attachment_correlation_cache = attachment_correlation_cache
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
        """Poll immediately on start, then wait for interval or stop signal.

        When _connect fails, applies exponential backoff with ±10 % jitter
        instead of the full poll interval so we retry sooner but avoid
        hammering a temporarily unreachable server.
        """
        while not self._stop.is_set():
            streak_before = self._connect_fail_streak
            try:
                self._poll()
            except Exception:
                log.exception("EmailScanner poll cycle failed")

            if self._connect_fail_streak > streak_before:
                # _connect failed during this cycle — back off exponentially
                n = self._connect_fail_streak
                delay = min(_BACKOFF_BASE_SECONDS * (2 ** (n - 1)), _BACKOFF_MAX_SECONDS)
                jitter = delay * random.uniform(-0.1, 0.1)
                actual = max(1.0, delay + jitter)
                log.warning(
                    "Connect failed (streak=%d), retrying in %.0f s", n, actual
                )
                self._stop.wait(timeout=actual)
            else:
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

        # Read epoch and next-UID from the server's SELECT response.
        current_uidvalidity = _parse_int_response(
            conn.untagged_responses.get("UIDVALIDITY")
        )
        current_uidnext = _parse_int_response(
            conn.untagged_responses.get("UIDNEXT")
        )

        folder_state = state.setdefault(folder, {})

        # First run: record high-water UID and exit; only future arrivals are scanned.
        if not folder_state.get("initialized"):
            self._rebaseline_folder(
                conn, folder, folder_state, current_uidvalidity, current_uidnext,
                emit_incident=False,
            )
            return

        # UIDVALIDITY check: UIDs are only valid within a single epoch.
        # A changed or absent-in-state UIDVALIDITY means stored last_uid is junk.
        stored_uidvalidity = folder_state.get("uidvalidity")
        if current_uidvalidity is not None:
            if stored_uidvalidity is None or stored_uidvalidity != current_uidvalidity:
                log.warning(
                    "UIDVALIDITY %s for folder %s (stored=%s server=%d) — "
                    "re-baselining; stored UIDs are now invalid",
                    "changed" if stored_uidvalidity else "absent from state",
                    folder, stored_uidvalidity, current_uidvalidity,
                )
                self._rebaseline_folder(
                    conn, folder, folder_state, current_uidvalidity, current_uidnext,
                    emit_incident=True,
                )
                return

        # UIDNEXT short-circuit: if the server's next-assignable UID hasn't moved,
        # nothing new arrived — skip the full UID SEARCH entirely.
        stored_uidnext = folder_state.get("last_seen_uidnext")
        if current_uidnext is not None and stored_uidnext == current_uidnext:
            log.debug("UIDNEXT unchanged (%d) in %s — skipping fetch", current_uidnext, folder)
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
            if current_uidnext is not None:
                folder_state["last_seen_uidnext"] = current_uidnext
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

        if current_uidnext is not None:
            folder_state["last_seen_uidnext"] = current_uidnext
        folder_state["last_poll"] = datetime.now(timezone.utc).isoformat()

    def _rebaseline_folder(
        self,
        conn: imaplib.IMAP4_SSL,
        folder: str,
        folder_state: dict,
        current_uidvalidity: int | None,
        current_uidnext: int | None,
        emit_incident: bool,
    ) -> None:
        """Record a new UID high-water mark. Called on first run or epoch change."""
        old_uidvalidity = folder_state.get("uidvalidity")

        status, data = conn.uid("search", None, "ALL")
        existing = data[0].split() if status == "OK" and data[0] else []
        last_uid = int(existing[-1]) if existing else 0

        folder_state["last_uid"] = last_uid
        folder_state["initialized"] = True
        if current_uidvalidity is not None:
            folder_state["uidvalidity"] = current_uidvalidity
        if current_uidnext is not None:
            folder_state["last_seen_uidnext"] = current_uidnext

        if emit_incident:
            self._queue.put({
                "source": "email_scanner",
                "event_type": "email_uidvalidity_reset",
                "severity": "low",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "summary": (
                    f"UIDVALIDITY epoch changed for folder {folder}: "
                    f"{old_uidvalidity} → {current_uidvalidity}. "
                    "Mailbox was likely recreated, migrated, or restored. Re-baselined."
                ),
                "metadata": {
                    "folder": folder,
                    "old_uidvalidity": old_uidvalidity,
                    "new_uidvalidity": current_uidvalidity,
                    "new_last_uid": last_uid,
                },
            })
        else:
            log.info(
                "First run: folder=%s last_uid=%d uidvalidity=%s (skipping %d existing emails)",
                folder, last_uid, current_uidvalidity, len(existing),
            )
            # Gap 12: scan recent unreads on first run if configured
            if self._first_run_scan_days > 0:
                self._scan_first_run_unread(conn, folder)

    def _scan_first_run_unread(
        self, conn: imaplib.IMAP4_SSL, folder: str
    ) -> None:
        """
        On first run, scan UNSEEN messages from the last first_run_scan_unread_days
        days so a phish sitting unread is caught immediately on installation.

        last_uid is already set to the max-existing UID by _rebaseline_folder,
        so these pre-baseline unreads will not be re-processed on the next poll.
        """
        since = date.today() - timedelta(days=self._first_run_scan_days)
        since_str = f"{since.day}-{since.strftime('%b')}-{since.year}"
        status, data = conn.uid("search", None, f"UNSEEN SINCE {since_str}")
        if status != "OK" or not data[0]:
            return
        unread_uids = data[0].split()
        if not unread_uids:
            return
        to_scan = unread_uids[:_MAX_PER_POLL]
        log.info(
            "First-run unread scan: folder=%s found %d unread since %s, scanning %d",
            folder, len(unread_uids), since_str, len(to_scan),
        )
        for uid in to_scan:
            try:
                self._process_message(conn, uid, folder)
            except Exception:
                log.exception(
                    "First-run unread scan failed UID %s in %s — skipped", uid, folder
                )

    def _process_message(
        self, conn: imaplib.IMAP4_SSL, uid: bytes, folder: str
    ) -> None:
        """
        Two-phase fetch: headers + BODYSTRUCTURE first, then individual parts.

        Phase 1 — BODY.PEEK[HEADER] + BODYSTRUCTURE: obtains the full header
        block and the MIME tree in one round trip, without loading any body.
        Phase 2 — BODY.PEEK[N] per part: fetches only text/plain and text/html
        parts needed for link extraction.  Each fetch is guarded by
        MAX_PART_BYTES and the running total is bounded by MAX_MESSAGE_BYTES.
        Parts that exceed either cap are skipped with oversized_part_skipped=True.
        Attachment metadata (name, MIME type, size) is read from the BODYSTRUCTURE
        and never requires a body fetch — this is the hook for Part D.
        """
        # ── Phase 1: headers + MIME tree ──────────────────────────────────────
        status, data = conn.uid("fetch", uid, "(BODY.PEEK[HEADER] BODYSTRUCTURE)")
        if status != "OK":
            log.warning("Phase-1 FETCH failed for UID %s in %s", uid, folder)
            return

        header_bytes = _extract_literal(data)
        if not header_bytes:
            log.warning("Empty header for UID %s in %s", uid, folder)
            return

        bs_str = _find_bodystructure_str(data)
        if bs_str is None:
            log.warning("No BODYSTRUCTURE for UID %s in %s — skipping", uid, folder)
            return

        try:
            bs_tree = _tokenize_bs(bs_str)
            bs_parts = _walk_bs_parts(bs_tree[0] if bs_tree else [])
        except Exception:
            log.exception("BODYSTRUCTURE parse error UID %s in %s", uid, folder)
            return

        msg_headers = email.message_from_bytes(header_bytes)

        # ── Phase 2: selective part fetching ──────────────────────────────────
        fetched_text_parts: list[tuple[bytes, str]] = []
        attachment_names: list[str] = []
        attachment_mimes: list[str] = []
        has_attachments = False
        oversized_part_skipped = False
        total_fetched = 0
        seen_ctypes: set[str] = set()

        attachment_manifest: list[dict] = []

        for part in bs_parts:
            ctype = f"{part['type']}/{part['subtype']}"
            seen_ctypes.add(ctype)

            is_text = part["type"] == "text" and part["subtype"] in ("plain", "html")
            # Non-text, non-multipart parts are treated as attachments (D1)
            is_attachment = (
                part.get("disposition") == "attachment"
                or (part["type"] not in ("text", "multipart") and part["type"] != "")
            )

            if is_attachment:
                has_attachments = True
                filename = part.get("filename") or f"attachment_part{part['part_num']}"
                if part.get("filename"):
                    attachment_names.append(filename)
                attachment_mimes.append(ctype)
                ext = Path(filename).suffix.lower()
                attachment_manifest.append({
                    "filename": filename,
                    "declared_mime": ctype,
                    "size_bytes": part["size"],
                    "double_extension": _double_extension(filename),
                    "dangerous_ext": ext in _DANGEROUS_EXTENSIONS,
                    "oversized": part["size"] > MAX_PART_BYTES,
                })
                continue

            if not is_text:
                continue

            if (part["size"] > MAX_PART_BYTES
                    or total_fetched + part["size"] > MAX_MESSAGE_BYTES):
                oversized_part_skipped = True
                log.warning(
                    "UID %s part %s is %d bytes (caps: part=%d msg=%d) — skipped",
                    uid, part["part_num"], part["size"],
                    MAX_PART_BYTES, MAX_MESSAGE_BYTES,
                )
                continue

            status2, data2 = conn.uid(
                "fetch", uid, f"(BODY.PEEK[{part['part_num']}])"
            )
            if status2 != "OK":
                log.warning("Part fetch failed UID %s part %s", uid, part["part_num"])
                continue
            part_bytes = _extract_literal(data2)
            if part_bytes:
                fetched_text_parts.append((part_bytes, ctype))
                total_fetched += len(part_bytes)

        html_only = (
            "text/html" in seen_ctypes and "text/plain" not in seen_ctypes
        )
        links = _extract_links_from_parts(fetched_text_parts)

        correlation_id = str(uuid.uuid4())

        metadata = extract_metadata(
            msg_headers,
            self._provider_authserv_id,
            _injected_links=links,
            _injected_attachments={
                "has_attachments": has_attachments,
                "attachment_names": attachment_names,
                "attachment_mimes": attachment_mimes,
                "attachment_manifest": attachment_manifest,
                "html_only": html_only,
            },
            oversized_part_skipped=oversized_part_skipped,
        )
        metadata["correlation_id"] = correlation_id

        # Build a compact human-readable summary for logging + SQLite input_summary
        sum_parts = [f"from={metadata['from_domain']}"]
        if metadata["reply_to_mismatch"]:
            sum_parts.append(f"reply_to={metadata['reply_to_domain']} [MISMATCH]")
        if metadata["attachment_names"]:
            sum_parts.append(f"attach={metadata['attachment_names']}")
        if metadata["links"]:
            sum_parts.append(f"links={len(metadata['links'])}")
        if oversized_part_skipped:
            sum_parts.append("oversized=True")
        summary = " | ".join(sum_parts)

        entry = {
            "source": "email_scanner",
            "event_type": "new_email",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "metadata": metadata,
        }
        self._queue.put(entry)

        # D3: register each attachment filename so daemon can link the file incident
        if self._attachment_correlation_cache is not None and attachment_manifest:
            ts = time.monotonic()
            for att in attachment_manifest:
                self._attachment_correlation_cache[att["filename"]] = (correlation_id, ts)

        log.info(
            "Queued: %s | spf=%s dkim=%s dmarc=%s | subj=%r",
            summary,
            metadata["spf"],
            metadata["dkim"],
            metadata["dmarc"],
            metadata["subject"][:60],
        )

    def _connect(self) -> imaplib.IMAP4_SSL | None:
        """Open and authenticate an IMAP SSL connection. Returns None on failure.

        Tracks consecutive failure streaks (any failure and auth-only) so that
        _run can apply exponential backoff and so that repeated auth failures
        emit an email_auth_failing incident instead of logging silently forever.
        Resets all counters on the first successful login.
        """
        try:
            conn = imaplib.IMAP4_SSL(self._server, self._port)
            conn.login(self._address, self._password)
            if self._connect_fail_streak:
                log.info(
                    "IMAP connection re-established after %d failure(s)",
                    self._connect_fail_streak,
                )
            self._connect_fail_streak = 0
            self._auth_fail_streak = 0
            self._auth_incident_sent = False
            return conn
        except imaplib.IMAP4.error as exc:
            log.error("IMAP auth failed: %s", exc)
            self._connect_fail_streak += 1
            self._auth_fail_streak += 1
            if (self._auth_fail_streak >= _AUTH_INCIDENT_THRESHOLD
                    and not self._auth_incident_sent):
                self._auth_incident_sent = True
                self._queue.put({
                    "source": "email_scanner",
                    "event_type": "email_auth_failing",
                    "severity": "high",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "summary": (
                        f"IMAP authentication has failed "
                        f"{self._auth_fail_streak} consecutive times "
                        f"for {self._address}. Check credentials or app-password."
                    ),
                    "metadata": {
                        "address": self._address,
                        "server": self._server,
                        "consecutive_auth_failures": self._auth_fail_streak,
                    },
                })
            return None
        except OSError as exc:
            log.error("IMAP connection error: %s", exc)
            self._connect_fail_streak += 1
            # network errors don't count toward the auth-specific threshold
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
    assert m["originating_ip_trusted"] is True
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
    assert m["originating_ip_trusted"] is True
    assert m["has_attachments"] is True
    assert "invoice_overdue.exe" in m["attachment_names"]
    assert m["has_external_links"] is True
    assert any("paypa1-secure.ru" in link["href"] for link in m["links"])
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
    assert any("upw0rk-verify.tk" in link["href"] for link in m["links"])
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

    print("=" * 60)
    print("Test 8: DOM link extraction with anchor-text capture (A4)")
    print("=" * 60)

    raw_a4 = textwrap.dedent("""\
        From: Scammer <phish@evil.ru>
        To: zeeshan@example.com
        Subject: A4 link extraction test
        Date: Sun, 08 Jun 2026 14:00:00 +0000
        Message-ID: <a4@evil.ru>
        Content-Type: text/html; charset=utf-8

        <html><body>

        <!-- Case 1: anchor text implies paypal.com but href goes elsewhere -->
        <a href="http://evil.ru/steal">paypal.com</a>

        <!-- Case 2: href with HTML-entity-encoded path -->
        <a href="http://evil.ru/&#x70;&#x61;&#x74;&#x68;">click here</a>

        <!-- Case 3: anchor text spans child tags -->
        <a href="https://bit.ly/3xEvil"><b>Click <span>Here</span></b></a>

        <!-- Case 4: data: URI must be filtered out -->
        <a href="data:text/html,<script>alert(1)</script>">not shown</a>

        <!-- Case 5: javascript: URI must be filtered out -->
        <a href="javascript:void(0)">also not shown</a>

        </body></html>
    """)
    msg_a4 = email.message_from_string(raw_a4)
    m = extract_metadata(msg_a4)
    lnks = m["links"]
    print(f"  links extracted: {lnks}")

    # Case 1: anchor-text mismatch detectable
    case1 = next((l for l in lnks if "evil.ru/steal" in l["href"]), None)
    assert case1 is not None, "Case 1 href not found"
    assert case1["text"] == "paypal.com", f"Case 1 anchor text wrong: {case1['text']!r}"
    print(f"  Case 1 mismatch: href={case1['href']!r}  text={case1['text']!r} PASSED")

    # Case 2: HTML entity decoded in href — &#x70;&#x61;&#x74;&#x68; = "path"
    case2 = next((l for l in lnks if l["href"] == "http://evil.ru/path"), None)
    assert case2 is not None, (
        f"Case 2 entity-decoded href not found (got hrefs: {[l['href'] for l in lnks]})"
    )
    print(f"  Case 2 entity decoded: href={case2['href']!r} PASSED")

    # Case 3: text across child tags concatenated
    case3 = next((l for l in lnks if "bit.ly" in l["href"]), None)
    assert case3 is not None, "Case 3 href not found"
    assert "click" in case3["text"].lower() and "here" in case3["text"].lower(), (
        f"Case 3 child-tag text not captured: {case3['text']!r}"
    )
    print(f"  Case 3 child-tag text: {case3['text']!r} PASSED")

    # Case 4 + 5: data: and javascript: URIs filtered
    assert not any(l["href"].startswith("data:") for l in lnks), "data: URI leaked"
    assert not any(l["href"].startswith("javascript:") for l in lnks), "javascript: URI leaked"
    print("  Case 4+5: data:/javascript: URIs filtered PASSED")

    print("  Test 8: PASSED\n")

    print("=" * 60)
    print("Test 7: Authentication-Results authserv-id validation (A3)")
    print("=" * 60)

    # Attack: attacker pre-injects a forged Authentication-Results claiming spf=pass.
    # It appears FIRST in the message (simulating a path where the provider doesn't
    # always prepend, or the attacker managed to reorder headers). Gmail's real header
    # follows with spf=fail. Without authserv-id validation the old code would have
    # returned spf=pass from the injected first header.
    raw_injected_ar = textwrap.dedent("""\
        From: Scammer <scammer@evil.ru>
        To: zeeshan@example.com
        Subject: Injected AR test
        Date: Sun, 08 Jun 2026 13:00:00 +0000
        Message-ID: <inject@evil.ru>
        Authentication-Results: evil.ru; spf=pass; dkim=pass; dmarc=pass
        Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
        Received: from evil.ru (evil.ru [185.220.101.99])
               by mx.google.com; Sun, 08 Jun 2026 13:00:00 +0000
        Content-Type: text/plain

        Injected AR header test.
    """)
    msg_injected = email.message_from_string(raw_injected_ar)
    m = extract_metadata(msg_injected)
    # Must use Gmail's header (second), NOT the attacker's injected first one
    assert m["spf"] == "fail",  f"Expected spf=fail from provider header, got {m['spf']!r}"
    assert m["dkim"] == "fail", f"Expected dkim=fail from provider header, got {m['dkim']!r}"
    assert m["dmarc"] == "fail", f"Expected dmarc=fail from provider header, got {m['dmarc']!r}"
    assert m["auth_results_unverified"] is False
    print(f"  spf={m['spf']} dkim={m['dkim']} dmarc={m['dmarc']} unverified={m['auth_results_unverified']}")
    print("  Injected spf=pass header ignored, provider header used: PASSED")

    # No provider stamp — all Authentication-Results headers have foreign authserv-ids
    raw_no_ar_stamp = textwrap.dedent("""\
        From: Sender <sender@somewhere.com>
        To: zeeshan@example.com
        Subject: No AR stamp test
        Date: Sun, 08 Jun 2026 13:01:00 +0000
        Message-ID: <noar@somewhere.com>
        Authentication-Results: someother-mx.net; spf=pass; dkim=pass; dmarc=pass
        Received: from somewhere.com (somewhere.com [203.0.113.50])
               by someother-mx.net; Sun, 08 Jun 2026 13:01:00 +0000
        Content-Type: text/plain

        No provider stamp.
    """)
    msg_no_ar = email.message_from_string(raw_no_ar_stamp)
    m = extract_metadata(msg_no_ar)
    assert m["spf"] == "none",  f"Expected none when stamp absent, got {m['spf']!r}"
    assert m["dkim"] == "none", f"Expected none when stamp absent, got {m['dkim']!r}"
    assert m["dmarc"] == "none", f"Expected none when stamp absent, got {m['dmarc']!r}"
    assert m["auth_results_unverified"] is True
    print(f"  spf={m['spf']} dkim={m['dkim']} dmarc={m['dmarc']} unverified={m['auth_results_unverified']}")
    print("  Absent provider stamp → auth_results_unverified=True: PASSED")

    # Property-value false-match guard: dmarc verdict inside smtp.mailfrom must not bleed
    raw_property_bleed = textwrap.dedent("""\
        From: Test <test@example.com>
        To: zeeshan@example.com
        Subject: Property bleed test
        Date: Sun, 08 Jun 2026 13:02:00 +0000
        Message-ID: <bleed@example.com>
        Authentication-Results: mx.google.com;
               spf=fail smtp.mailfrom=dmarc=pass@evil.com;
               dkim=none;
               dmarc=fail
        Content-Type: text/plain

        Property bleed test.
    """)
    msg_bleed = email.message_from_string(raw_property_bleed)
    m = extract_metadata(msg_bleed)
    assert m["spf"] == "fail",  f"Expected spf=fail, got {m['spf']!r}"
    assert m["dmarc"] == "fail", f"dmarc=pass in smtp.mailfrom must not bleed into verdict, got {m['dmarc']!r}"
    print(f"  spf={m['spf']} dmarc={m['dmarc']}")
    print("  Property-value false-match guard: PASSED")

    # Duplicate authserv-id attack: attacker injects a second mx.google.com header
    # BELOW the genuine one claiming spf=pass.  The topmost matching header is the
    # real provider stamp; the lower one is forged and must be ignored.
    raw_dup_authserv = textwrap.dedent("""\
        From: Scammer <scammer@evil.ru>
        To: zeeshan@example.com
        Subject: Dup authserv-id test
        Date: Sun, 08 Jun 2026 13:03:00 +0000
        Message-ID: <dup@evil.ru>
        Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
        Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
        Content-Type: text/plain

        Duplicate authserv-id attack.
    """)
    msg_dup = email.message_from_string(raw_dup_authserv)
    m = extract_metadata(msg_dup)
    assert m["spf"] == "fail",  (
        f"Topmost mx.google.com header must win; second (forged) header gave spf=pass, got {m['spf']!r}"
    )
    assert m["dkim"] == "fail", f"Expected dkim=fail from topmost header, got {m['dkim']!r}"
    assert m["dmarc"] == "fail", f"Expected dmarc=fail from topmost header, got {m['dmarc']!r}"
    print(f"  spf={m['spf']} dkim={m['dkim']} dmarc={m['dmarc']}")
    print("  Duplicate authserv-id (topmost match wins, forged second ignored): PASSED")

    # A6: DKIM signing domain (dkim_d) extracted from header.d= property
    raw_dkim_d = textwrap.dedent("""\
        From: Real Sender <sender@fiverr.com>
        To: zeeshan@example.com
        Subject: dkim_d extraction test
        Date: Sun, 08 Jun 2026 13:04:00 +0000
        Message-ID: <dkimd@fiverr.com>
        Authentication-Results: mx.google.com;
               spf=pass smtp.mailfrom=fiverr.com;
               dkim=pass header.i=@fiverr.com header.d=fiverr.com header.b="abc123";
               dmarc=pass header.from=fiverr.com
        Content-Type: text/plain

        dkim_d test.
    """)
    msg_dkimd = email.message_from_string(raw_dkim_d)
    m = extract_metadata(msg_dkimd)
    assert m["dkim_d"] == "fiverr.com", (
        f"Expected dkim_d='fiverr.com', got {m['dkim_d']!r}"
    )
    assert m["dkim"] == "pass"
    print(f"  dkim={m['dkim']} dkim_d={m['dkim_d']!r}")
    print("  DKIM signing domain extracted (A6): PASSED")

    # dkim_d is empty when DKIM verdict is absent
    raw_no_dkim = textwrap.dedent("""\
        From: Sender <sender@example.com>
        To: zeeshan@example.com
        Subject: No DKIM test
        Date: Sun, 08 Jun 2026 13:05:00 +0000
        Message-ID: <nodkim@example.com>
        Authentication-Results: mx.google.com; spf=pass; dmarc=pass
        Content-Type: text/plain

        No DKIM.
    """)
    msg_no_dkim = email.message_from_string(raw_no_dkim)
    m = extract_metadata(msg_no_dkim)
    assert m["dkim_d"] == "", f"Expected empty dkim_d when absent, got {m['dkim_d']!r}"
    assert m["dkim"] == "none"
    print(f"  dkim={m['dkim']} dkim_d={m['dkim_d']!r}")
    print("  dkim_d empty when DKIM absent (A6): PASSED")

    print("  Test 7: PASSED\n")

    print("=" * 60)
    print("Test 6: Trust-boundary IP extraction (A2)")
    print("=" * 60)

    # Attack: scammer pre-injects a forged Received header that makes the email
    # appear to originate from a trusted IP. Gmail prepends its own header on top.
    # The forged header is the SECOND entry (lower in the chain = sender-controlled).
    raw_forged = textwrap.dedent("""\
        From: Scammer <scammer@evil.ru>
        To: zeeshan@example.com
        Subject: Forged IP test
        Date: Sun, 08 Jun 2026 12:00:00 +0000
        Message-ID: <forged@evil.ru>
        Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
        Received: from evil.ru (evil.ru [185.220.101.99])
               by mx.google.com; Sun, 08 Jun 2026 12:00:00 +0000
        Received: from realbank.com (realbank.com [1.2.3.4])
               by unknownrelay.ru; Sun, 08 Jun 2026 11:59:00 +0000
        Content-Type: text/plain

        Forged chain test.
    """)
    msg_forged = email.message_from_string(raw_forged)
    m = extract_metadata(msg_forged)
    # Must use the Gmail-stamped hop, NOT the forged lower-chain entry
    assert m["originating_ip"] == "185.220.101.99", (
        f"Expected Gmail-stamped IP, got {m['originating_ip']!r}"
    )
    assert m["originating_ip_trusted"] is True
    print(f"  originating_ip={m['originating_ip']}  trusted={m['originating_ip_trusted']}")
    print("  Forged low-chain Received ignored: PASSED")

    # No provider stamp at all — should return empty + untrusted
    raw_no_stamp = textwrap.dedent("""\
        From: Sender <sender@somewhere.com>
        To: zeeshan@example.com
        Subject: No stamp test
        Date: Sun, 08 Jun 2026 12:01:00 +0000
        Message-ID: <nostamp@somewhere.com>
        Received: from somewhere.com (somewhere.com [203.0.113.50])
               by unknownrelay.ru; Sun, 08 Jun 2026 12:01:00 +0000
        Content-Type: text/plain

        No provider stamp.
    """)
    msg_no_stamp = email.message_from_string(raw_no_stamp)
    m = extract_metadata(msg_no_stamp)
    assert m["originating_ip"] == "", (
        f"Expected empty IP when stamp absent, got {m['originating_ip']!r}"
    )
    assert m["originating_ip_trusted"] is False
    print(f"  originating_ip={m['originating_ip']!r}  trusted={m['originating_ip_trusted']}")
    print("  Absent provider stamp → untrusted: PASSED")

    print("  Test 6: PASSED\n")

    print("=" * 60)
    print("Test 5: UIDVALIDITY epoch tracking")
    print("=" * 60)

    from unittest.mock import MagicMock, patch as _patch
    import queue as _queuemod

    def _make_mock_conn(uidvalidity: int, uidnext: int, all_uids: list[bytes]) -> MagicMock:
        conn = MagicMock()
        conn.select.return_value = ("OK", [str(len(all_uids)).encode()])
        conn.untagged_responses = {
            "UIDVALIDITY": [str(uidvalidity).encode()],
            "UIDNEXT":     [str(uidnext).encode()],
        }

        def uid_side_effect(command, *args):
            if command == "search":
                criterion = args[1] if len(args) > 1 else "ALL"
                if str(criterion) == "ALL":
                    return ("OK", [b" ".join(all_uids) if all_uids else b""])
                m = re.match(r"UID (\d+):\*", str(criterion))
                if m:
                    min_uid = int(m.group(1))
                    found = [u for u in all_uids if int(u) >= min_uid]
                    return ("OK", [b" ".join(found) if found else b""])
                return ("OK", [b""])
            if command == "fetch":
                spec = str(args[1]) if len(args) > 1 else ""
                if "BODYSTRUCTURE" in spec:
                    # Phase 1 — header + BODYSTRUCTURE for a tiny text/plain message
                    hdr = (
                        b"From: test@example.com\r\n"
                        b"Subject: Test\r\n"
                        b"Authentication-Results: mx.google.com; spf=pass\r\n"
                        b"\r\n"
                    )
                    bs = b'("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 4 1)'
                    return ("OK", [
                        (b"0 (BODY[HEADER] {%d}" % len(hdr), hdr),
                        b" BODYSTRUCTURE " + bs + b" )",
                    ])
                # Phase 2 — part body
                body = b"Body"
                return ("OK", [(b"0 (BODY[1] {%d}" % len(body), body), b")"])
            return ("OK", [b""])

        conn.uid.side_effect = uid_side_effect
        return conn

    _q5 = _queuemod.Queue()
    _scanner5 = EmailScanner(
        event_queue=_q5,
        imap_server="imap.example.com",
        imap_port=993,
        email_address="test@example.com",
        password="secret",
    )
    _state5: dict = {}

    # Poll 1 — first run: baseline with UIDVALIDITY=1111, two existing emails
    _c1 = _make_mock_conn(uidvalidity=1111, uidnext=103, all_uids=[b"100", b"101"])
    _scanner5._poll_folder(_c1, "INBOX", _state5)
    assert _state5["INBOX"]["initialized"] is True
    assert _state5["INBOX"]["uidvalidity"] == 1111
    assert _state5["INBOX"]["last_uid"] == 101
    assert _q5.empty(), "No incidents should be queued on first run"
    print("  Poll 1 (first run baseline): PASSED")

    # Poll 2 — UIDVALIDITY changed: must re-baseline + emit incident + log WARNING
    with _patch.object(log, "warning", wraps=log.warning) as _mock_warn:
        _c2 = _make_mock_conn(uidvalidity=9999, uidnext=103, all_uids=[b"100", b"101"])
        _scanner5._poll_folder(_c2, "INBOX", _state5)
    assert _state5["INBOX"]["uidvalidity"] == 9999
    assert _state5["INBOX"]["last_uid"] == 101
    assert not _q5.empty(), "Incident must be queued on UIDVALIDITY change"
    _incident = _q5.get_nowait()
    assert _incident["event_type"] == "email_uidvalidity_reset"
    assert _incident["severity"] == "low"
    assert _incident["metadata"]["old_uidvalidity"] == 1111
    assert _incident["metadata"]["new_uidvalidity"] == 9999
    assert _mock_warn.called, "log.warning must fire on UIDVALIDITY change"
    print("  Poll 2 (UIDVALIDITY flip → re-baseline + incident + WARNING): PASSED")

    # Poll 3 — new message arrives after re-baseline: must NOT be silently dropped
    _c3 = _make_mock_conn(uidvalidity=9999, uidnext=104, all_uids=[b"100", b"101", b"102"])
    _scanner5._poll_folder(_c3, "INBOX", _state5)
    assert _state5["INBOX"]["last_uid"] == 102, (
        f"New message after epoch reset must be picked up, got {_state5['INBOX']['last_uid']}"
    )
    print("  Poll 3 (new message after re-baseline picked up): PASSED")

    # Poll 4 — UIDNEXT unchanged: short-circuit, uid() must never be called
    _c4 = _make_mock_conn(uidvalidity=9999, uidnext=104, all_uids=[b"100", b"101", b"102"])
    _scanner5._poll_folder(_c4, "INBOX", _state5)
    assert _c4.uid.call_count == 0, "UIDNEXT short-circuit must skip uid() entirely"
    print("  Poll 4 (UIDNEXT short-circuit skips fetch): PASSED")

    print("  Test 5: UIDVALIDITY epoch tracking PASSED\n")

    print("=" * 60)
    print("Test 9: BODYSTRUCTURE-first two-phase fetch (A5)")
    print("=" * 60)

    _q9 = _queuemod.Queue()
    _scanner9 = EmailScanner(
        event_queue=_q9,
        imap_server="imap.example.com",
        imap_port=993,
        email_address="test@example.com",
        password="secret",
    )

    # ── Test 9a: 200 MB text/html part is skipped; small text/plain is fetched ──
    _HDR_9A = (
        b"From: attacker@evil.ru\r\n"
        b"To: target@example.com\r\n"
        b"Subject: Big message test\r\n"
        b"Date: Wed, 25 Jun 2026 10:00:00 +0000\r\n"
        b"Message-ID: <big@evil.ru>\r\n"
        b"Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail\r\n"
        b"Received: from evil.ru (evil.ru [185.220.101.1])\r\n"
        b"       by mx.google.com; Wed, 25 Jun 2026 10:00:00 +0000\r\n"
        b"\r\n"
    )
    # Part 1: text/plain, 100 bytes (under cap). Part 2: text/html, 200 MB (over cap).
    _BS_9A = (
        b'(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 100 2)'
        b'("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL "7BIT" 209715200 4000000)'
        b' "ALTERNATIVE")'
    )
    _BODY_PLAIN_9A = b"Check http://evil.ru/track for details."
    _fetch_calls_9a: list[str] = []

    def _uid_9a(command, uid_arg, *args):
        if command == "fetch":
            spec = str(args[0]) if args else ""
            _fetch_calls_9a.append(spec)
            if "BODYSTRUCTURE" in spec:
                return ("OK", [
                    (b"5 (BODY[HEADER] {%d}" % len(_HDR_9A), _HDR_9A),
                    b" BODYSTRUCTURE " + _BS_9A + b" )",
                ])
            # Part 1 body (text/plain, 100 B) — only this should be fetched
            return ("OK", [(b"5 (BODY[1] {%d}" % len(_BODY_PLAIN_9A), _BODY_PLAIN_9A), b")"])
        return ("OK", [b""])

    _conn9a = MagicMock()
    _conn9a.uid.side_effect = _uid_9a
    _scanner9._process_message(_conn9a, b"5", "INBOX")

    assert not _q9.empty(), "Event must be queued even for oversized message"
    _entry9a = _q9.get_nowait()
    assert _entry9a["metadata"]["oversized_part_skipped"] is True, (
        f"Expected oversized_part_skipped=True, got {_entry9a['metadata']['oversized_part_skipped']!r}"
    )
    assert _entry9a["metadata"]["from_domain"] == "evil.ru", (
        f"from_domain wrong: {_entry9a['metadata']['from_domain']!r}"
    )
    assert not any("BODY.PEEK[2]" in c for c in _fetch_calls_9a), (
        f"200 MB part (BODY.PEEK[2]) must not be fetched; calls were: {_fetch_calls_9a}"
    )
    print(f"  oversized_part_skipped={_entry9a['metadata']['oversized_part_skipped']} ✓")
    print(f"  fetch specs: {_fetch_calls_9a}")
    print("  Test 9a (200 MB part skipped, small part processed): PASSED")

    # ── Test 9b: normal message — headers, IP, and links all extracted correctly ──
    _HDR_9B = (
        b"From: phisher@scam.net\r\n"
        b"To: target@example.com\r\n"
        b"Subject: Normal size test\r\n"
        b"Date: Wed, 25 Jun 2026 11:00:00 +0000\r\n"
        b"Message-ID: <norm@scam.net>\r\n"
        b"Authentication-Results: mx.google.com; spf=fail; dkim=none; dmarc=fail\r\n"
        b"Received: from scam.net (scam.net [203.0.113.77])\r\n"
        b"       by mx.google.com; Wed, 25 Jun 2026 11:00:00 +0000\r\n"
        b"\r\n"
    )
    _BS_9B = b'("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL "7BIT" 2000 30)'
    _HTML_9B = b'<html><body><a href="http://scam.net/steal">Click here</a></body></html>'

    def _uid_9b(command, uid_arg, *args):
        if command == "fetch":
            spec = str(args[0]) if args else ""
            if "BODYSTRUCTURE" in spec:
                return ("OK", [
                    (b"6 (BODY[HEADER] {%d}" % len(_HDR_9B), _HDR_9B),
                    b" BODYSTRUCTURE " + _BS_9B + b" )",
                ])
            return ("OK", [(b"6 (BODY[1] {%d}" % len(_HTML_9B), _HTML_9B), b")"])
        return ("OK", [b""])

    _conn9b = MagicMock()
    _conn9b.uid.side_effect = _uid_9b
    _scanner9._process_message(_conn9b, b"6", "INBOX")

    assert not _q9.empty(), "Event must be queued for normal message"
    _entry9b = _q9.get_nowait()
    assert _entry9b["metadata"]["oversized_part_skipped"] is False
    assert _entry9b["metadata"]["from_domain"] == "scam.net"
    assert _entry9b["metadata"]["originating_ip"] == "203.0.113.77"
    assert _entry9b["metadata"]["originating_ip_trusted"] is True
    assert _entry9b["metadata"]["html_only"] is True
    assert any("scam.net/steal" in lnk["href"] for lnk in _entry9b["metadata"]["links"]), (
        f"Expected link from HTML body; got {_entry9b['metadata']['links']}"
    )
    print(f"  from_domain={_entry9b['metadata']['from_domain']} ✓")
    print(f"  originating_ip={_entry9b['metadata']['originating_ip']} ✓")
    print(f"  html_only={_entry9b['metadata']['html_only']} ✓")
    print(f"  links={_entry9b['metadata']['links']} ✓")
    print("  Test 9b (normal message, headers + links extracted): PASSED")

    print("  Test 9: BODYSTRUCTURE-first two-phase fetch PASSED\n")

    print("=" * 60)
    print("Test 10: A7 — first-run unread scan, auth backoff, default folders")
    print("=" * 60)

    # ── 10a: default folders include [Gmail]/Spam ─────────────────────────────
    _scanner_default_folders = EmailScanner(
        event_queue=_queuemod.Queue(),
        imap_server="imap.example.com",
        imap_port=993,
        email_address="test@example.com",
        password="secret",
    )
    assert "INBOX" in _scanner_default_folders._folders, "INBOX missing from defaults"
    assert "[Gmail]/Spam" in _scanner_default_folders._folders, (
        "[Gmail]/Spam missing from defaults"
    )
    assert _scanner_default_folders._folders == ["INBOX", "[Gmail]/Spam"], (
        f"Unexpected default folders: {_scanner_default_folders._folders}"
    )
    print(f"  default folders={_scanner_default_folders._folders} ✓")
    print("  Test 10a (default folders include Spam): PASSED")

    # ── 10b: first_run_scan_unread_days → UNSEEN SINCE search on first run ────
    _q10b = _queuemod.Queue()
    _scanner10b = EmailScanner(
        event_queue=_q10b,
        imap_server="imap.example.com",
        imap_port=993,
        email_address="test@example.com",
        password="secret",
        folders=["INBOX"],
        first_run_scan_unread_days=7,
    )

    _HDR_10B = (
        b"From: phisher@evil.ru\r\n"
        b"To: target@example.com\r\n"
        b"Subject: Unread phish\r\n"
        b"Date: Wed, 25 Jun 2026 09:00:00 +0000\r\n"
        b"Message-ID: <unread@evil.ru>\r\n"
        b"Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail\r\n"
        b"Received: from evil.ru (evil.ru [185.220.101.2])\r\n"
        b"       by mx.google.com; Wed, 25 Jun 2026 09:00:00 +0000\r\n"
        b"\r\n"
    )
    _BS_10B = b'("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "7BIT" 20 1)'
    _BODY_10B = b"Click http://evil.ru/phish to confirm."
    _search_calls_10b: list[str] = []

    def _uid_10b(command, uid_arg, *args):
        if command == "search":
            criterion = " ".join(str(a) for a in args)
            _search_calls_10b.append(criterion)
            if "ALL" in criterion:
                # Baseline: 3 existing messages
                return ("OK", [b"100 150 175"])
            if "UNSEEN" in criterion:
                # Unread from last 7 days: UIDs 150 and 175
                return ("OK", [b"150 175"])
            return ("OK", [b""])
        if command == "fetch":
            spec = str(args[0]) if args else ""
            if "BODYSTRUCTURE" in spec:
                return ("OK", [
                    (b"0 (BODY[HEADER] {%d}" % len(_HDR_10B), _HDR_10B),
                    b" BODYSTRUCTURE " + _BS_10B + b" )",
                ])
            return ("OK", [(b"0 (BODY[1] {%d}" % len(_BODY_10B), _BODY_10B), b")"])
        return ("OK", [b""])

    _conn10b = MagicMock()
    _conn10b.select.return_value = ("OK", [b"3"])
    _conn10b.untagged_responses = {
        "UIDVALIDITY": [b"5555"],
        "UIDNEXT": [b"200"],
    }
    _conn10b.uid.side_effect = _uid_10b

    _state10b: dict = {}
    _scanner10b._poll_folder(_conn10b, "INBOX", _state10b)

    assert _state10b["INBOX"]["last_uid"] == 175, (
        f"last_uid should be max of ALL existing UIDs (175), got {_state10b['INBOX']['last_uid']}"
    )
    assert any("UNSEEN" in c for c in _search_calls_10b), (
        f"UNSEEN SINCE search must be issued; got search calls: {_search_calls_10b}"
    )
    assert _q10b.qsize() == 2, (
        f"Expected 2 unread events (UIDs 150+175), got {_q10b.qsize()}"
    )
    event1 = _q10b.get_nowait()
    event2 = _q10b.get_nowait()
    assert event1["metadata"]["from_domain"] == "evil.ru"
    assert event2["metadata"]["from_domain"] == "evil.ru"
    print(f"  search calls: {_search_calls_10b}")
    print(f"  last_uid={_state10b['INBOX']['last_uid']} (max of ALL) ✓")
    print(f"  queued events={_q10b.qsize() + 2} (2 unread messages scanned) ✓")
    print("  Test 10b (first-run unread scan): PASSED")

    # ── 10c: first_run_scan_unread_days=0 → no UNSEEN search (default behavior) ─
    _search_calls_10c: list[str] = []

    def _uid_10c(command, uid_arg, *args):
        if command == "search":
            _search_calls_10c.append(" ".join(str(a) for a in args))
            return ("OK", [b"100 150 175"])
        return ("OK", [b""])

    _scanner10c = EmailScanner(
        event_queue=_queuemod.Queue(),
        imap_server="imap.example.com",
        imap_port=993,
        email_address="test@example.com",
        password="secret",
        folders=["INBOX"],
        first_run_scan_unread_days=0,  # default — skip all history
    )
    _conn10c = MagicMock()
    _conn10c.select.return_value = ("OK", [b"3"])
    _conn10c.untagged_responses = {"UIDVALIDITY": [b"1"], "UIDNEXT": [b"200"]}
    _conn10c.uid.side_effect = _uid_10c
    _scanner10c._poll_folder(_conn10c, "INBOX", {})
    assert not any("UNSEEN" in c for c in _search_calls_10c), (
        f"UNSEEN search must NOT be issued when first_run_scan_unread_days=0; "
        f"got: {_search_calls_10c}"
    )
    print("  first_run_scan_unread_days=0 → no UNSEEN search ✓")
    print("  Test 10c (default=0 preserves old behavior): PASSED")

    # ── 10d: K consecutive auth failures → email_auth_failing incident ────────
    _q10d = _queuemod.Queue()
    _scanner10d = EmailScanner(
        event_queue=_q10d,
        imap_server="imap.example.com",
        imap_port=993,
        email_address="test@example.com",
        password="wrong",
        folders=["INBOX"],
    )
    with _patch("imaplib.IMAP4_SSL") as _mock_ssl_10d:
        _mock_conn_10d = MagicMock()
        _mock_conn_10d.login.side_effect = imaplib.IMAP4.error("[AUTH] Bad credentials")
        _mock_ssl_10d.return_value = _mock_conn_10d
        for _ in range(_AUTH_INCIDENT_THRESHOLD):
            _scanner10d._connect()

    assert not _q10d.empty(), "email_auth_failing incident must be queued after K auth failures"
    _inc10d = _q10d.get_nowait()
    assert _inc10d["event_type"] == "email_auth_failing", (
        f"Wrong event_type: {_inc10d['event_type']!r}"
    )
    assert _inc10d["severity"] == "high"
    assert _scanner10d._auth_fail_streak == _AUTH_INCIDENT_THRESHOLD
    print(f"  event_type={_inc10d['event_type']} severity={_inc10d['severity']} ✓")
    print(f"  auth_fail_streak={_scanner10d._auth_fail_streak} ✓")
    print("  Test 10d (K auth failures → incident): PASSED")

    # Verify incident is NOT emitted again on the next failure (idempotent)
    with _patch("imaplib.IMAP4_SSL") as _mock_ssl_10d2:
        _mock_ssl_10d2.return_value = _mock_conn_10d
        _scanner10d._connect()
    assert _q10d.empty(), "Incident must only fire once per streak, not on every subsequent failure"
    print("  Incident fires once per streak (idempotent) ✓")
    print("  Test 10d (auth backoff incident): PASSED")

    print("  Test 10: A7 hardening PASSED\n")

    print("All tests passed.")
    print("(Live IMAP test: run with real .env credentials in integration test)")
