# CLAUDE.md — argus/monitors/
# Modules: file_watcher.py · email_scanner.py

Cross-cutting rules live in the root `CLAUDE.md`. This file contains only
contracts specific to the modules in this folder.

---

## file_watcher.py

**Partial-file guard.** `.crdownload` (and any other partial-download suffix) files must
not be processed. Wait for the partial suffix to disappear and for the file size to
stabilize before routing the event. Features extracted from a mid-write file are wrong
(partial hash, truncated magic bytes, incorrect entropy).

**Two distinct routing paths — never merge:**
- Staging zone (`~/Downloads`) events → `gate_keeper` (full quarantine-first pipeline)
- Desktop events → `feature_extractor` → inference (direct pipeline, no quarantine gate)

---

## email_scanner.py

**IMAP read-only invariant.** Use `BODY.PEEK` only — never any IMAP command that sets the
`\Seen` flag. The user's mailbox must be completely untouched by ARGUS.

**Email password enforcement point.** The credential-protection rule (root `CLAUDE.md` —
Credentials section) is enforced here, at scanner startup. Do not defer it to another
module. If `EMAIL_PASSWORD` exists in `.env`, this module migrates it and stops reading
from `.env` — no other module should touch that migration path.

**Manifest-only for attachments.** The scanner records an attachment manifest from
BODYSTRUCTURE only: `filename`, `declared_mime`, `size_bytes`, `double_extension`,
`dangerous_ext` (.exe/.scr/.bat/.ps1/.vbs/.js/.hta), `oversized`. It fetches zero
attachment bytes. When the user downloads naturally, `file_watcher` catches the file and
runs the full `gate_keeper` pipeline. "ARGUS never downloads anything without user
permission" is the principle this design enforces — do not reverse it.

**`correlation_id`** (uuid4): written into the email event metadata at scan time. The daemon
copies it into the file incident when a downloaded file matches a recently-seen manifest
(default 30-min window). This is the link between the email event and the file event in
the GUI — do not omit it.

**Exact intel is a symbolic override — never reaches the LLM.** `exact_intel_check` in the
email scoring path is a Python-set membership test. A hit locks the verdict `SUSPICIOUS`
without invoking local or cloud inference. This is the Channel 1 path (see root
`CLAUDE.md` — Exact-vs-fuzzy split).

**Three known bugs — Phase 1 is not closed until all three are fixed:**

1. **`_is_shortener` is never called.** It is defined in `feature_extractor` but never
   invoked in `_extract_email`. `any_link_shortener` is not rolled up into features and not
   consumed by `gate_keeper` — shortener links are invisible to scoring. Fix: call
   `_is_shortener(domain)` in the B1 link-domain loop, roll up `any_link_shortener`,
   consume it in C2 heuristic scoring.

2. **WHOIS cap counts cache hits.** Verified open: `_extract_email` calls
   `self._cached_whois(domain)` then increments `whois_count` unconditionally
   (`feature_extractor.py` ~L338–339), so a hit on the 24h-TTL cache still burns a slot of
   `MAX_LINK_WHOIS` (=5). It must count cache misses only (actual network calls). Fix: have
   `_cached_whois` signal hit vs. miss, and increment `whois_count` only on a miss.

3. **No `MAX_PARTS_PER_MESSAGE` count cap.** Verified open: the part loop
   (`email_scanner.py` ~L1013–1063) has size caps (`MAX_PART_BYTES`, `MAX_MESSAGE_BYTES`)
   and already sets `oversized_part_skipped=True` on a size overflow — but there is **no
   count cap**, so a 500-tiny-part email still forces ~500 sequential IMAP round trips,
   stalling the single poll thread (DoS-by-stall, not crash). Fix: add a named count cap
   (default 20); stop fetching parts past the limit and reuse the **existing**
   `oversized_part_skipped` flag, then continue with what was fetched.

**Cloud allowlist is owned by Phase-2 `router.py`, not this module.** `email_scanner`
produces raw features; allowlist enforcement happens at the router boundary. For reference,
the permitted cloud fields are: `sender_domain`, `whois_age`, `spf`, `dkim`, `dmarc`,
`dkim_aligned`, `link_domains` (query strings stripped), `any_link_lookalike`,
`any_text_href_mismatch`, `originating_ip` (only when `originating_ip_trusted`), and the
attachment manifest (no bytes). The email subject is `_sensitive` — local inference only,
never cloud.
