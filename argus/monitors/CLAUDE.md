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

**Three invariants a past audit found broken — fixed session 12 (2026-06-30), see
`HANDOFF.md` ES-bug-1/2/3. Kept here as the contracts, not as open bugs (2026-07-04
doc sweep, audit finding R2/R6 — a fixed bug left recorded as "not closed" here was
exactly the drift that sweep exists to catch):**

1. **`any_link_shortener` must reach scoring.** `_is_shortener(domain)` runs in the
   B1 link-domain loop, rolls up into `any_link_shortener`, and is consumed in C2
   heuristic scoring (+0.15). If a future edit to the B1 loop drops this wiring,
   shortener links go invisible to scoring again — that's the failure mode this
   contract guards against.

2. **WHOIS cap counts network calls, not cache hits.** `MAX_LINK_WHOIS` (=5) must
   burn a slot only on an actual miss against the 24h-TTL cache — a cache hit is a
   dict lookup, not a rate-limited call, and must not count against the cap.

3. **`MAX_PARTS_PER_MESSAGE` (=20) bounds IMAP round trips per message,
   independent of the byte-size caps** (`MAX_PART_BYTES`, `MAX_MESSAGE_BYTES`).
   Byte caps alone don't stop a many-tiny-part message from forcing hundreds of
   sequential round trips and stalling the single poll thread (DoS-by-stall, not
   crash). Past the count cap, stop fetching and set `oversized_part_skipped=True`
   (shared flag with the byte-cap path) — don't add a second flag.

**Cloud allowlist is owned by Phase-2 `router.py`, not this module.** `email_scanner`
produces raw features; allowlist enforcement happens at the router boundary. For reference,
the permitted cloud fields are: `sender_domain`, `whois_age`, `spf`, `dkim`, `dmarc`,
`dkim_aligned`, `link_domains` (query strings stripped), `any_link_lookalike`,
`any_text_href_mismatch`, `originating_ip` (only when `originating_ip_trusted`), and the
attachment manifest (no bytes). The email subject is `_sensitive` — local inference only,
never cloud. **Canonical source: `architecture/ARCHITECTURE.md` §3.5 — this is a reference
subset, not a second copy of record; if the two ever disagree, ARCHITECTURE.md wins and this
list is stale.**
