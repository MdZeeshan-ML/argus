# Adversarial Test Findings — A.R.G.U.S. Phase 1

Plain-language writeup of what the adversarial test suite in this directory found,
proved, or documented. Written from the attacker's side (see `_fixtures.py` module
docstring for the full framing) and scoped to code that's actually built — no findings
here are speculation about Phase 2/3/9.

Each entry: **what it is**, **why it matters**, **how bad it is**, **proof**.
Severity is plain-English, not a CVSS score: Real Gap (fix it), Heads-Up (verify by
hand, unclear from the interface alone), or Confirmed Defended (checked, and it holds).

## At a glance

| # | Finding | Severity | Layer |
|---|---------|----------|-------|
| 1 | Macro scan is extension-gated (`.doc`/`.docx` never inspected) | 🔴 Real Gap | feature_extractor |
| 2 | Polyglot PDF+PE (header-only magic check?) | 🟡 Heads-Up | feature_extractor |
| 3 | `.tmp`-named payload never generates an event | 🔴 Real Gap | file_watcher |
| 4 | `recursive=False` misses extracted-archive contents | 🔴 Real Gap (known, FW-1, parked) | file_watcher |
| 5a | Authentication-Results forgery | 🟢 Defended | email_scanner |
| 5b | Received-header `by`-host substring match | 🔴 Real Gap | email_scanner |
| 6 | ISO/IMG container smuggling | 🟢 Defended | gate_keeper |
| 7 | Vanished file still logged | 🟢 Defended | gate_keeper / logger |
| 8 | 0-byte / still-growing file held, not cleared | 🟢 Defended | gate_keeper |
| 9 | Double extension / MZ-in-disguise / `.url` never auto-clear | 🟢 Defended | gate_keeper |
| 10 | Auth-passing + homoglyph lookalike domains caught | 🟢 Defended | feature_extractor |
| 10 | Pure display-name freemail spoof | ⚪ Known blind spot (needs Phase 2) | — |
| 11 | Exact-hash bypass via 1-byte mutation, encoded IP literals | ⚪ By design (architectural) | gate_keeper |
| 12 | C1 symbolic-override lock, C3 forged-IP isolation | 🟢 Defended | gate_keeper |
| 13 | Zip bombs / giant files / event floods don't stall/crash | 🟢 Defended | feature_extractor / file_watcher / gate_keeper |
| 14 | Tamper-evident log detects edits + deletions | 🟢 Defended | logger |
| 15 | TOCTOU / ACL / `.lnk` — needs Windows boot | ⚪ Out of scope here | gate_keeper |

**Two Real Gaps stand out as worth fixing first:** #5b (an attacker-controlled IP can
be laundered through gate_keeper's C3 trust gate — the header check meant to prevent
exactly that) and #3 (a `.tmp`-named file is completely invisible to file_watcher
forever, not just temporarily). #1 and #4 are real but narrower/already-known.

---

## 1. Macro detection is gated by file extension, not by content — Real Gap

**What it is:** `feature_extractor.py`'s `_extract_file` only opens a file to check for
VBA macros when its extension is one of `.docm`, `.xlsm`, `.pptm`, `.xll`, `.iqy`,
`.slk`. A file with the exact same macro-laden ZIP/OOXML bytes, saved as `.doc` or
`.docx` instead, gets `has_macros = None` — the macro scanner never runs at all.

**Why it matters:** Microsoft Office does its own content sniffing, not extension
matching — it will still offer to run macros in a `.doc`-named file that's actually a
macro-enabled document underneath (with the usual "Enable Content" prompt, which
freelance-platform social-engineering lures are specifically designed to get clicked).
This is the exact "fake client brief" threat named in `CLAUDE.local.md` as a personal,
already-identified risk — a scammer posing as a Fiverr/Upwork client just needs to save
their payload with a plain `.doc`/`.docx` name instead of `.docm` and this specific
check contributes nothing.

**Severity:** Real Gap. Not a crash, not a false negative in the classic sense — it's a
scanner that silently doesn't run.

**Fix direction (not implemented — out of scope for this pass):** sniff the file's
actual structure (ZIP magic bytes / OLE compound-file magic bytes) to decide whether to
run `_check_office_macros`, instead of — or in addition to — the extension allowlist.

**Proof:** `test_file_masquerade.py::test_macro_payload_renamed_to_doc_is_never_even_inspected`
(paired with `test_macro_payload_detected_when_extension_is_in_the_checked_set`, which
proves the underlying macro scanner itself works fine — this is a scope/allowlist gap,
not a broken parser).

---

## 2. Polyglot PDF+PE (valid PDF header, executable appended after `%%EOF`) — Heads-Up

**What it is:** A file can start with a fully valid `%PDF-1.4` header — everything a
PDF reader or a header-only magic-byte check looks at — and carry a complete MZ/PE
executable blob appended after the PDF's own `%%EOF` marker. PDF readers ignore
trailing bytes; a second-stage tool, or the same file simply renamed to `.exe`, would
run the appended payload.

**Why it matters:** this is a textbook polyglot technique (same family as GIFAR-style
attacks). It's cheap to build and specifically defeats "check the first few bytes"
style detection.

**Severity:** Heads-Up, not confirmed Real Gap. In the one test run, this artifact
scored `UNANALYZED` with `magic_bytes_desc='PDF'` — consistent with a magic-byte check
that only looks at the file's start, but I did not read `_magic_identify`'s internals
to confirm that's actually why (per the "no line-by-line audit" scope for this pass).
Recommend a manual look at whether `python-magic`/the wrapping code ever scans past the
header.

**Proof:** `test_file_masquerade.py::test_polyglot_pdf_with_trailing_pe_is_a_documented_blind_spot`
(prints the observed verdict/magic description for review; does not hard-assert a
verdict, since I can't back that assertion without the deeper read this task said to skip).

---

## 3. `.tmp` (and other "in-progress download" suffixes) permanently hides a file from FileWatcher — Real Gap

**What it is:** `file_watcher.py`'s `_is_temp_file` treats any file ending in `.tmp`,
`.crdownload`, `.part`, `.partial`, `.download`, `.!ut`, `.opdownload`, or `.crswap`
(or starting with `~$`) as an in-progress browser download and skips it on
`on_created` — no event is ever queued. This makes sense for genuine partial downloads,
which get renamed on completion (caught by `on_moved`). But nothing requires the file
to actually be a partial download — an attacker who delivers `payload.tmp` directly
(e.g. via a direct download link, not through a browser's temp-then-rename flow) and
never renames it gets a complete, final, fully-malicious file sitting in Downloads that
FileWatcher will never generate a single event for, ever.

**Why it matters:** this is a total, silent bypass of the file-watching layer — not
"scored low," not "held for review," genuinely invisible. If the victim later
double-clicks `payload.tmp` directly (some file associations don't care about the
extension, or the victim renames it themselves outside of a tracked move), ARGUS never
saw it happen.

**Severity:** Real Gap.

**Proof:** `test_file_watcher_evasion.py::test_tmp_suffix_permanently_evades_created_event`.

---

## 4. `recursive=False` misses files delivered inside an extracted subfolder — Confirmed, already tracked (FW-1)

**What it is:** `FileWatcher.start()` schedules each watch directory with
`recursive=False` ("Downloads/Cleared/ files are already clean — don't re-process," per
the code comment — that reasoning covers `Cleared/` specifically, not arbitrary
subfolders). Any file created inside a *new* subdirectory of Downloads — e.g. what
happens when a victim extracts a downloaded `.zip` "portfolio samples" archive — is
invisible to the watcher entirely, same as finding #3: no event, ever.

**Why it matters:** this is the exact "new client sends a .zip of reference files, one
of which is a masquerading executable" delivery shape, and it routes around file
monitoring by construction, not by evading any specific check.

**Severity:** Confirmed real. **This is not a new discovery** — it's `HANDOFF.md`'s own
tracked item **FW-1 (CRITICAL)**, explicitly parked ("Zeeshan reopens when ready"). This
test exists as a reproducible regression-guard for when that reopens, not as new news.

**Proof:** `test_file_watcher_evasion.py::test_recursive_false_misses_files_in_extracted_subdirectory`.

---

## 5a. Authentication-Results header forgery — Confirmed Defended

**What it is:** an attacker who controls part of the SMTP relay path (or just crafts
raw headers directly) inserts their own fake `Authentication-Results: mx.google.com;
spf=pass; dkim=pass; dmarc=pass` header, hoping a naive parser just looks for *any*
header claiming success rather than the one your actual mail provider stamped.

**Why it matters:** if this worked, every auth-based signal in the whole pipeline
(reply-to mismatch scoring, DKIM alignment) would be trivially spoofable from
outside — this is usually where "did you actually validate Authentication-Results"
security reviews find real bugs.

**Severity:** Confirmed Defended. `_parse_auth_results` explicitly requires (1) the
`authserv-id` to **exactly equal** (`!=` comparison, not substring) the configured
provider — rejects a forged foreign stamp — **and** (2) only trusts the *topmost*
document-order header with that matching id — rejects a forged header injected below
the genuine provider-stamped one, which is where a sender-side forgery attempt would
land. Verified against real forged-header test messages in both directions.

**Proof:** `test_email_social_engineering.py::test_forged_authentication_results_header_below_real_one_is_rejected`,
`::test_authentication_results_with_wrong_authserv_id_is_untrusted`.

---

## 5b. Received-header sender-IP trust check uses substring match, not exact match — Real Gap

**What it is:** `_extract_originating_ip` decides whether a `Received:` header's IP is
trustworthy with this check:

```python
if provider_authserv_id.lower() not in by_host:
    continue
```

That's substring containment (`in`), not an exact host/domain-boundary match — the
same class of bug as `if "paypal.com" in url`, which also wrongly matches
`paypal.com.evil.ru`. An attacker who controls `attacker.ru` can point a subdomain
mail server at `mx.google.com.attacker.ru`, use that literal string as the `by` host
in a `Received:` header they insert, and the check passes — `"mx.google.com" in
"mx.google.com.attacker.ru"` is `True` in Python. The header is then treated as
genuinely stamped by the real receiving MX, and the attacker-chosen IP comes back as
`originating_ip_trusted = True`.

**Why it matters:** `originating_ip_trusted` is exactly the flag that gates whether an
IP gets checked against exact-intel feeds (`gate_keeper`'s C3 contract: "sender_ip
passed only when trusted — forged IP must not steer intel"). This bug means that gate
can be tricked into treating an attacker-supplied IP as verified sender
infrastructure — the opposite of what C3 exists to prevent. This is a more serious
finding than 5a: 5a's equivalent check is exact-match and correctly defended; this one,
checking conceptually the same kind of trust, is not.

**Severity:** Real Gap.

**Fix direction (not implemented — out of scope for this pass):** match the `by` host
against the provider hostname as a domain suffix (`by_host == target or
by_host.endswith("." + target)`), the same shape `_parse_auth_results` already uses
correctly for `authserv_token`.

**Proof:** `test_email_social_engineering.py::test_received_header_by_clause_substring_match_is_spoofable`
(paired with `::test_received_header_with_unrelated_by_host_is_ignored`, which
confirms the parser isn't just trusting the first Received header it sees — this is
specifically a substring-match issue, not "no check at all").

---

## 6. ISO/IMG "container smuggling" — Confirmed Defended

**What it is:** delivering a payload inside a mountable disk image (`.iso`/`.img`)
instead of a raw executable, hoping it reads as an inert "disk image" file type rather
than triggering executable-focused heuristics.

**Severity:** Confirmed Defended. `gate_keeper._gate3_route` explicitly routes anything
with `gate3_category == "archive_image"` to `HUMAN_DECISION_REQUIRED` — it can never be
silently auto-cleared, regardless of what static heuristics say about it. This isn't
new work; it just wasn't tested before this pass.

**Proof:** `test_file_masquerade.py::test_iso_disk_image_container_never_reaches_cleared`.

---

## 7. Deleting the file mid-scan does not erase its incident record — Confirmed Defended

**What it is:** if a file vanishes (self-deleted by malware, removed by the user,
caught by real-time AV) between being detected and `gate_keeper` finishing its
stability check, does that event leave any trace?

**Severity:** Confirmed Defended. `gate_keeper.process()`'s `_finalize` call happens
for every outcome, including "vanished" — an incident is still logged (verdict
`UNANALYZED`, reason "File disappeared before analysis could complete"). An attacker
who deletes their own dropper immediately after execution does not get a clean audit
log — there's still a row saying *something* arrived and disappeared before it could be
scanned. The code comment marks this as a deliberate fix ("previously returned without
any SQLite record — silent gap in the audit trail"), so this was already known and
already closed; this pass just adds a test for it.

**Proof:** `test_containment_integrity.py::test_vanished_file_still_logs_an_incident`.

---

## 8. 0-byte and still-growing files are held, never silently cleared — Confirmed Defended

**What it is:** two DoS-adjacent shapes — (a) drop a 0-byte placeholder and hope it's
ignored/waved through, (b) keep a file "still writing" forever (trickle bytes in slowly)
past the 60-second stability window, hoping to keep it permanently in limbo while still
usable.

**Severity:** Confirmed Defended for both. A 0-byte file gets `HOLD_FOR_HUMAN` (not
cleared, not ignored). A file still growing after the stability timeout gets
`HOLD_UNANALYZED`, explicitly noted in the code as a prior audit fix ("previously
returned True here if size > 0 — a file still being written was analyzed on partial
content... a possible CLEAN verdict for bytes that don't exist yet"). Both hold the
file in the staging zone rather than releasing it.

**Proof:** `test_containment_integrity.py::test_zero_byte_file_is_held_not_cleared`,
`::test_still_growing_file_past_stability_window_is_held_not_cleared`.

---

## 9. Double extensions, MZ-in-disguise, and `.url` shortcuts never auto-clear — Confirmed Defended

Carried over from the first pass of this suite, still holding after the extra tests
added in this round:
- `invoice.pdf.exe` (double extension) and a raw MZ/PE header saved as `.pdf` both
  score `SUSPICIOUS`/route away from `CLEARED`.
- A `.url` Internet Shortcut pointing at a remote `.exe` never auto-clears either
  (`GATE3_EXTENSIONS` routing forces it through Gate 3).

**Proof:** `test_file_masquerade.py::test_double_extension_never_reaches_cleared_via_gatekeeper`,
`::test_mz_header_in_pdf_extension_scores_suspicious`,
`::test_url_shortcut_never_reaches_cleared_via_gatekeeper`.

---

## 10. Auth-passing lookalike domains, TLD-homoglyph brand squats, Cyrillic-homoglyph senders — Confirmed Defended

Domain-identity checks (`_check_lookalike`, skeleton + Levenshtein) catch these even
when SPF/DKIM/DMARC all legitimately pass on attacker-owned infrastructure, and even
when no ASCII substring match is possible (Cyrillic homoglyphs). Reply-To mismatch,
DKIM-signed-but-misaligned-domain ("authenticated spoof"), and shortener-hides-mismatch
lures all score `SUSPICIOUS` too.

**Known, deliberately un-fixed blind spot:** pure display-name spoofing from a genuine
freemail address ("Fiverr Support <random123@gmail.com>", no links/attachments yet) has
no domain-identity or auth-failure signal to key on — current behavior is `UNANALYZED`.
This is explicitly the gap Phase 2 (content-reading LLM tier) exists to close; the
symbolic layer alone was never meant to catch this.

**Proof:** `test_email_social_engineering.py` (whole file).

---

## 11. Exact-hash matching is trivially evaded by one-byte mutation — Confirmed, by design

A single bit flip in a known-bad file changes its SHA-256 completely; Channel 1 (exact
match) cannot and is not meant to catch this — it's why CLAUDE.md mandates a separate
fuzzy/heuristic layer at all. Decimal- and hex-encoded IP literals in URLs
(`http://3232235521/`) also evade the raw-IP-literal check the same way, since
`ipaddress.ip_address()` requires dotted-quad/colon notation. Both are architectural
consequences, not bugs, and are the reason `heuristic_verdict`'s independent scoring
signals exist as a backstop.

**Proof:** `test_threat_intel_evasion.py::test_single_byte_mutation_evades_exact_hash_match`,
`::test_decimal_encoded_ip_evades_raw_ip_literal_check`,
`::test_hex_encoded_ip_evades_raw_ip_literal_check`.

---

## 12. C1 exact-intel lock and C3 forged-IP protection both hold — Confirmed Defended

A hard-fact hit (known-bad URL) locks `SUSPICIOUS`/`0.95` even when every other signal
in a message is clean, and the C2 scoring path is never even reached once C1 hits — the
neuro-symbolic override invariant holds at the one layer where it's implemented today.
Separately, a forged/unverifiable `originating_ip` (trust flag `False`) is never
checked against IP intel feeds, so a spoofed Received-header IP can't be used to frame
an innocent address or launder a bad one through an untrusted header path.

**Proof:** `test_threat_intel_evasion.py::test_c1_exact_intel_lock_overrides_an_otherwise_clean_score`,
`::test_forged_sender_ip_is_not_queried_against_intel_when_untrusted`.

---

## 13. Resource-exhaustion shapes (zip bombs, giant files, event floods) don't stall or crash the pipeline — Confirmed Defended

A scaled-down nested zip bomb and a 3 MB high-entropy file both complete feature
extraction in well under a second (the `entropy_sample_bytes` cap actually bounds the
work, not just the intent to). A 40-file burst into a 5-slot bounded queue drops the
overflow cleanly (`queue.Full` caught, logged, never crashes the watcher thread) rather
than blowing up or blocking. A 30-file burst through `GateKeeper.process` with a real
`ArgusLogger` attached produces exactly 30 verdicts, all with real incident IDs, with
the audit hash chain still verifying intact afterward.

**Proof:** `test_file_masquerade.py::test_zip_bomb_entropy_extraction_is_time_bounded`,
`::test_giant_high_entropy_file_extraction_is_time_bounded`;
`test_availability_dos.py` (whole file).

---

## 14. Tamper-evident audit log genuinely detects tampering and deletion — Confirmed Defended

Directly rewriting a logged verdict via raw SQL, or deleting a row outright, both break
`ArgusLogger.verify_chain()` and are attributed to the correct incident. The public API
surface has no `update_incident`/`delete_incident` method to abuse in the first place.
Adversarial content (null bytes, 200KB strings, control-character escape sequences
mimicking a fake terminal alert) logs cleanly without crashing the logger or corrupting
the hash chain.

**Proof:** `test_containment_integrity.py` (whole file).

---

## 15. Not independently verifiable without a Windows boot — Out of scope, named for completeness

True TOCTOU on `gate_keeper._move_to_quarantine` (does the mover re-check file identity
right before moving, or trust an earlier classification?), the effectiveness of the
`icacls` deny-execute ACL on the staging zone, and real `.lnk` binary shortcut parsing
all require the Windows boot per `CLAUDE.local.md`'s platform-coupling rule and were not
exercised here. The one adjacent thing that IS provable cross-platform —
`_is_staged`'s path classification gives an identical answer before and after a
same-path symlink swap, because it never re-resolves what the path currently points
at — is tested, to at least show the *shape* of the race at the one layer available on
Linux.

**Proof:** `test_containment_integrity.py::test_path_string_classification_cannot_distinguish_a_post_check_symlink_swap`.
