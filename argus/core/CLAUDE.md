# CLAUDE.md — argus/core/
# Modules: logger.py · gate_keeper.py · daemon.py

Cross-cutting rules live in the root `CLAUDE.md`. This file contains only
contracts specific to the modules in this folder.

---

## logger.py

**SHA-256 hash-chain invariant.** Each row's hash is computed over the previous row's hash
plus the current row's content. This is a correctness requirement, not style. Tampering is
made *detectable*, not *impossible* — the chain proves alteration after the fact; it does
not prevent it. The distinction matters and must be stated honestly in the README.

**`threading.Lock` on all writes.** Through Phase 8 the event-processor is the main writer,
but it is not the only one — the main thread writes startup/shutdown/tamper-check incidents,
and Phase 4 (tray: user-confirm updates) and Phase 7 (cloud-sync) add more writers. Any
interleaving corrupts the hash chain, so the lock is a correctness requirement, not a
forward-looking nicety. (Single lock + single connection is acknowledged debt — fine while
writes stay low-volume; revisit at Phase 9.)

**Known debt (do not fix without explicit instruction):**
- `chain_hash` covers only `incident_id`, `timestamp`, `verdict`, and `chain_hash` — not
  `features`, `reasoning`, or `confidence`. Editing those columns is undetectable. Deliberate
  tradeoff (performance vs. coverage). Must be documented in `threat_model.md`.
- `verify_chain()` runs at daemon startup only. In-session tamper + restore before shutdown
  evades detection. Known; acceptable for Phase 1.
- A crash between the `incidents` INSERT and the `daily_stats` counter update leaves stats
  stale. Correct fix is a SQLite trigger (atomic with INSERT), not Python. Defer to Phase 8.

---

## gate_keeper.py

**Gate sequence: four gates, strict order. Cheaper gates run first. Never skip a gate.**

> **Note (gate-count contradiction resolved against live code):** the canonical count is
> **four** gates: 1, 1.5, 2, 3 (`gate_reached` ∈ {1, 15, 2, 3}). The code contradicts
> itself — the `GateKeeper` class docstring already says "four-gate" but the module-level
> docstring (line 5) still says "Three-gate security pipeline." Fix only that module-level
> line on next touch.

| Gate | What | Cost |
|---|---|---|
| Gate 1 | Windows Defender (MpCmdRun.exe, 60s timeout) | Cheapest authoritative check |
| Gate 1.5 | VirusTotal SHA-256 hash lookup (skip if no API key) | Hash only; free tier |
| Gate 2 | Static analysis: feature extraction + `heuristic_verdict()` (Phase 2 inference slots in via `inference_router`) | More expensive |
| Gate 3 | Dynamic/human routing: sandbox (scripts), HUMAN_DECISION (executables) | Most expensive; stubbed until Phase 3 |

Gate 3 returning `UNAVAILABLE` → route to `HOLD_FOR_HUMAN`. This is correct behavior.

**VirusTotal rate limit.** Free tier = 4 req/min — enforced by `_vt_rate_limit_wait()`
(sliding 60s window, blocks when 4 requests are in-flight). Verified present.

> **Gap (this audit):** the architecture record lists "hash caching" as a gate_keeper
> property, but the live code has **only** the rate limiter — no result memoization by
> SHA-256. A repeated hash re-queries VT and burns a rate slot. Contract for whoever
> touches this next: add a SHA-256 → verdict cache and check it before the network call.
> Do not state hash-caching as existing behavior until it does.

**ACL deny-execute on the staging zone** (`~/Downloads`) must be set before analysis
completes, not after. The file must not be executable while the pipeline is running.

**Move logging integrity.** A failed move to quarantine or cleared must NOT be logged as
succeeded. The log record must reflect the actual filesystem outcome.

**Exact intel gate.** `exact_intel_check()` is a Python-set membership test (O(1)).
A hit locks the verdict SUSPICIOUS before any inference runs. The LLM is never invoked
on an exact-match hit. Interface stub is present; Phase 3 `threat_feeds.py` populates it.

---

## daemon.py

**Threading model (verified against the daemon.py docstring — single shared queue, single
consumer). Producers never consume; the one consumer owns all dispatch and the synchronous
SQLite write.**

| Thread | Role |
|---|---|
| Main | Blocks in `wait_for_shutdown()`; pystray takes this slot in Phase 4 |
| file-watcher | watchdog Observer; produces **both** staged and desktop file events into the shared `event_queue` |
| email-scanner | IMAP poll; produces email events into the **same** `event_queue` |
| event-processor | **Single consumer**: reads `event_queue`, dispatches staged → `gate_keeper`, desktop/email → `extractor` + heuristics + `logger`. Logging is synchronous here — there is **no** separate logger thread |
| cloud-sync-stub | Drains `sync_queue` (Phase 7 adds real BigQuery/GCS writes) |

> **Correction (this audit):** an earlier draft and the source directive both described
> separate "staged-file-events," "gate_keeper-dispatch," and "logger" threads. The live code
> has none of those — one `event_queue`, one `event-processor` consumer, synchronous logging.
> Do not split these without an architectural decision recorded in `HANDOFF.md`.

Inter-thread communication is via `queue.Queue` (`event_queue`, `sync_queue`) only. The one
exception is the D3 `_attachment_correlation_cache` dict, shared between the email-scanner
(writes) and event-processor (reads/pops) — the documented exception, not a precedent.

**Event routing rule** (in `_dispatch`):
- `source == "file_watcher" and staged` → `gate_keeper.process(event)`
- otherwise → `extractor.extract(event)` → `heuristic_verdict()` (Phase 2 inference slots in here) → `logger`

**Graceful shutdown** must drain in-flight events before exit. `stop()` signals shutdown,
stops monitors first (no new events), then joins the processor (up to 90s: 60s Defender + 30s
buffer) so the queue fully drains. A shutdown mid-analysis must not silently drop a verdict.
