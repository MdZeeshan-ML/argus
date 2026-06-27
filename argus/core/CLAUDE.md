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

**`threading.Lock` on all writes.** Multiple daemon threads write concurrently. Without the
lock, interleaved writes corrupt the chain. The lock is a correctness requirement.

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

> **Note:** The module-level docstring currently reads "Three-gate security pipeline" —
> this is a misnomer. The live implementation defines four gates: 1, 1.5, 2, and 3.
> `gate_reached` takes values 1, 15 (Gate 1.5), 2, or 3. Fix the docstring on next touch.

| Gate | What | Cost |
|---|---|---|
| Gate 1 | Windows Defender (MpCmdRun.exe, 60s timeout) | Cheapest authoritative check |
| Gate 1.5 | VirusTotal SHA-256 hash lookup (skip if no API key) | Hash only; free tier |
| Gate 2 | Static analysis: feature extraction + inference | More expensive |
| Gate 3 | Dynamic/human routing: sandbox (scripts), HUMAN_DECISION (executables) | Most expensive; stubbed until Phase 3 |

Gate 3 returning `UNAVAILABLE` → route to `HOLD_FOR_HUMAN`. This is correct behavior.

**VirusTotal rate limit.** Free tier = 4 req/min. Cache first, network second. Never issue
a VT request without checking the hash cache first.

**ACL deny-execute on the staging zone** (`~/Downloads`) must be set before analysis
completes, not after. The file must not be executable while the pipeline is running.

**Move logging integrity.** A failed move to quarantine or cleared must NOT be logged as
succeeded. The log record must reflect the actual filesystem outcome.

**Exact intel gate.** `exact_intel_check()` is a Python-set membership test (O(1)).
A hit locks the verdict SUSPICIOUS before any inference runs. The LLM is never invoked
on an exact-match hit. Interface stub is present; Phase 3 `threat_feeds.py` populates it.

---

## daemon.py

**Five concurrent execution contexts and their ownership:**
- Main thread: pystray tray icon (pystray must own the main thread — framework requirement)
- Thread 1: staged-file-events → `gate_keeper`
- Thread 2: desktop-file-events → `feature_extractor` → inference → `logger`
- Thread 3: email-poll → `email_scanner` → scoring → `logger`
- Thread 4: cloud-sync queue processor (async, best-effort, non-blocking)

Thread boundaries are not to be blurred without an architectural decision recorded in
`HANDOFF.md`.

**Event routing rule:**
- `event.staged == True` → `gate_keeper.process(event)`
- `event.staged == False` → `extractor.extract(event)` → inference → `logger`

**Graceful shutdown** must drain in-flight events before exit. A shutdown mid-analysis must
not silently drop a verdict.
