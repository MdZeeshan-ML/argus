# CLAUDE.md — argus/analysis/
# Modules: feature_extractor.py (Phase 1 — built) · inference/ (Phase 2 — not built) · rag/ (Phase 3 — not built)

Cross-cutting rules live in the root `CLAUDE.md`. This file contains only
contracts specific to the modules in this folder.

---

## feature_extractor.py — Phase 1 (built)

**Privacy boundary enforcement point.** This is where the root `CLAUDE.md` privacy
invariant ("file contents never leave a module") is enforced in practice. Reads bytes for
structure only: magic bytes, Shannon entropy, PE headers, `Zone.Identifier` ADS, Office
macro detection. Never interprets content for meaning. Only the resulting metadata dict
leaves this module.

**WHOIS cache.** 24h TTL. Cache check must precede every network call. This module owns
the cache and the rate-limit logic for domain lookups.

**Fixed session 12 (2026-06-30):** the WHOIS cap in `_extract_email` was incrementing on
all lookups including cache hits; it now counts only cache misses (actual network calls).
Contract detail lives in `argus/monitors/CLAUDE.md` (email_scanner.py section) since the
call site is the B1 loop there — don't regress it on the next touch of that loop.

---

## inference/ — Phase 2 (not yet built)

> Do not build any module in this folder until Phase 2 starts. The contracts below are
> locked requirements to honor when the phase opens — they are not descriptions of
> existing code.

Build order within this folder: `classifier.py` → `local.py` → `cloud.py` → `router.py`
→ `explainer.py`. `consensus.py` is deferred to Phase 8.

**`router.py` must enforce (F1):**
- Sanitize all attacker-controlled feature strings and set `injection_attempt_detected=True`
  before any prompt is constructed — never after.
- Enforce the cloud allowlist (E3). Permitted file features for cloud: `filename`,
  `extension`, `sha256`, `entropy`, `magic_bytes`. For email features see
  `argus/monitors/CLAUDE.md`. Strip query strings from all link fields before cloud.
  **Canonical source: `architecture/ARCHITECTURE.md` §3.5** — this is a reference subset,
  not a second copy of record; if the two disagree, ARCHITECTURE.md wins.
- Gate `originating_ip` on `originating_ip_trusted` before it goes to cloud.

**The LLM is a rendering layer, not the decision layer.** The security verdict that drives
containment is produced by the deterministic/symbolic layers and written to SQLite
immediately as structured JSON. Human-readable explanation is produced by `explainer.py`,
called on demand when a user opens an incident in the GUI — never at verdict time.

**Routing thresholds (classifier fast path):**
- `prob > 0.9` → verdict SUSPICIOUS, locked, no LLM call
- `prob < 0.1` → verdict CLEAN, locked, no LLM call
- `0.1–0.9` → local LLM (qwen3:1.7b via Ollama); if still uncertain → cloud escalation

**Cold-start fallback.** `heuristic_verdict()` in `gate_keeper.py` is the fallback when no
trained model file is present. `classifier.py` wraps it: no model → run heuristics; model
present → model takes priority. Same graceful-degradation pattern across the system. Do
not break this fallback when building the classifier.

---

## rag/ — Phase 3 (not yet built)

> Do not build any module in this folder until Phase 3 starts. The contracts below are
> locked requirements to honor when the phase opens.

**`threat_feeds.py` must populate two independent stores (F2). These must never be merged.**

**Channel 1 — Exact match:**
- Data structure: Python sets (hash set, URL set, IP set)
- Query: O(1) set membership; returns True/False, no score
- Consumer: `gate_keeper.exact_intel_check()` (symbolic layer)
- On a hit: verdict locked SUSPICIOUS; LLM is never invoked
- Loaded via `exact_intel_load()` interface (stub already present in `gate_keeper`)

**Channel 2 — Fuzzy/semantic:**
- Data structure: ChromaDB embedding index
- Query: similarity search; top-k with scores
- Consumer: LLM prompt as RAG context; treated as evidence, not locked fact

**Why these must never be merged:** see root `CLAUDE.md` (Exact-vs-fuzzy threat-intel split)
and `architecture/ARCHITECTURE.md` §3.3 for the full rationale — not restated here per the
one-home-per-rule rule (2026-07-04 doc-sweep, audit finding R5).

> **Open question before this folder gets built (audit finding C1, 2026-07-04):** the four
> approved feeds are indicator feeds (URLs/hashes/IPs) — exact-match data by nature. No
> document yet specifies what Channel 2 actually embeds; embedding raw indicator strings
> does not produce meaningful semantic similarity, and the fuzzy jobs named elsewhere
> (lookalike domains, young domains, entropy) are already solved by deterministic features
> built in Phase 1. Before writing `threat_feeds.py`'s Channel 2 half, answer in writing:
> what is Channel 2's corpus? See `architecture/audit.md` finding C1 for the full argument.
> Not resolved here — flagged, per the project's own contradiction-flagging convention.

**Approved feed sources:** URLhaus, MalwareBazaar, OpenPhish, AbuseIPDB. All ingested via
API — no manual downloads. VirusTotal redistribution is prohibited by ToS; VT stays
bring-your-own-key on the user side and is never redistributed.
