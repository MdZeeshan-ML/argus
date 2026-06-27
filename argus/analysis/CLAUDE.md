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

**Known debt:** The WHOIS cap in `_extract_email` increments on all lookups including cache
hits; it must count only cache misses. Fix tracked in `argus/monitors/CLAUDE.md` (Bug 2)
— fix on next touch of the B1 loop.

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

**Why these must never be merged.** A similarity score can be rationalized away by the 1.7B
local model. A set-membership test cannot. Exact-match indicators collapsed into the
embedding index become fuzzy probability — the symbolic override ceases to be an override.
This channel split is the Paper 1 contribution; do not undermine it.

**Approved feed sources:** URLhaus, MalwareBazaar, OpenPhish, AbuseIPDB. All ingested via
API — no manual downloads. VirusTotal redistribution is prohibited by ToS; VT stays
bring-your-own-key on the user side and is never redistributed.
