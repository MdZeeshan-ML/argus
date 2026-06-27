# CLAUDE.md — A.R.G.U.S.
# Automated Real-time Guardian for User Systems

---

## Session Start Protocol — Every Session, No Exceptions

1. Read `CLAUDE.md` (this file)
2. Read `HANDOFF.md` — current state, what was last built, what is next
3. Confirm to the user: phase, last built, building now
4. Then begin

---

## Build Position

Phase 1 (Core Daemon) functionally complete; closure gated on manual tests and README
written from memory. Phase 2 (Inference) is next. Live cursor lives in `HANDOFF.md`.
Module-specific contracts live in each subfolder's `CLAUDE.md`.

---

## Architecture Invariants — Cross-Cutting

**Three-tier inference.** Fast classifier → local LLM (uncertain zone only) → cloud
escalation. The LLM is a rendering layer, not the decision layer. Containment decisions are
made by the deterministic/symbolic layer and execute before the LLM runs.

**Neuro-symbolic override.** Symbolic constraints (hard rules, MITRE ATT&CK graph) override
neural outputs unconditionally. A 1.7B model can rationalize away a fact; a graph rule or
set-membership test cannot. Where a hard fact exists, the symbolic layer decides.

**Exact-vs-fuzzy threat-intel split.** Two channels, never merged:
- Channel 1 (exact — hash/URL/IP): Python sets; O(1) membership test; consumed by
  `gate_keeper.exact_intel_check`; locks verdict SUSPICIOUS; LLM never invoked on a hit.
- Channel 2 (fuzzy/semantic): ChromaDB embedding index; top-k similarity with scores;
  consumed by the LLM as RAG context; treated as evidence, not locked fact.

**Privacy boundary.** File contents never leave a module. Only metadata travels to
inference. `feature_extractor` reads bytes for structure only, never content for meaning.

**Universal contract.** SQLite is written first, synchronously, before anything else.
Nothing executes in the staging zone without a verdict. Cloud sync is async, non-blocking.

---

## Credentials

Email password and GCP service-account path → OS keyring (`keyring` library / Windows
Credential Manager / DPAPI). Low-value revocable keys (NIM, VirusTotal) may stay in
`.env`. On first run: if `EMAIL_PASSWORD` found in `.env`, migrate to keyring, print
one-time removal instruction, never read from `.env` again. `keyring` is the one approved
new dependency this cycle. Maximum one new dependency per cycle; explicit approval required.

## Anti-Drift Rule

Before adding any rule to this file, ask: does it apply to every module regardless of what
is being built? If no → it belongs in the relevant subfolder `CLAUDE.md`. If yes → check
it is not already in a subfolder file. If it is, remove it from there. **One home per rule.**

## Self-Annealing

On any error: diagnose root cause (read the traceback) → fix autonomously → add inline
comment (what broke and why) → log in `HANDOFF.md` change log (newest on top, `## [` prefix)
→ retry → only escalate if genuinely exhausted all approaches. Never fake success.

## Session Handoff Protocol

End of session: `git add -A && git commit -m "session N: [brief]"` → `git push` → update
`HANDOFF.md` (built, current state, next step, unresolved decisions, change log entry).

---

## Hard Rules

1. Read `HANDOFF.md` before every session — no exceptions
2. Never hardcode secrets — keys from `.env` or OS keyring (see Credentials above)
3. Never commit `.env`, `*.db`, `chroma_db/`, `models/`, credentials
4. Never pass raw file contents or email bodies to any LLM
5. Never modify the inference prompt template without explicit instruction
6. Never add dependencies outside the approved stack without asking first
7. Never skip verification between phases
8. Never dispatch a sub-agent silently — say what and why
9. Never fake success — report failures straight with specifics
10. Never write tests before the module being tested is complete
11. Log every self-anneal in `HANDOFF.md`
12. Flag contradictions inline with `> **Contradiction:**` — do not silently resolve

---

## Coding Standards

- Type hints on all function signatures; one-line docstring on every class and public method
- Copyright header on every `.py`: `# A.R.G.U.S. — Automated Real-time Guardian for User Systems` / `# Copyright (C) 2026  MdZeeshan-ML | GPL v3`
- Structured logging via `logging` module — no bare `print()`
- All file paths via `pathlib.Path`, never string concatenation
- Config from `.env` at startup, validated immediately — fail fast
- Catch specific exceptions, log full traceback, never silent `pass`
- Every module has `if __name__ == "__main__":` block for standalone testing
