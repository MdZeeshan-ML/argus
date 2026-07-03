---
description: Close out an ARGUS session — sweep stale doc references, update HANDOFF.md's cursor, commit. Never pushes.
disable-model-invocation: true
---

Run the ARGUS Session Handoff Protocol (root `CLAUDE.md`), fixed to also close
the doc-drift gap the 2026-07-04 architecture audit found (see
`architecture/audit.md`, finding R2/R6 — bugs fixed in code were still
recorded open in four separate files because no step ever swept them).

Do this in order:

1. **Establish what actually changed.** Run `git status` and `git diff` (or
   `git diff --staged` if already staged). Do not rely on memory of the
   conversation — confirm against the real diff.

2. **Sweep stale references.** For every finding/bug/gap this session fixed,
   grep across `HANDOFF.md`, root `CLAUDE.md`, `argus/*/CLAUDE.md`, and (if
   present) `architecture/*.md` for its identifier or description. Update or
   remove every stale mention — a fix recorded in only one place is exactly
   the failure mode this step exists to prevent. Report which files you
   touched and why.

3. **Update `HANDOFF.md`'s cursor**, prepended above the current top entry:
   phase, what was built this session, what's next, anything parked/
   unresolved. Keep it to what a session-start read actually needs — phase,
   last built, next step, open items. If `HANDOFF.md` is now pushing past
   ~150 lines, propose moving everything older than the last 2 sessions into
   a dated archive file and ask before doing it; don't do it silently.

4. **Stage and commit.** Use the repo's existing message convention
   (`session N: <brief description>`). Do not use `git add -A` — stage named
   files only, and show me `git status` after staging so I can see exactly
   what's about to be committed before you run `git commit`.

5. **Stop after the commit.** Per the Git Safety Protocol, never push without
   explicit instruction — tell me the commit is ready and wait.

If anything in steps 1–3 is ambiguous (e.g., you can't tell whether a change
was intentional or a stray edit), ask rather than guessing.
