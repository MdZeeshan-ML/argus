---
description: Scaffold a self-contained task brief before building a module or feature (for claude/claude-code-sop.md, Part 3).
argument-hint: [module-or-feature name]
---

Scaffold a task brief for: $ARGUMENTS

Follow the template in `for claude/claude-code-sop.md` Part 3 exactly (Goal,
Interface contract, Acceptance criteria, Constraints, Non-goals, Definition of
done). Fill in what you can find yourself:

- Grep the relevant `argus/*/CLAUDE.md`, root `CLAUDE.md`, and (if present)
  `architecture/ARCHITECTURE.md` for existing contracts, invariants, or known
  debt naming "$ARGUMENTS". List the exact file:section pointers you found —
  don't restate their content here, point at them.
- If "$ARGUMENTS" already has a module file, note its current state (built /
  stubbed / not started) from the live code, not from a doc that might be
  stale.
- State the environment line explicitly: portable (Linux dev + test) or
  Windows-locked (mock on Linux, manual verify on Windows boot) — per
  CLAUDE.local.md's platform-coupling table.

**Where you cannot fill a section** — no acceptance criteria exist yet, the
interface contract isn't decided, the constraint set is unclear — say so
explicitly instead of guessing. Per the SOP's own rule, a gap here means the
task isn't ready to build yet, not something to paper over.

Output the filled-in brief and **stop** — do not start building. Wait for
review and explicit approval before writing any code.
