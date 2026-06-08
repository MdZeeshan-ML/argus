---
name: smallest-unit-of-autonomy
type: concept
tags: [ai-agents, deployment, safety, fde, agent-architecture, autonomy]
sources: [forward-deployed-engineering-101]
related: [skills/forward-deployed-engineering, concepts/automation-decision-framework, concepts/autonomous-experimentation-loop]
created: 2026-05-21
updated: 2026-05-21
---

# Smallest Unit of Autonomy

**Start with the narrowest possible agent capability. Prove it works. Then expand.**

A deployment principle from the [[skills/forward-deployed-engineering]] methodology. The pattern it prevents: deploying a fully-capable agent, discovering failures in production, and having no incremental fallback. The alternative is a capability ladder — each rung proven before the next is granted.

## The Pattern

1. Identify the full capability chain you eventually want
2. Find the smallest step in that chain that is independently useful
3. Deploy only that step and run evals against it
4. Grant the next capability only after the current rung is proven reliable

## Canonical Example

A software workflow, expanding incrementally:

| Rung | Capability granted | Reversibility |
|---|---|---|
| 1 | Detects a bug, writes a summary ticket | Read-only on codebase; low-risk |
| 2 | Writes code to fix the bug | Write to local branch; reviewable |
| 3 | Pushes a PR | Triggers CI; reviewable before merge |
| 4 | Auto-merges on green CI | Harder to reverse; requires high confidence |

Rung 2 does not start until rung 1 is proven. Rung 4 may never be appropriate depending on the system.

## Why This Works

**Failure containment**: a narrow agent causes narrow failures. A read-only agent cannot overwrite production data. A ticket-writing agent cannot break the build. Each expansion increases the blast radius, but only after the previous blast radius has been validated.

**Debugging surface**: when a narrow agent fails, the failure is small and localizable. When a broad agent fails with many interacting capabilities, failures are complex and potentially irreversible.

**Trust accumulation**: each proven rung builds justified confidence — in the agent's behavior, in the eval framework, in the deployment environment. Skipping rungs skips the trust.

## Anti-Pattern: Big Bang Deployment

Building the full agent first and deploying it to production without a proven capability ladder. Failure modes:
- The agent works in sandbox but fails on the long tail of real inputs
- Failures in an advanced step are caused by bugs in an earlier step, now invisible
- Rollback requires removing all agent involvement, not just the failing capability

## Connection to Evals

The capability ladder only works if each rung has evals. Without evals, "proven" is undefined. See the Evals phase in [[skills/forward-deployed-engineering]] for how to build a golden dataset and step-level grading.

## Connection to the Autonomous Experimentation Loop

The smallest-unit-of-autonomy principle defines *when* to expand capability. The [[concepts/autonomous-experimentation-loop]] defines *how* to improve performance within a fixed capability level. They operate at different layers: this concept governs capability expansion; the loop governs output quality within a stable capability.

## Open Questions
- How do you handle workflows where intermediate rungs aren't independently useful — only the full chain delivers value?
- What's the right threshold for "proven"? A number of clean runs? Eval pass rate above some floor? Time in production without incident?
- Does the optimal rung size change with model capability — i.e., should you grant more autonomy upfront as models become more reliable?

---

## Related Hormozi Frameworks
- [[$100M Scaling/Key Frameworks & Summaries|$100M Scaling — Key Frameworks & Summaries]]
