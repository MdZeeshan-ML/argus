---
name: skills-vs-subagents
type: concept
tags: [claude-code, agents, architecture, context-management, ai, doe]
sources: [turn-claude-code-executive-assistant, agentic-workflows-build-sell-2026, claude-skills-full-course-2026]
related: [strategies/personal-ai-executive-assistant, skills/claude-code-ea-setup, concepts/autonomous-experimentation-loop, concepts/doe-framework, concepts/context-pollution, entities/nick-saraev, concepts/progressive-disclosure, skills/content-repurposing-pipeline, skills/building-claude-skills]
created: 2026-05-21
updated: 2026-05-22
---

# Skills vs Sub-agents

A fundamental architectural distinction in Claude Code agent systems. Both extend what an agent can do, but they differ in context scope, cost profile, and appropriate use case.

## Skills
A **skill** is a Markdown instruction file invoked within the *current context window*. When the agent uses a skill, it reads the file and executes within the same conversation thread — with full access to prior context, the active model, and accumulated state.

**Best for:** Tasks that benefit from conversational awareness: content written in the user's voice, decisions that reference earlier context, anything where the accumulated thread is an asset rather than noise.

**Triggering:** Skills are invoked via `/skill-name` or natural language that matches the skill's description keywords. The agent scans YAML frontmatter across all skills in `.claude/skills/` to identify the best match — a mechanism called **skill matching**. See [[concepts/progressive-disclosure]] for how frontmatter lazy-loading keeps inactive skills at ~60–70 tokens in context (vs. ~500 tokens fully loaded).

## Sub-agents
A **sub-agent** is an independent agent spawned by the main agent. It receives a *fresh context window*, has no memory of the parent conversation, and can be configured to run a different — usually cheaper — model.

**Best for:** Isolated, repeatable tasks where a clean slate is preferable or cost is a concern:
- Background research (Haiku instead of Opus is 10–20× cheaper; quality of raw data retrieval is comparable)
- Batch processing or parallel workloads
- Tasks where prior context would introduce bias or confusion
- Any sub-task that doesn't need the main agent's accumulated state

**Canonical parallel example:** The [[skills/content-repurposing-pipeline]] spawns 3 sub-agents simultaneously — one for tweet thread, one for LinkedIn post, one for newsletter draft. Each output is independent, benefits from clean state, and the parallel execution collapses 3 sequential runs into 1 elapsed time. This is the clearest live demonstration of the "Can run in parallel: Yes" row in the decision table below.

## YAML Frontmatter
Both skills and sub-agents should use **YAML frontmatter** at the top of their Markdown files. Claude Code will not add it by default — it must be explicitly required in CLAUDE.md or specified at creation time.

Frontmatter enables Claude Code to:
- Understand what the skill/agent does and when to invoke it
- Parse intent cheaply (structured metadata vs. reading prose)
- Produce consistent behavior across repeated calls

Example:
```yaml
---
name: research
description: Deep research via external API, tailored to current project context
model: claude-haiku-4-5  # sub-agents only
triggers: [research, investigate, look into]
---
```

## Decision Heuristic

| Criterion | Skill | Sub-agent |
|---|---|---|
| Needs conversation context | Yes | No |
| Cost sensitivity | Low | High |
| Can run in parallel | No | Yes |
| Needs a fresh perspective | No | Yes |
| Output feeds back into main thread | Yes | Optional |

## Relationship to Autonomous Experimentation
Sub-agents are a natural fit for the [[concepts/autonomous-experimentation-loop]] — they can run hypothesis tests in parallel with clean state, with results aggregated by the orchestrating main agent. The research EA in a [[syntheses/specialized-ea-fleet-architecture]] is a primary example: Haiku sub-agents handle data retrieval in parallel; Sonnet synthesizes the combined output.

## Relationship to Fleet Architecture
In a specialized EA fleet, the skills-vs-subagents distinction operates at two levels simultaneously:

1. **Within each specialized EA:** individual skills (same context window) vs. sub-agents (fresh context, cheaper model) — the standard distinction
2. **Across the fleet:** specialized EAs themselves function as a kind of macro-sub-agent from the orchestrator's perspective — the orchestrator delegates to a specialized EA the same way a main agent delegates to a sub-agent: pass context in, receive output back, no shared state

This recursive structure (orchestrator → EA → sub-agent) is what makes model selection per tier so powerful: Opus for orchestration, Sonnet for EA-level reasoning, Haiku for isolated data tasks.

## DOE Sub-agent Taxonomy

[[concepts/doe-framework]] defines two specific sub-agent roles that recur across most mature workflow libraries. From [[entities/nick-saraev]] in [[sources/agentic-workflows-build-sell-2026]]:

### Reviewer Sub-agent
**Purpose**: independent code quality assessment, unbiased by the context that produced the code.

The key value is the fresh context: a reviewer sub-agent sees only the finished code, not the reasoning session that built it. This removes anchoring bias. The main agent knows why it made each decision; the reviewer has no such prior — which is why it catches issues the main agent rationalizes away.

**Typical invocation**: "Review the execution scripts in `/execution/` for correctness, error handling, and adherence to DOE conventions. Report issues. Do not modify files."

### Document Sub-agent
**Purpose**: keep directives synchronized with evolved execution scripts, without polluting the build context with documentation work.

As execution scripts are updated through [[concepts/self-annealing]], directives can become stale — they describe behavior that has since been changed or extended. The document sub-agent reads both the current directive and the current execution scripts and updates the directive to match.

**Typical invocation**: "Read `/execution/scrape_leads.py` and `/directives/scrape_leads.md`. Update the directive to reflect the current script behavior, especially any edge cases or parameters that have changed."

### Lease Privilege Principle

Sub-agents in DOE workflows operate under least privilege:
- They receive only the context they need for their specific task
- They cannot modify credentials or system prompt files
- They do not spawn further sub-agents (the chain is: main orchestrator → sub-agent, and no deeper)
- Their scope is defined in the invocation; they do not self-expand

The no-recursive-spawning rule is both a safety constraint and a [[concepts/context-pollution]] control: chains of sub-agents spawning sub-agents rapidly become unauditable and token-expensive.

---

## Open Questions
- Is there a practical limit on how many sub-agents a single main agent can orchestrate before overhead degrades output quality?
- The DOE lease privilege principle says sub-agents cannot spawn sub-agents. In practice, what breaks if this rule is violated — is it just cost/pollution, or does it produce reliability failures?
- At the fleet level, does the orchestrator treat specialized EAs as "skills" (same context window, full awareness) or "sub-agents" (fresh context, isolated), and what are the tradeoffs of each choice?
