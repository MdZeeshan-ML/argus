---
name: progressive-disclosure
type: concept
tags: [claude-code, skills, context-management, token-efficiency, architecture]
sources: [claude-skills-full-course-2026]
related: [concepts/context-pollution, concepts/skills-vs-subagents, skills/building-claude-skills, skills/claude-code-ea-setup]
created: 2026-05-22
updated: 2026-05-22
---

# Progressive Disclosure

The mechanism by which Claude Code loads skill content lazily — only when a skill is triggered by name or keyword match — rather than loading all skill content into the context window at conversation start.

---

## How It Works

Every skill in `.claude/skills/` has a YAML frontmatter block at the top of its `skill.md`:

```yaml
---
name: inbox-cleaner
description: Clean up Gmail inbox by reading all unread emails, identifying which ones are important, and marking the rest as read. Use when: cleaning inbox, triaging email, or clearing unread notifications.
tools: [Bash, Read, Grep, mcp__gmail]
---
```

**At conversation start:** Only the frontmatter for each skill is loaded — roughly 60–70 tokens per skill. The full skill body (step-by-step instructions, scripts, context) is not in the context window.

**When a skill is triggered:** The agent performs **skill matching** — it scans the name, description, and trigger keywords from all loaded frontmatter blocks and identifies the best match for the user's request. Once matched, the full `skill.md` content is loaded into context before execution.

Nick Saraev: "What this means is in practice, if I were to show you guys all of the different skills that are currently loaded into context, they basically all look like this [frontmatter only]."

---

## Token Economics

| State | Token cost per skill | Notes |
|---|---|---|
| At rest (frontmatter only) | ~60–70 tokens | Always in context |
| Triggered (full skill loaded) | ~500 tokens | Loaded on demand |
| Without this mechanism | ~500 tokens | Always in context |

**Savings per skill at rest:** ~430 tokens permanently removed from baseline context.

**At scale (Nick's production workspace with 30–40 skills):** 12,900–17,200 tokens saved per turn when skills are not being actively used. This is roughly the equivalent of eliminating an entire small-to-medium document from every conversation.

---

## Skill Matching

Skill matching connects a user's natural-language request to the right skill without requiring exact slash-command syntax:

1. User types "get me 50 dental leads"
2. Agent scans all skill frontmatter descriptions for relevance
3. Finds: "Find business leads, scrape contact information, export to Google Sheet" — best match
4. Loads the full `skill.md` for that skill into context
5. Executes with full instructions available

This means a skill triggers on both its exact `/name` slash command *and* semantically similar natural language. The `description` field in frontmatter is the primary matching surface — write it to include the language you'd naturally use when asking for the task, including synonyms and use-case phrases.

---

## Relationship to Context Pollution

Progressive disclosure is the primary skill-level mitigation for [[concepts/context-pollution]]. Without it, a skill-heavy workspace permanently pays the full token cost of every skill on every message. With it, the baseline context stays lean regardless of how many skills exist.

The specific failure modes it prevents:

- **Noise dilution**: inactive skill instructions don't crowd out task-relevant content
- **Instruction conflict**: skill-specific directives only appear when that skill is running, not competing with unrelated tasks
- **Cost accumulation**: providers charge per token; at scale (hundreds of daily runs), 430 tokens per dormant skill becomes significant

---

## The Conversation Structure

In a skills-enabled Claude Code workspace, the context layout looks like:

```
[CLAUDE.md / agents.md]          ← always loaded
[Skill 1 frontmatter]            ← always loaded (~60–70 tokens)
[Skill 2 frontmatter]            ← always loaded (~60–70 tokens)
...
[Skill N frontmatter]            ← always loaded (~60–70 tokens)
─────────────────────────────────── skill triggered ──
[Full skill body for triggered skill]  ← loaded on demand (~500 tokens)
[User prompt]                    ← your request
```

This means: no matter how large the skill library, baseline context overhead scales as N × 60–70 tokens (frontmatter), not N × 500 tokens (full content). Adding the 40th skill costs ~65 tokens, not 500.

---

## Relationship to DOE Modular Directives

[[skills/agentic-workflow-building]] uses a parallel mechanism: DOE directives are loaded one at a time by the orchestrator, not all at once. The concepts are structurally identical — lean index at rest, full content loaded on demand — but implemented differently:

| | DOE Modular Directives | Claude Code Progressive Disclosure |
|---|---|---|
| Trigger | Orchestrator routing logic | User slash-command or keyword match |
| Lazy-load unit | Individual directive files | Skill.md + supporting scripts |
| Index format | Meta-directive references | YAML frontmatter in each skill |

Both exist to prevent context from filling with instructions irrelevant to the current task.

---

## Open Questions

- Is there a practical limit on how many skills can coexist in a workspace before frontmatter scanning becomes slow or produces false matches?
- Does the order of skills in `.claude/skills/` affect matching priority when two skills have overlapping descriptions?
- How does progressive disclosure interact with the CLAUDE.md pointer-based context system used in EA setups — are they complementary or do they produce duplicate overhead?
