---
name: agentic-workflow-building
type: skill
tags: [agentic-workflows, doe, automation, claude-code, python, workflow-building, practical]
sources: [agentic-workflows-build-sell-2026]
related: [concepts/doe-framework, concepts/self-annealing, concepts/compound-error-probability, concepts/context-pollution, concepts/cloud-deployment-pattern, strategies/agentic-workflow-business, entities/nick-saraev, skills/building-claude-skills, concepts/progressive-disclosure]
created: 2026-05-21
updated: 2026-05-22
---

# Agentic Workflow Building

The practical skill of constructing [[concepts/doe-framework]] workflows: from workspace setup through directive authoring, execution script development, system prompt configuration, testing, and cloud deployment.

---

## Prerequisites

**Tool stack:**
- Claude Code (IDE or CLI) — primary orchestrator environment
- Python 3.10+ — execution script language
- Modal (`pip install modal`) — cloud deployment platform
- An `.env` file with API keys for relevant services
- Git or equivalent — version control for the workflow library

**Mental model:**
- Directives = natural language SOPs; you write these
- Execution scripts = deterministic Python; Claude writes or co-writes these
- System prompt (`agents.md`) = the instructions the orchestrator lives inside; you curate this over time
- Self-annealing = the workflow improves itself; you enable it via system prompt instructions

---

## Phase 1: Workspace Setup

Create the folder structure first. The agent can bootstrap this from scratch given the system prompt file.

```
workspace/
  agents.md          ← system prompt (and CLAUDE.md, gemini.md for portability)
  .env               ← API keys; never committed to version control
  directives/        ← .md files, one per workflow
  execution/         ← .py files, one per atomic function
  tmp/               ← agent scratch space (delete between sessions)
  resources/         ← reference materials for agent (optional)
```

**agents.md minimum content:**
1. Framework explanation + rationale (why DOE exists)
2. Self-annealing instruction (verbatim, see [[concepts/self-annealing]])
3. Autonomy instruction ("Run autonomously; come to me only when you cannot proceed")
4. Workspace structure description
5. Safety rules (cost threshold, credential immutability, no secrets in code, change logging)

**Portability rule**: maintain `agents.md`, `CLAUDE.md`, and `gemini.md` as identical copies. All three exist so the same workspace works across Claude, Gemini, and GPT without modification.

---

## Phase 2: Directive Authoring

Write the directive as a Markdown SOP in `/directives/`. One file per workflow capability.

### Directive Template

```markdown
# [Workflow Name]

## Objective
[One sentence: what this workflow does.]

## Inputs
- [Input 1]: [description, format, where it comes from]
- [Input 2]: [description, format]

## Process

1. [Step description] — call `execution/script_name.py` with [parameters]
2. [Step description]
3. [Step description]

## Definition of Done
- [Quality criterion]: [e.g., "Google Sheet URL with ≥100 rows populated"]
- [Quality criterion]

## Edge Cases
- [Known exception and how to handle it]
- [API quirk and workaround]

## Fallback Behavior
- If [primary tool] fails: try [fallback tool] instead
- If all approaches fail: return [specific failure message], do not return empty success

## Change Log
[Append entries as self-annealing updates accumulate]
- [YYYY-MM-DD] [What changed, why, what edge case now handled]
```

**Naming rules**: descriptive filenames, no acronyms, no code inside the directive. The person who never touches code should be able to read and improve any directive.

### Meta-Directives

Once individual directives are stable, chain them under an umbrella directive:

```markdown
# New Client Onboarding

## Process
1. Scrape leads → follow `scrape_leads.md`
2. Enrich emails → follow `enrich_emails.md`
3. Generate proposal → follow `create_proposal.md`
4. Send welcome → follow `send_welcome_email.md`
```

The orchestrator loads individual directives on demand — the meta-directive provides routing; each child directive provides execution detail.

---

## Phase 3: Execution Script Development

**Principle**: atomic, deterministic, reusable. One job per script. Tell the agent what to build, not how — Claude Code will write the Python.

**Prompting pattern for script generation:**
> "Write a Python script `upload_to_gsheet.py` that takes a list of dicts and uploads it to a Google Sheet. Read the sheet ID and credentials from `.env`. Return the sheet URL on success. Throw a descriptive exception on failure — no silent errors."

**Quality checklist for each script:**
- [ ] Reads all secrets from `.env`, never hardcoded
- [ ] Returns a clear value on success
- [ ] Raises a descriptive exception (not silent failure) on error
- [ ] One job; does not try to do multiple things
- [ ] Inputs and outputs are explicit (no side effects through global state)
- [ ] If calling an LLM internally: low temperature, defined output schema, isolated from main orchestration loop

**Common execution scripts to build first:**
- `upload_to_gsheet.py` — used by almost every workflow
- `send_email.py` — email dispatch; reused across outreach + notification workflows
- `scrape_appify.py` — Apify actor runner; reused across all scraping directives
- `enrich_apollo.py` — Apollo lead enrichment; core of most B2B outbound pipelines

---

## Phase 4: System Prompt Tuning

The system prompt is the highest-leverage part of the workspace. A strong `agents.md` is what separates a reliable workflow from a brittle one.

**Curate over time**: every time the agent makes a systematic mistake, add an instruction that prevents it. The system prompt accumulates wisdom from every failure.

**The key self-annealing instruction (verbatim):**
> "When you encounter an error, first diagnose it, then fix it, then update your scripts and directives to handle similar errors in the future. Try very hard before escalating to me."

**Autonomy scaffolding:**
> "Run autonomously. Test each system yourself. Come to me only if you are 100% confident you cannot solve this without human input."

**Change log instruction:**
> "After every fix, add an entry to the directive change log: what changed, why, and what edge case it handles."

Nick: "The prompt right now is kind of the moat." A well-developed system prompt is hard to reverse-engineer from outputs alone and reflects weeks of accumulated error resolution.

---

## Phase 5: Testing and Self-Annealing

**Testing pattern:**
1. Run the workflow with a real (small) dataset
2. Observe failures — do not fix them manually
3. Let the agent diagnose and fix per its self-annealing instructions
4. Monitor the change log for evidence that fixes are being recorded
5. Re-run; confirm the fixed edge case is resolved
6. Repeat until the workflow passes its definition-of-done criteria on 3 consecutive runs

**Parallel build pattern** (for uncertain approaches):
- When unsure of the best approach, build 3–5 variations simultaneously in `/tmp/approach-1/`, `/tmp/approach-2/`, etc.
- Run all variants on the test dataset
- Evaluate outputs; keep the best; delete the rest
- This is faster than iterating on a single approach when the solution space is genuinely ambiguous

**Order-of-magnitude rule**: only invest time optimizing a step if the improvement is ≥10× in speed or reliability. Marginal gains (10% faster) introduce error risk from the change itself that outweighs the benefit.

---

## Phase 6: Cloud Deployment

Deploy only execution scripts, never the orchestrator. See [[concepts/cloud-deployment-pattern]] for full detail.

**Deployment checklist:**
- [ ] Script tested locally with real data, ≥3 successful runs
- [ ] All secrets moved to Modal Secrets (not hardcoded)
- [ ] Trigger type defined (webhook or cron schedule)
- [ ] Cost threshold check built into the script
- [ ] Notification hook set up (Slack or email on completion)
- [ ] Modal spend limit configured in billing settings

---

## Workflow Library Growth

**Addition criteria**: add a new directive + execution script when:
- A workflow will run more than once
- The manual version of the task takes >30 minutes
- The process is rule-based enough for an agent to follow reliably

**Composition criteria**: create a meta-directive when two or more individual directives are consistently run in sequence for the same purpose.

**Maintenance discipline**:
- Review change logs monthly — if the same type of edge case keeps appearing, add a structural fix in the directive rather than relying on runtime detection
- Archive (not delete) directives for workflows that are no longer active — they're references for future builds

---

## Relationship to Claude Code Skills

DOE directives (`/directives/*.md`) and Claude Code native skills (`.claude/skills/[name]/skill.md`) are complementary patterns that serve different trigger modes:

| | DOE Directives | Claude Code Skills |
|---|---|---|
| Primary use | Autonomous, multi-step background workflows | User-triggered, slash-command tasks |
| Triggered by | Orchestrator routing logic or cron/webhook | User typing `/skill-name` or matching phrase |
| Lives in | `directives/` folder | `.claude/skills/` hidden folder |
| Lazy-loading | Meta-directive references | [[concepts/progressive-disclosure]] — YAML frontmatter (~60–70 tokens) |
| Self-improvement | [[concepts/self-annealing]] — directive change log + system prompt | [[concepts/self-healing-skills]] — skill.md auto-patched on error |

A mature workspace may use both: DOE for background workflows triggered by cron or webhook; Claude Code skills for on-demand tasks invoked by the operator. See [[skills/building-claude-skills]] for the skill construction methodology.

---

## Open Questions

- What is the right scope for the initial directive in a new domain — should it start narrow (one step) and expand, or start broad (full workflow) and be refined down?
- How should conflicting instructions between agents.md (system-level) and a specific directive be resolved — should directives be allowed to override system prompt rules for domain-specific exceptions?
- As the execution script library grows, is there value in a shared registry (index of all scripts, their inputs/outputs, their callers) to make reuse easier to discover?
