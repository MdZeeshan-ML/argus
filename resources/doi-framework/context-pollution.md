---
name: context-pollution
type: concept
tags: [agentic-workflows, llm-limitations, context-window, sub-agents, performance, architecture]
sources: [agentic-workflows-build-sell-2026, claude-skills-full-course-2026]
related: [concepts/doe-framework, concepts/skills-vs-subagents, concepts/cloud-deployment-pattern, entities/nick-saraev, concepts/progressive-disclosure]
created: 2026-05-21
updated: 2026-05-22
---

# Context Pollution

The degradation of LLM output quality as context window token count grows. More tokens in context means more signal for the model to process — but also more noise, more competing instructions, and more opportunity for prior content to distort current reasoning.

Context pollution is a practical constraint in all long-running agentic workflows: the agent that begins a task at 10K tokens performs measurably better than the same agent at 80K tokens, even on tasks that don't inherently require the earlier context.

---

## Mechanisms

Several factors contribute to context pollution:

**1. Noise dilution**: relevant instructions are buried under prior tool outputs, error messages, retries, and intermediate reasoning. The model's effective attention on the current instruction weakens.

**2. Instruction conflict**: prior context may contain instructions, examples, or formats that contradict the current task. The model attempts to satisfy all context content simultaneously, producing incoherent compromises.

**3. Prior error contamination**: if earlier steps produced errors, those error messages and failed outputs remain in context. The model pattern-matches to them, increasing probability of repeating the same failure mode.

**4. Framework overhead**: loading all MCP server function definitions at conversation start adds 15,000+ tokens of overhead before any task begins — 300 tokens × 50 functions, all injected into every subsequent API call. This is pure pollution with no per-request benefit after the initial loading.

**5. Recency bias interaction**: transformer attention has known bias toward recent tokens; as context grows, the model relies more heavily on recent tokens and less on earlier instructions, making the behavior of long conversations harder to predict.

---

## Quantifying the Problem: MCP Overhead Example

A workspace using raw MCP server integration with 50 registered functions pays:

- 300 tokens per function definition × 50 functions = **15,000 tokens overhead**
- At Claude's API pricing, this overhead cost is paid on every single API call
- At scale (hundreds of runs per day), this becomes a significant cost driver
- More importantly, those 15,000 tokens of function definitions compete with task-relevant context in every call

DOE execution scripts avoid this entirely: execution scripts are not function-definition injected into every API call. The orchestrator calls them by name via file execution, with no context window footprint.

---

## The Sub-Agent Solution

[[concepts/skills-vs-subagents]] covers the architectural solution in full. The key mechanism: **sub-agents get fresh context windows.**

When a task is delegated to a sub-agent:
- The sub-agent starts with zero prior context
- It receives only what it needs for its specific task
- Its output is returned to the main agent without the sub-agent's working memory polluting the main context

This makes sub-agents the correct tool for any operation that:
- Generates large intermediate outputs (web scraping results, document analysis)
- Has messy intermediate reasoning that shouldn't contaminate later steps
- Is independent enough that it doesn't require the main context's history

The two canonical DOE sub-agent types exist precisely because of context pollution risk:
- **Reviewer sub-agent**: gets the code cold, without the accumulated context of the build session — which is what makes its review useful. An in-context review would be biased by the reasoning that produced the code.
- **Document sub-agent**: syncs directives with execution scripts without polluting the build context with documentation work.

---

## Mitigation Strategies

In rough order of effectiveness:

1. **Sub-agents** — isolate polluting work in fresh context. Highest effectiveness; appropriate for discrete tasks.

2. **Execution scripts instead of MCP** — keep tool definitions out of context. DOE's execution layer directly addresses MCP overhead.

3. **Modular directives** — load only the directive for the current task, not the full workflow library. One directive at a time; orchestrator references others by name but does not load them until needed.

4. **Skill progressive disclosure** — Claude Code's native skills keep only YAML frontmatter in context (~60–70 tokens per skill) while lazy-loading full skill content (~500 tokens) only when triggered. A workspace with 20+ skills saves ~8,600 tokens per turn at rest; at 30–40 skills, the savings exceed 12,000 tokens. See [[concepts/progressive-disclosure]].

5. **TMP folder discipline** — scratch work goes to `/tmp/`, not in-context. Agent writes intermediate results to disk and reads them back only when needed, preventing the context from accumulating scratchpad content.

6. **Context compaction at session boundaries** — when handing off to a new session (new conversation, new invocation), summarize rather than passing full history. A well-summarized handoff message is 500 tokens; the full prior context might be 80,000.

7. **Temperature management** — lower temperature slightly on later steps in a long workflow. Doesn't reduce pollution directly, but reduces the amplification of noise.

---

## Relationship to DOE

Context pollution is one of the core design motivations for [[concepts/doe-framework]]:

- **Directive modular loading**: prevents the full workflow library from entering context
- **Execution scripts**: eliminates MCP function definition overhead
- **Sub-agent delegation**: isolates messy intermediate work
- **TMP workspace**: gives the agent a place to write without accumulating in-context

A well-structured DOE workspace is implicitly a context pollution management system.

---

## Open Questions

- Is there a measurable threshold — a token count — at which context pollution becomes the dominant source of workflow errors, versus [[concepts/compound-error-probability]] from multi-step execution?
- As context windows expand (2M+, 10M+ tokens), does context pollution remain a practical concern, or does attention architecture evolve to handle it?
- How does context pollution interact with the directive change log in self-annealing workflows — as the log grows, does it help (historical context for better decisions) or hurt (token pollution from accumulated records)?
