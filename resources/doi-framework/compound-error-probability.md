---
name: compound-error-probability
type: concept
tags: [agentic-workflows, reliability, mathematics, error-handling, doe, llm-limitations]
sources: [agentic-workflows-build-sell-2026]
related: [concepts/doe-framework, concepts/self-annealing, concepts/automation-decision-framework, entities/nick-saraev]
created: 2026-05-21
updated: 2026-05-21
---

# Compound Error Probability

The mathematical reason raw LLMs fail as business automation tools: **success probability compounds multiplicatively across steps.** A chain of individually-reliable steps quickly becomes an unreliable system. The formula is straightforward and unforgiving.

> "If you have five steps and each of them are 90% successful... you end up not with a 90% success rate — you end up with a 59% success rate." — Nick Saraev

---

## The Math

For N independent steps each with success rate P:

```
Total success = P^N
```

| Steps | 99% each | 95% each | 90% each | 80% each |
|---|---|---|---|---|
| 1 | 99% | 95% | 90% | 80% |
| 3 | 97% | 86% | 73% | 51% |
| 5 | 95% | 77% | 59% | 33% |
| 10 | 90% | 60% | 35% | 11% |
| 20 | 82% | 36% | 12% | 1% |

A 10-step workflow where each step is 90% reliable succeeds just **35%** of the time. A 20-step workflow: **12%**. These are not theoretical edge cases — they describe the everyday failure mode of multi-step LLM automation in production.

---

## Why LLMs Are Probabilistic At Every Step

LLMs are probabilistic at the architectural level, not just in their training data:

1. **Token sampling**: Each output token is drawn from a probability distribution over the vocabulary. Even with temperature 0, there's a distribution; most implementations use non-zero temperature in practice.
2. **Temperature and top-p sampling**: Standard generation parameters deliberately introduce randomness to avoid degenerate (repetitive) outputs.
3. **Input sensitivity**: Small changes in phrasing, context window content, or token order can shift output meaningfully — the same "prompt" run twice with different prior context isn't the same prompt.
4. **Mixture-of-experts routing** (where applicable): Model capacity is distributed across expert networks; different inputs activate different experts, introducing architecture-level variance.

This is not a fixable property of current LLMs — it is foundational to how they work. Business automation design must account for it, not assume it away.

---

## Business Stakes

A 5% error rate sounds acceptable until you apply it to business operations:

- 5% wrong invoice amounts: financial liability, customer trust damage, manual auditing cost on every cycle
- 5% misrouted support tickets: customer complaints compound; lost revenue attributable to resolution delay
- 5% incorrect data entries in a CRM: corrupted list quality, downstream deliverability damage, wrong signals to analytics

**The compounding problem is worse than intuition suggests** because errors in step 3 of a 10-step workflow contaminate every downstream step — the effective error rate on the *output* is higher than the error rate at each step.

---

## Why DOE Solves This

[[concepts/doe-framework]] addresses compound error probability through **separation of concerns**:

1. **Execution scripts are deterministic**: A Python script that sorts data, makes an API call, or formats a spreadsheet has 0% error rate from computational variance. Same input → same output, always. This eliminates probabilistic error from the majority of workflow steps.

2. **Only routing decisions remain probabilistic**: The orchestration layer makes judgment calls (which directive to follow, which tool to call, how to interpret ambiguous input). These are simple classifications — low N, tractable success probability.

3. **Self-annealing reduces recurring errors to near-zero**: After the first failure, the edge case is encoded into the execution script and directive. That specific failure path becomes deterministic (handled by code) rather than probabilistic. See [[concepts/self-annealing]].

4. **Definition-of-done enforcement catches failures before they compound**: The orchestrator checks its output against the stated criteria. A step that returns the wrong quantity or wrong format triggers a retry at that step rather than silently poisoning downstream steps.

---

## Practical Implication: Specificity Reduces N

One actionable lever is **prompt specificity**. Vague instructions require more inference steps to decompose, increasing N. Precise instructions reduce the number of sub-decisions the LLM must make per task.

Example:
- Vague: "Write a cold email to this lead." → LLM must infer: format, length, tone, offer, CTA, personalization angle — 6+ implicit decisions, each a step
- Specific: "Write a 3-sentence cold email using the first-line template in `/directives/cold-email.md`, using [Name] and [Company] as personalization inputs, ending with the calendar link CTA." → 1 routing decision

The DOE directive layer operationalizes this: every directive is a maximally-specific SOP. The LLM isn't generating the plan — it's executing a pre-specified one.

---

## Open Questions

- At what step count and per-step reliability does it become impractical to architect around compound error probability — i.e., when does the coordination overhead of DOE exceed the reliability gain?
- Is the independence assumption valid? If step failures are correlated (same misunderstanding causes errors in steps 3, 7, and 10), does compound error probability overstate or understate the real failure rate?
- How does compound error probability interact with model capability improvements — if frontier models reach 99% per-step reliability, does the DOE execution-script approach remain necessary, or is it only warranted below some capability threshold?
