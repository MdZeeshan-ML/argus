---
name: cloud-deployment-pattern
type: concept
tags: [agentic-workflows, cloud, deployment, modal, automation, doe, serverless]
sources: [agentic-workflows-build-sell-2026]
related: [concepts/doe-framework, concepts/context-pollution, strategies/agentic-workflow-business, skills/agentic-workflow-building, entities/nick-saraev]
created: 2026-05-21
updated: 2026-05-21
---

# Cloud Deployment Pattern

The architecture for deploying [[concepts/doe-framework]] workflows to run unattended in the cloud. The central rule: **only execution scripts go to the cloud — never the LLM orchestrator.**

> "We don't upload the orchestrator itself... All we really do is upload the execution scripts themselves which are the deterministic parts." — Nick Saraev

---

## The Core Rule and Its Rationale

The LLM orchestrator is the probabilistic layer of a DOE workflow. In an attended session (Claude Code, IDE), the human operator can observe the orchestrator's reasoning, catch hallucinations, and redirect when it goes off-course. In unattended cloud operation, there is no such oversight.

Deploying the orchestrator to run unattended amplifies its stochastic behavior:
- Each run is a fresh conversation context (no accumulated learning within the run)
- Errors that would be caught by a watching human compound silently
- Cost from runaway reasoning loops has no circuit breaker

The execution scripts, by contrast, are deterministic Python. They don't hallucinate. Given the same input, they produce the same output. They can run unattended safely.

**The cloud deployment pattern therefore deploys only the deterministic layer.** The orchestrator runs locally or on-demand, generating the inputs that execution scripts need. The scripts then execute in the cloud.

---

## Trigger Patterns

Cloud-deployed execution scripts are triggered by two mechanisms:

### Event-Driven (Webhooks)
- A new lead fills out a form → webhook fires → `enrich_lead.py` runs
- A client sends an email → webhook fires → `parse_and_route.py` runs
- A payment is received → webhook fires → `generate_invoice.py` runs

Webhook-triggered execution is reactive: something happens in the world, the script responds. Ideal for real-time data flows.

### Schedule-Driven (Cron)
- Every day at 6am → `scrape_new_leads.py` runs, appends to Google Sheet
- Every Monday → `generate_weekly_report.py` runs, emails summary
- Every hour → `check_campaign_metrics.py` runs, logs to resource.md

Cron-triggered execution is proactive: the script runs on a fixed schedule regardless of external events. Ideal for monitoring, aggregation, and regular maintenance workflows.

---

## Modal as Deployment Platform

**Modal** (modal.com) is Nick Saraev's recommended platform for DOE execution script deployment. Key properties:

- **Serverless**: no persistent infrastructure to manage; functions spin up on trigger, spin down after completion
- **Pay-per-use**: charged only for compute time during execution; ~$5 in credits lasts weeks for typical agentic workloads
- **Webhook URLs out of the box**: each deployed function gets a URL that can be called by any external service
- **Cron support**: built-in scheduling with cron syntax
- **Python-native**: execution scripts (Python) deploy with minimal modification; dependencies are declared in the Modal decorator
- **Persistent storage**: Modal volumes allow execution scripts to read/write shared state across invocations (e.g., a running resource.md that persists between cron runs)

### Basic Modal Deployment Pattern

```python
import modal

app = modal.App("my-workflow")

@app.function(
    schedule=modal.Cron("0 6 * * *"),  # 6am daily
    secrets=[modal.Secret.from_name("my-env-secrets")]
)
def scrape_leads():
    # execution script content here
    pass

@app.function()
@modal.web_endpoint(method="POST")
def handle_webhook(data: dict):
    # webhook handler content here
    pass
```

Secrets (API keys from `.env`) are managed through Modal's secrets system — never hardcoded in the deployed scripts.

---

## What Stays Local

Some workflow components should not move to the cloud:

| Component | Location | Reason |
|---|---|---|
| LLM orchestrator | Local / IDE | Probabilistic; needs human oversight in non-trivial cases |
| `agents.md` / `CLAUDE.md` | Local | System prompt; evolves through use; not a deployable artifact |
| Directives | Local (or shared repo) | Human-readable SOPs; updated frequently |
| `.env` secrets | Local / Modal Secrets | Never exposed in deployed scripts |
| New workflow builds | Local (TMP folder) | Building and testing belongs in the attended environment |

---

## Deployment Decision Criteria

A workflow should move to cloud deployment when:

1. **It needs to run while you're not available**: during sleep, weekends, when you're on other work
2. **It's fully self-contained**: execution scripts handle all compute; orchestrator involvement after initial build is minimal
3. **It has a clear trigger**: either a deterministic schedule or a specific real-world event
4. **It's been tested locally**: the workflow has run successfully enough times to have self-annealed past initial edge cases

Premature cloud deployment is a trap: untested execution scripts that silently fail in the cloud are harder to debug than local failures.

---

## Cost Management

Unattended cloud execution requires explicit cost controls:

1. **API cost threshold in execution scripts**: "If total API spend this run exceeds $X, stop and notify me." Many API providers support usage queries; build the check into the script.
2. **Modal spend limits**: set a hard cap in Modal's billing settings; execution stops rather than running up an unexpected bill
3. **Execution time limits**: Modal functions have configurable timeout limits; set these conservatively for new deployments
4. **Monitoring**: Slack webhook or email notification for every scheduled run, reporting rows processed, API calls made, and any errors encountered

---

## Open Questions

- How should the workflow library be organized when some directives have cloud-deployed execution scripts and others run locally — does the workspace structure need to distinguish deployed vs. local execution?
- As LLM inference cost continues to drop (Opus 4.5 already 3× cheaper than one year prior), does the risk/benefit of deploying the orchestrator to the cloud eventually shift to make it viable?
- What is the minimum viable monitoring setup for a cloud-deployed DOE workflow — what does a useful daily digest look like?
