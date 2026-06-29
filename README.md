# A.R.G.U.S.
### Automated Real-time Guardian for User Systems

A lightweight personal security daemon for Windows that monitors your Downloads folder and email inbox for commodity malware, phishing, and malicious files — before you open them.

> **Status:** Phase 1 (Core Daemon) nearing completion. Active development.

---

## What it does

ARGUS runs silently in the background and intercepts files and emails before you interact with them.

**File pipeline (Downloads)**
1. Detects new files arriving in Downloads
2. Applies a deny-execute ACL immediately — the file cannot run while being analyzed
3. Runs a four-gate pipeline: Windows Defender → VirusTotal hash lookup → static feature extraction → dynamic/human routing
4. On a clean verdict: moves the file to `Downloads/Cleared/` with normal permissions
5. On a suspicious verdict: quarantines the file and logs a full audit record

**Email pipeline (IMAP)**
- Scans incoming emails for phishing signals: auth failure (SPF/DKIM/DMARC), domain lookalikes, link mismatches, suspicious attachments
- Records attachment manifests so that when you download an attachment, it is automatically linked back to the originating email
- Read-only — never modifies your mailbox

**Threat intelligence**
- Exact-match channel: SHA-256 hashes, URLs, IPs checked against threat feeds (O(1) Python set lookup) — a hit locks the verdict immediately, no inference needed
- Fuzzy channel: semantic similarity via ChromaDB embeddings, used as evidence context for the local LLM

---

## Architecture

```
File event ──► gate_keeper ──► [Defender → VirusTotal → Static → Dynamic] ──► Quarantine / Cleared/
                                                                               └──► SQLite audit log
Email event ──► feature_extractor ──► heuristic_verdict ──────────────────────────► SQLite audit log
                                           ▲
                                    threat_feeds (Phase 3)
                                    local LLM — qwen3:1.7b (Phase 2)
                                    cloud LLM — Kimi K2 via NIM (Phase 2, escalation only)
```

**Three-tier inference (Phase 2):** fast classifier → local LLM (uncertain zone only) → cloud escalation. The LLM is a rendering layer — containment decisions are made by the deterministic layer and execute before inference runs.

**Neuro-symbolic override:** hard rules and MITRE ATT&CK graph constraints override neural outputs unconditionally.

---

## Threat model

ARGUS targets **opportunistic threats against individual users** — phishing, commodity malware, malicious downloads from untrusted sources. It is not enterprise EDR and does not claim to defend against targeted or nation-state attackers.

Primary threat surface this was designed around:
- Malicious files disguised as client briefs (PDF/DOCX) from freelance platforms
- Phishing impersonating Fiverr, Upwork, Razorpay, PayPal
- Typosquatted pip packages
- Fraudulent payment-gateway links

---

## Stack

| Component | Technology |
|---|---|
| Language | Python 3.13 |
| File watching | watchdog |
| Local inference | Ollama — qwen3:1.7b |
| Cloud inference | NVIDIA NIM — moonshotai/kimi-k2-instruct |
| Threat intel (exact) | Python sets — SHA-256 / URL / IP feeds |
| Threat intel (fuzzy) | ChromaDB embeddings |
| Audit log | SQLite with SHA-256 hash chain |
| Cloud sync | GCP BigQuery / GCS (Phase 7) |
| Credentials | OS keyring (DPAPI on Windows) |

---

## Build phases

- [x] Phase 1 — Core Daemon (file watcher, email scanner, gate pipeline, logger)
- [ ] Phase 2 — Inference (local LLM router, feature extraction, RAG)
- [ ] Phase 3 — Threat feeds (exact intel population, MITRE graph)
- [ ] Phase 4 — System tray UI
- [ ] Phase 7 — Cloud sync
- [ ] Phase 9 — Linux port

---

## License

GPL v3 — see [LICENSE](LICENSE)

Copyright (C) 2026 MdZeeshan-ML
