# CLAUDE.md — A.R.G.U.S.
# Automated Real-time Guardian for User Systems

## What This Project Is

A.R.G.U.S. is a personal, open-source, AI-powered security daemon for Windows.
Named after the hundred-eyed giant of Greek mythology who never sleeps, it
watches five attack surfaces simultaneously — files, emails, pip/npm packages,
browser extensions, and clipboard — and analyzes everything using a local or
cloud AI model to determine if it is a threat.

When something suspicious appears, A.R.G.U.S. explains exactly why in plain
language, quarantines it automatically, and logs the decision with full
reasoning. Every day at midnight it generates a PDF threat report and syncs
the incident history to Google Cloud.

Unlike commercial security tools, A.R.G.U.S. runs data locally by default.
Files never leave the machine. When cloud analysis is used, only metadata —
never file contents — leaves the device. Over time it learns: every incident
logged becomes training data for a fine-tuning pipeline that specializes the
local model on the user's specific threat environment.

This is NOT a commercial product. It is a personal protection tool that is
open-sourced so others can contribute monitors, threat feeds, and fine-tuned
model weights back to the community.

**Full name:** A.R.G.U.S. — Automated Real-time Guardian for User Systems  
**License:** GPL v3  
**Platform:** Windows 11/10 (primary), Linux/macOS via community contribution  
**Python:** 3.11+

---

## Developer Context

- Developer: Zeeshan (solo, IIT Madras data science student)
- Experience: Strong Python, SQL, BeautifulSoup. Minimal prior GUI/async experience.
- Learning style: Build incrementally. Explain decisions when making non-obvious choices.
  Do NOT write large code dumps. Build one module at a time, verify it works, move on.
- Time budget: 1–2 hours/day
- Tutor mode: YES. Explain what each component does and why as you build it.
  But keep explanations inline as comments — do not write essays in chat.

---

## Build Order — STRICT. Do Not Skip Ahead.

Build in this exact sequence. Do not start Phase 2 until Phase 1 is verified working.

### Phase 1 — Core Daemon (Week 1)
1. `argus/core/logger.py` — SQLite logging with tamper-evident append-only design
2. `argus/monitors/file_watcher.py` — watchdog-based Downloads + Desktop monitor
3. `argus/monitors/email_scanner.py` — IMAP poller (Gmail compatible)
4. `argus/analysis/feature_extractor.py` — metadata extraction (hash, magic bytes, entropy, WHOIS)
5. `argus/core/daemon.py` — main event loop wiring monitors to extractor
6. Manual test: trigger a fake suspicious file, verify SQLite log entry

### Phase 2 — Inference Layer (Week 2)
7. `argus/analysis/inference/local.py` — Ollama client (OpenAI-compatible)
8. `argus/analysis/inference/cloud.py` — NIM client (OpenAI-compatible)
9. `argus/analysis/inference/router.py` — mode switch logic + fallback
10. `argus/analysis/inference/consensus.py` — multi-run voting for uncertain cases
11. Integration test: file trigger → feature extraction → inference → log verdict

### Phase 3 — RAG Layer (Week 3)
12. `argus/analysis/rag/embedder.py` — ChromaDB + sentence-transformers setup
13. `argus/analysis/rag/threat_feeds.py` — PhishTank, OpenPhish, MalwareBazaar ingestion
14. `argus/analysis/rag/whitelist.py` — personal known-good loader from private config
15. Wire RAG into inference: retrieved context injected into prompt before LLM call

### Phase 4 — Response + Tray (Week 4)
16. `argus/response/notifier.py` — Windows toast notifications via plyer
17. `argus/response/quarantine.py` — auto-move suspicious files to quarantine dir
18. `argus/tray/tray_app.py` — pystray system tray icon with right-click menu
19. `launch_argus.vbs` — invisible background launch script
20. Startup shortcut via shell:startup

### Phase 5 — Additional Monitors (Week 5)
21. `argus/monitors/package_monitor.py` — pip/npm install watcher + typosquat detection
22. `argus/monitors/browser_monitor.py` — Chrome/Firefox extension directory watcher
23. `argus/monitors/clipboard_monitor.py` — UPI/payment address verification

### Phase 6 — GUI (Week 6)
24. `argus/api/server.py` — FastAPI local server (localhost:7734) serving incident data
25. `argus/gui/frontend/` — HTML/CSS/JS frontend (three views: Dashboard, Detail, Settings)
26. `argus/tray/tray_app.py` — update to open PyWebView window on click

### Phase 7 — Cloud Sync (Week 7)
27. `argus/cloud/bigquery_client.py` — streaming insert of incidents
28. `argus/cloud/gcs_client.py` — hourly log rotation + upload
29. `argus/cloud/drive_client.py` — daily PDF report generator + Drive upload
30. `argus/cloud/report_generator.py` — weasyprint PDF report from daily SQLite query

### Phase 8 — Training Pipeline (After 3+ months of data collection)
31. `training/data_export.py` — SQLite → HuggingFace dataset format
32. `training/synthetic_gen.py` — Kimi K2 synthetic data generator
33. `training/kaggle_finetune.ipynb` — QLoRA fine-tuning notebook for Kaggle
34. `training/evaluate.py` — model evaluation script

---

## Self-Annealing — Required Behavior

When you encounter ANY error during building or testing:
1. Diagnose the root cause — do not guess, read the traceback
2. Fix it autonomously
3. Update the affected module with an inline comment explaining what broke and why
4. Append a change log entry to HANDOFF.md: `[date] [module] [what broke] [what fixed]`
5. Retry and confirm the fix works
6. Only escalate to Zeeshan if you have genuinely exhausted all approaches

Run autonomously. Test each module yourself immediately after building it.
Do NOT stop and ask for help on errors you can diagnose and fix.
Do NOT return partial success silently — if a step fails its definition of done, retry with a different approach before reporting back.

Every error that gets fixed makes Argus stronger. Treat failures as improvement opportunities, not blockers.

---

## Module Trigger Phrases

Use these exact phrases to tell Claude Code which module to build next:
- "build the logger" → `argus/core/logger.py`
- "build the watcher" → `argus/monitors/file_watcher.py`
- "build the scanner" → `argus/monitors/email_scanner.py`
- "build the extractor" → `argus/analysis/feature_extractor.py`
- "wire the daemon" → `argus/core/daemon.py`
- "build local inference" → `argus/analysis/inference/local.py`
- "build cloud inference" → `argus/analysis/inference/cloud.py`
- "build the router" → `argus/analysis/inference/router.py`
- "build consensus" → `argus/analysis/inference/consensus.py`
- "build the embedder" → `argus/analysis/rag/embedder.py`
- "build threat feeds" → `argus/analysis/rag/threat_feeds.py`
- "build the notifier" → `argus/response/notifier.py`
- "build quarantine" → `argus/response/quarantine.py`
- "build the tray" → `argus/tray/tray_app.py`
- "build the api" → `argus/api/server.py`
- "build the gui" → `argus/gui/frontend/`
- "build bigquery sync" → `argus/cloud/bigquery_client.py`
- "build gcs sync" → `argus/cloud/gcs_client.py`
- "build the report" → `argus/cloud/report_generator.py`

---

## Sub-Agent Rule (Phase 3 Onwards)

RAG queries, cloud sync writes, and PDF generation are deterministic operations.
Run these as isolated calls with minimal context — do not load full inference
context for database writes, file uploads, or embedding lookups.
Keep the main daemon thread clean. Deterministic work stays deterministic.

---

## Architecture Rules — Never Violate These

### Data Flow
```
Event trigger → Feature extraction → RAG context retrieval →
LLM inference (local or cloud) → Verdict → SQLite log →
[notify user] [quarantine if needed] [cloud sync async]
```

### Privacy Boundary — CRITICAL
- Never pass raw file contents to any LLM (local or cloud)
- Never pass raw email bodies to cloud model — extract metadata only
- Only metadata goes to NIM/Kimi K2: filename, extension, hash, origin URL,
  entropy score, magic bytes, sender domain, WHOIS age, SPF/DKIM result
- Full reasoning text from LLM is stored locally in SQLite only
- Cloud sync (BigQuery) gets metadata + verdict + confidence score
  — never the full model reasoning chain for privacy

### Credentials — Zero Tolerance for Hardcoding
- All API keys in `.env` file, loaded via `python-dotenv`
- `.env` must be in `.gitignore` before first commit — check this
- Google service account JSON at `~/.argus/credentials/service_account.json`
  — outside project directory entirely, never committed
- Config template at `configs/config.example.json` with placeholder values only

### Offline Resilience
- SQLite is always written first, synchronously, before anything else
- Cloud sync is async, best-effort, non-blocking
- If NIM is unreachable, automatically fall back to local Ollama
- If Ollama is not running, log incident as UNANALYZED and notify user
- Daemon must never crash due to network failure

### Threading Model
- Main thread: pystray tray icon (required — pystray must own main thread)
- Thread 1: daemon event loop (monitors + inference)
- Thread 2: FastAPI server (GUI backend)
- Thread 3: cloud sync queue processor
- Use `threading.Thread(daemon=True)` for all background threads
- Use `queue.Queue()` for inter-thread communication — no shared mutable state

---

## Tech Stack — Fixed, Do Not Substitute

| Component | Library | Version |
|---|---|---|
| File watching | watchdog | latest |
| Email | imaplib (stdlib) | — |
| Feature extraction | python-magic, pefile, hashlib | latest |
| LLM inference | openai (OpenAI-compatible client) | latest |
| Local LLM | Ollama (external, must be running) | — |
| Cloud LLM | NVIDIA NIM via openai client | — |
| Vector DB | chromadb | latest |
| Embeddings | sentence-transformers (all-MiniLM-L6-v2) | latest |
| Tray icon | pystray + Pillow | latest |
| GUI window | pywebview | latest |
| GUI frontend | HTML + CSS + vanilla JS | — |
| API server | fastapi + uvicorn | latest |
| Notifications | plyer | latest |
| PDF reports | weasyprint | latest |
| Google Cloud | google-cloud-bigquery, google-cloud-storage, google-api-python-client | latest |
| Auth | google-auth, python-dotenv | latest |
| DB | sqlite3 (stdlib) | — |
| Packaging | pyproject.toml | — |

**DO NOT use:** tkinter, PyQt, PySide, customtkinter, Flask (use FastAPI), 
requests (use httpx for async), any GUI framework other than PyWebView+HTML.

---

## SQLite Schema — Do Not Modify Without Updating BigQuery Schema Too

```sql
CREATE TABLE incidents (
    incident_id       TEXT PRIMARY KEY,
    timestamp         TEXT NOT NULL,
    date              TEXT NOT NULL,
    monitor_type      TEXT NOT NULL,
    input_summary     TEXT,
    features          TEXT,        -- JSON string
    rag_matches       TEXT,        -- JSON string
    model_used        TEXT,
    model_version     TEXT,
    reasoning         TEXT,        -- full CoT — local storage only
    verdict           TEXT NOT NULL,
    confidence        REAL,
    action_taken      TEXT,
    user_confirmed    INTEGER,     -- NULL=unreviewed, 1=confirmed, 0=false positive
    false_positive    INTEGER DEFAULT 0,
    training_exported INTEGER DEFAULT 0,
    synced_bigquery   INTEGER DEFAULT 0,
    synced_gcs        INTEGER DEFAULT 0
);

CREATE TABLE daily_stats (
    date              TEXT PRIMARY KEY,
    total_events      INTEGER DEFAULT 0,
    threats_detected  INTEGER DEFAULT 0,
    false_positives   INTEGER DEFAULT 0,
    report_generated  INTEGER DEFAULT 0,
    report_drive_url  TEXT
);
```

---

## Inference Prompt Template — Chain of Thought Format

Every LLM call (local and cloud) uses this exact structured format.
Do not change this without updating the fine-tuning data format too.

```
System:
You are Argus, a cybersecurity threat analyst. Analyze the provided metadata 
and reason step by step. Never analyze file contents directly — only metadata.
Output must follow the exact XML structure below. No preamble, no postamble.

User:
<input>
  <monitor_type>{file|email|url|package|browser|clipboard}</monitor_type>
  <summary>{human readable one-line description}</summary>
  <features>{JSON of extracted features}</features>
  <threat_intel>{top 3 RAG matches with similarity scores}</threat_intel>
  <whitelist_check>{matched/not_matched}</whitelist_check>
</input>

Required output format:
<analysis>
  <observe>List every anomalous feature observed</observe>
  <classify>Match to known threat category or explain why clean</classify>
  <confidence>Rate 0.0-1.0 and explain the rating</confidence>
  <verdict>SUSPICIOUS or CLEAN or UNCERTAIN</verdict>
  <category>MALWARE|PHISHING|SUPPLY_CHAIN|FRAUD_PAYMENT|SPOOFED_SENDER|CLEAN|UNKNOWN</category>
  <action>QUARANTINE or BLOCK or MONITOR or ALLOW</action>
  <reason_summary>One sentence for the daily report</reason_summary>
</analysis>
```

---

## GUI Design Specification

**Stack:** PyWebView (native window) + FastAPI (local API) + HTML/CSS/JS (frontend)  
**Port:** localhost:7734  
**Window size:** 900x600, resizable, no browser chrome  

**Color palette (dark theme, non-negotiable):**
```css
--bg-primary: #0f1117;
--bg-surface: #1a1d27;
--bg-border: #2a2d3a;
--text-primary: #e8eaf0;
--text-secondary: #6b7080;
--color-safe: #22c55e;
--color-warning: #f59e0b;
--color-threat: #ef4444;
--color-accent: #6366f1;
```

**Typography:**
- UI text: Inter (Google Fonts, loaded locally for privacy)
- Technical values (hashes, IPs, paths): JetBrains Mono

**Three views only:**
1. Dashboard — status card + recent activity feed + mode toggle
2. Threat Detail — full incident breakdown with user confirm/dismiss actions
3. Settings — monitor toggles, mode config, email config, feed status, export button

**Tray icon states:**
- Green circle = protected, no unreviewed threats
- Yellow circle = currently analyzing
- Red circle = unreviewed threat needs attention
- Grey circle = daemon error or paused

---

## Google Cloud Configuration

**Project name:** argus-personal  
**Service account name:** argus-daemon  

**APIs to enable:**
- BigQuery API
- Cloud Storage API  
- Google Drive API

**Service account roles:**
- BigQuery Data Editor
- Storage Object Creator
- Drive File Creator (scoped to Argus folder only)

**BigQuery dataset:** argus_personal  
**BigQuery table:** incidents (schema matches SQLite above minus `reasoning` column)  
**GCS bucket:** argus-logs-{your-uid}/YYYY/MM/DD/HH.jsonl  
**Drive folder:** Argus Daily Reports/  
**Report filename format:** Argus_Report_YYYY-MM-DD.pdf  

**Sync schedule:**
- BigQuery: real-time streaming insert per incident (async)
- GCS: hourly rotation
- Drive PDF: daily at 23:55 local time via `schedule` library

---

## Private Files — Must Never Be Committed

Add to `.gitignore` before first commit:
```
.env
configs/config.json
configs/service_account.json
~/.argus/
data/personal_whitelist.json
data/my_clients.json
models/
logs/
chroma_db/
*.db
*.sqlite
__pycache__/
.venv/
dist/
build/
```

---

## Coding Standards

- Type hints on all function signatures
- Docstring on every class and public method (one line minimum)
- Structured logging via Python `logging` module — no bare `print()` in production code
- All file paths via `pathlib.Path`, never string concatenation
- Config loaded from `.env` at startup, validated immediately — fail fast if missing keys
- Exception handling: catch specific exceptions, log with full traceback, never silent pass
- Every module has an `if __name__ == "__main__":` block for standalone testing

---

## What Claude Code Should NOT Do

- Do not write the full project in one session — one module at a time
- Do not skip the manual verification step between phases
- Do not hardcode any path, key, or credential
- Do not use synchronous blocking calls inside the async inference layer
- Do not pass raw file contents or raw email bodies to any LLM
- Do not modify the prompt template format without explicit instruction
- Do not add dependencies not in the tech stack table without asking first
- Do not write tests before the module being tested is complete and verified

---

## Session Handoff Protocol

At the end of every Claude Code session, before closing:
1. Run: `git add -A && git commit -m "session: {brief description}"`  
2. Write a `HANDOFF.md` in project root with:
   - What was built this session
   - Current state (what works, what doesn't)
   - Next step to start next session
   - Any unresolved decisions

Load `HANDOFF.md` at the start of every new session before doing anything else.

---

## Repository Structure (Final State)

```
argus/                           ← root folder (repo name: argus)
├── CLAUDE.md                    ← this file
├── CLAUDE.local.md              ← personal preferences (gitignored)
├── HANDOFF.md                   ← session continuity (gitignored)
├── README.md                    ← public face of project
├── LICENSE                      ← GPL v3
├── CONTRIBUTING.md
├── SECURITY.md
├── CHANGELOG.md
├── .gitignore
├── pyproject.toml
├── .env.example                 ← template, committed
├── .env                         ← actual keys, gitignored
│
├── argus/
│   ├── __init__.py
│   ├── core/
│   │   ├── daemon.py
│   │   ├── config.py
│   │   └── logger.py
│   ├── monitors/
│   │   ├── file_watcher.py
│   │   ├── email_scanner.py
│   │   ├── package_monitor.py
│   │   ├── browser_monitor.py
│   │   └── clipboard_monitor.py
│   ├── analysis/
│   │   ├── feature_extractor.py
│   │   ├── rag/
│   │   │   ├── embedder.py
│   │   │   ├── threat_feeds.py
│   │   │   └── whitelist.py
│   │   └── inference/
│   │       ├── router.py
│   │       ├── local.py
│   │       ├── cloud.py
│   │       └── consensus.py
│   ├── response/
│   │   ├── notifier.py
│   │   └── quarantine.py
│   ├── api/
│   │   └── server.py
│   ├── gui/
│   │   └── frontend/
│   │       ├── index.html
│   │       ├── styles.css
│   │       └── app.js
│   ├── tray/
│   │   └── tray_app.py
│   └── cloud/
│       ├── bigquery_client.py
│       ├── gcs_client.py
│       ├── drive_client.py
│       └── report_generator.py
│
├── training/
│   ├── README.md
│   ├── kaggle_finetune.ipynb
│   ├── data_export.py
│   ├── synthetic_gen.py
│   └── evaluate.py
│
├── configs/
│   ├── config.example.json
│   └── threat_feeds.example.json
│
├── data/
│   └── sample_dataset.json      ← 100 anonymized examples, committed
│
├── docs/
│   ├── architecture.md
│   ├── setup.md
│   ├── monitors.md
│   ├── training_pipeline.md
│   ├── threat_model.md
│   └── private_data_guide.md
│
├── tests/
│   ├── test_feature_extractor.py
│   ├── test_rag.py
│   └── test_inference.py
│
└── launch_argus.vbs             ← invisible Windows background launcher
```
