# 10 · Product Architecture

**Project:** PiQuaChu 🛡️ · v2.1.0
**Purpose:** The deployed product shape — components, interfaces, data flow, deployment
modes — as a user actually runs it.

---

## 1. Product surfaces

| Surface | Stack | User value |
|---|---|---|
| **Web dashboard** | React · Vite · Chakra v2 · framer-motion · lucide-react | Upload zip, live scan logs, 4-standard compliance matrix, threat map, timeline, findings triage (filter/sort), remediation plans, DevSecOps assistant, PDF/JSON report, CBOM export |
| **REST API** | Flask · Flask-Limiter · Flask-CORS · SQLite (WAL) | Programmatic access to everything the dashboard does |
| **Local CLI agent** | Python (`cipher_cli.py`) | Zero-trust offline scan / telemetry / remediate / patch / cbom / selfcheck |
| **Ops worker** | Python (`worker.py`) | Benchmark + selfcheck entry points for CI |
| **Optional Celery worker** | Celery + Redis | Horizontal scaling of scan jobs |

## 2. Component map

```
frontend/                          backend/
  src/App.tsx        orchestration   app.py        Flask API + JobManager + SQLite
  src/components/                    jobs.py       shared job pipelines (thread+celery)
    ComplianceMatrix  4 standards    tasks.py      Celery app + tasks
    ThreatMap         risk heat      scanner.py    5-engine detection
    TimelineChart     history        rules.yaml    106 NIST-tagged semgrep rules
    AssistantPanel    chat           compliance.py verdict matrix + scores
    ReportModal       PDF/JSON       remediation.py plans + assistant (Groq optional)
    ReadinessGauge    score dial     patcher.py    Python+Java AST patches
  src/ScanLogs.tsx    terminal       deps.py       manifest/lockfile CVE scan
  src/types.ts        contracts      keyfiles.py   PEM/OpenSSH/PKCS#12 detection
                                     cbom.py       CycloneDX 1.7 CBOM
                                     cipher_cli.py zero-trust CLI
                                     benchmark/    49-case labeled corpus + runner
                                     test_samples/ vulnerable + compliant fixtures
```

## 3. Primary data flow — zip scan (happy path)

```
Browser                 Flask API                Execution backend            Engines
   │  POST /api/v1/         │                          │                       │
   │  sast-scan (zip)       │  sync validation:        │                       │
   │───────────────────────►│  50MB cap · zip-slip     │                       │
   │                        │  bomb/entry guards       │                       │
   │  202 + task_id         │  job_manager.submit ─────┤                       │
   │◄───────────────────────│                          │ thread OR celery      │
   │                        │                          │  │                    │
   │  GET /scan/{id}/logs   │   run_sast_job:          │  ├─ safe_extract_zip  │
   │───────────────────────►│   (jobs.py, shared)      │  ├─ scan_directory ──►│ semgrep → ast →
   │  (poll, live terminal) │                          │  ├─ build matrix ────►│ compliance.py
   │◄───────────────────────│                          │  ├─ persist ──────────►│ SQLite
   │                        │                          │  └─ plans ───────────►│ remediation.py
   │  GET /scan/{id}        │  SUCCESS: findings +     │                       │ (+ Groq optional)
   │───────────────────────►│  compliance + plans      │                       │
   │◄───────────────────────│◄─────────────────────────┤                       │
   │                        │                          │                       │
   │  render: matrix · gauge· threat map · timeline · table · report          │
```

Status lifecycle: `PENDING → ANALYSING → SUCCESS | FAILED` — persisted in SQLite so
polling survives API restarts; orphaned jobs are failed on startup; `jobs.logs` streams
the live terminal (append-only, capped 500 lines).

## 4. Zero-trust flow (no source egress)

```
Local machine                                   Backend
─────────────                                   ───────
cipher_cli.py telemetry repo/
  ├─ full local scan (all engines)
  ├─ anonymize → {algorithm, standard,
  │  severity, verdict, count} tuples only
  └─ prints the exact permitted payload ───────► POST /api/v1/compliance/check
                                                   ├─ verdict preview (sync)
                                                   └─ telemetry-audit job (async)
```
LLM enrichment (Groq) receives the same anonymized metadata — never source code.

## 5. Execution backends (dual mode, one contract)

| Mode | Trigger | Behavior |
|---|---|---|
| **Threads (default)** | no env | Daemon thread per job; SQLite WAL for concurrency; zero extra infra |
| **Celery + Redis** | `PIQUACHU_BROKER_URL` set | `JobManager.submit` routes to `piquachu.sast_scan` / `piquachu.telemetry_audit` tasks; worker runs the **same** `jobs.py` pipelines; results still persisted to SQLite → identical polling API |

Both modes share: safe extraction → multi-engine scan → compliance matrix → persist
(`scan_history` + `findings`) → remediation plans → SUCCESS payload.

## 6. API surface (X-API-Key required)

| Endpoint | Method | Rate limit | Purpose |
|---|---|---|---|
| `/` | GET | — | Health/metadata |
| `/api/v1/sast-scan` | POST | 10/h | Zip upload → 202 + task_id |
| `/api/v1/scan/{task_id}` | GET | 120/min | Poll status + full result |
| `/api/v1/scan/{task_id}/logs` | GET | 120/min | Live terminal logs |
| `/api/v1/compliance/check` | POST | 30/h | Ingest anonymized telemetry (zero-trust) |
| `/api/v1/scans` | GET | 60/min | Scan history (timeline) |
| `/api/v1/scans/{id}/cbom` | GET | 60/min | CycloneDX 1.7 CBOM |
| `/api/v1/reliability` | GET | 60/min | Live benchmark metrics (cached 5 min) |
| `/api/v1/assistant/query` | POST | 30/min | DevSecOps chat (scan-grounded) |

## 7. Persistence model (SQLite `piquachu.db`)

```
scan_history(id, timestamp, filename, pqc_score, verdict, compliance_json, findings_json)
findings(id, scan_id, file_path, line_number, algorithm, key_size, severity, status,
         nist_standard, created_at)
remediation_plans(id, finding_id, suggested_code, migration_notes, llm_response, source, created_at)
jobs(id, status, scan_id, payload, result, logs, created_at, updated_at)
```
WAL journaling + busy_timeout=5000 so request threads and job threads (or the Celery
worker process) never deadlock. `_safe_json_loads` makes one corrupt row non-fatal.

## 8. Security architecture

- **Auth:** `X-API-Key`; production keys via `PIQUACHU_API_KEYS` env list; dev fallback
  keys never used when env is set.
- **Upload hardening:** 50 MB cap · 250 MB decompressed budget · 5000 entries ·
  zip-slip / absolute-path / symlink rejection; temp dirs removed in `finally`.
- **CORS:** allow-list `localhost:5173–5176` or `PIQUACHU_CORS_ORIGINS`.
- **Headers:** nosniff, frame-ancestors DENY, no-referrer, permissions-policy, no-store.
- **Rate limits:** per-IP (Flask-Limiter, in-memory; Redis backend = roadmap).
- **Privacy:** zero-trust telemetry contract (§4); LLM gets metadata only.

## 9. Deployment modes

| Mode | Recipe | Use when |
|---|---|---|
| Local dev | `python app.py` + `npm run dev` | development |
| Self-hosted prod | threads mode behind any WSGI server | single host |
| Scaled prod | Redis + `celery -A tasks worker` (+ N workers) | heavy/parallel scans |
| Air-gapped | CLI only; no Groq key; everything offline | classified environments |

## 10. Failure modes & degradation

| Failure | Behavior |
|---|---|
| semgrep missing/broken venv | Self-healing launcher → Python ast fallback engine |
| javalang not installed | Java patching skipped (never mis-patched); Python patching unaffected |
| GROQ_API_KEY unset | Deterministic local plans + knowledge-base assistant |
| Redis down in Celery mode | Threads mode unaffected (independent deployments); jobs stay persisted |
| Corrupt JSON row | `_safe_json_loads` returns default; endpoint stays up |
| Restart mid-scan | Orphan recovery fails the job cleanly; history intact |
