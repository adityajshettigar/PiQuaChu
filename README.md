<!-- README.md -->
# PiQuaChu 🛡️

> **NIST Post-Quantum Cryptography compliance engine.** Upload any source archive and
> get a per-standard compliance verdict against **all four NIST-finalized PQC standards** —
> FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA) and **206 (FN-DSA / FALCON)** — with
> AI-generated migration plans, automatic AST remediation patches (Python **and** Java),
> and a SOC-grade dashboard.

---

## What PiQuaChu Does

1. **PQC Compliance Checking (FIPS 203 / 204 / 205 / 206)** — Upload a `.zip` of your codebase
   and get an unambiguous compliance verdict for every NIST-finalized post-quantum standard,
   including **FN-DSA (FALCON) — the 4th standard, published as FIPS 206 in May 2025**.
2. **AI Migration Plans** — Every finding gets a drop-in code replacement, dependency
   changes, justification, and risk assessment (deterministic local rule engine, optionally
   enriched by Groq).
3. **AST Remediation Patches** — `python cipher_cli.py patch <target>` rewrites **Python
   and Java** mechanically (md5→sha256, ECB→GCM, `random`→`secrets`, `java.util.Random`→
   `SecureRandom`, weak RSA signatures→SHA256withRSA), produces unified diffs, applies them
   in place, or opens a GitHub PR (`--pr`).
4. **DevSecOps Assistant** — A floating AI engineer that answers questions about your scan
   results, the NIST standards, and recommended migration steps.
5. **Weighted risk scoring** — every scan reports `risk_score` (0–100) and
   `risk_level` (low/medium/high/critical) that weights legacy findings by category
   (RSA/ECDSA > SHA-1 > AES-128), complementing the readiness `pqc_score`.
6. **Version-aware dependencies** — bundled CVE advisory matching on declared
   crypto-library versions plus lockfile (transitive) scanning
   (package-lock.json, Pipfile.lock, poetry.lock, Cargo.lock, go.sum, yarn.lock).
7. **Key-material breadth** — OpenSSH private/public keys (`id_*`,
   `authorized_keys`), PuTTY `.ppk`, and PKCS#12/`.pfx` containers alongside PEM.
8. **Transport-config evidence** — detects OpenSSH hybrid key exchange
   (`sntrup761x25519-sha512@openssh.com`, `mlkem768x25519-sha256`) and TLS hybrid groups
   (`X25519MLKEM768`, `X25519Kyber768Draft00`) in `sshd_config`, `nginx.conf`, etc. — the
   same detection surface as network flow analyzers like `CipherIQ/pqc-flow`, but read
   statically from config.

### The four NIST standards

| Standard | Algorithm | Former name | Role |
|---|---|---|---|
| **FIPS 203** | **ML-KEM** | CRYSTALS-Kyber | Key Encapsulation — general encryption |
| **FIPS 204** | **ML-DSA** | CRYSTALS-Dilithium | Digital Signatures — primary |
| **FIPS 205** | **SLH-DSA** | SPHINCS+ | Digital Signatures — hash-based backup |
| **FIPS 206** | **FN-DSA** | **FALCON** | Digital Signatures — lattice (NTRU), hash-and-sign |

Only these algorithms (and approved hybrids like `X25519MLKEM768`, `sntrup761x25519`) count
as *compliant*. RSA, ECDSA, ECDH, DSA, EdDSA, MD5, SHA-1, DES/3DES/RC4 and TLS 1.0/1.1 are
flagged with their exact FIPS migration target.

---

## Semantic (AST-based), not regex

Detection is **semantic**: `semgrep` parses the Abstract Syntax Tree of Python, Java,
JavaScript/TypeScript, Go, C/C++, Rust and PHP and matches against `backend/rules.yaml`
(**106 rules** — both positive PQC-usage rules and negative legacy rules, all tagged with
NIST metadata), covering ECB mode, static IVs, static KDF salts, weak randomness,
RSA PKCS#1 v1.5 padding and secret→weak-algorithm taint in addition to the core
algorithm set. A zero-dependency native Python `ast` walker acts as a fallback engine
when semgrep is unavailable.

The ruleset includes **positive FN-DSA evidence** for liboqs (`oqs.Signature("Falcon-512")`),
the `pqcrypto` Python/Rust packages, Bouncy Castle PQC (`Falcon512Signer` /
`Falcon1024Signer`), liboqs C (`OQS_SIG_alg_falcon_512`) and PQClean-style clean
implementations (`PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair`).

### Ecosystem alignment

PiQuaChu's detection surface and migration targets align with the maintained
post-quantum ecosystem:

- **`itzmeanjan/falcon`** — reference C++ implementation of FALCON-512/1024; FALCON became
  NIST's 4th standardized algorithm (FN-DSA / **FIPS 206**) — the reason PiQuaChu audits it.
- **`CipherIQ/pqc-flow`** — runtime/network PQC detection (SSH KEX, TLS groups); PiQuaChu
  mirrors that detection surface statically in transport configs, for repos where the
  network layer is not capturable.
- **`PQClean/PQClean`** (retired → successors) — clean, portable, testable PQC
  implementations; PiQuaChu flags `mlkem-native`, `mldsa-native`, `slhdsa-c`, `liboqs`
  and Pornin's Falcon as first-class migration dependencies in remediation plans.

---

## Compliance verdict model

Each standard gets one of four statuses:

| Status | Meaning |
|---|---|
| `compliant` | NIST-approved PQC algorithm of that standard detected |
| `partial` | PQC usage found **and** legacy algorithm of the same category remains |
| `non_compliant` | Only legacy algorithms of that category found |
| `not_detected` | No cryptography of that category used |

Plus a `pqc_score` (0–100), a project `verdict`, `risk_score`/`risk_level`, and advisory
counts for hashing / symmetric / TLS / secrets / dependencies / KDF / randomness layers.

## Zero-trust local analysis

The **CLI agent never uploads source code**. `python cipher_cli.py telemetry <target>`
prints exactly the anonymized payload (algorithm names, standard, severity, verdict)
that is permitted to leave the machine — no file paths, variable names, or source.

---

## Architecture

```
┌─────────────────────────────────────────┐
│  React Frontend  (Vite · Chakra v2)     │
│  Compliance Matrix (4 standards) ·      │
│  Threat Map · AI Assistant · Timeline   │
│  · PDF report · sortable/filterable     │
│    findings table · onboarding guide    │
└──────────────────┬──────────────────────┘
                   │ REST / JSON  (X-API-Key)
┌──────────────────▼──────────────────────┐
│  Flask API  (backend/app.py)            │
│  /api/v1/sast-scan · /scan/{task_id}    │
│  /api/v1/assistant/query · /api/v1/scans│
│  /api/v1/compliance/check · /cbom       │
│  JobManager: threads (default) OR       │
│  Celery+Redis (PIQUACHU_BROKER_URL)     │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│  Analysis Engine                        │
│  scanner.py  ── semgrep (AST) rules     │
│               └─ Python ast fallback    │
│               └─ config/transport scan  │
│  compliance.py  → NIST matrix + score   │
│  remediation.py → migration plans + LLM │
│  patcher.py     → Python + Java AST     │
│                  remediation patches    │
│  deps.py · keyfiles.py → CBOM inputs    │
└─────────────────────────────────────────┘
```

---

## Quickstart

### 1. Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt   # includes semgrep + optional celery/redis/javalang
python app.py
```

> The venv activation matters: it puts `semgrep` on PATH so the AST engine is used.
> Without semgrep, the app transparently falls back to the built-in Python AST scanner.

The API runs at `http://localhost:5000`. API key for local dev: `super-secret-key-123`
(send it as the `X-API-Key` header). Production keys come from the
`PIQUACHU_API_KEYS` env var (comma-separated).

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Optional env vars: `VITE_API_URL` (default
`http://localhost:5000`) and `VITE_API_KEY`.

### 3. Optional: Groq-powered remediation & chat

```bash
export GROQ_API_KEY="gsk_..."
# optional: export GROQ_MODEL="llama-3.3-70b-versatile"
```

Without a key, everything works with the deterministic local rule engine; with a key,
remediation plans and open-ended chat questions are answered by Groq.

### 4. Optional: Celery workers for production scaling

The default deployment runs jobs in-process (daemon threads + SQLite WAL) — perfect for
self-hosting. To scale horizontally or isolate heavy scans:

```bash
# 1. Start Redis (or point at an existing one)
redis-server --daemonize yes

# 2. Start a Celery worker
export PIQUACHU_BROKER_URL=redis://localhost:6379/0
cd backend
celery -A tasks worker --loglevel=info

# 3. Run the API with the same env var — new jobs are routed to the worker
export PIQUACHU_BROKER_URL=redis://localhost:6379/0
python app.py
```

Polling, live logs and results are identical in both modes — jobs stay persisted in
SQLite, so the API surface does not change.

---

## Local CLI agent

```bash
cd backend
source venv/bin/activate

# Full compliance report (matrix + findings) — 4 standards incl. FIPS 206
python cipher_cli.py scan path/to/code.zip --output report.json

# Anonymized telemetry only (zero-trust)
python cipher_cli.py telemetry path/to/code.zip

# Migration plans for every finding
python cipher_cli.py remediate path/to/code.zip

# AST remediation patches (Python + Java) → unified diffs, applied in place
python cipher_cli.py patch path/to/code.zip --output patches/

# Engine health check (rules loaded, standards coverage)
python cipher_cli.py selfcheck
```

Works on `.zip` archives or directories.

---

## API Reference

All endpoints (except `/`) require `X-API-Key: super-secret-key-123` (or a key from
`PIQUACHU_API_KEYS`).

### `POST /api/v1/sast-scan` — PQC compliance scan (zip upload)

`multipart/form-data`, field `file`. Rate limit: 10/hour. Returns `202` + `task_id`;
poll for results.

**Response (after polling `GET /api/v1/scan/{task_id}`)**

```json
{
  "status": "SUCCESS",
  "scan_id": 3,
  "engine": "semgrep+ast",
  "findings": [
    {
      "file": "src/auth/KeyManager.java",
      "line": 38,
      "vulnerability": "deprecated-rsa-java",
      "severity": "ERROR",
      "nist_standard": "FIPS 203",
      "category": "key-encapsulation",
      "pqc_compliant": false,
      "target_algorithm": "ML-KEM",
      "verdict": "FAIL",
      "recommendation": "PQC compliance (FIPS 203): RSA …"
    },
    {
      "file": "src/sign/FnDsaDemo.java",
      "line": 12,
      "vulnerability": "pqc-fndsa-java",
      "severity": "INFO",
      "nist_standard": "FIPS 206",
      "pqc_compliant": true,
      "verdict": "PASS",
      "recommendation": "PQC compliant (FIPS 206): FN-DSA (FALCON) detected …"
    }
  ],
  "compliance": {
    "pqc_score": 42,
    "risk_score": 61,
    "risk_level": "high",
    "verdict": "non_compliant",
    "standards": {
      "FIPS 203": { "algorithm": "ML-KEM", "status": "non_compliant", "…": "…" },
      "FIPS 204": { "algorithm": "ML-DSA", "status": "not_detected", "…": "…" },
      "FIPS 205": { "algorithm": "SLH-DSA", "status": "not_detected", "…": "…" },
      "FIPS 206": { "algorithm": "FN-DSA", "status": "compliant", "…": "…" }
    },
    "advisory": { "hashing": 1, "symmetric": 0, "tls": 0, "total": 1 },
    "summary": "PQC readiness score 42/100. …"
  }
}
```

### `GET /api/v1/scan/{task_id}` and `GET /api/v1/scan/{task_id}/logs`

Poll status (`PENDING` → `ANALYSING` → `SUCCESS` | `FAILED`) with live terminal logs.
On success the full findings + compliance matrix + `remediation_plans[]` are returned.

### `GET /api/v1/scans` — scan history (timeline)

```json
{ "scans": [ { "id": 3, "timestamp": "…", "filename": "app.zip", "pqc_score": 42, "verdict": "non_compliant" } ] }
```

### `GET /api/v1/scans/{scan_id}/cbom` — CycloneDX Cryptographic Bill of Materials

### `POST /api/v1/compliance/check` — ingest CLI telemetry (zero-trust)

Accepts `{ "telemetry": { "algorithm_telemetry": […] } }` from
`cipher_cli.py telemetry`. Returns an initial verdict and dispatches an audit job.
**No source code is ever uploaded.**

### `POST /api/v1/assistant/query` — DevSecOps chat

```json
{ "question": "Show me all RSA findings in the last scan" }
```

Answers using the latest scan context + NIST knowledge (Groq when configured).

### `GET /api/v1/reliability` — live detection metrics

Accuracy / Precision / Recall / F1 over the labeled corpus (see Testing).

---

## Project structure

```
backend/
  app.py            Flask API: scan endpoints, job manager (threads/Celery), SQLite schema
  jobs.py           shared background pipelines (thread backend + Celery tasks)
  tasks.py          Celery app + task definitions (PIQUACHU_BROKER_URL)
  scanner.py        semgrep AST engine + Python ast fallback + transport-config scan
  rules.yaml        106 NIST PQC rules (Python/Java/JS/TS/Go/C/C++/Rust/PHP) + metadata
  compliance.py     verdict engine (PASS/WARN/FAIL, 4-standard matrix, score, telemetry)
  remediation.py    migration plan generator (local + Groq) + assistant answers
  patcher.py        Python (ast) + Java (javalang) remediation patch generator
  deps.py           version-aware dependency + lockfile scanner (bundled CVEs)
  keyfiles.py       OpenSSH / PuTTY / PKCS#12 key-material scanner
  cbom.py           CycloneDX 1.5 Cryptographic Bill of Materials generator
  cipher_cli.py     zero-trust local CLI agent
  benchmark/        labeled reliability corpus (47 cases) + runner
  test_compliance.py · test_extras.py · test_api.py   (no pytest needed)
  test_samples/     known-vulnerable + PQC-compliant fixtures (5+ languages)
frontend/
  src/App.tsx               dashboard orchestration (sortable/filterable findings)
  src/components/          ComplianceMatrix (4 standards), ThreatMap, TimelineChart,
                           AssistantPanel, ReportModal
  src/types.ts             shared types + NIST standard constants
```

---

## Validation & reliability

PiQuaChu is graded against a **hermetic labeled corpus of 47 cases** covering:
PQC-compliant code (ML-KEM, ML-DSA, SLH-DSA, **FN-DSA**), classical/weak crypto
(RSA/ECDSA/DES/MD5/SHA-1), obfuscation, wrappers, unreachable code, mixed-verdict repos,
PEM/OpenSSH/PKCS#12 key material, dependency/lockfile risk, and transport-config
evidence (hybrid SSH KEX / TLS groups).

```
Corpus   : 47 labeled cases
Accuracy : 1.0000   Precision : 1.0000 (0 false positives)
Recall   : 1.0000 (0 false negatives)   F1 : 1.0000
```

> **External validation roadmap** (security-team ask): run PiQuaChu against
> known-vulnerable applications such as OWASP Juice Shop and publish the results,
> plus a CVE-derived regression set (e.g. node-forge CVE-2022-24771,
> cryptography CVE-2023-49083) already wired into the dependency scanner.

## Testing

```bash
cd backend
python3 test_compliance.py          # 62 unit checks (engine, plans, assistant, FIPS 206)
python3 test_extras.py              # 59 checks (rules, risk, deps, keyfiles, patchers, config)
python3 test_api.py                 # 90 integration checks (Flask test client)
python3 worker.py benchmark         # reliability metrics over the 47-case corpus
semgrep --config rules.yaml --validate   # ruleset schema validation
```

```bash
cd frontend
npm run build   # TypeScript + Vite production build
npm run lint
```

Known-vulnerable samples in `backend/test_samples/` cover all five languages; run
`python cipher_cli.py scan backend/test_samples` to see the engine in action.

---

## Roadmap (from the product review)

- **Multi-tenant auth** — replace the shared API key with per-team keys + RBAC
  (currently: `PIQUACHU_API_KEYS` env list is the production path).
- **External validation report** — run against OWASP Juice Shop / real-world CVEs and
  publish metrics (see Validation section).
- **Rate limiting via Redis** — swap Flask-Limiter's in-memory storage for the Redis
  backend when running multi-worker.
- **More Java patcher rewrites** — DES/3DES→AES-GCM and full ML-DSA/FN-DSA signature
  swaps (beyond the current mechanical digest/mode/RNG fixes).

---

## Contributing

Pull requests are welcome. For significant changes, open an issue first to discuss your
proposal. Please ensure all API changes are reflected in this README.
