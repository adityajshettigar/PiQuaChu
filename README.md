<!-- README.md -->
# PiQuaChu 🛡️

> **Developer-first, local-first post-quantum cryptography discovery and migration assistant.**
> Point it at a source archive or directory and get standards-mapped evidence of
> cryptography usage, migration guidance, reviewable patches, and a standards-valid
> CycloneDX 1.7 CBOM.

PiQuaChu is a **discovery** tool. A rule match is evidence of a code pattern — it is
not proof of runtime behaviour, correct parameters, FIPS 140 module validation, or
organisation-wide compliance. The product language and API reflect that boundary.

---

## What PiQuaChu does

1. **PQC discovery against the standards registry** — detects recognized PQC algorithm
   evidence for the three finalized NIST standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA,
   FIPS 205 SLH-DSA) and for FN-DSA/FALCON, whose standard (FIPS 206) is **still in
   development**. Detected FN-DSA usage is reported as algorithm evidence, not as a
   finalized-standard pass.
2. **Legacy-crypto discovery** — RSA, ECDSA/EdDSA, ECDH, DSA, DES/3DES, RC4, MD5/SHA-1,
   AES-128, ECB/CBC misuse, static salts/IVs, weak randomness, TLS/SSH configuration
   evidence, dependency advisories and key material.
3. **Category-aware migration guidance** — ML-KEM is suggested for key establishment;
   ML-DSA/SLH-DSA for signatures; MD5/SHA-1 map to SHA-256/SHA-3 (legacy integrity),
   not to a PQC signature. AES is treated as symmetric crypto, not as a failed PQC scheme.
4. **Local remediation plans and patches** — deterministic offline plans; optional Groq
   enrichment of **metadata only**. `cipher_cli.py patch` defaults to dry-run, emits
   unified diffs, re-parses Python/Java, and flags changes that need manual protocol or
   nonce work.
5. **CycloneDX 1.7 CBOM** — native `cryptographic-asset` components with evidence
   occurrences, schema-validated against the bundled official 1.7 JSON schema.
6. **Machine-readable outputs** — JSON reports, anonymized telemetry and a CycloneDX
   1.7 CBOM. CI/SARIF/PR gating is planned separately; gates should use new actionable
   findings, not score deltas.

### Standards lifecycle (authoritative registry)

| Standard | Algorithm | Former name | Role | Lifecycle |
|---|---|---|---|---|
| **FIPS 203** | **ML-KEM** | CRYSTALS-Kyber | Key encapsulation | **Final** (2024-08-13) |
| **FIPS 204** | **ML-DSA** | CRYSTALS-Dilithium | Digital signatures — primary | **Final** (2024-08-13) |
| **FIPS 205** | **SLH-DSA** | SPHINCS+ | Digital signatures — hash-based | **Final** (2024-08-13) |
| **FIPS 206** | **FN-DSA** | FALCON | Digital signatures — lattice | **In development** |

The registry lives in `backend/standards.py`; it records official source URLs, a review
date, aliases, primitives and exact parameter-set security levels. Re-check NIST before
changing a lifecycle status — never hard-code a guessed finalization date.

---

## Verdict semantics

Per-standard public statuses (kept backward compatible):

| Status | Meaning |
|---|---|
| `compliant` | PQC evidence for a **finalized** standard, no legacy evidence of that category |
| `partial` | PQC evidence **and** legacy evidence in the same category |
| `non_compliant` | Legacy evidence only for that category |
| `not_detected` | No qualifying evidence observed — **unknown/not observed, not a pass** |
| `transitional` | Hybrid classical+PQC key-establishment evidence |
| `detected_in_development` | Algorithm evidence for a standard still in development (FIPS 206); **not** a finalized pass |

Each standard also carries additive evidence fields: `evidence_status`
(`detected` / `legacy_detected` / `mixed` / `not_detected` /
`unsupported_or_inconclusive`), `standard_lifecycle`, `confidence`, `rationale`,
`evidence_coverage`, `source` and `reviewed`.

Project verdicts:

- `non_compliant` — legacy evidence in at least one standard category.
- `at_risk` — mixed evidence, or legacy advisory evidence.
- `transitional` — hybrid migration evidence only.
- `incomplete` — some PQC evidence, but not every finalized standard is covered.
- `compliant` — positive evidence for **every finalized** standard and no legacy evidence.
- `not_assessed` — no qualifying cryptographic evidence observed at all.

`pqc_score` (readiness heuristic) and `risk_score` (weighted risk heuristic) are product
metrics with versioned formulas (`readiness-v1`, `risk-v1`), not NIST-issued scores.

### Compatibility note for existing clients

- The existing keys (`status`, `pqc_score`, `verdict`, `standards`, `advisory`, findings)
  are preserved; the new evidence fields are additive.
- Behavioural change: a scan with no qualifying evidence now returns
  `verdict: "not_assessed"` instead of `"compliant"`. Treat `not_detected` as unknown,
  never as a pass.
- New status `detected_in_development` (FIPS 206) and new verdicts `not_assessed` /
  `incomplete` must be accepted by clients that whitelist values.
- CBOM output moved from `specVersion` 1.5 with `type: cryptography` to **1.7** with
  `type: cryptographic-asset`. There is no 1.5 compatibility serializer; consumers must
  migrate. `assessment.semantics_version` (`evidence-v1`) identifies the corrected
  semantics.

---

## Scope and limitations

- **Static discovery only.** PiQuaChu cannot see runtime-only cryptography, dynamically
  loaded libraries, remote service behaviour, or negotiated live TLS/SSH unless a
  separate probe captures it.
- **Pattern evidence ≠ compliance.** A match does not prove the primitive is used
  correctly, the parameters are approved, the implementation is FIPS 140 validated, or
  the application is compliant.
- **Known blind spots.** Dynamic dispatch, reflection, generated code, custom wrappers
  and interprocedural flows may be missed. Language coverage differs: semgrep handles
  Python, Java, JS/TS, Go, C/C++, Rust and PHP; the zero-dependency Python AST fallback
  covers Python only. Auxiliary scanners add config, dependency and key-file evidence.
- **`not_detected` is not safe.** It means no matching evidence was observed.
- **Suggested fixes need review.** ECB→GCM changes nonce/tag handling and data formats;
  MD5/SHA-1→SHA-256 can break protocols and identifiers; RNG swaps can break
  deterministic tests; `MD5withRSA`→`SHA256withRSA` is still classical RSA.
- **AI is optional and metadata-only.** With `GROQ_API_KEY` set, remediation egress is
  built only from an allowlist (rule id, category, standard, target algorithm, language,
  severity, opaque recommendation id); chat sends scan scores/statuses and the user's
  question. Source text, snippets, file paths, repository names, variable names,
  secrets, keys and archives are never sent, and model output cannot trigger tools or
  patches. Without a key, everything works offline. See
  [`docs/security/threat-model.md`](docs/security/threat-model.md).
- **No execution of scanned code.** Archives are treated as untrusted data; package
  lifecycle scripts and third-party build scripts are never executed.

### Relationship to upstream projects

PQClean was archived read-only upstream; it is retained only as a legacy reference and
fixture source (pinned by commit where used). Maintained implementations should be taken
from the successors named by the upstream retirement notice (`mlkem-native`,
`mldsa-native`, `slhdsa-c`, `liboqs`) and their lifecycle/provenance documented.

---

## Architecture

```
┌─────────────────────────────────────────┐
│  React Frontend (Vite · TS · tokens)    │
│  Discovery matrix · threat map ·        │
│  assistant · timeline · PDF/JSON report │
└──────────────────┬──────────────────────┘
                   │ REST / JSON (X-API-Key)
┌──────────────────▼──────────────────────┐
│  Flask API (backend/app.py)             │
│  /api/v1/sast-scan · /scan/{task_id}    │
│  /api/v1/scans · /cbom · /assistant     │
│  JobManager: threads OR Celery+Redis    │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│  Analysis engine                        │
│  scanner.py      semgrep AST + Python   │
│                  AST + transport/config │
│  dataflow_python bounded constant prop. │
│  dataflow_java   javalang JCA sinks     │
│  evidence.py   → one evidence model,    │
│                  fingerprints, dedupe   │
│  compliance.py → registry-mapped matrix │
│  standards.py  → authoritative registry │
│  metrics.py    → ruleset/corpus hashes  │
│  remediation.py→ category-aware plans   │
│  patcher.py    → Python + Java patches  │
│  deps.py · keyfiles.py · cbom.py        │
└─────────────────────────────────────────┘
```

The thread and Celery backends share the same pipeline in `jobs.py`; polling, live logs
and result shapes are identical.

---

## Quickstart

### Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

The API runs at `http://localhost:5000`. Local dev key: `super-secret-key-123`
(`X-API-Key` header). Production keys come from `PIQUACHU_API_KEYS`.

### Frontend

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173
npm test         # Vitest + Testing Library
```

Optional: `VITE_API_URL`, `VITE_API_KEY`. The key is inlined into the bundle, so it is
for localhost-only use.

UI foundation (Phase 1 of the frontend redesign) is documented in
[`docs/frontend-audit.md`](docs/frontend-audit.md): one token layer in
`src/index.css` (light/dark OKLCH), self-hosted fonts, hand-written shadcn-style
primitives in `src/components/ui/`, the app shell in
`src/components/app-shell/`, and a typed API client in `src/lib/api.ts`. The
classic scan console (`src/pages/classic-console.tsx`) is still Chakra-based and is
ported in a later phase; both surfaces talk to the same API.

### Optional: Groq enrichment

```bash
export GROQ_API_KEY="gsk_..."
# optional: export GROQ_MODEL="llama-3.3-70b-versatile"
```

### Team mode (multi-tenant)

```bash
cd backend
export PIQUACHU_TENANCY_MODE=team
python authz.py create-tenant acme --name "ACME"
python authz.py create-key acme ci-bot --role developer --expires-days 90  # shown once
python authz.py list-keys --tenant acme
```

The local default needs no such setup. With more than one API worker, also set
`PIQUACHU_RATE_LIMIT_STORAGE_URI` to Redis — see the operations guide.

### Optional: Celery workers

```bash
export PIQUACHU_BROKER_URL=redis://localhost:6379/0
cd backend
celery -A tasks worker --loglevel=info
python app.py
```

---

## CLI

```bash
cd backend

# Discovery report
python cipher_cli.py scan path/to/code.zip --output report.json

# Anonymized telemetry (algorithm-level only)
python cipher_cli.py telemetry path/to/code.zip

# Migration plans
python cipher_cli.py remediate path/to/code.zip

# Reviewable patches: DRY-RUN by default; --apply writes atomically with backups
python cipher_cli.py patch path/to/code.zip --output patches/
python cipher_cli.py patch path/to/src/                             # diff only
python cipher_cli.py patch path/to/src/ --include-candidates --apply # opt-in write
python cipher_cli.py patch --rollback path/to/src/.piquachu-backups/<stamp>/manifest.json

# Baseline gate (the same semantics the CI workflows use)
python cipher_cli.py scan path/to/src/ --update-baseline .piquachu-baseline.json
python cipher_cli.py scan path/to/src/ --baseline .piquachu-baseline.json --fail-on new-high
python cipher_cli.py scan path/to/src/ --no-baseline --fail-on new-high  # explicit, baseline-free

# SARIF 2.1.0 (validated against the official schema before writing; no snippets)
python cipher_cli.py scan path/to/src/ --sarif piquachu.sarif

# CycloneDX 1.7 CBOM
python cipher_cli.py cbom path/to/code.zip --output cbom.json

# Registry + engine health
python cipher_cli.py selfcheck

# Runtime evidence: READ-ONLY, opt-in (current process or an explicit same-UID PID)
python cipher_cli.py runtime --enable --json
python cipher_cli.py runtime --enable --pid <pid> --json

# Reliability corpus metrics
python worker.py benchmark
```

---

## CI workflow: baseline gate + SARIF

The rule is **new findings only**, never an aggregate score delta: a finding already in
the baseline cannot fail a `new-*` gate, but a change in severity/category/standard is
reported as `changed` (and fails a `changed-*` gate).

```bash
# 1) commit a baseline once (explicit, reviewed, never automatic in CI)
python cipher_cli.py scan . --update-baseline .piquachu-baseline.json

# 2) CI: compare against the baseline from the base branch and gate only new findings
python cipher_cli.py scan . --baseline .piquachu-baseline.json --fail-on new-high \
    --sarif piquachu.sarif
```

Exit codes are the CI contract: `0` pass, `1` gate triggered, `2` usage/baseline error
(fail safe — a missing or corrupt baseline is **never** reported as “no new issues”).

* `.github/workflows/piquachu-scan.yml` — least-privilege (`contents: read` in the scan
  job), SHA-pinned actions, no secrets exposed to PR code, SARIF artifact always
  uploaded, code-scanning upload in a separate opt-in job.
* `.gitlab-ci.yml` — merge-request job, pinned `python:3.12.7` image, SARIF + JSON
  artifacts, plus a native `gl-sast-report.json` declared under
  `artifacts:reports:sast` and validated against the pinned official GitLab schema
  before writing. Only actionable ERROR/WARNING findings become SAST vulnerabilities;
  PASS evidence, informational and inconclusive findings stay in the JSON/SARIF
  artifacts (the excluded count is reported in `scan.messages`). Rendering in the
  Security tab depends on the instance licence tier.

Patch safety: `cipher_cli.py patch` never applies a rewrite by default, only touches
`.py`/`.java` regular files inside the target root, refuses symlinks/traversal/parse
errors, writes atomically with backups and a rollback manifest, and refuses to overwrite
a file that changed since the diff was generated. MD5→SHA-256, `random`→`secrets` and
ECB→GCM are **candidates/manual-only**, never unconditional substitutions.

---

## API reference

All `/api/` endpoints except `GET /api/v1/health` and `GET /api/v1/ready` require
`X-API-Key`. In team mode the key resolves to a tenant + role and every object read is
tenant-scoped (cross-tenant IDs return `404`, not an existence oracle).

- `POST /api/v1/sast-scan` — zip upload; returns `202` + `task_id`.
- `GET /api/v1/scan/{task_id}` — status, findings, compliance matrix, remediation plans.
- `GET /api/v1/scan/{task_id}/logs` — live scan logs.
- `GET /api/v1/scans` — scan history.
- `GET /api/v1/scans/{scan_id}/cbom` — CycloneDX 1.7 CBOM.
- `GET /api/v1/scans/{scan_id}/sarif` — SARIF 2.1.0 for a completed scan (`application/sarif+json`; official-schema validated; no snippets, no host paths).
- `POST /api/v1/sast-scan` also accepts optional `baseline` (JSON file, strictly validated) and `fail_on` (e.g. `new-high`) form fields; the completed job then carries `baseline_delta`, `gate` and `sarif_url`. Additive only — clients that omit them see the unchanged response.
- `POST /api/v1/compliance/check` — ingest anonymized CLI telemetry.
- `POST /api/v1/assistant/query` — chat over the latest scan + standards knowledge.
- `GET /api/v1/reliability` — hermetic corpus metrics with `metric_source`, ruleset/corpus fingerprints, `generated_at`/`age_seconds`, a `stale` flag, separate `release_gates`, and `external_validation` (`not-run` unless `PIQUACHU_EXTERNAL_REPORT` points at a published external report).
- `GET /api/v1/health` / `GET /api/v1/ready` — public liveness/readiness; backend types only (no secrets, paths or stack traces). Readiness is `503` when the DB or a distributed limiter is unavailable.
- `GET|POST /api/v1/admin/tenants`, `GET|POST /api/v1/admin/keys`, `POST /api/v1/admin/keys/{id}/rotate`, `DELETE /api/v1/admin/keys/{id}`, `GET /api/v1/admin/audit` — tenant/key administration and audit events (`owner`/`admin`). A generated secret is returned once and only a verifier is stored.

### Example compliance matrix (abridged)

```json
{
  "pqc_score": 40,
  "risk_score": 60,
  "risk_level": "high",
  "verdict": "non_compliant",
  "standards": {
    "FIPS 203": {
      "algorithm": "ML-KEM",
      "status": "non_compliant",
      "evidence_status": "legacy_detected",
      "standard_lifecycle": "final",
      "confidence": "high",
      "rationale": "2 legacy key-encapsulation finding(s) and no ML-KEM evidence.",
      "compliant_count": 0,
      "legacy_count": 2
    },
    "FIPS 206": {
      "algorithm": "FN-DSA",
      "status": "detected_in_development",
      "evidence_status": "detected",
      "standard_lifecycle": "in_development",
      "rationale": "1 FN-DSA evidence finding(s); FIPS 206 is still in development, so this is algorithm evidence, not a finalized-standard pass.",
      "compliant_count": 1,
      "legacy_count": 0
    }
  },
  "assessment": {
    "status": "static_discovery",
    "evidence_coverage": "static source-pattern evidence only",
    "standards_registry_reviewed": "2026-10-18",
    "semantics_version": "evidence-v1",
    "score_formula_version": "readiness-v1",
    "risk_formula_version": "risk-v1"
  }
}
```

### CBOM

`GET /api/v1/scans/{scan_id}/cbom` emits CycloneDX 1.7 with
`components[].type = "cryptographic-asset"`, `cryptoProperties.algorithmProperties`,
evidence occurrences (relative paths only), and genuine CVE advisories only. Policy
findings such as `AES/ECB detected` are not serialized as vulnerabilities; they remain
in PiQuaChu's native findings report. The official schema is bundled in
`backend/schemas/` and every fixture BOM is validated with `jsonschema`.

---

## Security and operations (Phase 4)

- **Two modes.** `local` (default) keeps the single-user path: a `PIQUACHU_API_KEYS`
  key is owner of the `local` tenant, with no setup. `team` requires tenant-scoped keys
  with roles `owner`/`admin`/`analyst`/`developer`/`viewer`; the shared key only keeps
  working with an explicit `PIQUACHU_LEGACY_ENV_KEYS=1` migration flag. Secrets are
  generated with a CSPRNG, shown once, stored as an HMAC verifier and verified in
  constant time; keys can expire, be revoked and rotated.
- **Central authorization.** Authentication runs once in middleware; routes declare a
  permission, and every scan/job/log/CBOM/SARIF/assistant query is tenant-scoped in SQL.
  Unknown roles deny by default. Background workers re-read the job row and reject a
  mismatched tenant or a payload path outside the upload root.
- **Rate limiting.** Per-route limits keyed by tenant+principal (or a trusted-proxy-aware
  IP) — never the API key. Redis storage is used when configured; production refuses
  multi-worker in-memory limits, and a limiter outage fails closed (`503`) unless you
  explicitly choose `degraded`.
- **Archive hardening.** Entry-count, total/per-file and compression-ratio budgets,
  duplicate/case-fold/NUL/traversal/symlink/encrypted-entry rejection, no nested-archive
  expansion, temp cleanup on success, failure and restart.
- **Audit.** Structured events (auth failures, scan lifecycle, exports, key/tenant admin,
  patch apply, runtime probe) with actor/tenant/action/result/object/correlation id.
  Fields are sanitized and length-bounded; no key, snippet or secret is written. This is
  an append-only application log (SQLite + 0600 JSONL with rotation/retention), **not** a
  WORM compliance ledger.
- **Runtime evidence (opt-in MVP).** `cipher_cli.py runtime --enable` reads only this
  interpreter or one explicit same-UID PID, read-only: module names/versions and
  `/proc/<pid>/maps` paths; Java classpath is labelled *configured*, not loaded. No
  memory, secrets, `sudo`, daemon or network (a live TLS probe needs an explicit target
  **and** `--allow-live-probe`). Missing permission is `not_collected`, never “no crypto”.
- **Honest boundaries.** SQLite is single-host only. Audit is application-level. There is
  no SSO/IdP, HA, WORM audit or enterprise-wide runtime/PKI inventory.

See [`docs/security/threat-model.md`](docs/security/threat-model.md),
[`docs/operations/self-hosting.md`](docs/operations/self-hosting.md) and
[`docs/operations/release-checklist.md`](docs/operations/release-checklist.md).

---

## Validation and testing

Counts are generated from executable sources — do not trust a hard-coded number in a
document:

```bash
cd backend
python report_counts.py          # rules, corpus cases, fixtures, suite checks
python report_counts.py --json
```

Test suites (script-style; pytest is not required):

```bash
cd backend
python test_compliance.py        # compliance engine
python test_standards.py         # registry integrity + evidence semantics
python test_cbom.py              # CycloneDX 1.7 schema + fixtures
python test_extras.py            # rules, deps, keyfiles, patcher
python test_dataflow.py          # evidence model, bounded data-flow, metrics
python test_api.py               # Flask integration (slow: full corpus via /reliability)
python test_phase3.py            # baselines, SARIF schema, patcher safety, CI files
python test_phase4.py            # tenancy/RBAC/IDOR, Redis limiter, migration, uploads, AI egress, runtime, audit
python test_celery_integration.py  # real Redis broker + real Celery worker (opt-in; BLOCKED if no service)
python test_runtime_java.py      # real JVM loaded-class evidence via jcmd (opt-in; BLOCKED if no JDK)
python test_docs.py              # documentation consistency
python worker.py benchmark       # labeled-corpus metrics
semgrep --config rules.yaml --validate
```

External validation (manual ground truth, pinned commits; nothing is executed, nothing
is uploaded):

```bash
git clone --depth 1 --branch v17.1.1 https://github.com/juice-shop/juice-shop.git /tmp/pqc-ext/owasp-juice-shop
git clone --depth 1 --branch 3.5.1    https://github.com/paramiko/paramiko.git     /tmp/pqc-ext/paramiko
python -m benchmark.external_eval --all --workdir /tmp/pqc-ext --output /tmp/external.json
```

Frontend:

```bash
cd frontend
npm run build
npm run lint
npm test
```

The bundled hermetic corpus contains **62 labeled cases**
(`backend/benchmark/corpus.py`): binary cases scored as TP/FP/FN/TN plus cases whose
honest outcome is “a human must review the runtime value” (`UNDERTERMINED`, reported
separately and never forced into the confusion matrix). It is a regression corpus, not
external validation, and never establishes real-world recall on its own.

**External ground truth** lives in `backend/benchmark/external_ground_truth.py`
(manually reviewed call sites, pinned commits) and is scored by
`python -m benchmark.external_eval --all --workdir /tmp/pqc-ext`. Synthetic and
external metrics are reported separately and never blended:

| Source | Target | Precision | Recall | F1 |
|---|---|---|---|---|
| hermetic corpus | 62 labeled cases | 1.0000 | 0.9762 | 0.9880 |
| external ground truth | OWASP Juice Shop 17.1.1 (`39b4686`) | 1.0000 | 0.2500 | 0.4000 |
| external ground truth | paramiko 3.5.1 (`ed8b097`) | 0.8421 | 0.5161 | 0.6400 |
| external ground truth | pooled (micro) | 0.8571 | 0.4615 | 0.6000 |

Re-run `python worker.py benchmark` and the external command for current values; the
full report (scope, rubric, false positives/negatives, threats to validity) is
`docs/engineering/phase-2-report.md`. Never modify labels to improve a score.

Metric provenance is exposed, not implied: `/api/v1/reliability` and
`worker.py benchmark` carry `metric_source` (`hermetic`, `external-ground-truth` or
`not-run`), the ruleset/corpus sha256 fingerprints, `generated_at` and `age_seconds`,
plus a `stale` flag so a five-minute cache never looks current.

---

## Project structure

```
backend/
  app.py             Flask API, job manager, SQLite WAL schema
  jobs.py            shared thread/Celery scan pipeline
  scanner.py         semgrep AST + Python AST + transport/config evidence
  standards.py       authoritative standards registry + validation
  compliance.py      registry-mapped matrix, evidence semantics, scores
  remediation.py     category-aware migration plans (+ optional Groq)
  patcher.py         Python/Java reviewable patches (dry-run by default)
  deps.py            dependency + lockfile advisory scanner
  keyfiles.py        PEM/OpenSSH/PuTTY/PKCS#12 key-material scanner
  cbom.py            CycloneDX 1.7 generator + official schema validation
  cipher_cli.py      local-first CLI
  cbom_cases.py      CBOM fixture scenarios
  cbom_fixtures/     committed, schema-valid fixture BOMs
  schemas/           bundled official CycloneDX 1.7 + SARIF 2.1.0 JSON schemas
  dataflow_python.py bounded Python constant propagation (supplemental engine)
  dataflow_java.py   bounded Java AST/data-flow via javalang (optional parser)
  evidence.py        shared evidence model, stable fingerprints, dedupe
  metrics.py         metric provenance, freshness and release gates
  baseline.py        versioned baseline schema, delta classification, gate policy
  sarif.py           SARIF 2.1.0 generator + official-schema validation
  config.py          environment validation, tenancy mode, limiter/proxy settings
  authz.py           tenants, hashed API principals, RBAC, rotation (CLI)
  migrations.py      versioned additive schema upgrade, backup + rollback
  audit.py           structured audit events, sanitization, rotation/retention
  runtime_probe.py   opt-in read-only runtime evidence (separate source)
  benchmark/         labeled regression corpus, external ground truth + eval
  test_*.py          script-style suites (incl. test_phase3.py)
frontend/
  src/App.tsx              router + shell composition
  src/pages/               overview, connection, classic scan console
  src/components/ui/       design-system primitives (tokens, no demo content)
  src/components/app-shell/ sidebar, mobile sheet, theme, connection status
  src/lib/                 typed API client, standards registry, utils
  src/types.ts             shared scanner types + status constants
```

---

## Contributing

Pull requests are welcome. Keep claims aligned with evidence, update the standards
registry rather than scattering lifecycle strings, add tests with each behaviour change,
and never commit credentials, scanned source archives or generated key material.
