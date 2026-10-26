# 08 · Experiment Plan

**Project:** PiQuaChu 🛡️
**Purpose:** Every experiment, benchmark and test campaign the project runs — what is
measured, how, and what counts as pass/fail.

---

## 1. Experiment portfolio

| # | Experiment | Question answered | Method | Location |
|---|---|---|---|---|
| E1 | Reliability benchmark | Does the engine label risk correctly? | 49-case labeled corpus → confusion matrix | `backend/benchmark/runner.py` |
| E2 | Unit campaigns | Do engine/scoring/patch components behave? | 3 self-asserting suites | `test_compliance.py`, `test_extras.py` |
| E3 | API integration | Does the HTTP contract hold end-to-end? | Flask test client, 90 checks | `test_api.py` |
| E4 | Ruleset schema validation | Is every semgrep rule loadable? | `semgrep --config rules.yaml --validate` | CI/manual |
| E5 | Job-queue scaling | Does Celery mode behave identically to threads? | Redis + worker, dispatch→poll round-trip | `tasks.py`, ops runbook |
| E6 | Frontend build integrity | Does the dashboard compile clean? | `npm run build` + `npm run lint` | `frontend/` |
| E7 | Ruleset selfcheck | Are rules + standards coverage present? | `cipher_cli.py selfcheck` | CLI |

---

## 2. E1 — Reliability benchmark (primary experiment)

### 2.1 Hypothesis
A semantic (AST) rule engine achieves perfect risk classification on a corpus designed
to defeat regex scanning (obfuscation, wrappers, indirection, unreachable code, haystacks).

### 2.2 Design
- **Corpus:** 49 hermetic cases (`benchmark/corpus.py`), each a synthetic project with a
  ground-truth label (see 02 · Dataset Specification §2). Includes CVE-derived
  regression cases (node-forge CVE-2022-24771, cryptography CVE-2023-49083) promoted
  from the bundled `deps.py` advisories.
- **Independent variable:** scanner verdict (risk present / absent).
- **Dependent metrics:** Accuracy, Precision, Recall, F1 + per-case latency.

### 2.3 Protocol
```bash
cd backend
python3 worker.py benchmark            # human report
python3 worker.py benchmark --json     # machine-readable
python3 worker.py benchmark --output metrics.json
```
Per case: materialize `build_case_dir()` → `scanner.scan_directory()` →
`actual_risk(result)` = (any non-PQC finding) OR (verdict ∈ {non_compliant, at_risk,
transitional}) → confusion label vs `expected_risk(label)`.

### 2.4 Current results (verified)
```
Corpus   : 49 labeled cases (incl. 2 CVE-derived regression cases)
Accuracy : 1.0000   Precision : 1.0000 (0 false positives)
Recall   : 1.0000 (0 false negatives)   F1 : 1.0000
```

### 2.5 Pass criterion
F1 = 1.0 with 0 FP and 0 FN on the full corpus. Any regression blocks merge.

### 2.6 External validation (E1 roadmap — ✅ implemented)
`benchmark/external.py` runs the production scanner against a real, known-vulnerable
application (OWASP Juice Shop) and emits a benchmark-shaped JSON report, so external
results are directly comparable with corpus results:

```bash
# option A — clone automatically (shallow, pinned ref):
cd backend && python3 worker.py external --clone --output external_report.json

# option B — use an existing clone:
git clone --depth 1 https://github.com/juice-shop/juice-shop.git /tmp/juice-shop
python3 worker.py external --repo /tmp/juice-shop --output external_report.json
```

External runs are **observational** (no per-case ground truth exists for a real app):
the report records detection surface — per-file findings, by-category counts,
verdict, pqc_score/risk_score, rules fired — while keeping the benchmark's JSON keys
(`corpus_size`, `confusion`, `metrics`) with `fp/fn/tn = null` and an explanatory note.
Status: implemented and smoke-tested (`worker.py external --repo test_samples` → 41
findings, benchmark-shaped report); the Juice Shop run itself + published write-up
remains the security-team's action item.

---

## 3. E2 — Unit campaigns

| Suite | Focus | Checks | Command |
|---|---|---|---|
| `test_compliance.py` | verdict engine, scoring, plans, assistant, FIPS 206 flows | 62 | `python3 test_compliance.py` |
| `test_extras.py` | rules, risk weights, deps, keyfiles, patchers (py+java incl. DES/3DES), config evidence | 73 | `python3 test_extras.py` |
| `test_api.py` | endpoints, auth, rate limits, job lifecycle, zip hardening | 90 | `python3 test_api.py` |

Pass criterion: all green, zero skips of security-relevant assertions.

Targeted positive-detection tests (close the "COMPLIANT cases can't catch broken
positive rules" gap): `test_fips206_positive_detection`,
`test_fips206_detection_all_standards`.

---

## 4. E3 — API integration experiment

Exercised via Flask test client (no live server):
- Auth: missing/invalid/valid `X-API-Key`; `PIQUACHU_API_KEYS` env path.
- Scan lifecycle: upload → 202 `task_id` → poll PENDING→ANALYSING→SUCCESS → full payload
  (findings + 4-standard matrix + remediation plans) → CBOM retrieval.
- Zero-trust ingestion: `POST /api/v1/compliance/check` with telemetry payload → verdict.
- Hardening: >50 MB rejection, zip-slip, zip-bomb budget, entry-count cap, CORS
  allow-list, security headers, per-IP rate limits (incl. rewritten WAF-era test now
  aimed at `/compliance/check`).
- Persistence regression: explicit column selection on `jobs` (guards the historic
  `SELECT *` misalignment 500).

---

## 5. E4 — Ruleset schema validation

```bash
semgrep --config rules.yaml --validate
```
Pass criterion: **0 configuration errors across all 106 rules.**
(✅ Fixed 2026-09: the 4 Rust rules previously failed pattern validation because the
`use pqcrypto_X::...;` ellipsis form is unparseable for semgrep's Rust tree-sitter on
the pinned build; rewritten to the equivalent `use pqcrypto_X::*;` glob form plus
qualified-call alternatives. See CHANGELOG.)

---

## 6. E5 — Celery/Redis scaling experiment

```bash
export PIQUACHU_BROKER_URL=redis://localhost:6379/0
celery -A tasks worker --loglevel=info
python app.py          # same env var → jobs routed to the worker
```
Verified end-to-end: job dispatched → worker consumed → SQLite job row SUCCESS →
pollable via identical API. Pass criterion: byte-identical polling contract to thread
mode (same `/api/v1/scan/<id>` payload shape and log streaming).

---

## 7. E6 — Frontend build

```bash
cd frontend && npm run build && npm run lint
```
Pass criterion: TypeScript-clean build (~665 kB JS gzipped, chakra+icons manually
chunked), zero lint errors.

---

## 8. E7 — Engine selfcheck

```bash
python3 cipher_cli.py selfcheck
```
Pass criterion: registry validates, rules load (count via `report_counts.py`), and
lifecycle coverage is reported for three finalized standards plus FIPS 206 (in development).

---

## 9. Run matrix (what "all green" means)

```
python3 test_compliance.py    # 62 ✓
python3 test_extras.py        # 73 ✓
python3 test_api.py           # 90 ✓
python3 worker.py benchmark   # 49 cases, F1 1.0000 ✓
semgrep --config rules.yaml --validate   # 0 errors (Rust rules fixed) ✓
npm run build && npm run lint            # clean ✓
```

## 10. Experiment backlog

| Idea | Rationale |
|---|---|
| Latency profiling per corpus category | Identify slow engines (semgrep cold start dominates). |
| Adversarial corpus expansion (more obfuscation patterns) | Stress the semantic-claim. |
| Cross-repo benchmark vs public vulnerable apps (Juice Shop) | External validity. |
| A/B: local vs Groq-enriched plan quality rubric | Quantify LLM uplift (if any). |
