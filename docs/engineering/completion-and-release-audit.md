# Completion and release audit

**Date:** 2026-10-21
**Branch:** `main` @ `f892c50`
**Worktree:** dirty (83 entries: 18 modified tracked files + 65 untracked paths) — *left dirty for
review; nothing was committed, pushed, deployed, published or PR'd in this pass.*
**Scope:** remediation/verification pass on the existing repository. No `git reset`,
`git clean`, `git checkout --`, force-add, mass reformat, dependency upgrade or
database drop occurred. No secrets, keys or credentials were printed, copied or written.

## Executive summary

Three concrete gaps named by the completion brief were implemented and verified locally:

1. **GitLab native SAST report** (`gl-sast-report.json`) — was explicitly *not implemented*.
   Now exported by `backend/gitlab_sast.py`, validated against the pinned official schema
   (tag v15.2.5), declared under `artifacts:reports:sast`, with the artifact kept on gate
   failure. `test_phase3.py` 225 → **252 checks**.
2. **Celery in-flight hard kill + redelivery + idempotent resume** — was PENDING. The scan
   row + `scan_id` now commit in one transaction and `_persist_scan` /
   `_remediate_findings_job` are idempotent, so a redelivered job never duplicates rows and
   never re-scans committed work. Verified against a real `redis-server` with the worker
   **process group SIGKILLed** mid-scan. `test_celery_integration.py` 17 → **36 checks**.
3. **Real-JVM loaded-class runtime evidence** — was `not_collected: helper not
   implemented`. Now a bounded same-UID `jcmd VM.class_hierarchy` attach, verified against a
   real OpenJDK 17 fixture JVM. New `test_runtime_java.py` — **23 checks**.

Full suite after the changes: **9 mandatory suites, 1387 checks, all passed**, plus the two
tool-backed suites (59 checks). `git diff --check` exit 0.

**What is still missing and therefore blocks release acceptance:** the external recall
gate (0.4615 vs target ≥ 0.80) and frontend Phases 2–4 (only the Phase 1 shell exists).
Hosted CI, a live Groq call, browser UAT and a multi-worker soak remain
PENDING/BLOCKED. Nothing here was waived.

## Release verdict

> **NOT RELEASE-READY — EXTERNAL RECALL GATE FAILED**
> Secondary blockers: frontend phases 2–4 not implemented; hosted CI (GitHub/GitLab)
> not verified; live Groq and multi-worker soak not executed.

`LOCAL IMPLEMENTATION VERIFIED` applies to the backend surface; it does **not** extend to
enterprise production readiness, formal certification, HA, SSO or full-estate inventory.

## What changed in this pass

### Backend evidence / CBOM
- No CBOM behaviour change. Note: `docs/engineering/phase-2-report.md` §10 records that
  **CBOM inventory derivation is still rule-ID-centric** — asset completeness beyond
  recognized rules remains an open item (A09, FAIL).
- `_persist_scan` / `_remediate_findings_job` made idempotent per scan id (app.py).
- `jobs.py`: atomic scan-row + `scan_id` write; `resume_if_complete` /
  `resume_committed_scan` recovery; `scan.resumed` audit event.
- `tasks.py`: both Celery tasks answer redelivered messages for completed jobs from the
  stored result instead of re-marking/re-running.

### Detection / benchmark
- No rule, threshold or label change. Synthetic (62 cases) and external ground truth are
  reported separately and were not merged or tuned.

### GitLab / GitHub CI
- `backend/gitlab_sast.py` (new), `backend/schemas/gitlab-sast-report-format-v15.2.5.json`
  (pinned official schema, commit `94999aa479bd7607fb28e28701754021fe3a6723`),
  `cipher_cli.py scan --gitlab-sast`, `.gitlab-ci.yml` (emits + declares the SAST report),
  `test_phase3.py` (exporter suite; the old "does not claim a native SAST report" assertion
  was replaced with the stronger positive contract).
- GitHub workflow unchanged (already least-privilege, SHA-pinned, secrets-free PR scan).

### Runtime / workers
- `backend/runtime_probe.py`: `_java_loaded_classes` (jcmd), `_looks_like_jvm`,
  `_parse_loaded_classes`; classpath and loaded-class claims separated by confidence.
- `backend/test_runtime_java.py` (new).

### Docs
- `README.md` (GitLab SAST section, new test suite list, CRLF→LF normalization),
  `CHANGELOG.md` (this pass, explicitly unreleased), `phase-3-report.md`,
  `phase-4-report.md`, `docs/operations/release-checklist.md`, and this audit.

### Frontend / design system
- **Nothing.** Frontend work in this pass was zero; the app still has only
  `/`, `/console`, `/connection` (Phase 1 shell + classic console).

## Already correct and left intact

Standards registry and lifecycle semantics, CycloneDX 1.7 generation + validation,
evidence/fingerprint model, rule-ID canonicalization, baseline/delta/gate, SARIF 2.1.0,
guarded patcher, RBAC/tenancy, key lifecycle, Redis limiter + outage modes, upload
hardening, AI egress allowlist/redaction, audit logging, migrations, the synthetic
benchmark, the Phase 1 frontend work and every previously passing suite. No duplicate
subsystem was introduced; the GitLab exporter reuses the normalized finding contract.

## Commands and results (this pass, exit codes captured)

| Command | Exit | Result |
|---|---|---|
| `cd backend && ./venv/bin/python report_counts.py` | 0 | 9 mandatory suites **1387 checks** all passed; optional: celery 36, runtime-java 23 |
| `cd backend && ./venv/bin/python test_phase3.py` | 0 | ALL **252** CHECKS PASSED |
| `cd backend && ./venv/bin/python test_celery_integration.py` | 0 | ALL **36** CHECKS PASSED (real redis-server + real worker) |
| `cd backend && ./venv/bin/python test_runtime_java.py` | 0 | ALL **23** CHECKS PASSED (OpenJDK 17.0.20 + jcmd) |
| `cd backend && ./venv/bin/python test_api.py` | 0 | ALL **141** CHECKS PASSED |
| `cd backend && ./venv/bin/python test_docs.py` | 0 | ALL **161** CHECKS PASSED (re-run after README edits) |
| `cd frontend && npm run build` | 0 | re-verified in this pass |
| `cd frontend && npm run lint` | 0 | re-verified in this pass |
| `cd frontend && npm test` | 0 | re-verified in this pass |
| `cd backend && ./venv/bin/semgrep --validate --config rules.yaml` | 0 | 0 errors, 106 rules (baseline run) |
| `git diff --check` | 0 | no whitespace errors after README normalization |
| CLI: `scan /tmp/pqc-gl --gitlab-sast … --fail-on new-high` | 1 | gate fires (expected) and the SAST artifact is still written and schema-valid |
| CLI: `scan … --gitlab-sast … --fail-on none` | 0 | artifact written, 0 schema errors via `jsonschema.Draft7Validator` |

External ground truth numbers below come from the committed report
(`docs/engineering/data/phase-2-external-validation.json`); the external evaluation was
**not** re-run in this pass.

## Acceptance matrix

| ID | Requirement | Status | Evidence |
|---|---|---|---|
| A01 | Repo and user changes preserved | PASS | `git status`/`git diff` recorded before and after; no reset/clean/force-checkout; 83 working-tree entries intact (18 modified + 65 untracked) |
| A02 | Current test counts reconciled | PASS | `report_counts.py` → 1387 checks, exit 0; suites listed with counts |
| A03 | Synthetic benchmark reproduced | PASS | 62 cases TP 41 / FP 0 / FN 1 / TN 17 (acc .9831, F1 .9880), `worker.py benchmark` |
| A04 | External ground truth reproduced | PASS (artifact) | committed external report (juice-shop + paramiko); **not re-run in this pass** |
| A05 | External false negatives adjudicated | PASS | `phase-2-report.md` §10 adjudications; minified-JS FN root-caused and bounded |
| A06 | **External quality gate** (P ≥ .90, R ≥ .80, F1 ≥ .85) | **FAIL — release blocker** | measured P .8571 / R .4615 / F1 .6000; no label tuning or suppression was applied |
| A07 | NIST lifecycle mapping correct | PASS | `standards.py` (FIPS 203/204/205 final, 206 in development), `test_standards.py` 157 |
| A08 | CBOM schema valid | PASS | `test_cbom.py` 175; CycloneDX 1.7 official schema |
| A09 | CBOM inventory completeness | **FAIL (open)** | derivation still rule-ID-centric beyond the recognized inventory; documented, not hidden |
| A10 | Sensitive material redacted | PASS | phase-4 redaction tests; new GitLab exporter asserts no snippets/secrets/host paths |
| A11 | Rule-ID canonicalization / dedupe | PASS | out-of-tree CLI regression in `test_phase3.py`; single severity map shared by SARIF + GitLab |
| A12 | CLI baseline gate correct | PASS | no-change pass, new-high → exit 1, corrupt/missing baseline → exit 2, valid SARIF |
| A13 | GitHub workflow secure/valid | PASS (local) | SHA-pinned actions, `contents: read`, no secrets, no `pull_request_target` |
| A14 | **Hosted GitHub CI + SARIF ingestion** | PENDING_USER_CONFIRMATION | requires push + code-scanning; exact steps in `release-checklist.md` §1 |
| A15 | **GitLab SAST exporter + schema** | PASS | `test_gitlab_sast_export` (27 checks): schema v15.2.5 valid, negative cases, artifact kept on gate failure |
| A16 | **Hosted GitLab pipeline / Security tab** | PENDING_USER_CONFIRMATION | requires a GitLab project with the MR pipeline; licence tier gates the UI render |
| A17 | Celery queued restart | PASS | worker stopped/restarted with a queued job → same job id completes |
| A18 | **Celery active hard kill / redelivery / idempotency** | PASS | worker **process group SIGKILLed** mid-scan; redelivery → SUCCESS, exactly 1 scan row, no duplicate findings/plans; crash-after-commit window resumed, audited |
| A19 | Java runtime probe | PASS (real JVM) | `test_runtime_java.py`: OpenJDK 17 + jcmd attach; classpath vs loaded-class claims separated; `hidepid` denial BLOCKED (option not in effect here) |
| A20 | Multi-worker soak | **BLOCKED (not run)** | needs multi-gunicorn + Redis + Celery under load; harness not written |
| A21 | Live Groq integration | **BLOCKED (no credential)** | no `GROQ_API_KEY` configured; payload builder + mocks only, never presented as live |
| A22 | RBAC / migration / upload / limiter regressions | PASS | `test_phase4.py` 249 checks incl. real two-instance Redis limiter |
| A23 | Spotlight card quality | PASS | scoped listener, single style injection, reduced-motion + focus tests (Phase 1 suite) |
| A24 | Flux loader truthfulness | PASS | controlled/indeterminate states, no simulated percent in production |
| A25 | Bento uses real data | PASS | tests assert no demo metrics/avatars/fake switches |
| A26 | **Frontend screens actually implemented** | **FAIL (incomplete)** | only `/`, `/console`, `/connection` exist; findings workbench, remediation review, history/delta, CBOM export, reliability view and assistant are **not** built |
| A27 | Frontend security | PASS (local) | no production key in bundle; dev key documented as localhost-only; no `dangerouslySetInnerHTML` |
| A28 | Frontend a11y / responsive | PARTIAL | jsdom covers focus/keys/labels; **manual browser UAT PENDING** (no browser here) |
| A29 | Frontend build / typecheck / lint / tests | PASS | `npm run build`, `npm run lint`, `npm test` exit 0 in this pass |
| A30 | Human UAT | PENDING_USER_CONFIRMATION | checklist in `release-checklist.md` §1; not marked pass by writing it |
| A31 | Documentation consistency | PASS | `test_docs.py` 161 checks; counts regenerated, not hand-typed |
| A32 | Release control | PASS | no commit/push/deploy/publish/PR; worktree reported dirty; `git diff --check` exit 0 |

## Blocked / pending items with reproduction steps

| Item | Status | What you need to run | Expected result |
|---|---|---|---|
| Hosted GitHub Actions + SARIF | PENDING | push a branch, open a PR touching a file with legacy crypto | scan job red with `::error::…gate FAILED…`, SARIF artifact present, code-scanning ingests |
| Hosted GitLab MR pipeline | PENDING | enable the MR pipeline in a GitLab project | job red/green per policy, `gl-sast-report.json` in Security tab (licence permitting) |
| Live Groq request | BLOCKED | `export GROQ_API_KEY=…; <opt-in integration command>` (benign synthetic prompt only) | one redacted request; 401/429/5xx paths degrade to local mode |
| `/proc` hidepid denial | BLOCKED | rerun `test_phase4.py` with `hidepid=2` on `/proc` | permission-denied path observed on a real mount |
| Multi-worker soak | NOT RUN | 2+ gunicorn workers + Redis + Celery, bounded load | recorded p50/p95, memory growth, no duplicate rows/isolation errors |
| Frontend phases 2–4 | NOT IMPLEMENTED | build findings/remediation/history/CBOM/reliability/assistant routes | route audit + browser flow in §5.8 of the frontend brief |

## Residual technical limitations

- **Data-flow analysis is bounded and language-dependent** (Python, Java): interprocedural
  calls, object fields, reflection, dynamic dispatch, wrappers and env/config-derived
  values can be missed. This is documented, not presented as general taint tracking.
- **External recall is far below the release target** (R 0.4615 vs ≥ 0.80): PiQuaChu
  under-detects real-world crypto call sites; treat external recall as the top open risk.
- CBOM completeness is bounded by recognized inventory (rule-ID-centric derivation).
- Runtime evidence is point-in-time, same-UID, single-process; not a host inventory.
- WORM audit storage is not implemented; audit is application-level.
- Single-host SQLite only; multi-host, HA, SSO and enterprise inventory are out of scope.

## Confirmation

No data reset, no destructive git cleanup, no secrets written, no deployment, publish,
commit, push or PR was performed. The worktree remains dirty for your review.
