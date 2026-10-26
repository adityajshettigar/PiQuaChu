# Phase 4 report — operational security, tenancy, runtime evidence, release readiness

Date: 2026-10-20 (final verification run: 2026-10-21) · Version: `2.4.0` · Schema: version 1
Status: **implemented and verified locally; awaits user acceptance.** Nothing was
deployed, published, committed/pushed or opened as an external PR.

This report separates what was executed (`PASS`) from what could not be executed here
(`BLOCKED`, `PENDING USER CONFIRMATION`). A mocked service is never reported as proof of
a real deployment.

---

## 1. Threat model and changed boundaries

Full model: [`docs/security/threat-model.md`](../security/threat-model.md). Assets,
trust boundaries, attacker capabilities and 20 abuse cases are documented with the
control and residual risk for each.

Changed in Phase 4:

| Boundary | Before | Now |
|---|---|---|
| Untrusted request → API | shared-key check per route | one auth middleware + `@requires(permission)`; tenant-scoped SQL |
| API → worker | caller-supplied payload | worker loads the job row, takes tenant from it, rejects mismatch and foreign paths |
| Source archive → filesystem | zip-slip/symlink/size guards | + per-file/ratio budgets, duplicates/case-fold/NUL/ADS/encrypted refusal, containment re-check, nested archives not expanded |
| Process → remote AI | hand-built prompts | two allowlist builders; data marked untrusted; no tools; bounded output; redacted errors |
| Process → host runtime | none | opt-in read-only probe, same-UID only, no memory/secrets, no network by default |
| Operator → config | scattered env reads | `config.validate_startup` fails closed in production |
| Audit | normal logs | structured, sanitized, rotating events (application-level, not WORM) |

**Not changed / out of scope:** SSO/IdP, per-object ACLs, HA, WORM audit, multi-host
SQLite, container/K8s inventory, live network scanning.

## 2. Migration details and proof existing data survived

`migrations.py` adds (never drops): `schema_migrations`, `tenants`, `principals`,
`audit_events`, `settings`; `scan_history.tenant_id/principal_id`;
`jobs.tenant_id/principal_id`; indexes.

- Before the first upgrade of a populated DB, a snapshot is written with the SQLite
  backup API to `<db>.pre-phase4.bak` (0600), never overwriting an existing snapshot.
- Existing rows are backfilled to tenant `local` (`DEFAULT 'local'`) — nothing is lost.
- Upgrade is idempotent (`schema_migrations`), and `rollback` restores the snapshot after
  an integrity check.

Proof (test `test_migration_preserves_existing_data`, 21 checks): a legacy DB with 2
scans, 2 findings, 1 remediation plan and 1 job was upgraded in a copy →
all row counts and values intact (`old-2.zip`, score 77), tenant backfilled to `local`,
backup verified to predate the upgrade (no `tenant_id` column), second run applied
nothing, and rollback removed a row written after the upgrade and returned schema
version 0.

The repository's own development DB was also upgraded in place during this work (backup
created); no scan/job/remediation rows were dropped.

## 3. Authorization matrix and tenant-isolation results

| Permission | owner | admin | analyst | developer | viewer |
|---|---|---|---|---|---|
| scan:create | ✓ | ✓ | ✓ | ✓ | — |
| scan:read / report:read | ✓ | ✓ | ✓ | ✓ | ✓ |
| remediation:read | ✓ | ✓ | ✓ | ✓ | — |
| baseline:read/write | ✓ | ✓ | ✓ | read | — |
| telemetry:write | ✓ | ✓ | ✓ | — | — |
| assist:query | ✓ | ✓ | ✓ | ✓ | — |
| patch:dry_run / patch:apply | ✓ | ✓ | — | ✓ | — |
| reliability:read | ✓ | ✓ | ✓ | ✓ | ✓ |
| runtime:read | ✓ | ✓ | ✓ | — | — |
| tenant:admin / key:admin / audit:read | ✓ | ✓ | — | — | — |

Unknown roles and unknown permissions deny by default. Tests: role matrix (11),
HTTP enforcement (7), key lifecycle (20), constant-time comparison, and IDOR across
scans, jobs, logs, CBOM, SARIF, assistant context and telemetry jobs.

Real HTTP run in `team` mode (Flask server + curl, scratch DB):

| Check | Result |
|---|---|
| no key / legacy shared key in team mode | `401` / `401` |
| viewer submits a scan | `403` |
| acme scan upload → poll | `202` → `SUCCESS`, findings > 0, `evidence_source: static` |
| globex polls acme job / exports acme SARIF | `404` / `404` |
| globex scan history | `{"scans":[]}` |
| acme creates a key, lists keys | `201`, secret shown once, list contains 0 secrets |
| viewer / owner read audit | `403` / `200` |
| audit log & DB modes | `600` / `600`, no key values in the audit file |

## 4. Rate-limiter backend and degradation mode

- Storage: `PIQUACHU_RATE_LIMIT_STORAGE_URI`, else the Redis Celery broker, else
  `memory://`. Production + `PIQUACHU_WORKERS>1` + memory = **refuse to start**.
- Identity: `tenant:<id>:principal:<id>`, or `ip:<client>` where the client IP only
  honours `X-Forwarded-For` from an explicitly trusted proxy. The API key is never used
  as a storage key.
- `closed` (default): storage outage → `503` “Rate limiter unavailable”; the exception is
  recognised as a limiter failure, not a generic 500.
- `degraded`: outage → request allowed, logged, and `/api/v1/ready` returns `503`.
- Limits: scan 10/h, poll & logs 120/min, telemetry 30/h, exports 60/min, assistant
  30/min, admin 30/h, health 120/min — all env-overridable.

Executed against a **real** Redis/Valkey process: two independent Flask app instances
sharing one storage URI — three requests on instance A then a fourth on instance B
returned `429`. With Redis stopped: `degraded` returned `200`, `closed` raised a real
connection error and the API mapping returned `503`. No mock was used for either.

## 5. Upload / job / storage hardening

- Archive: entry count, total uncompressed, per-file (25 MiB), per-entry and total
  compression ratio (200:1), encrypted-entry refusal, NUL/control chars, drive letters,
  ADS, `..`, absolute paths, symlinks/devices/FIFOs/sockets, duplicate and case-fold
  collisions. Post-extraction containment + symlink re-check. Nested archives are opaque.
- Temp dirs: removed on success, failure and rejection (a leaking 400/413 path was found
  and fixed); startup removes stale `piquachu-upload-*` dirs owned by the same user.
- Jobs: tenant/principal in the row; payload tenant mismatch and foreign paths refused;
  duplicate submission ignored; stale-only orphan recovery (no cross-process kills);
  bounded logs (500); `scan_id` attached to the job; transactional scan insert.
- Celery: `acks_late`, `task_reject_on_worker_lost`, configurable visibility timeout,
  same `run_job` pipeline.
- Storage: DB + WAL/SHM chmod 0600, audit file 0600; SQLite documented as single-host
  only.
- Secret handling: key-material and hardcoded-secret findings no longer export snippets
  or line text; secret-like assignments are redacted in neighbouring context. (Found
  during Phase 4 testing; regression test added.)
- Out-of-tree scan dedupe: semgrep namespaces `check_id` with the config path when the
  scanned target is outside the rules directory (e.g. `worker.py external --repo …`), so
  the same site was reported twice and gates double-counted. Rule ids are canonicalized
  at parse time; regression test runs a real out-of-tree CLI scan. (Found during the
  UAT gate rehearsal; regression test added.)
- `migrations.py rollback` without a snapshot printed a stack trace on the exact command
  the rollback runbook documents; it now prints `ERROR: …`, exits `2`, and leaves the DB
  untouched. (Found during the UAT rollback rehearsal; regression test added.)

## 6. AI egress allowlist and payload evidence

Outbound bodies are built only by `remediation.build_llm_payload` and
`build_assistant_payload`. Finding egress keys are exactly:
`rule_id, category, nist_standard, target_algorithm, language, severity, lifecycle,
finding_count, recommendation_id` (opaque hash). Assistant egress is exactly
`payload_version, question, scan_context{pqc_score, verdict, risk_level, standards}`.

Tests capture the actual `requests.post` body and assert it contains no file path,
snippet, `SECRET =`, private-key marker, repository URL, finding message or API key; the
system prompt marks the data untrusted; no `tools`/`functions` are sent; model output is
length-bounded and risk-constrained; provider exceptions are reduced to the type + HTTP
status. The user's question is transmitted when remote AI is enabled (size-capped at
2000 chars) and the API response carries that privacy note.

## 7. Runtime inventory methods, permissions and blind spots

`cipher_cli.py runtime --enable [--pid N] [--json]`:

| Evidence | Method | Permission / limit |
|---|---|---|
| Python modules/versions | `sys.modules` names; `importlib.metadata` versions | current interpreter only; no import of scanned code |
| Loaded shared objects | `/proc/<pid>/maps` path column | same UID; may be `not_collected` under hidepid/ptrace |
| Java classpath | `/proc/<pid>/cmdline` `-cp/--class-path` | labelled **configured**, not loaded |
| Java loaded classes | `jcmd <pid> VM.class_hierarchy -i -s` (same-UID attach) | JDK required; bounded 15 s timeout + retained-output cap; `not_collected` when jcmd/attach is unavailable — never “no crypto loaded” |
| OpenSSL runtime | `ssl.OPENSSL_VERSION` | current interpreter |
| Live TLS | one explicit `host:port` handshake | requires `--allow-live-probe`; no default network |

No memory, secrets, credentials or private keys are read; no `ldd` on untrusted binaries;
PID 1/0/invalid and other-UID PIDs are refused; no sudo, daemon or installation. Items
carry `evidence_source: runtime` (static findings carry `static`); coverage/errors/limits
are reported; missing permission is `not_collected`. Runtime output is CLI/JSON only and
is not sent to AI or telemetry.

## 8. Automated tests and evidence

Commands (from `backend/`, using the project venv):

| Command | Result |
|---|---|
| `./venv/bin/python report_counts.py` | **9 mandatory suites, 1387 checks, all passed** (`test_phase3.py`: 252, `test_phase4.py`: 249) + 2 service/tool-backed suites, 59 checks, passed |
| `./venv/bin/python test_phase4.py` | **ALL 249 CHECKS PASSED** |
| `./venv/bin/python test_celery_integration.py` | **ALL 36 CHECKS PASSED** (real `redis-server` + real `celery -A tasks worker`, incl. in-flight hard kill + redelivery + resume) |
| `./venv/bin/python test_runtime_java.py` | **ALL 23 CHECKS PASSED** (real OpenJDK 17 JVM, real `jcmd` attach) |
| `./venv/bin/python test_api.py` | 141 passed |
| `./venv/bin/python test_phase3.py` | 252 passed |
| `./venv/bin/python worker.py benchmark` | 62 cases: TP 41 / FP 0 / FN 1 / TN 17; acc 0.9831, P 1.0000, R 0.9762, F1 0.9880 (unchanged after the rule-id fix) |
| `./venv/bin/semgrep --validate --config rules.yaml` | 0 errors, 106 rules |
| `cd frontend && npm run build && npm run lint` | exit 0 / exit 0 |
| CLI smoke (`cipher_cli.py scan … --json`, `cipher_cli.py runtime --enable --json`, `cipher_cli.py runtime`) | scan 41 findings / `at_risk` / `evidence_source: static`; runtime `evidence_source: runtime`, `memory_inspected: false`, `network_used: false`; runtime without `--enable` → exit 2 |
| Real HTTP team-mode run (manual, curl) | table in §3 |
| Migration on a populated copy | §2 |

Redis-based limiter and outage tests run **inside** `test_phase4.py` against a real
`redis-server`/Valkey process; if the binary is unavailable the suite prints
`⊘ BLOCKED` with the command to run, and never counts it as passed.

### Celery + Redis integration (automated, real services)

`backend/test_celery_integration.py` starts a **private `redis-server`** on a free
port and a **real `celery -A tasks worker` process**, then (36 checks):

| Check | Result |
|---|---|
| Celery backend enabled in the API process | ✓ |
| Real worker process reports ready | ✓ (worker PID ≠ API PID) |
| Scan submitted over HTTP is accepted (`202`) and completes `SUCCESS` | ✓ |
| The API process started **no thread** for the job (work went to the broker) | ✓ |
| Worker log shows `piquachu.sast_scan` received **and** succeeded | ✓ |
| Job row carries the submitting tenant **and** principal | ✓ |
| Scan row is attributed to the same tenant; CBOM readable by that tenant | ✓ |
| Tampered broker message (payload claims another tenant) → job `FAILED` | ✓ |
| The refused job wrote **no** scan row | ✓ |
| Another tenant cannot poll the job (`404`) or read its logs (`404`) | ✓ |
| Active task hard-killed mid-scan (`SIGKILL` to the worker **process group**) | ✓ |
| Killed worker process is really gone; job is not recorded `SUCCESS` | ✓ |
| Broker redelivers the **same** job id after the visibility timeout | ✓ |
| Redelivery produces exactly **one** scan row, no duplicate findings, no duplicate plans | ✓ |
| Redelivery after the scan row committed → **resume**, not re-scan (upload dir gone) | ✓ |
| Resume is logged (`scan.resumed` audit event) — recovery is never silent | ✓ |

The suite reports `⊘ BLOCKED` (with the exact command) when `redis-server` or
`celery` is unavailable; a blocked run is never counted as a pass, and
`report_counts.py` lists it separately from the mandatory suites.

### Blocked / not executed here

- **PENDING USER CONFIRMATION:** actual GitHub Actions and GitLab pipeline runs,
  code-scanning upload, fork/protected-variable behaviour. CI YAML is structurally
  asserted only.
- **PENDING USER CONFIRMATION:** browser-level pass over the dashboard (no browser in
  this environment). API paths the UI calls are covered.
- **PENDING USER CONFIRMATION:** a live remote-AI call with a real `GROQ_API_KEY` (only
  the payload builder and mocks were exercised).
- **PENDING:** load/soak test with multiple gunicorn workers + Redis + Celery
  (the two-process Redis limiter, the single-worker Celery pipeline and the
  in-flight hard-kill recovery are proven; multi-worker soak is not).
- **PENDING:** `/proc` permission denial under a real `hidepid` mount (the
  denial code path is unit-tested; the mount option was not in effect here).
- **PENDING USER CONFIRMATION:** a hosted GitLab pipeline run. The native
  `gl-sast-report` exporter is implemented and schema-validated locally
  (§8); rendering in a Security tab depends on the instance licence tier.
- **Intentionally not implemented:** WORM audit.
- **Out of scope:** multi-host SQLite.

## 9. Deployment, backup, restore, rollback

See [`docs/operations/self-hosting.md`](../operations/self-hosting.md) and
[`docs/operations/release-checklist.md`](../operations/release-checklist.md).

Short form: stop service → `sqlite3 piquachu.db ".backup ..."` → deploy → set
`PIQUACHU_ENV=production`, keys/pepper, Redis URI, CORS allow-list → start one worker →
`/health` and `/ready` 200 → smoke scan → start the rest. Rollback: stop service →
`python migrations.py rollback --db piquachu.db --yes` (or restore your own `.backup`) →
start. Rows written after a snapshot are lost.

## 10. Release readiness assessment

| Item | Status | Evidence |
|---|---|---|
| Single-user local mode unchanged/frictionless | **PASS** | local-mode config, dev/env key tests, existing suite |
| Team mode + key lifecycle (expiry/revoke/rotate) | **PASS** | §3, `test_key_lifecycle_and_hashing` |
| RBAC + default deny + tenant isolation (IDOR) | **PASS** | matrix + HTTP/IDOR tests + real HTTP run |
| Data-preserving migration + backup + rollback | **PASS** | §2 |
| Startup validation / fail-closed production config | **PASS** | `test_startup_validation_fails_closed` |
| Distributed rate limiting across processes | **PASS (local Redis)** | §4; real two-instance test |
| Limiter outage closed/degraded behaviour | **PASS** | §4 |
| Celery backend equivalence + worker tenant isolation | **PASS (real broker + real worker)** | §8, `test_celery_integration.py` (36 checks) |
| Celery in-flight hard kill + redelivery + idempotent resume | **PASS (real worker process group killed)** | §8; `jobs.resume_if_complete` / `resume_committed_scan`; atomic scan-row + `scan_id` transaction |
| Java loaded-class runtime evidence on a real JVM | **PASS (OpenJDK 17 + jcmd)** | §7, `test_runtime_java.py` (23 checks) |
| GitLab native SAST report (schema + exporter) | **PASS (local, official schema v15.2.5)** | `backend/gitlab_sast.py`, `test_phase3.py`; hosted pipeline PENDING |
| Upload hardening + temp cleanup | **PASS** | `test_upload_*` |
| Secret/key material never persisted in findings | **PASS** | `test_upload_budgets_and_cleanup` |
| AI egress allowlist / injection / redaction | **PASS (payload-level)** | §6; live provider **PENDING** |
| Runtime probe opt-in + permissions | **PASS (Linux; Python + JVM loaded classes)** | §7; live TLS and `hidepid` denial **PENDING** |
| Audit logging + retention | **PASS as application log** | §8; not WORM by design |
| Health/readiness redaction | **PASS** | `test_health_redaction` |
| Documented UAT commands behave as written | **PASS** | rollback-without-snapshot error path, out-of-tree `--baseline/--fail-on/--sarif` gate (exit 1 + SARIF), `patch` dry-run, `authz`/`migrations` CLI — all re-run during final verification |
| Ops/release documentation | **PASS** | docs set + `.env.example` |
| CI provider executions / code scanning | **PENDING USER CONFIRMATION** | not run here |
| Dashboard browser pass | **PENDING USER CONFIRMATION** | no browser |
| Multi-host / HA / shared SQLite | **OUT OF SCOPE (not claimed)** | stated boundary |

Exit statement: this is a **hardened single-host self-hosted release candidate**. It is
not “production ready” in the sense of HA, SSO or enterprise-wide inventory, and no such
badge is added.

---

## Manual user-acceptance checklist (not yet run by the user)

Mark each after running it. Commands assume `cd backend`, a disposable copy of the DB
where relevant, and `redis-server` for the distributed checks.

1. **Local mode still works.** Unset `PIQUACHU_TENANCY_MODE`, set `PIQUACHU_API_KEYS`,
   start the API, upload a zip with the key → `202`, poll to `SUCCESS`.  
   *Expected:* no tenant setup required.
2. **Multi-tenant setup.** `export PIQUACHU_TENANCY_MODE=team`;
   `python authz.py create-tenant acme`; `python authz.py create-key acme owner --role owner`
   → secret printed once; `list-keys` shows only a prefix.
3. **Cross-tenant access denied.** With acme's scan id and a globex key:
   `GET /api/v1/scans/{id}/sarif` → `404`; globex `/api/v1/scans` does not list it.
4. **Redis-backed limiter across two API processes.** Start two API processes with
   `PIQUACHU_WORKERS=2` and `PIQUACHU_RATE_LIMIT_STORAGE_URI=redis://...`; exceed a route
   limit through process A, then B → `429` from B. `/api/v1/health` reports
   `rate_limiter.backend: redis`.
5. **Scan survives worker restart.** With Celery, stop the worker, submit a scan
   (`PENDING`), start the worker → `SUCCESS` with the same job id. (Verified here; re-run
   in your deployment. The in-process pipeline, the real-worker execution and the
   refusal of a tampered broker message are automated in
   `test_celery_integration.py`, including an **in-flight hard kill** of the worker
   process group, broker redelivery of the same job id and an idempotent resume that
   keeps exactly one scan row; the queued-job restart and the in-flight kill paths are
   both automated.)
6. **Existing SQLite history survives migration.** Copy the DB, run
   `python migrations.py status --db copy.db` then `upgrade`; old scans/jobs are listed
   under the `local` tenant; `*.pre-phase4.bak` exists.
7. **AI payload allowlist.** With `GROQ_API_KEY` set, run one remediation/assistant call
   and inspect the provider request (or proxy) → only allowlisted metadata/scores; no
   paths, snippets, secrets or repository URL.
8. **Runtime probe opt-in and permission states.** `python cipher_cli.py runtime` →
   exit 2, no collection. `--enable --json` → `evidence_source: runtime`,
   `memory_inspected: false`, missing maps permission shows `not_collected`, PID 1 is
   refused.
9. **CBOM passes the official schema.** `python test_cbom.py` (bundled CycloneDX 1.7
   schema) → all checks pass; export a CBOM and validate in your own tooling.
10. **CI gate catches a new high finding.** Commit a baseline, add a new high-severity
    fixture, run `python cipher_cli.py scan . --baseline ... --fail-on new-high --sarif ...`
    → exit 1 and a SARIF result. (Provider pipeline execution still to confirm.)
11. **Patch dry-run never writes.** `python cipher_cli.py patch <dir>` → prints diffs,
    `git status` shows no modification; only `--apply` writes (with backups/rollback).

Stop here and wait for explicit user confirmation before deploying, publishing or
opening external PRs.
