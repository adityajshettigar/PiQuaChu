# Release checklist and rollback runbook

A release is a **tag plus evidence**, not a green test run. Do not add a
"production ready" or "enterprise compliant" badge on the strength of tests
alone: the claim must match the tenancy mode, DB topology, validation coverage
and audit maturity that were actually exercised.

## 1. Pre-release gates

| Gate | Command | Required result |
|---|---|---|
| Full suite (script suites) | `cd backend && ./venv/bin/python report_counts.py` | all suites pass, checks total recorded |
| Phase 4 acceptance | `./venv/bin/python test_phase4.py` | `ALL n CHECKS PASSED` (no failing group) |
| Hermetic benchmark | `./venv/bin/python worker.py benchmark` | metrics unchanged or explained; no silent regression |
| Semgrep rules | `./venv/bin/semgrep --validate --config backend/rules.yaml` | 0 errors |
| SARIF schema | covered by `test_phase3.py` | official OASIS schema validation passes |
| CBOM schema | `./venv/bin/python test_cbom.py` | CycloneDX 1.7 schema validation passes |
| CI YAML | `test_phase3.py` structural checks | parse/shape only — not proof of a provider run |
| GitLab SAST artifact | `test_phase3.py` → `test_gitlab_sast_export` | `gl-sast-report.json` validates against the pinned official schema v15.2.5; artifact kept when the gate fails |
| Frontend | `cd frontend && npm ci && npm run build && npm run lint` | exit 0 |
| Docs claims | `./venv/bin/python test_docs.py` | registry/version/count claims consistent |
| Migration rehearsal | copy a populated DB, run `migrations.py status/upgrade` | data preserved, backup created |
| Redis limiter | `test_phase4.py` with `redis-server` available | shared counter across two app instances |
| Celery backend | `./venv/bin/python test_celery_integration.py` | `ALL 36 CHECKS PASSED` (real broker + real worker, incl. in-flight hard kill, redelivery and idempotent resume); `⊘ BLOCKED` is reported when no service is available |
| JVM runtime evidence | `./venv/bin/python test_runtime_java.py` | `ALL 23 CHECKS PASSED` (real JVM + jcmd); `⊘ BLOCKED` is reported when no JDK is available |
| Secrets | `git diff` review | no real keys, `.env`, DB, audit log or backup committed |

Automated results must be recorded with the exact command and the commit/working
tree they ran against. Provider pipeline runs, code-scanning upload and browser
checks are **PENDING USER CONFIRMATION** until the user runs them — never
reported as passed.

## 2. Deployment checklist

1. Stop the service (`systemctl stop piquachu` or your supervisor).
2. Snapshot the DB (`sqlite3 piquachu.db ".backup ..."`), mode 0600, off-host if
   possible; snapshot the audit JSONL and its rotations.
3. Deploy code; install `requirements.txt` in a fresh venv (review the diff).
4. Set `PIQUACHU_ENV=production`, keys/pepper, Redis limiter URI, CORS allow-list,
   trusted proxies (only if your proxy rewrites `X-Forwarded-For`).
5. Start one API worker; check `/api/v1/health` then `/api/v1/ready` = 200.
6. Run a smoke scan with a non-production key; verify `/api/v1/scans` scoping.
7. Start remaining workers / Celery worker; confirm one queued job completes.
8. Verify audit events appear (auth failure, scan submit, export) and the log is
   0600.
9. Announce limits: single host, SQLite, application-level audit.

## 3. Rollback

Automatic snapshot (first Phase 4 upgrade):

```bash
systemctl stop piquachu
cd backend
./venv/bin/python migrations.py rollback --db piquachu.db --yes
systemctl start piquachu
```

Manual restore (any release):

```bash
systemctl stop piquachu
sqlite3 /backup/piquachu-<date>.db ".backup 'piquachu.db'"
chmod 600 piquachu.db piquachu.db-wal piquachu.db-shm 2>/dev/null || true
systemctl start piquachu
```

Notes:
- Rows written after the snapshot are lost; export reports first if needed.
- The code rollback is a normal `git checkout <previous-tag>` + dependency
  reinstall. Schema version 1 is read-compatible with Phase 3 code except that
  Phase 3 code ignores the new tables/columns.
- Never "fix" a bad migration by deleting the database. Restore the snapshot.

## 4. Supported versions and known limitations

- **Supported**: the current release and the immediately previous release for
  upgrades/migrations on a single host. No long-term-support branch yet.
- **SQLite**: single host only; not supported on network filesystems or as a
  shared multi-host database.
- **Rate limiting**: in-memory is single-process; production with >1 worker
  requires Redis.
- **Audit**: application-level append-only JSONL + SQLite; not WORM and not a
  compliance ledger.
- **Runtime evidence**: opt-in MVP (current interpreter / one same-UID PID);
  not a runtime/PKI inventory and no agent.
- **Remote AI**: opt-in; metadata-only allowlist; the user's question is
  transmitted when enabled.
- **Identity**: API keys + RBAC only; no SSO, no IdP, no per-object ACLs.

## 5. Incident and vulnerability reporting

Replace the placeholders below with your own contact before distributing:

- Security contact: `security@example.invalid` (placeholder — set before release)
- Reporting channel: private issue/email; do **not** open a public issue for a
  vulnerability.
- Acknowledgement target: 5 business days; triage decision within 10.
- Scope: the PiQuaChu code and documented deployment. Third-party services
  (Groq, Redis, GitHub/GitLab) follow their own disclosure policies.
- Evidence to include: version/commit, deployment mode (local/team), a
  minimal reproduction, and whether source archives or keys may have been
  exposed. Never include real API keys, private keys or customer source.

This policy is a template, not a promise of a staffed security team.
