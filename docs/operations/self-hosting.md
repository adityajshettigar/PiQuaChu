# PiQuaChu self-hosting and operations guide (Phase 4)

This guide covers the operational path actually implemented: a single-host
self-hosted API + dashboard, SQLite storage, optional Redis-backed rate limiting
and an optional Celery worker. It states limits instead of implying more.

Supported platforms: Linux (x86_64/arm64) and macOS for local development.
Windows is supported for the CLI; the API is expected behind WSL/Git Bash. The
scanner needs `semgrep` in the virtualenv; `javalang` is optional (Java patches
are skipped, never mis-applied, when absent).

---

## 1. Install

```bash
git clone <your-fork> PiQuaChu && cd PiQuaChu/backend
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
cp ../.env.example ../.env          # then edit; never commit .env
```

Run the API:

```bash
cd backend
./venv/bin/python app.py            # development server, port 5000
# production-style:
./venv/bin/gunicorn -w 2 -b 127.0.0.1:5000 app:app
```

Dashboard (development):

```bash
cd frontend && npm ci && npm run dev
```

## 2. Two supported modes

### A. Local / single-user (default, zero setup)

`PIQUACHU_TENANCY_MODE=local`. The request key is either
`PIQUACHU_API_KEYS` (comma-separated) or, outside production, the built-in
development keys (`super-secret-key-123`, `piquachu-admin`). That key acts as
**owner of the `local` tenant**. No tenant or key setup is required — this is
the frictionless developer path and it is covered by the test suite.

```bash
export PIQUACHU_API_KEYS="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

### B. Team mode (tenant-scoped keys + RBAC)

`PIQUACHU_TENANCY_MODE=team`. Shared env keys are rejected unless
`PIQUACHU_LEGACY_ENV_KEYS=1` (migration window only).

```bash
cd backend
python authz.py create-tenant acme --name "ACME"
python authz.py create-key acme ci-bot --role developer --expires-days 90
#   → {"key_id": "...", "api_key": "pqk_ab12cd34_...", ...}   shown ONCE
python authz.py list-keys --tenant acme       # prefixes only, never secrets
python authz.py rotate-key <key_id>           # new secret, old key revoked
python authz.py revoke-key <key_id>
python authz.py disable-tenant <tenant>       # all keys stop authenticating
python authz.py matrix                        # role → permission matrix
```

Roles: `owner`/`admin` (all), `analyst` (scan, exports, baseline, telemetry,
assistant, runtime), `developer` (scan, exports, patch dry-run/apply),
`viewer` (read-only). Unknown roles and unknown permissions deny by default.

The same actions are available over HTTP when authenticated as owner/admin:
`GET|POST /api/v1/admin/tenants`, `GET|POST /api/v1/admin/keys`,
`POST /api/v1/admin/keys/<id>/rotate`, `DELETE /api/v1/admin/keys/<id>`,
`GET /api/v1/admin/audit`.

## 3. Environment configuration

`.env.example` at the repository root is the authoritative template (placeholders
only, documented defaults). Load it however your process manager prefers, e.g.
`set -a; . ../.env; set +a`.

Security-critical settings are validated at import
(`config.validate_startup`). In production the process **refuses to start** on:
missing `PIQUACHU_API_KEYS` in local mode (dev defaults are never accepted),
wildcard CORS, multi-worker in-memory rate limiting, an invalid limiter failure
mode, or a Redis limiter URI without the `redis` package.

## 4. Database migration, backup and rollback

The schema is versioned (`schema_migrations`, currently version 1). Startup runs
an **additive** migration: new tables/columns only, no drops or recreations.
The first upgrade of a populated database writes
`<db>.pre-phase4.bak` via the SQLite backup API (mode 0600).

```bash
python migrations.py status --db /path/to/piquachu.db    # what will change
python migrations.py upgrade --db /path/to/piquachu.db  # explicit upgrade
```

Rehearse on a copy first:

```bash
cp -p piquachu.db /tmp/rehearsal.db
python migrations.py upgrade --db /tmp/rehearsal.db
```

Backup (stop writes first, or use the SQLite backup API):

```bash
sqlite3 piquachu.db ".backup '/backup/piquachu-$(date +%F).db'"
chmod 600 /backup/piquachu-*.db
# include the WAL/SHM only if you copy files instead of using .backup
```

Restore:

```bash
systemctl stop piquachu            # or kill the API + workers
sqlite3 /backup/piquachu-2026-10-20.db ".backup 'piquachu.db'"
chmod 600 piquachu.db*
systemctl start piquachu
```

Rollback to the automatic pre-upgrade snapshot (stop the service first):

```bash
python migrations.py rollback --db piquachu.db --yes
```

Rollback restores the snapshot exactly; rows written after the upgrade are
lost, so export anything you need first. There is no automatic destructive
migration path.

## 5. Redis rate limiting (multi-worker)

In-memory limits are per process. With more than one API worker, point the
limiter at Redis:

```bash
export PIQUACHU_RATE_LIMIT_STORAGE_URI=redis://127.0.0.1:6379/0
export PIQUACHU_RATE_LIMIT_FAILURE_MODE=closed      # default
export PIQUACHU_WORKERS=4
```

If `PIQUACHU_BROKER_URL` (Celery) is a Redis URL and no explicit storage URI is
set, it is reused for limits. Buckets are `tenant:<id>:principal:<id>` (or a
trusted-proxy-aware IP for unauthenticated requests) — **never the API key**.

Failure modes:

| Mode | Behaviour when Redis is down | When to use |
|---|---|---|
| `closed` (default) | request refused with `503` (`Rate limiter unavailable`) | abuse control must not disappear |
| `degraded` | request allowed; outage logged and visible via `/api/v1/ready` | availability outweighs abuse control |

`GET /api/v1/ready` returns 503 when the configured limiter backend is
unreachable. `/api/v1/health` reports only the backend type and failure mode.

## 6. Celery worker (optional scale-out)

Default jobs run in daemon threads. For worker isolation or multiple consumers:

```bash
export PIQUACHU_BROKER_URL=redis://127.0.0.1:6379/0
cd backend
./venv/bin/celery -A tasks worker --loglevel=info --concurrency=2
```

- The worker runs the same `jobs.run_job` pipeline as threads.
- Every task re-reads the job row and **rejects a payload whose tenant differs
  from the row**, and refuses archive paths outside the server upload dir.
- `acks_late` + `task_reject_on_worker_lost` re-queue after a crash;
  `PIQUACHU_CELERY_VISIBILITY_TIMEOUT` (default 3600 s) controls redelivery of a
  message whose worker was hard-killed. Lower it for faster recovery at the
  cost of possible duplicate execution (the row check prevents a completed job
  from producing a second scan).
- Off-host broker: use `rediss://` with a password/ACL and a private network.
  PiQuaChu does not configure broker TLS or credentials for you.
- SQLite is still the result store: the API and every worker must run on the
  **same host**. Do not point Celery workers at a SQLite file on NFS/SMB.

## 7. Storage and permissions

- `piquachu.db` and its `-wal`/`-shm` sidecars are chmod 0600 (best effort at
  startup). The service user must own the containing directory.
- Audit JSONL defaults to `backend/piquachu-audit.jsonl` (0600), rotates at
  `PIQUACHU_AUDIT_MAX_BYTES`, keeps `PIQUACHU_AUDIT_BACKUPS`, and prunes DB rows
  older than `PIQUACHU_AUDIT_RETENTION_DAYS` at startup.
- Upload extraction dirs are created under the system temp dir as
  `piquachu-upload-*`, always removed in `finally`, and leftovers older than
  `PIQUACHU_STALE_UPLOAD_SECONDS` are removed at startup (same-UID, prefix
  matched, symlinks skipped).

## 8. Runtime discovery (opt-in)

Read-only, local, no memory/secret access:

```bash
./venv/bin/python cipher_cli.py runtime --enable                 # this process
./venv/bin/python cipher_cli.py runtime --enable --pid "$(pgrep -f myapp)" --json
./venv/bin/python cipher_cli.py runtime --enable \
    --live-tls internal.example:443 --allow-live-probe          # ONE explicit host
```

Permissions: same OS user as the target process. `/proc/<pid>/maps` may be
unreadable (`hidepid=2`, ptrace restrictions) — that is reported as
`not_collected` with a reason, never as "no crypto". PID 1, other-UID PIDs and
invalid PIDs are refused. No `sudo` is required or suggested; no `ldd` is run on
untrusted executables; nested archives are never expanded.

Runtime evidence is CLI/JSON first and is **not** uploaded to AI or telemetry.
Static findings carry `evidence_source: "static"`; runtime items carry
`"runtime"` — they are never merged into one "complete" inventory.

## 9. Health, readiness, troubleshooting

| Endpoint | Purpose | Notes |
|---|---|---|
| `GET /api/v1/health` | liveness + backend types | no auth, no secrets/paths |
| `GET /api/v1/ready` | DB + limiter readiness | 503 when a dependency is down |

| Symptom | Check | Fix |
|---|---|---|
| `Refusing to start with unsafe configuration` | logged error list | set `PIQUACHU_API_KEYS`, use Redis with >1 worker, remove wildcard CORS |
| `401` with a new key | `python authz.py check-key <key>` | wrong tenant/role? revoked/expired? tenant disabled? |
| `403` on a route | `python authz.py matrix` | role lacks the permission |
| `429` immediately | `/api/v1/ready`, limiter logs | raise `PIQUACHU_RATE_LIMIT_*` or reset the bucket |
| `503 Rate limiter unavailable` | Redis reachable? | fix Redis or set `degraded` (documented fail-open) |
| Job stuck `ANALYSING` | `piqachu_jobs` row `updated_at` | it is failed automatically after `PIQUACHU_ORPHAN_GRACE_SECONDS` |
| `database is locked` | long-running readers | keep transactions short; SQLite is single-host |
| Cross-tenant `404` | expected | IDs are tenant-scoped; use the owning tenant's key |

## 10. Offline operation

The scanner, rules, baseline/gate, SARIF, CBOM, patching and runtime probe are
fully offline. Remote AI is opt-in and only needs egress when `GROQ_API_KEY` is
set; the local rule engine remains the default source. Dependency advisories are
bundled — record the snapshot date from `/api/v1/reliability` (`ruleset`,
`corpus`, `generated_at`) and re-review on your own cadence. No remote scan, PR
creation or package install happens automatically.
