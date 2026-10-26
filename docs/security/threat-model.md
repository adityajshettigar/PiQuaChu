# PiQuaChu threat model (Phase 4)

Status: **working security document**, reviewed 2026-10-20 for the Phase 4 build.
It describes what the code actually does, not an aspirational enterprise posture.
PiQuaChu is a **single-host, self-hosted discovery tool**: static evidence, an
optional metadata-only remote AI enrichment, an opt-in read-only runtime probe,
and a local SQLite database. It is not a runtime/PKI inventory product and it is
not a compliance certificate.

---

## 1. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Source archives and extracted source | OS temp dir `piquachu-upload-*` (deleted in `finally`) | may contain secrets, IP, credentials |
| Scan results (findings, snippets) | `backend/piquachu.db` + API responses | reveal weak crypto, file layout, secrets |
| Baseline / SARIF / CBOM artifacts | caller's filesystem, CI artifacts | baseline tampering could hide regressions |
| API keys (tenant principals) | verifier only in `principals.key_hash` | authenticate scans, exports, patching |
| Legacy shared keys (`PIQUACHU_API_KEYS`) | process environment | owner-level access to the `local` tenant |
| Audit events | `audit_events` table + `piquachu-audit.jsonl` | accountability, incident reconstruction |
| Remote-AI credential (`GROQ_API_KEY`) | process environment | billable third-party access |
| Database file + WAL/SHM | single host, mode 0600 (best effort) | full tenant data |
| TLS/SSH config, key files observed during a scan | never persisted beyond metadata | key material exposure |

## 2. Trust boundaries

```
                 ┌──────────────────────────────────────────────┐
  browser/CI ──▶ │  HTTP API (Flask)                            │
  (untrusted)    │  auth middleware → RBAC → tenant-scoped SQL  │
                 │  rate limiter (memory or Redis)              │
                 └──────────────┬───────────────────────────────┘
                                │ server-created temp upload dir only
                 ┌──────────────▼───────────────────────────────┐
                 │  Scan worker (daemon thread or Celery)       │
                 │  archive validation → extraction → engines   │
                 └──────────────┬───────────────────────────────┘
                                │ tenant from the persisted job row
                 ┌──────────────▼───────────────────────────────┐
                 │  SQLite (WAL) — single host                  │
                 └──────────────────────────────────────────────┘

  scans ──▶ local rule engine (default)   ──▶ nothing leaves the host
        └─▶ remote AI (opt-in, allowlisted) ──▶ provider over TLS
```

1. **Untrusted → API**: every `/api/` route except `/`, `/api/v1/health`,
   `/api/v1/ready` requires a valid key; object IDs are never authorization.
2. **API → worker**: the queue message is untrusted. The worker re-reads the
   job row (`jobs._validate_job_context`), takes the tenant from the row,
   rejects a mismatched payload tenant, and refuses payload paths outside
   `tempfile.gettempdir()/piquachu-upload-*`.
3. **Worker → source tree**: archive validation runs before any extraction;
   extraction is containment-checked again afterwards.
4. **Process → remote provider**: only `remediation.build_llm_payload` and
   `build_assistant_payload` construct outbound bodies (allowlist).
5. **Process → host runtime**: `runtime_probe` is opt-in, same-UID, read-only,
   path/name metadata only; no memory, no secrets, no network by default.
6. **Operator → configuration**: `config.validate_startup` fails closed for
   security-critical production settings.

## 3. Attacker capabilities considered

- Remote unauthenticated attacker (network or browser via CORS/CSRF surface).
- Authenticated low-privilege tenant user (`viewer`, `developer`, `analyst`).
- A tenant attempting to reach another tenant's data by guessing/knowing IDs.
- A CI job or malicious pull request running the scanner on attacker-controlled
  source (archive contents and comments are hostile).
- Someone who obtained one API key (theft, log leak, CI variable exposure).
- A local unprivileged process trying to influence queued jobs (Celery message
  tampering, shared temp directory).
- A poisoned dependency or advisory feed inside the scanned repository.

**Not considered**: a host root attacker, a malicious operator (who owns the DB
and pepper), or a compromised Python runtime. Those imply game over for a
self-hosted single-host tool.

## 4. Abuse cases and controls

| # | Abuse case | Control implemented | Residual risk |
|---|---|---|---|
| 1 | ZIP bomb / decompression bomb | `scanner.validate_zip_entries`: entry count, total uncompressed budget, per-file cap, per-entry and total compression-ratio limits, encrypted entries refused (`test_upload_budgets_and_cleanup`) | Ratio limits can reject legitimate giant generated files; tune via env |
| 2 | Parser crash / resource exhaustion | Engine diagnostics reported as `not collected`, not a pass; semgrep timeout; upload/telemetry/question caps; bounded remediation (60 plans) and job logs (500 lines) | A pathological source file can slow one scan; no per-engine memory cap |
| 3 | Path traversal / symlink escape | Absolute paths, drive letters, `..`, ADS, NUL/control chars, symlink/device/FIFO/socket entries rejected before writing; post-extraction containment + symlink re-check (`safe_extract_zip`) | None known; library quirks covered by post-check |
| 4 | Duplicate/case-fold archive entries (overwrite tricks) | Normalized case-insensitive collision detection rejects the archive | Unicode confusables are treated as distinct names |
| 5 | Nested archive smuggling | Nested archives are stored as opaque files and never expanded; count is logged (`archive_diagnostics`) | A later tool that expands them is outside this boundary |
| 6 | API-key theft / replay | Keys verified by HMAC-SHA256 verifier in constant time; prefix is only an index; revocation/expiry/tenant-disable enforced per request; TLS recommended at the proxy | No binding to client certificate/IP; a stolen key works until revoked |
| 7 | Brute force / key enumeration | Per-route limits (scan/poll/logs/exports/admin/assistant/telemetry) keyed by tenant+principal or client IP; unknown prefixes spend a dummy comparison; 401 is uniform | In-memory limiter is per-process; Redis is required for multi-worker |
| 8 | Cross-tenant IDOR | Every scan/job/export/log/assistant query includes `WHERE tenant_id=?`; cross-tenant returns 404 (no existence oracle); key minting is tenant-scoped (`test_tenant_isolation_across_resources`) | A future route must remember the pattern; no ORM-level row security |
| 9 | Job/task ID guessing | UUIDv4 ids, tenant-scoped `JobManager.get`; logs require `scan:read` **and** the job tenant | IDs are not secrets; they are authz-checked |
| 10 | Log / telemetry leakage | Audit fields sanitized (CR/LF/control chars, length caps, forbidden keys); no auth header, token, key or snippet is logged; API errors are generic; `/health` and `/ready` expose no paths/secrets (`test_health_redaction`) | Normal application logs are not an immutable audit trail |
| 11 | SQLite lock contention | WAL + `busy_timeout=5000` + short transactions; startup recovery only fails *stale* rows so a second process cannot kill a live job (`test_job_tenant_context_and_recovery`) | SQLite remains single-host; see §6 |
| 12 | Celery message manipulation | Worker validates the persisted row, rejects tenant mismatch and non-upload paths; `acks_late` + visibility timeout for crash recovery | A broker-level attacker can drop/delay messages (availability) |
| 13 | Poisoned dependency / CVE data | Dependency findings cite the local advisory snapshot; no remote feed is fetched at scan time; unknown rules are never dropped (`sarif._rule_descriptor`) | Advisory data can go stale — see `/api/v1/reliability` provenance |
| 14 | Prompt injection through findings/comments | Remote payload is built only from allowlisted normalized metadata (`remediation.LLM_ALLOWED_FIELDS`); system prompt marks it untrusted; no tools/function calling; assistant context is scores only; tests assert forbidden fields are absent | Model output is untrusted text and must be reviewed before use |
| 15 | CI secret exposure | CI workflows use least privilege and SHA-pinned actions; scanner never needs the API key for a local scan; `.env*` ignored; examples contain placeholders | Operator-managed secrets in their own CI |
| 16 | Unsafe patch writes | Dry-run default; class matrix; atomic write + backup + rollback manifest; content-hash conflict detection; traversal/symlink/non-regular/parse-error refusals; all-or-nothing batch; confirmed-only PR | Semantics of a remediation still need human review |
| 17 | Runtime probe over-privilege | Opt-in (`--enable`), same-UID only, PID 1/invalid refused, no memory/secret reads, no `ldd` on untrusted binaries, no network unless explicit target + flag; missing permission = `not_collected` | Runtime evidence is a point-in-time sample, not an inventory |
| 18 | Stale standards / advisories | Registry review date and lifecycle surfaced; FIPS 206 stays "in development"; docs and tests guard against stale claims (`test_docs.py`) | Re-review cadence is manual |
| 19 | Unsafe production defaults | `config.validate_startup`: production without keys, wildcard CORS, multi-worker memory limiter, invalid failure mode, missing redis package → refuse to boot; dev keys never in production | Operator can still set `PIQUACHU_ENV=development` on a public host (documented) |
| 20 | Audit tampering / injection | Append-only application semantics, 0600 file, rotation, retention, sanitized fields; DB + JSONL | Not WORM; host root/DB owner can edit both |

## 5. Security assumptions

- TLS is terminated by the operator's reverse proxy; PiQuaChu itself serves
  HTTP. Do not expose it directly to an untrusted network.
- The OS user running the service is trusted and isolated from other tenants.
- The database file, backup and audit file are readable only by that user.
- In team mode each tenant receives its own keys; the shared env key is a
  migration aid, not a production boundary.
- `PIQUACHU_TRUSTED_PROXIES` is only set when the proxy overwrites
  `X-Forwarded-For`; otherwise client-supplied headers are ignored.
- Remote AI (`GROQ_API_KEY`) is opt-in. When enabled, the user's **question** is
  transmitted; users are told not to paste secrets or source.

## 6. Deployment boundaries (stated, not hidden)

- **SQLite is supported for a single host / small self-hosted deployment.**
  It is **not** validated on network filesystems or as a shared multi-host
  database. Multi-host storage is out of scope for this phase.
- **In-memory rate limiting is per process.** Production startup refuses
  `PIQUACHU_WORKERS>1` with memory storage; use Redis.
- **Thread and Celery backends share the same pipeline and DB**, but Celery
  requires a broker you operate (authentication/TLS off-host is your
  responsibility; see the operations guide).
- **Audit logging is application-level, not WORM/compliance-grade.** It is not
  an immutable ledger and does not by itself satisfy an audit standard.
- **Runtime discovery is an MVP**: current interpreter and one authorized PID,
  read-only; no daemon, no agent installation, no network inventory.

## 7. Out of scope for Phase 4

SSO/OIDC/SAML, an identity provider, per-object ACLs beyond tenant scope,
HA/leader election, multi-region storage, WORM audit, FIPS 140 module
validation, container/Kubernetes/cloud asset inventory, live network scanning
of hosts, private-key/secret extraction, and PKI certificate lifecycle
management. The product language must not imply otherwise.
