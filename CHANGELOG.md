# CHANGELOG

All notable changes to PiQuaChu. Format based on [Keep a Changelog](https://keepachangelog.com/).

---

## [Unreleased] — Financial design system — 2026-10-26

Visual-system pass over the frontend. No route, copy, API contract or scan behaviour
changes; the same pages read the same data and render the same states.

### Fixed
- **The app rendered unstyled.** `src/index.css` never imported Tailwind, so no utility
  class existed at runtime — the page was raw text on a black body. The stylesheet now
  starts with `@import "tailwindcss"` and the utilities are generated again.
- **Chakra's CSS reset silently overrode every Tailwind utility it shared a property with.**
  Chakra injects that reset unlayered, and unlayered CSS outranks all cascade layers, so
  heading sizes, button fills and vertical rhythm collapsed while colours still applied.
  `resetCSS={false}` on the provider; Tailwind's preflight (in `@layer base`) is the reset.
  Chakra's global element styles are gone from `theme.ts` for the same reason — they pinned
  the document to the dark palette and made the light theme impossible.
- **Fonts were never loaded.** IBM Plex Sans and IBM Plex Mono are now imported from the
  self-hosted `@fontsource` packages that were already in `package.json`.

### Changed
- **Design tokens rewritten as the Financial system**: navy-black ground (`#07090e`),
  panel (`#10141c`), warm orange accent (`#ff951f`), pale gold values (`#edcd8c`), ink and
  muted ink (`#f4f5f7` / `#c9ced8`), hairline line colour (`#303139`), 5px panel radii,
  40px control radii, 160ms interaction motion. Legacy component token names (`--surface`,
  `--primary`, `--radius-lg`, …) are kept as aliases so every page inherits the system
  without a rewrite.
- **Opaque panels, no glass.** The blur/`backdrop-filter` treatment and the page-wide amber
  ambient blobs are gone; warm light is local to the hero object and the closing field.
- **IBM Plex Sans/Mono replace Space Grotesk/Inter/JetBrains Mono.** Values, scan ids,
  timestamps and readiness scores are monospaced with tabular figures; important numbers
  take the pale gold value colour.
- **Michroma carries titles and headings.** The display face is self-hosted from
  `@fontsource/michroma` (400, the only weight it ships) and applied to `h1`–`h4`, the
  Chakra `Heading` component and the `font-display` utility. Heading weight synthesis is
  disabled so the single weight is drawn as-is.
- **Pill controls, hairline badges.** Buttons and icon controls use the 40px control radius;
  status badges are hairline rectangles, not coloured pills.
- **Overview page rebuilt as the Financial composition**: broad promise beside a framed
  record with offset outlines, a ruled strip of real scope facts, a three-column capability
  matrix, the stored-scan table, and a tinted closing field. Every number is real — the
  readiness value is the latest stored scan and the standard counts come from the registry.
- **Shell and Chakra theme follow the same palette**, so the legacy classic console at
  `/console` is themed too. Its animated multicolour dropzone border is now a single warm
  hairline with no sweep.

### Verification
- `tsc -b` clean; `vite build` clean; `vitest run` **78/78**.
- Rendered and inspected at 1440, 1200, 900 and 520px, with reduced motion forced, on
  `/`, `/scan`, `/history` and `/standards`. Dark theme confirmed; the light theme is
  derived from the same palette but was not visually reviewed.

---

## [Unreleased] — completion pass — 2026-10-21

Local remediation/verification pass. Nothing is released, committed, pushed or deployed
on the strength of this entry. Hosted GitHub/GitLab runs, a live Groq call, browser UAT
and a multi-worker soak remain PENDING USER CONFIRMATION.

### GitLab SAST — native report (was an explicit gap)

#### Added
- **`backend/gitlab_sast.py`** — `gl-sast-report` exporter fed by the same normalized
  findings as SARIF. Validated against the pinned official schema
  (`backend/schemas/gitlab-sast-report-format-v15.2.5.json`, tag v15.2.5, commit
  `94999aa479bd7607fb28e28701754021fe3a6723`) before writing; refuses (exit 2) rather
  than emitting an invalid artifact. Deterministic UUIDv5 ids from the finding
  fingerprint (stable across re-runs and line shifts); ERROR→High, WARNING→Medium — the
  same mapping SARIF uses, never recomputed per exporter.
- **Scope policy**: only actionable ERROR/WARNING findings become vulnerabilities. PASS
  evidence, informational and inconclusive findings are excluded **and counted** in
  `scan.messages` (never silently dropped). No source snippets, no
  `raw_source_code_extract`, no secrets, no absolute host paths; secret-bearing findings
  keep location but never echo a value.
- **`cipher_cli.py scan --gitlab-sast FILE`** — official-schema validated before write;
  the artifact is still written when the `--fail-on` gate fails (exit 1), so CI keeps it
  on a red pipeline. `.gitlab-ci.yml` now emits `gl-sast-report.json` and declares
  `artifacts:reports:sast` (`when: always`).

#### Verification
- `test_phase3.py` **225 → 252 checks**: schema-valid export, deterministic ids, severity
  mapping, exclusion accounting, empty/malformed-finding handling, three negative schema
  cases (invalid severity/type/empty identifiers), and CLI end-to-end with the artifact
  preserved on gate failure. The previous assertion “gitlab does not claim a native SAST
  report” was replaced with the stronger positive contract.

### Celery — in-flight hard kill, redelivery, idempotent resume (was PENDING)

#### Fixed
- A redelivered job could create a **duplicate scan row** if the worker died after the
  scan-history insert but before the terminal status write, and could duplicate
  remediation plans. Now: the scan-history insert and `jobs.scan_id` update commit in
  **one** transaction; `_persist_scan` and `_remediate_findings_job` are idempotent per
  scan; and `jobs.resume_if_complete` / `resume_committed_scan` answer a redelivered
  message from the committed scan instead of re-running it (the upload directory may
  already be gone). The resume is logged and audited (`scan.resumed`) — never silent.
- `test_celery_integration.py` **17 → 36 checks**: the worker **process group** is
  `SIGKILL`ed mid-scan against a real `redis-server`; the broker redelivers the same job
  id after the visibility timeout; exactly one scan row, no duplicate findings, no
  duplicate plans; the crash-after-commit window is resumed (not re-scanned).

### Runtime evidence — real JVM loaded classes (was `not implemented in v1`)

#### Added
- **`runtime_probe._java_loaded_classes`** — bounded same-UID `jcmd <pid>
  VM.class_hierarchy -i -s` attach (15 s timeout, retained-output cap, no shell, no
  memory/GC/env/command-line secrets). Only class **names** from known crypto namespaces
  are retained; configured classpath stays a separate, low-confidence claim.
- **`backend/test_runtime_java.py`** — 23 checks against a real OpenJDK 17 JVM fixture
  (`Cipher` + `MessageDigest`): loaded crypto classes reported as high-confidence,
  classpath/loaded distinction, no application values exported, target unmodified;
  jcmd-missing / attach-refused / timeout / non-JVM / PID-1 paths all report
  `not_collected` or denied with a reason — never “no crypto loaded”. Reported as
  `⊘ BLOCKED` (not a pass) when no JDK is present.

### Verification (this pass)

| Command | Result |
|---|---|
| `./venv/bin/python report_counts.py` | 9 mandatory suites, **1387 checks**, all passed; 2 tool-backed suites (celery 36, runtime-java 23) passed |
| `./venv/bin/python test_celery_integration.py` | ALL 36 CHECKS PASSED (real broker + real worker, in-flight hard kill) |
| `./venv/bin/python test_runtime_java.py` | ALL 23 CHECKS PASSED (OpenJDK 17 + jcmd) |
| `cd frontend && npm run build && npm run lint && npm test` | exit 0 / 0 / 0 |
| `git diff --check` | exit 0 (README normalized from CRLF to LF — whitespace only) |

#### Changed
- `README.md`, `docs/engineering/phase-3-report.md`, `phase-4-report.md`,
  `docs/operations/release-checklist.md` updated to the measured counts and to the
  implemented GitLab/Celery/Java state.

### Still open (explicitly)

- **External recall gate (release blocker):** the held-out external evaluation is
  precision 0.8571 / recall 0.4615 / F1 0.6000 against targets of 0.90/0.80/0.85. It was
  **not** reached; the residual false negatives are enumerated in
  `docs/engineering/phase-2-report.md` §10.
- Frontend Phases 2–4 (findings workbench, remediation review, history, CBOM export,
  reliability view, assistant, browser tests) are **not** implemented — only the Phase 1
  shell exists. Browser UAT is PENDING.
- Hosted GitHub/GitLab runs, live Groq request, multi-worker soak, `/proc` `hidepid`
  denial under a real mount — PENDING / BLOCKED as documented in
  `docs/engineering/phase-4-report.md` §8.

---

## [Unreleased] — Phase 4 — 2026-10-20

Phase 4 is implemented and verified locally but **awaits user sign-off**; nothing is
released, committed or pushed on the strength of this entry alone. Provider CI runs,
browser UAT and any real multi-host deployment remain PENDING USER CONFIRMATION.

### Phase 4 — operational security, tenant isolation, runtime evidence

#### Added
- **`backend/authz.py`** — tenant/workspace identity with per-key principal records:
  `pqk_<prefix>_<secret>` format, CSPRNG generation, HMAC-SHA256 verifier (pepper from
  `PIQUACHU_KEY_PEPPER` or generated once), constant-time verification, one-time secret
  display, expiry, revocation, rotation (`rotated_from`), tenant disable, and an explicit
  role matrix (`owner`/`admin`/`analyst`/`developer`/`viewer`) with default-deny for
  unknown roles/permissions. CLI: `authz.py create-tenant|create-key|list-keys|rotate-key|revoke-key|check-key|matrix`.
- **`backend/migrations.py`** — versioned additive schema (`schema_migrations`, version 1):
  `tenants`, `principals`, `audit_events`, `settings`, plus `tenant_id`/`principal_id` on
  `scan_history` and `jobs`. Never drops or recreates a table; one-time pre-upgrade SQLite
  backup, `status`/`upgrade`/`rollback` commands, integrity-checked restore.
- **`backend/audit.py`** — structured security events (auth failure/denial, scan
  submit/complete/failure, report export, key/tenant administration, patch generation/
  apply/rollback, runtime probe) written to SQLite and a 0600 rotating JSONL file, with
  CR/LF + control-character sanitization, forbidden-field redaction, length caps,
  retention pruning and tenant-scoped reads. Application-level only — not WORM.
- **`backend/config.py`** — one place for tenancy mode, CORS allow-list, trusted proxies,
  limiter storage/failure mode, upload/audit budgets and startup validation. Production
  refuses to start with dev keys, wildcard CORS, a multi-worker in-memory limiter or an
  invalid failure mode.
- **`backend/runtime_probe.py`** + `cipher_cli.py runtime --enable` — opt-in, read-only
  runtime evidence: current-interpreter modules/versions, `/proc/<pid>/maps` shared-object
  paths for an authorized same-UID PID, Java classpath labelled *configured* (never
  *loaded*), and a single explicit TLS handshake only with `--allow-live-probe`. No
  memory, secrets, `sudo`, daemon, package install or default network access; missing
  permission is `not_collected`, never “no crypto”. Evidence carries source/method/
  timestamp/coverage/errors/confidence.
- **API** — `GET /api/v1/health` and `/api/v1/ready` (public, redacted), tenant/key
  administration endpoints under `/api/v1/admin/*`, and an audit-event endpoint.
  `baseline`/`fail_on` upload fields are unchanged; `scan_id` is now also persisted on the
  job row for both backends.
- **`.env.example`** (placeholders only), [`docs/security/threat-model.md`](docs/security/threat-model.md),
  [`docs/operations/self-hosting.md`](docs/operations/self-hosting.md),
  [`docs/operations/release-checklist.md`](docs/operations/release-checklist.md),
  [`docs/engineering/phase-4-report.md`](docs/engineering/phase-4-report.md).
- **`backend/test_phase4.py`** — 249 checks: RBAC/default-deny, key lifecycle/expiry/
  rotation, constant-time comparison, cross-tenant IDOR across every resource, migration
  preservation + backup + rollback, startup validation, rate-limit identity, **real
  Redis** limiter shared across two app instances + closed/degraded outage, job tenant
  context/duplicates/stale recovery, archive hardening, AI egress allowlist/injection/
  redaction, runtime opt-in/PID denial, audit sanitization/retention, health redaction.
- **`backend/test_celery_integration.py`** — 17 checks against a **real** broker and a
  **real** worker process: a private `redis-server` and `celery -A tasks worker` are
  started by the suite; a scan submitted over HTTP is executed by the worker (the API
  process runs no thread), the job/scan rows keep the submitting tenant and principal, a
  tampered broker message claiming another tenant is refused (job fails, no scan row),
  and another tenant cannot poll the job or read its logs. Reports `⊘ BLOCKED` with a
  reproducible command when `redis-server`/`celery` are unavailable — never a fake pass.

#### Changed
- **Authentication is centralized**: one middleware resolves the principal, routes declare
  a permission via `@requires`, and object reads are tenant-scoped in SQL (`WHERE
  tenant_id=?`). Cross-tenant IDs return `404`. The legacy shared key authenticates as
  owner of the `local` tenant; team mode rejects it unless `PIQUACHU_LEGACY_ENV_KEYS=1`.
  `PIQUACHU_MULTI_TENANT=1` remains an alias for `PIQUACHU_TENANCY_MODE=team`.
- **Rate limiting** is keyed by tenant+principal (trusted-proxy-aware IP when
  unauthenticated) and uses Redis when `PIQUACHU_RATE_LIMIT_STORAGE_URI` (or the Celery
  broker) is configured. `closed` (default) refuses with `503` during a storage outage;
  `degraded` is explicit fail-open. Limits are env-configurable per route.
- **Jobs** carry tenant/principal in the persisted row; workers validate the row, reject a
  mismatched payload tenant and any path outside `piquachu-upload-*`. Startup recovery
  only fails *stale* rows (no killing another process's live job), duplicate submissions
  are ignored, Celery uses `acks_late` + worker-lost rejection with a configurable
  visibility timeout.
- **Uploads**: per-file and compression-ratio budgets, duplicate/case-fold/NUL/control/
  drive/ADS rejection, encrypted entries refused, nested archives never expanded, stale
  upload dirs cleaned at startup, temp dirs always removed.
- **AI egress** is now built only by `build_llm_payload`/`build_assistant_payload`
  (allowlisted normalized metadata + scores), with the data marked untrusted, no tools/
  function calling, bounded model output and redacted provider errors.
- `backend/tenants.py` is a deprecated shim over `authz.py` (no second auth model).
  `cbom` tool version is `2.4.0`.

#### Fixed
- Upload temp directories leaked when a baseline/`fail_on` validation failed after the
  archive was saved.
- A second API process could mark another process's live `PENDING`/`ANALYSING` job as
  `FAILED` at startup (now age-based).
- Key-material and hardcoded-secret findings copied the secret line into `snippet`/
  `line_text` (and into neighbouring findings' context); sensitive files now export
  metadata only, and secret-like assignments are redacted in snippets.
- Provider exception text could reach remediation plans and assistant answers (now type +
  HTTP status only).
- `migrations.py rollback` printed a raw `FileNotFoundError` traceback when no pre-upgrade
  snapshot existed (the documented rollback runbook hits this path); it now prints
  `ERROR: …` and exits `2`, leaving the database untouched.
- Scanning a target **outside** the rules directory reported every finding twice: semgrep
  namespaced `check_id` with the config path (`home.user.repo.backend.<rule>`) while the
  native AST engine used the canonical id, so dedupe saw two rules and gates
  double-counted. Rule ids are now canonicalized at parse time (dot-suffix resolution;
  unknown ids pass through unchanged). In-repo scans and benchmark metrics are unchanged.

#### Limits (stated, not hidden)
- SQLite remains single-host; network-filesystem/multi-host storage is out of scope.
- Audit is application-level, not an immutable compliance ledger.
- No SSO/IdP, per-object ACLs, HA, or enterprise-wide runtime/PKI inventory.
- Runtime evidence is a point-in-time sample of one process, not a host inventory.

---

## [Unreleased] — Phase 3 — 2026-10-20

Phase 3 is implemented and verified locally but **awaits user sign-off**; nothing is
released, committed or pushed on the strength of this entry alone. Provider CI runs
(GitHub Actions, GitLab) are still PENDING USER CONFIRMATION.

### Phase 3 — safe remediation, baseline/delta, SARIF and CI workflow

#### Added
- **`backend/baseline.py`** — versioned baseline (`schema_version: 1`) with strict import
  validation (no source, no secrets, no host paths; wildcard/prefix suppressions and
  over-long waivers rejected), `new` / `persistent` / `moved` / `changed` / `suppressed` /
  `resolved` classification, disclosed uncertainty for rename/move and ruleset drift,
  suppression expiry that re-surfaces findings, and `--update-baseline` that always shows
  what changes and never overwrites silently or inside CI.
- **`backend/sarif.py`** — SARIF 2.1.0 output validated against the bundled official
  OASIS schema: tool/rule descriptors with help URIs, run properties (ruleset/engine/
  model versions, baseline counts, gate), stable `pquFingerprint/v1` partial
  fingerprints, percent-encoded repository-relative paths (Unicode/space/Windows safe),
  parser failures as notifications, and no snippets/secrets/host paths by default.
- **Gate policy** (`--fail-on new-error|new-high|new-warning|changed-error|any-high|none`,
  `--gate-inconclusive`, `--no-baseline`) with exit codes `0` pass / `1` gate / `2`
  usage-or-baseline error — a missing or corrupt baseline fails safe instead of
  reporting “no new issues”.
- **Guarded patcher** (`backend/patcher.py`): dry-run by default; applicability classes
  `safe-mechanical` / `conditional-candidate` / `manual-only`; atomic writes with
  backups and a rollback manifest; content-hash conflict detection; all-or-nothing
  batches; idempotence; refusals for traversal, symlinks, non-regular files, unsupported
  types, non-UTF-8 and parse errors; `--pr` must preview, scope-check and be confirmed.
- **CI integrations**: `.github/workflows/piquachu-scan.yml` (least privilege, SHA-pinned
  actions, no secrets in PR code, SARIF artifact + optional code-scanning upload) and
  `.gitlab-ci.yml` (MR job, pinned image, SARIF/JSON artifacts, no false native-report
  claim).
- **API/UI**: optional `baseline` + `fail_on` fields on `POST /api/v1/sast-scan`,
  `GET /api/v1/scans/{id}/sarif`, `scan_history.baseline_json` migration, and a dashboard
  baseline-gate panel (status, counts, failing findings, SARIF download).
- **`backend/test_phase3.py`** — 225 checks covering the Phase 3 test matrix.

#### Changed
- MD5/SHA-1→SHA-256, `random`→`secrets` and digest swaps are **no longer applied
  automatically**; ECB/DES and PQC migrations are `manual-only`. `cipher_cli.py patch`
  reports candidates with preconditions and explains why nothing was written in dry-run.
- `scan --json/--output` keeps every scanner key (`diagnostics`,
  `engine_disagreements`) and adds `baseline_delta` / `gate` / `sarif` when requested;
  `report_counts.py` now includes `test_phase3.py`.

---

## [Unreleased] — Phase 2 — 2026-10-19

Phase 2 is implemented and verified but **awaits user sign-off**; nothing is released or
committed on the strength of this entry alone. Engine/evidence version is `2.3.0`
(`evidence-v2`); the release number is intentionally left open.

### Phase 2 — bounded data flow, shared evidence model, external validation

#### Added
- **`backend/evidence.py`** — one evidence model (`evidence-v2`) shared by every engine:
  stable `pqc1-…` fingerprints (rule + root-relative file identity + call signature +
  scope, so line shifts do not create new findings and same-named files never collide),
  documented confidence tiers, `evidence_type`, rationale/limitations, provenance,
  cross-engine deduplication, and explicit `engine_disagreements` when different rules
  match the same line.
- **`backend/dataflow_python.py`** — bounded intraprocedural constant propagation
  (alias imports, assignment chains, concatenation/formatting, agreeing if/else joins,
  depth-1 wrappers, env/config values tracked as unresolved) into Python crypto sinks.
- **`backend/dataflow_java.py`** — bounded `javalang` pass (static fields, local chains,
  concatenation, wrappers, method parameters as unresolved) into JCA `getInstance` sinks
  and cipher-transformation classification; parser availability and failures are reported.
- **`backend/metrics.py`** — ruleset/corpus sha256 fingerprints, metric source
  (`hermetic` / `external-ground-truth` / `not-run`), `age_seconds` + `stale`, and
  separate release gates.
- **External validation** — `benchmark/external_ground_truth.py` (pinned OWASP Juice
  Shop v17.1.1 and paramiko 3.5.1 with manually reviewed per-call-site labels and a
  written rubric) and `benchmark/external_eval.py`; committed report in
  `docs/engineering/data/phase-2-external-validation.json`.
- **13 new corpus cases** (`50…62`): data-flow positives, false-positive bait, parser
  failure isolation, and `UNDERTERMINED` cases reported outside the confusion matrix.
  Cases now assert `expect_rules` / `forbid_rules` / `expect_confidence`.
- **`backend/test_dataflow.py`** — 94 checks over the evidence model, both data-flow
  engines, deduplication, fingerprints, egress and metric provenance.

#### Changed
- `/api/v1/reliability` and `worker.py benchmark` publish metric provenance and true
  freshness; a stale cache is flagged and refreshed instead of looking current.
- `scanner.py` normalizes every engine into the shared model, merges duplicate evidence
  with provenance retained, and exposes parser-failure/unresolved-value diagnostics.
- README documents the new engines, corpus count, external baselines and the metric
  provenance fields.

#### Fixed
- Cross-engine duplicates (same rule from semgrep and a data-flow engine on the same
  line) no longer double-count; findings store root-relative paths instead of bare
  basenames, so directory identity survives normalization.

---

## [2.3.0] — 2026-10-18

### Phase 1 — standards truth, evidence semantics and CycloneDX 1.7

#### Added
- **`backend/standards.py`** — authoritative, data-driven standards registry with
  lifecycle (`final` / `in_development`), official sources, review date, aliases,
  primitives and exact parameter-set NIST levels. Validation fails loudly on alias
  collisions, duplicate IDs, invalid categories and in-development publication claims.
- **Evidence semantics** on every standard: `evidence_status`, `standard_lifecycle`,
  `confidence`, `rationale`, `evidence_coverage`, `source`, `reviewed`. Findings now
  carry `evidence_kind`, lifecycle, confidence, rationale and limitations.
- **`detected_in_development`** status: FN-DSA/FALCON evidence is reported as algorithm
  evidence, never as a finalized FIPS 206 pass.
- **`not_assessed` / `incomplete`** project verdicts; an empty scan is no longer called
  compliant.
- **CycloneDX 1.7 CBOM** with native `cryptographic-asset` components, evidence
  occurrences (relative paths only), genuine CVE advisories only, and validation against
  the bundled official 1.7 JSON schema (`backend/schemas/`, pinned to specification tag
  1.7.2). Committed fixtures live in `backend/cbom_fixtures/`; regenerate with
  `backend/generate_cbom_fixtures.py`.
- **`backend/report_counts.py`** — canonical generator for rule/corpus/fixture counts and
  executed suite checks. Documentation no longer hard-codes these numbers.
- **Phase 1 tests**: `test_standards.py`, `test_cbom.py`, plus CBOM endpoint coverage in
  `test_api.py`; frontend status vocabulary updated.

#### Changed
- README and supporting docs now say **three finalized NIST PQC standards plus FN-DSA
  (in development)** and document scope/limitations, including static-analysis blind
  spots and metadata-only AI egress.
- CBOM policy findings (ECB, weak hash, missing PQC) are no longer serialized as
  vulnerabilities; only genuine advisories with CVE identifiers are.
- Migration guidance is category-aware: ML-KEM for key establishment, ML-DSA/SLH-DSA for
  signatures, SHA-256/SHA-3 for legacy hashes, AES-256-GCM for symmetric crypto.
- Frontend labels and statuses reflect discovery/evidence language, and the pre-existing
  unused-variable build failure in `quantum-flux.tsx` was fixed.

---

## [2.2.0] — 2026-09-27

### Part 1 — QuantumFlux hero integration

#### Added
- **Tailwind CSS v4** (CSS-first — no `tailwind.config.js` needed) via `@tailwindcss/vite` plugin, wired in `vite.config.ts` and imported in `src/index.css`. Coexists with the existing Chakra v2 system: Tailwind is scoped to the `src/components/ui/*` shadcn-convention components; the dashboard keeps its Chakra theme.
- **`@/*` path alias** in `tsconfig.app.json` (`paths`) and `vite.config.ts` (`resolve.alias`) — the shadcn import convention (`@/components/ui/...`).
- **`src/components/ui/quantum-flux.tsx`** — the QuantumFlux component exactly as provided: animated canvas mesh/particle background, pointer repulsion physics, play/pause control, `headline` prop. Two adaptations were *required* for compilation, both behavior-preserving (documented because the brief said "exact code"):
  1. `const { width, height } = dimensionsRef.current` (object destructure) instead of copying the source's invalid `width/height` property access on a ref object — the provided snippet did not type-check.
  2. One missing `ctx.beginPath()` before the arc fill in the node-draw loop (the source relied on `arc()` implicitly beginning a path, which streaks trails in Chrome).
- **`src/components/ui/demo.tsx`** — demo export exactly as provided.
- **Hero integration in `App.tsx`** — `<QuantumFlux headline="PIQUACHU" />` replaces the static gradient-text hero banner. The mesh canvas sits in a rounded, bordered 340–460px responsive container; the tagline + four NIST standard chips overlay at the bottom with `pointerEvents: none` so canvas interaction is unblocked; the component's own header/play-pause layer stays interactive.

#### Why `/src/components/ui` (shadcn convention)
The default shadcn components path is **`/components/ui`** (relative to the project root — here `frontend/src/components/ui` because the app root is `src/`). This exact path matters:
1. **Registry resolution** — `npx shadcn@latest add <component>` copies into `components/ui` and generates imports as `@/components/ui/<name>`. A different path breaks every future registry install without manual rewrite.
2. **Consistent imports** — all shadcn-style components reference each other and `@/lib/utils` via the `@` alias; keeping the convention means zero import surgery when adding components later.
3. **Ecosystem compatibility** — copy-pasted community components (like QuantumFlux) assume the same layout, so they drop in unmodified.

#### Dependencies
- Added: `clsx`, `tailwind-merge` (runtime); `tailwindcss`, `@tailwindcss/vite` (dev). `lucide-react` was already present.

---

### Part 2 — Product/engineering gaps closed

#### 2.1 External validation (E1 roadmap) — IMPLEMENTED
- **New `backend/benchmark/external.py`**: runs the production scanner against a real application (OWASP Juice Shop by default) and emits a report in the **same JSON shape as `worker.py benchmark`** (`corpus_size`, `confusion`, `metrics`, `by_category`, `results`) so external and corpus reports are directly comparable. External runs are observational (no per-case ground truth), so `fp/fn/tn` are `null` with an explanatory note; `tp` = legacy findings detected.
- **Wired into `worker.py`** as `python3 worker.py external --repo <path>` or `--clone` (auto-clones Juice Shop shallow, pinned ref `master`, reuses existing clones). `--output report.json`, `--json`, `--no-scan` (re-print) supported.
- **Smoke-tested**: `worker.py external --repo test_samples` → 41 findings, benchmark-shaped report, 3.4s. The full Juice Shop run + published write-up remains the security team's action item (documented in `09 Validation Protocol.md` §7).

#### 2.2 CVE-derived regression cases — G4 still 1.0
- **Two new permanent corpus cases** in `benchmark/corpus.py` (corpus 47 → **49 cases**):
  - `48_cve_2022_24771_node_forge` — node-forge 0.9.1 (< 1.3.0) in package.json → expected `NO_CODE_USAGE_DEPENDENCY_RISK`
  - `49_cve_2023_49083_cryptography` — cryptography 41.0.7 (< 42.0.2) in requirements.txt → expected `NO_CODE_USAGE_DEPENDENCY_RISK`
- **G4 verified**: 49 cases, Accuracy/Precision/Recall/F1 = **1.0000**, 0 FP, 0 FN.
- **Attempted & rejected**: a "patched version" control case (node-forge 1.3.1 → expected no risk) — it produced a false positive *by design*: `deps.py` flags any declared legacy-capable library as `dependency-legacy-crypto-lib` regardless of version, which is correct (the library stays quantum-vulnerable-capable even when its CVE is patched). Case removed; limitation documented in `corpus.py` and `09 Validation Protocol.md` §6.

#### 2.3 Java patcher expansion — DES/3DES → AES-GCM
- **`patcher.py`**: new `_JAVA_DES_TRANSFORM_RE` matches `Cipher.getInstance("DES…")`, `"DESede/…"`, `"3DES…"` (bare algorithm or full transform) and rewrites to `"AES/GCM/NoPadding"` via the existing AST-guided literal replacement + re-parse guard (javalang).
- **Honest flagging**: the transform swap is mechanical (same Cipher API), but the `change.detail` explicitly warns that **key material MUST be replaced** (DES 56-bit/3DES 112/168-bit keys are incompatible with AES) and a fresh 12-byte GCM nonce is required — the audit trail says exactly what the bot did and did not do.
- **4 new test checks** (`test_java_patcher_des_rewrites`) covering DES/ECB, DESede/CBC, 3DES/CBC, and the bare `"DES"` form, plus the key-replacement flag and re-parse guard. `test_extras.py` now runs **73 checks** (previously 59 — javalang was missing from the venv, so the existing Java tests were silently skipping; `javalang` installed this session and those now run).

#### 2.4 Rust ruleset — ROOT-CAUSED AND FIXED (was: permanent limitation)
- **Investigation**: isolated each of the 4 failing Rust rules (`pqc-mldsa-rust`, `pqc-mlkem-rust`, `pqc-slhdsa-rust`, `pqc-fndsa-rust`) into minimal configs and ran `semgrep --validate` (pinned build 1.172.0) on pattern variants.
- **Root cause**: the `pattern-inside: | use pqcrypto_X::...; ...` form — a `...` **ellipsis inside a Rust `use` path** — is unparseable by semgrep's Rust tree-sitter on this build (`Stdlib.Parsing.Parse_error`). Not a semgrep bug to link upstream: ellipsis-in-use-path is simply not a supported pattern form for Rust.
- **Fix**: rewrote all 4 rules to the equivalent, validating **`use pqcrypto_X::*;` glob form** (verified: `use pqcrypto_dilithium::*;` + bare-call patterns → valid), and added **qualified-call alternatives** (`pqcrypto_dilithium::keypair(...)` etc.) so detection works with or without the glob import.
- **Result**: `semgrep --config rules.yaml --validate` → **0 configuration errors across all 106 rules** (previously 4 skips). The "known limitation" is closed, not documented.

#### 2.5 Multi-tenant auth — SCAFFOLDED (feature-flagged)
- **New `backend/tenants.py`**: minimal per-team API key model.
  - `api_tenants` table: `team_id`, `api_key_hash` (SHA-256, unique), `active` (soft-revoke), `created_at`, `last_used_at` — created **only** when the flag is on.
  - `create_team()` (prints raw key once), `validate_tenant_key()` (+`last_used_at` touch), `revoke_team()`, `list_teams()` (fingerprint view, never key material).
  - CLI: `python3 tenants.py create|revoke|list <team_id>`.
- **`app.py`**: `_authorized()` now tries the env-list first (unchanged), then — only when **`PIQUACHU_MULTI_TENANT=1`** — falls back to tenant-key validation. Flag off (default) ⇒ zero behavior change; flag on but init fails ⇒ logged, disabled, env-list auth continues (can't lock yourself out).
- **Verified by smoke test**: create → accept, wrong-key reject, revoke → reject, env-key path intact with flag off. RBAC/per-team scan isolation explicitly deferred (PRD roadmap).

#### 2.6 Docs updated
- **`PRD.md`**: roadmap table now carries per-item **Status** (external-validation runner ✅ / publication pending; multi-tenant scaffold ✅ / RBAC pending; Java DES/3DES ✅; Rust rules ✅); NFR-1 and metrics table updated to 49 cases / 225 checks / 0 rule-validation errors.
- **`09 Validation Protocol.md`**: G4 gate = 49 cases; G5 gate = 0 errors across 106 rules; known-limitations table records the Rust fix (struck through) and the legacy-lib-always-flagged design limit; §7 rewritten to reflect the implemented external runner.
- **`08 Experiment Plan.md`**: E1 roadmap item replaced by the implemented external-validation section (usage commands, observational-report semantics); corpus/test counts refreshed.

---

### Part 3 — UI/UX polish pass

#### Design system
- **`types.ts`**: added `STATUS_SCHEME` (single source of truth: compliant=cobalt, partial=amber, non_compliant=crimson, not_detected=ink, transitional=violet), `PANEL` recipe, and `panelGlow(scheme)` helper (border-color + soft colored glow on hover) — used across matrix, threat map and future components for one consistent border/radius/glow language.
- Aesthetic: deep near-black panels (`ink.800`/`ink.900`), monospace accents on all data/scores/rule ids, consistent `xl`/`lg` radii, subtle glow on hover — matching the QuantumFlux hero's console look.

#### Components
- **ComplianceMatrix**: status-colored card borders (from `STATUS_STYLE`) + per-status `panelGlow`; smoother staggered entrance (`ease: [0.16,1,0.3,1]`, 0.45s); verdict badge monospace; compliant/legacy counts color-coded cobalt/crimson; `transitional` added to verdict badge map and tooltips.
- **ReadinessGauge**: framer-motion scale/fade entrance; SVG `feGaussianBlur` glow on the filled arc (hero-consistent); score numerals now mono; responsive max-width.
- **ThreatMap**: responsive card widths (`calc(50% - 6px)` with min/max, wraps on mobile instead of fixed 220px); `panelGlow` hover; `Collapse animateOpacity` (smoother than before); category counts colored by state (critical=compliant=amber); lucide icon sizing via props.
- **TimelineChart**: line **draws itself in** (`motion.path pathLength`), dots pop in staggered; the line stroke now uses the crimson→amber→cobalt gradient (was flat white); responsive min-width 280px (was 420px — no more horizontal scroll on phones); mono axis labels.

#### Findings table
- **Sticky header** (`position: sticky` on `Thead`, ink.900 bg, hairline shadow) inside the scroll container.
- **Better badges**: mono font, `xs` size — PASS/FAIL/WARN and FIPS standard tags consistent with the matrix.
- **Inline expandable remediation plans**: rows with a matching plan are clickable (`aria-expanded`), recommendation clamps to 2 lines until expanded; expanding reveals an inline panel (no navigation) with risk-if-skipped badge, dependencies, plan source (groq/local mono badge), the full drop-in code in a scrollable mono `<pre>`, and the justification. Multiple rows can be open at once.

#### Onboarding / empty state
- Replaced the paragraph-first panel with a **guided 3-step flow**: `01 Drop your .zip` (FileArchive icon) → `02 Watch the AST scan` (Radar) → `03 Fix with one click` (ClipboardList) — numbered icon tiles, one line each; the four-standard grid and feature list retained below.

#### Responsive audit (<768px)
- Hero: height scales 340→460px; tagline/chips wrap; canvas untouched.
- Dropzone padding `p={{base:6, md:12}}`; stats grid `base:1 / sm:2 / lg:4` (was 1/4 — cards no longer squeeze 4-across on phones).
- ThreatMap cards wrap; TimelineChart no longer forces 420px min-width; table cells wrap on mobile (`App.css` media rule); onboarding steps stack.
- `prefers-reduced-motion` still honored (hero border animation, gauge needle).

#### Verified
- `npm run build` ✓ (tsc + vite, ~3.2s) · `npm run lint` ✓ 0 problems
- `test_compliance.py` 62/62 · `test_extras.py` 73/73 · `test_api.py` 90/90 · `worker.py benchmark` 49 cases F1 **1.0000** · `semgrep --validate` 0 errors / 106 rules

---

## [2.1.0] and earlier

See `summary.txt` (complete project dossier) and `README.md`.
