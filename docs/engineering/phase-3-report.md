# PiQuaChu — Phase 3 report: safe remediation, baseline gate, SARIF and CI workflow

**Status:** implemented, verified locally, **awaiting user sign-off**
**Date:** 2026-10-20
**Baseline:** Phase 2 report (`docs/engineering/phase-2-report.md`), accepted state
884 checks / 62 corpus cases / hermetic F1 0.9880.
**Scope of this phase:** turn findings into a developer workflow — guarded automated
remediation, a versioned scan baseline with deterministic delta/gate semantics, SARIF
2.1.0, GitHub Actions + GitLab CI integrations, and the API/UI controls needed to drive
them. **No** tenant/RBAC, no runtime discovery, no new detection engine, no release.

---

## 1. The workflow this phase implements

| Step | Command (or UI action) | Guarantee |
|---|---|---|
| 1 | `cipher_cli.py scan <dir\|zip>` | read-only local analysis; never executes the target's code |
| 2 | `--json / --output`, `--sarif piquachu.sarif` | machine-readable report + SARIF (official-schema validated) |
| 3 | `--baseline .piquachu-baseline.json` | compare against the committed baseline (or base branch in CI) |
| 4 | — | `new` / `persistent` / `moved` / `changed` / `suppressed` / `resolved` |
| 5 | `--fail-on new-high` | gate on **new actionable findings**, never on an aggregate score delta |
| 6 | `cipher_cli.py patch <dir>` | dry-run unified diff with preconditions; nothing written |
| 7 | `patch <dir> --include-candidates --apply` | explicit write: atomic, backed up, conflict-checked, rollback manifest |

Reproducibility rule: the CI job runs exactly the command shown here with the same policy,
so a developer can reproduce a CI verdict locally (`scan . --baseline … --fail-on …`).

---

## 2. Command reference (implemented)

```bash
# baseline lifecycle
scan <t> --update-baseline FILE [--force] [--allow-in-ci]   # explicit; prints changes
scan <t> --baseline FILE [--fail-on POLICY] [--gate-inconclusive]
scan <t> --no-baseline   [--fail-on POLICY]                 # explicit baseline-free mode
scan <t> --sarif FILE    [--sarif-include-snippets]         # local opt-in snippets only
scan <t> --json --output report.json                        # full scanner result + delta/gate

# remediation
patch <dir>                                # DRY-RUN (default)
patch <dir> --output patches/              # patch artifacts + patch-manifest.json
patch <dir> --include-candidates --apply   # opt-in write (backups + rollback manifest)
patch --rollback <manifest.json>           # restore (refuses files edited after apply)
patch <dir> --pr --repo o/n --branch b [--yes]  # opt-in PR: preview → scope check → confirm
```

Exit codes (`scan`; the CI contract): `0` pass, `1` gate triggered, `2` usage error or an
unusable baseline (fail safe). A missing/corrupt baseline **never** reports “no new
issues”.

API surface (additive, backward compatible):

* `POST /api/v1/sast-scan` accepts optional `baseline` (JSON file) and `fail_on` fields;
  malformed baselines/policies are rejected with `400` at upload time (never a silent
  clean scan).
* The completed job carries `baseline_delta`, `gate` and `sarif_url` **only** when one
  of those fields was supplied.
* `GET /api/v1/scans/{id}/sarif` → `application/sarif+json`, schema-validated before it
  is served, 401 without a key, 404 for an unknown scan, rate-limited (60/min).
* `scan_history.baseline_json` is added by an idempotent migration; legacy rows still
  produce SARIF (with no fabricated baseline status).

---

## 3. Baseline schema and identity semantics

Document format (`baseline.KIND = "piquachu-baseline"`, `schema_version = 1`):

```json
{
  "kind": "piquachu-baseline",
  "schema_version": 1,
  "generated_at": "2026-10-20T00:00:00+00:00",
  "scanner_version": "...", "engine_version": "...", "model_version": "evidence-v2",
  "ruleset": {"sha256": "<64 hex>", "rule_count": 106, "version": "ruleset-v2"},
  "findings": [{"fingerprint": "pqc1-…", "rule_id": "…", "path": "src/a.py",
                "category": "hashing", "severity": "WARNING",
                "confidence": "medium", "site": "h=…"}],
  "suppressions": [{"kind": "rule-file|fingerprint", "rationale": "…",
                    "expires": "YYYY-MM-DD", "rule_id": "…", "path": "…"}],
  "expired_suppressions": []
}
```

Properties (verified in `backend/test_phase3.py`):

* **No source code, no line numbers, no secrets, no absolute/host paths.** Call-site
  identity is stored as a sha1 *digest* (`site: "h=…"`), never as text.
* **Line shifts never create findings**: the fingerprint is
  `sha1(rule ‖ file identity ‖ call signature ‖ scope)`. Moving a finding 30 lines down
  keeps it `persistent`.
* **Renames/moves are best-effort and declared**: a fingerprint miss falls back to a
  unique `(rule, site)` match → `moved` (`movedFrom` recorded) **and**
  `uncertain.is_uncertain = true` with a stated reason. Two candidate entries → the
  finding is `new` **plus** `uncertain_identity`, never silently resolved.
* **Ruleset drift is disclosed**: a ruleset sha256 mismatch adds an uncertainty reason
  instead of pretending classification is exact.
* **Strict import**: unknown fields, wrong schema version, absolute/drive-letter paths,
  bad fingerprints/severities, wildcard/prefix/directory suppressions, short rationales,
  missing or >365-day expiries are all rejected (`BaselineError` → exit 2 / HTTP 400).
* **Suppression expiry is honest**: an expired waiver moves to `expired_suppressions`
  (inactive, reported on the delta) so the finding *re-surfaces* instead of either
  staying waived forever or breaking the whole pipeline.
* **`--update-baseline` is never implicit**: it prints added/removed/changed entries and
  suppressions, refuses to overwrite without `--force`, and refuses outright when
  `CI`/`GITHUB_ACTIONS`/`GITLAB_CI` is set (unless `--allow-in-ci`).

---

## 4. Gate policy

`--fail-on <scope>-<level>`, with aliases (`high`→ERROR, `medium`→WARNING, `low`→INFO):

| Policy | Fails on |
|---|---|
| `new-error` (default with `--baseline`) | new findings at ERROR |
| `new-high` (CI workflows) | same as `new-error`, spelled with the level alias |
| `new-warning` | new WARNING or ERROR |
| `changed-error` | already-baselined findings whose severity/category/standard changed |
| `any-high` / `any-error` | any present finding at/above the level (including persisting ones) |
| `none` | never fails (report only) |

* Baselines subtract: a `new-*` gate cannot fail on a baselined finding, but a
  severity/category/standard change is reported as `changed` and fails a `changed-*`
  gate.
* **Draft/low-confidence findings annotate, they do not gate** by default
  (`confidence_tier == "inconclusive"` or informational); `--gate-inconclusive` opts in.
* Scope and level are validated before the scan runs (invalid policy → exit 2 / 400).

---

## 5. Patcher: applicability matrix

Default is **dry-run**; only `safe-mechanical` edits are ever applied automatically, and
`--apply` is required to write anything.

| Rewrite | Class | Applied by default? | Preconditions / why |
|---|---|---|---|
| `random.randbytes(n)` → `secrets.token_bytes(n)` (secret-named target, non-test) | `safe-mechanical` | only with `--apply` | same type/length; test paths are skipped |
| `random.choice/randint/…` → `secrets.token_bytes(32)` (secret-named target) | `conditional-candidate` | no | length/type may change; must be key material |
| `hashlib.md5/sha1/md4` → `sha256`, `hashlib.new("md5")` → `"sha256"` | `conditional-candidate` | no (`--include-candidates`) | digest may be persisted/exchanged or part of a protocol |
| AES/DES/DES3 ECB → GCM | `manual-only` | **never** | needs nonce generation/uniqueness, tag storage+verification, decrypt compatibility, ciphertext migration |
| Java `Cipher.getInstance("DES/…")` → AES/GCM | `manual-only` | **never** | same, plus provider/interop context |
| Java `MessageDigest` MD5/SHA-1 → SHA-256, `withRSA` digest swap | `conditional-candidate` | no | improving the digest is **not** PQC migration; RSA/DSA keys remain quantum-vulnerable |
| `java.util.Random` → `SecureRandom` | `conditional-candidate` (only when the tree shows cryptographic use) | no | deterministic/non-security uses must not change |
| ML-KEM / ML-DSA / SLH-DSA adoption | `manual-only` | **never** | requires library/API/protocol choice (no proven adapter) |

Every record carries: `applicability`, `reason`, `rule_ids`, `old_sha256`/`new_sha256`,
`validation {command, ok}`, `confidence`, `follow_up` steps, and the unified `diff`.

Safety model (all covered by tests):

* Refuses: path traversal, `..`, targets resolving outside the root (including symlink
  swaps between analysis and write), symlinks, non-regular files (FIFOs), unsupported
  extensions, non-UTF-8 files.
* Parse failures are **refused**, never regex-patched, and the file is left
  byte-identical.
* Writes are atomic (same-directory temp file, `fsync`, `os.replace`, mode preserved),
  with an original backup plus `manifest.json` (`local_artifact: true`).
* Conflict detection: a content-hash (and full-content) comparison aborts before any
  byte is written if the file changed since the diff was generated.
* Batches are all-or-nothing (validation phase before any write; mid-batch failure
  restores what was written).
* Idempotent: a second run over an applied tree produces no further diff.
* Rollback refuses to clobber files edited after apply.
* `--pr` prints a preview (title/body/files/hashes) with **zero network I/O**, requires
  `--repo`, `--branch` and explicit confirmation (`--yes` or interactive), validates the
  token's write scopes before the first mutation, and refuses without confirmation.
  A refused/skipped record can never be written even if a caller re-populates its diff.

---

## 6. SARIF 2.1.0

* Validated against the **official OASIS schema** bundled at
  `backend/schemas/sarif-schema-2.1.0.json` with `jsonschema` Draft4 (4.25.1). The CLI
  refuses to write an artifact that fails validation; the API returns `500` rather than
  an invalid document.
* Tool identity (`PiQuaChu` + version), rule descriptors with `helpUri`
  (`…/backend/rules.yaml`), rule properties (`nistStandard`, `category`, `pqcCompliant`,
  precision), and run properties (scanner, `engineVersion`, `modelVersion`,
  `generatedAt`, `ruleset`, baseline counts/uncertainty, gate policy + failure count).
* Severity mapping: `ERROR→error`, `WARNING→warning`, `INFO→note`; unknown severities
  fall back to `warning` and say so (`mappedLevel`/`unknownSeverity`).
* Stable partial fingerprints (`pquFingerprint/v1` = Phase 2 fingerprint) so line
  shifts and re-runs de-duplicate.
* Locations: repository-relative, percent-encoded URIs (`src/üñî code#1.py` →
  `src/%C3%BC%C3%B1%C3%AE%20code%231.py`), Windows separators normalized, drive letters
  stripped, `uriBaseId: SRCROOT` with a relative `originalUriBaseIds` — no absolute host
  path can appear.
* No snippets by default (`--sarif-include-snippets` is a local opt-in that reads only
  inside the scan root; CI never passes it). Parser failures become
  `toolExecutionNotifications`, never fake results.
* Edge cases covered by tests: no findings, missing location (`properties.unlocated`),
  multi-line regions, cross-engine duplicates, unknown rule (`properties.unknownRule`),
  Unicode/space/Windows paths, absolute host path input, baseline status/suppression
  metadata.

---

## 7. CI integrations

### GitHub Actions — `.github/workflows/piquachu-scan.yml`

* `pull_request` + `push` to `main`; workflow-level `permissions: {}` (nothing by
  default), the scan job declares only `contents: read`.
* All third-party actions pinned to immutable commit SHAs (`checkout`,
  `setup-python`, `upload-artifact`, `download-artifact`, `codeql-action/upload-sarif`),
  release tag kept in a comment.
* Local CLI mode only — **no secrets** (`X-API-Key`, Groq, tokens) are passed to the
  job, so fork PRs run safely and PR code never sees a credential.
* Baseline resolution order: `git show origin/<base>:.piquachu-baseline.json`
  (`fetch-depth: 0`), then the checkout's own baseline (push builds), then an
  **explicit `--no-baseline`** (all findings count as new) — never a silent “clean”.
* Gate: `--fail-on new-high`; a `2` (baseline/usage error) fails the job immediately;
  a `1` (gate) is recorded, SARIF is uploaded as an artifact first, then enforced.
* Code-scanning upload is a **separate** job (`security-events: write` only there), runs
  only for same-repo PRs/pushes, and is `continue-on-error` so feature ineligibility
  never blocks the gate.

### GitLab CI — `.gitlab-ci.yml`

* Merge-request (+ default-branch push) job, pinned `python:3.12.7` image, no
  services, no privileged container, `GIT_DEPTH: "0"` so
  `CI_MERGE_REQUEST_DIFF_BASE_SHA` is available.
* Baseline from the MR diff base, then the checkout, then explicit `--no-baseline`.
* Same `--fail-on new-high` semantics; artifacts: `piquachu.sarif`,
  `gl-sast-report.json`, `piquachu-report.json`, `piquachu-scan.log` (14 days,
  `when: always`).
* **Native GitLab SAST report**: `gl-sast-report.json` is produced by
  `backend/gitlab_sast.py` and declared under `artifacts:reports:sast`. It is validated
  against the pinned official schema (`backend/schemas/gitlab-sast-report-format-v15.2.5.json`)
  before writing and refuses (exit 2) rather than emitting an invalid artifact. Only
  actionable ERROR/WARNING findings become vulnerabilities; PASS evidence,
  informational and inconclusive findings stay in the JSON/SARIF artifacts and the
  excluded count is reported in `scan.messages`. Schema correctness is local; the
  Security-tab render depends on the instance licence tier (PENDING provider run).

---

## 8. API and UI

Dashboard additions (Chakra patterns, keyboard reachable, no decorative state):

* Optional **baseline attach** (`baseline.json`) + gate policy select next to the
  dropzone; sent as `baseline`/`fail_on` form fields. Without a baseline the UI behaves
  exactly as before (additive contract).
* A **baseline gate panel** after a scan: `PASSED` / `BLOCKED` / `DELTA ONLY`, the
  policy, counts (`new`, `persistent`, `changed`, `resolved`, `suppressed`), the failing
  findings (capped at 8 with a pointer to SARIF), and an explicit
  “comparison is best-effort” alert when identity could not be proven.
* **Download SARIF** for the current scan (authenticated fetch → blob download).

The UI stays intentionally simpler than the CLI: patch preview/apply and PR creation
remain CLI-only, where the diff, preconditions and confirmation live.

---

## 9. Test evidence (executed 2026-10-20)

```bash
cd backend && python report_counts.py
# test_compliance.py      passed exit=0 checks=68
# test_standards.py       passed exit=0 checks=157
# test_cbom.py            passed exit=0 checks=175
# test_extras.py          passed exit=0 checks=86
# test_dataflow.py        passed exit=0 checks=98
# test_api.py             passed exit=0 checks=141
# test_phase3.py          passed exit=0 checks=252   (was 225; +27 = GitLab SAST exporter)
# test_docs.py            passed exit=0 checks=161
```

| Check | Result |
|---|---|
| `python test_phase3.py` (new) | **252 checks**, exit 0 — incl. the GitLab SAST exporter suite (schema-valid export, deterministic ids, severity mapping, exclusion accounting, negative schema cases, CLI end-to-end with the artifact preserved on gate failure) |
| `python test_api.py` | 141 checks, exit 0 (incl. 40 new baseline/SARIF/migration/rate-limit checks) |
| `python worker.py benchmark` | 62 cases — TP 41, FP 0, FN 1 (minified JS RSA, known), TN 17; accuracy 0.9831, P 1.0000, R 0.9762, F1 0.9880; gates `hermetic_fixtures/pass`, `hermetic_expectations/pass`, `false_positive_floor/pass`, `external_baseline/not-run` |
| `semgrep --config rules.yaml --validate` | `0 configuration error(s), 106 rule(s)` |
| SARIF schema validation | official OASIS 2.1.0 schema, `jsonschema` 4.25.1 Draft4 — 0 errors across all fixtures/edge cases |
| Frontend `npm run build` | exit 0 (`tsc -b` + `vite build`, 2801 modules) |
| Frontend `npm run lint` | exit 0 (eslint, no warnings) |
| CI YAML parsing | both files parse (PyYAML or `ruamel.yaml` 0.19.1); structure asserted (permissions, SHA pins, artifacts, gate flag) |

`test_phase3.py` covers the Phase 3 matrix explicitly: baseline build/validate/privacy,
missing + corrupt baseline, line-shift stability, rename/move best-effort, ambiguity,
new/persistent/moved/changed/suppressed/resolved classification, suppression expiry,
policy scope/level parsing and outcomes (including annotations vs `--gate-inconclusive`),
silent-overwrite and CI-write refusals, SARIF schema + all listed edge cases, dry-run
default, candidate opt-in, atomic apply + backup + rollback, post-apply edit refusal,
conflict/all-or-nothing, multi-root refusal, traversal/symlink/FIFO/unsupported-type/
parse-error refusals, PR confirmation and preview (no network), CLI exit codes
(`0/1/2`), CLI patch apply + rollback, and CI file structure.

CLI patches were exercised against throwaway directories only. **No branch, commit, PR,
release or remote change was created** in this phase.

---

## 10. Limitations and PENDING items

* **GitHub/GitLab provider runs were not executed here** — YAML syntax/structure and the
  local equivalent commands are verified, which is *not* proof the workflows run in
  provider CI. See the UAT table.
* Code-scanning upload, fork-PR behavior, protected variables and artifact retention are
  documented assumptions, not measured results.
* GitLab native `gl-sast` reporting is implemented and locally schema-validated
  (§7); a hosted GitLab pipeline run and Security-tab render are still PENDING.
* Rename/move identity is best-effort by design; where it is ambiguous the delta says
  `is_uncertain` instead of claiming a clean result.
* Patch semantics are reviewed, not proven: `conditional-candidate` rewrites depend on
  the stated preconditions, and ECB/DES/PQC migrations stay `manual-only` on purpose.
* The UI controls were type-checked, built and linted; they were **not** exercised in a
  browser here (no browser in this environment). Baseline/gate/SARIF behavior is covered
  through the HTTP API tests instead.
* Token scope verification for `--pr` reads classic-PAT scopes; fine-grained tokens are
  reported as `fine-grained-unverified` because GitHub does not expose their permission
  set through that endpoint.

---

## 11. User UAT checklist (PENDING USER CONFIRMATION)

| # | Action | Expected | Status |
|---|---|---|---|
| 1 | `cd backend && python test_phase3.py` | 252 checks pass, exit 0 | PENDING |
| 2 | `cd backend && python report_counts.py` | 8 suites pass, checks total 1111 | PENDING |
| 3 | `cd backend && python cipher_cli.py scan . --update-baseline .piquachu-baseline.json` then scan with `--baseline … --fail-on new-high` | exit 0; delta shows 0 new / N persistent | PENDING |
| 4 | Add a new RSA/ECDSA call and re-run the same command | exit 1; gate names the new finding | PENDING |
| 5 | `cd backend && python cipher_cli.py patch <dir>` then `--include-candidates --apply` then `--rollback <manifest>` | dry-run writes nothing; apply creates backups + manifest; rollback restores bytes | PENDING |
| 6 | Open a PR adding one legacy-crypto file on a repo with the workflow installed | scan job red with `::error::…gate FAILED…`; SARIF artifact present | PENDING |
| 7 | Same repo, PR with no new findings | scan job green; SARIF artifact present; code-scanning step optional/`continue-on-error` | PENDING |
| 8 | Repo without a committed baseline | workflow logs `explicit --no-baseline`; every actionable finding counts as new | PENDING |
| 9 | GitLab MR pipeline on a fork/shallow clone | job green/red per policy, artifacts published, no protected variables required | PENDING |
| 10 | Dashboard: attach `baseline.json`, pick `new-high`, scan | gate panel shows PASSED/BLOCKED + counts; SARIF download works | PENDING |
| 11 | `cd frontend && npm run build && npm run lint` | both exit 0 | PENDING |

**Stop condition:** Phase 3 ends here. Phase 4 has not been started and will not start
without explicit sign-off.
