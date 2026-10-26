# Phase 1 — Standards truth, evidence semantics and CycloneDX 1.7

**Status:** implementation complete; **USER ACCEPTANCE PENDING**
**Date:** 2026-10-18
**Scope:** Phase 1 only. No detection expansion (Phase 2), CI/SARIF gating (Phase 3),
tenant/RBAC or runtime discovery (Phase 4).

---

## 1. Baseline and repository reality

The checkout was **not clean** at start. `git status --short` showed 18 modified tracked
files and a large set of untracked backend/frontend/docs files (the working tree contained
substantially more code than the last commit). All pre-existing modifications and
untracked work were preserved; no reset, clean, DB reset or mass rewrite was performed.

### Baseline commands (before Phase 1 changes)

| Command | Baseline result | Notes |
|---|---|---|
| `git branch --show-current` | `main` | Last commit `f892c50` |
| `./venv/bin/python test_compliance.py` | exit 0, **62 checks** | Passed |
| `./venv/bin/python test_extras.py` | exit 0, **59 checks** | Java patcher tests silently skipped: `javalang` absent |
| `./venv/bin/python test_api.py` | exit 1, **90 checks**, 3 failures | Failures: "legacy findings flagged", "engine uses semgrep", "semgrep binary located" — all caused by missing `semgrep` in the venv |
| `worker.py benchmark` (no semgrep) | exit 0, F1 **0.7547** | AST-only fallback; many cross-language FNs |
| `npm run build` | **exit 2** | Pre-existing TS6133 unused `Activity` / `headline` in `quantum-flux.tsx` |
| `npm run lint` | **exit 1** | Same two unused-variable errors |

### Environment gap and resolution

The venv listed in `backend/` lacked runtime/test dependencies already pinned in
`backend/requirements.txt`. The pinned versions were installed locally (no upgrades
beyond those pins): `semgrep==1.154.0`, `javalang==0.13.0`, `jsonschema==4.25.1`
(with `referencing`). This was an environment repair, not a code change.

After installing the pinned dependencies, the **pre-change** baseline became:

| Command | Result after pinned deps |
|---|---|
| `test_compliance.py` | exit 0, 62 checks |
| `test_extras.py` | exit 0, 73 checks (Java tests now run) |
| `test_api.py` | exit 0, 90 checks |
| `worker.py benchmark` | exit 0, 49 cases, F1 **0.9846** (1 FN: `34_minified_js_rsa`) |
| `npm run build` / `npm run lint` | still failed (2 unused vars) |

No Phase 1 regression was present in that baseline; the two documented pre-existing
failures were the frontend unused variables and the semgrep-missing environment.

---

## 2. What changed

### 2.1 Authoritative standards registry — `backend/standards.py` (new)

Single source of truth for:

- canonical ID, algorithm, former name, role, primitive, category;
- lifecycle (`final` / `in_development`), publication date, official source URL,
  review date;
- aliases, migration note, exact parameter-set → NIST quantum security level;
- category-aware migration guidance (`MIGRATION_GUIDANCE`).

Lifecycle decisions encoded at review time:

| Standard | Lifecycle | Evidence |
|---|---|---|
| FIPS 203 / ML-KEM | `final`, published 2024-08-13 | `https://csrc.nist.gov/pubs/fips/203/final` |
| FIPS 204 / ML-DSA | `final`, published 2024-08-13 | `https://csrc.nist.gov/pubs/fips/204/final` |
| FIPS 205 / SLH-DSA | `final`, published 2024-08-13 | `https://csrc.nist.gov/pubs/fips/205/final` |
| FIPS 206 / FN-DSA | `in_development`, no publication date | NIST PQC project page (FALCON selected, FIPS coming soon) |

`validate_registry()` runs on import and fails on duplicate IDs, alias collisions,
invalid primitive/category, non-https provenance, non-ISO review dates, in-development
publication claims, and missing NIST level maps.

### 2.2 Corrected evidence semantics — `backend/compliance.py`

- `STANDARDS` is now derived from the registry (no duplicated lifecycle claims).
- Per-standard public `status` remains backward compatible:
  `compliant | partial | non_compliant | not_detected | transitional`, plus the new
  `detected_in_development` for FIPS 206.
- Additive fields per standard: `evidence_status`, `standard_lifecycle`,
  `lifecycle_label`, `confidence`, `evidence_coverage`, `rationale`, `source`, `reviewed`,
  `primitive`, `category`.
- Findings add `standard_lifecycle`, `evidence_kind`, `confidence`, `rationale`,
  `limitations`; existing fields are unchanged.
- Project verdicts: `non_compliant | at_risk | transitional | incomplete | compliant |
  not_assessed`.
  - **Empty scan → `not_assessed`**, not `compliant`.
  - `compliant` requires positive evidence for **every finalized** standard and no
    legacy evidence.
  - Legacy-only or unknown legacy evidence is `at_risk`, never a pass.
  - A PQC-capable dependency alone is `incomplete` (evidence, not a standard pass).
- `pqc_score` / `risk_score` formulas are unchanged but now carry
  `assessment.score_formula_version` (`readiness-v1`),
  `assessment.risk_formula_version` (`risk-v1`) and
  `assessment.semantics_version` (`evidence-v1`), plus a registry review date and a
  limitations string.
- Telemetry is still path/source-free and now includes `standard_lifecycle`.

### 2.3 CycloneDX 1.7 CBOM — `backend/cbom.py` (rewritten)

- `specVersion` is `1.7`; `bomFormat` `CycloneDX`; UUID `serialNumber`; `version: 1`.
- `metadata.tools` uses the 1.6+ tools object; `metadata.component` is the project.
- Assets are `components[].type = "cryptographic-asset"` with:
  - `assetType: algorithm` + `algorithmProperties.primitive` / `algorithmFamily`
    (only when the official 1.7 enum accepts the family) / `parameterSetIdentifier` /
    `nistQuantumSecurityLevel` (only when an exact parameter set was observed) /
    `mode` / `padding`;
  - `assetType: related-crypto-material` for key material (no key bytes);
  - `assetType: protocol` for TLS/SSH configuration evidence.
- Evidence occurrences use normalized **relative** paths and line numbers; absolute host
  paths are stripped.
- Findings are aggregated by asset variant; duplicate occurrences collapse to one
  component with multiple occurrences.
- `vulnerabilities[]` contains **only** genuine advisories with real CVE identifiers
  (currently dependency matches). ECB misuse, weak hashes, missing PQC usage and other
  policy findings are intentionally **not** serialized as vulnerabilities. Their count is
  recorded in `metadata.properties["piquachu:policy_findings_not_in_vulnerabilities"]`.
- `validate_cbom()` validates against the bundled official schema using
  `jsonschema` + `referencing`; it raises `CbomValidationUnavailable` (reported as
  BLOCKED by tests) rather than pretending validation succeeded.

### 2.4 Official schema pin — `backend/schemas/`

Bundled from CycloneDX specification tag **1.7.2**, commit
`349314a9d7671d7d2ca5b711a725f49a73979da6`:

- `bom-1.7.schema.json`
- `cryptography-defs.schema.json`
- `spdx.schema.json`
- `jsf-0.82.schema.json`

Source: `https://github.com/CycloneDX/specification/tree/1.7.2/schema`.

### 2.5 Migration guidance is category-aware

- Key establishment → ML-KEM.
- Signatures → ML-DSA / SLH-DSA; FN-DSA explicitly marked provisional/in development.
- MD5/SHA-1 → SHA-256/SHA-3, described as legacy integrity remediation, **not** PQC
  signature migration.
- AES/AES-128 → AES-256-GCM; AES is symmetric and not declared "non-PQC" merely for not
  being a PQC scheme.
- RNG, KDF, TLS, secrets, dependencies each retain separate reasoning.
- Groq prompt no longer calls FN-DSA a finalized/approved replacement.

### 2.6 Frontend

- `types.ts`: new statuses/evidence fields; `detected_in_development` style; updated
  labels ("PQC EVIDENCE", "NOT OBSERVED").
- `ComplianceMatrix.tsx`: "NIST PQC Discovery Matrix"; FIPS 206 shows
  "standard in development"; tooltips state that `not_detected` is not a pass.
- `ReportModal.tsx`: discovery/readiness wording; empty findings explicitly say it is not
  an assessment of security/compliance.
- `App.tsx`: removed "four NIST-finalized" copy; FIPS 206 chip says in development;
  `not_assessed` gets a neutral alert instead of "no issues".
- `TimelineChart.tsx`: "Readiness Evolution".
- `quantum-flux.tsx`: removed two unused locals that broke the pre-existing build.

### 2.7 Documentation

- `README.md` rewritten around discovery/evidence, lifecycle table, exact status
  semantics, scope/limitations, metadata-only AI egress, CycloneDX 1.7 and generated
  counts (`report_counts.py`).
- `CHANGELOG.md`: new 2.3.0 entry.
- `summary.txt`: prominent Phase 1 correction notice; stale standards/CBOM/count claims
  corrected.
- `need-to-know/02, 03, 04, 09, 10` and `graphviz.svg`: lifecycle, CBOM version, corpus
  and rule-count wording reconciled.
- `backend/test_samples/fndsa_sign.py` and `backend/benchmark/corpus.py` comments no
  longer claim FIPS 206 was published/finalized.
- `backend/rules.yaml` header documents that FIPS 206 positives are algorithm evidence.

### 2.8 Counts are generated, not hard-coded

`backend/report_counts.py` is the canonical generator:

```bash
cd backend
python report_counts.py
python report_counts.py --json
python report_counts.py --markdown
```

It reads the registry/rules/corpus/fixtures and **executes** the script-style suites,
parsing their actual "ALL N CHECKS PASSED" totals. It reports `failed` for any suite with
a non-zero exit or missing total.

---

## 3. Status semantics and compatibility impact

| Public status | Meaning |
|---|---|
| `compliant` | PQC evidence for a finalized standard, no legacy evidence of that category |
| `partial` | PQC + legacy evidence in the same category |
| `non_compliant` | Legacy evidence only |
| `not_detected` | No qualifying evidence observed — unknown, **not a pass** |
| `transitional` | Hybrid classical+PQC evidence |
| `detected_in_development` | Algorithm evidence for an in-development standard (FIPS 206) |

`evidence_status` uses: `detected | legacy_detected | mixed | not_detected |
unsupported_or_inconclusive`.

### Migration notes for API clients

- Existing keys (`status`, `pqc_score`, `verdict`, `standards`, `advisory`, findings) are
  retained. New fields are additive.
- **Behavioural change:** an empty/no-crypto scan now returns `verdict: not_assessed`
  (previously `compliant`). `not_detected` is no longer treated as a pass.
- **New status:** `detected_in_development` for FIPS 206. Clients that whitelist statuses
  must accept it.
- **New project verdicts:** `not_assessed`, `incomplete`.
- **CBOM breaking change:** `specVersion` 1.5 → 1.7; component `type` `cryptography` →
  `cryptographic-asset`; `vulnerabilities` now contains genuine CVEs only. No 1.5/1.6
  compatibility serializer was kept because no existing consumer was identified in the
  repository. Consumers must migrate to 1.7.
- **Telemetry** adds `standard_lifecycle`; still contains no paths/source.

---

## 4. Schema validation evidence

Validator: `jsonschema==4.25.1` (Draft 7) with `referencing` local resource registry.
Schema: bundled `backend/schemas/bom-1.7.schema.json` (official 1.7.2 tag).

Validated artifacts:

1. 10 committed fixture BOMs in `backend/cbom_fixtures/` (legacy only, PQC KEM, PQC
   signature, FN-DSA in development, mixed, duplicate evidence, dependency CVE, key
   material, no crypto, malformed/unknown input).
2. `GET /api/v1/scans/{id}/cbom` response in `test_api.py`.
3. CLI artifact: `cipher_cli.py cbom test_samples --output /tmp/cbom_cli.json`
   (CycloneDX 1.7, 13 components; schema OK).

Reproduce:

```bash
cd backend
venv/bin/python generate_cbom_fixtures.py
venv/bin/python test_cbom.py
venv/bin/python -c "import json, cbom; cbom.validate_cbom(json.load(open('/tmp/cbom_cli.json')))"
```

---

## 5. Recomputed counts (2026-10-18)

Generated by `venv/bin/python report_counts.py`:

| Metric | Value |
|---|---|
| Standards registry reviewed | 2026-10-18 |
| Rules loaded | 106 (FIPS 203: 27, FIPS 204: 16, FIPS 205: 9, FIPS 206: 6, advisory/other: 48) |
| Labeled corpus cases | 49 |
| Committed CBOM fixtures | 10 |
| `test_compliance.py` | passed, 68 checks |
| `test_standards.py` | passed, 157 checks |
| `test_cbom.py` | passed, 175 checks |
| `test_extras.py` | passed, 73 checks |
| `test_api.py` | passed, 98 checks |
| `test_docs.py` | passed, 161 checks |
| **Checks executed (all suites)** | **732** |

Distinctions: these are **assertion/check executions**, not pytest-collected test
functions, and not labeled corpus cases. The corpus has 49 labeled cases; the CBOM
fixtures are 10 serialized artifacts.

---

## 6. Test results

All commands run from `backend/` with `PATH="$PWD/venv/bin:$PATH"`.

| Command | Exit | Result |
|---|---|---|
| `venv/bin/python test_compliance.py` | 0 | ALL 68 CHECKS PASSED |
| `venv/bin/python test_standards.py` | 0 | ALL 157 CHECKS PASSED |
| `venv/bin/python test_cbom.py` | 0 | ALL 175 CHECKS PASSED (schema validation ran, not BLOCKED) |
| `venv/bin/python test_extras.py` | 0 | ALL 73 CHECKS PASSED (javalang present; no skips) |
| `venv/bin/python test_api.py` | 0 | ALL 98 CHECKS PASSED (incl. CBOM endpoint schema check) |
| `venv/bin/python test_docs.py` | 0 | ALL 161 CHECKS PASSED |
| `venv/bin/python report_counts.py` | 0 | 732 checks, all suites passed |
| `venv/bin/python cipher_cli.py selfcheck` | 0 | registry valid, 106 rules, FIPS 206 `in_development` note |
| `venv/bin/python cipher_cli.py cbom test_samples --output /tmp/cbom_cli.json` | 0 | CycloneDX 1.7, 13 assets, 0 CVEs; schema OK |
| `venv/bin/semgrep --config rules.yaml --validate` | 0 | Ruleset validates |
| `venv/bin/python worker.py benchmark` | 0 | 49 cases, TP=32 FP=0 FN=1 TN=16, precision 1.0000, recall 0.9697, F1 0.9846 |
| `cd frontend && npm run build` | 0 | TypeScript + Vite build clean |
| `cd frontend && npm run lint` | 0 | ESLint clean |

### Skipped / blocked / limitations

- No test reported BLOCKED in the final run: `jsonschema` was available and official
  schema validation executed.
- Java patcher tests are not skipped in the final run (`javalang` installed).
- The benchmark logs two `ERROR:root:Semgrep execution failed` lines for the expected
  empty/malformed corpus cases; the scanner falls back and the metrics above are the
  measured result. This is pre-existing logging noise, not a hidden pass.
- One benchmark FN remains: `34_minified_js_rsa` (minified JavaScript RSA). It is
  recorded, not label-edited.
- Manual UAT items below remain **PENDING USER CONFIRMATION**.

---

## 7. Open issues, risks and assumptions

1. **CBOM asset inference is conservative.** Assets are derived from structured rule-id
   tokens. Findings whose rule id has no recognizable primitive are intentionally omitted
   from the CBOM and remain in PiQuaChu's native report. A future improvement is
   structured `crypto_asset` metadata in `rules.yaml`.
2. **CycloneDX 1.7 family enum limitations.** `FN-DSA` and generic `RSA` are not accepted
   values for `algorithmProperties.algorithmFamily` in the official 1.7 enum; those
   components omit `algorithmFamily` and carry the name/primitive instead.
3. **Native findings still contain absolute paths on API scans.** CBOM sanitizes paths,
   but `findings[].file` in the native API remains as scanned. That is outside Phase 1's
   CBOM scope and should be normalized in Phase 3.
4. **FIPS 206 status must be re-reviewed.** The registry is data-driven; when NIST
   publishes FIPS 206, update `standards.py` (lifecycle, publication date, source, review
   date) and re-run the registry/doc tests. Do not hard-code a finalization date.
5. **No 1.5/1.6 CBOM compatibility mode.** No existing consumer was found in the repo;
   adding an untested duplicate serializer was rejected. If an external consumer appears,
   add an explicitly named compatibility format.
6. **`pqc_score` remains a heuristic.** It is documented as readiness, versioned, and not
   a NIST score. `not_assessed` prevents an empty scan from being presented as compliant,
   but the score itself still starts at 100; consumers must read `assessment.status` and
   the standard statuses.
7. **Benchmark is regression evidence, not external validation.** The 49-case corpus is
   synthetic/hermetic. External precision/recall requires a pinned, manually labelled
   repository (Phase 2).
8. **Semgrep/version sensitivity.** Detection results depend on the installed semgrep
   build. Results in this report were measured with semgrep 1.154.0.
9. **Docs beyond the repo.** `need-to-know/graphviz.svg` text was corrected in place; the
   diagram was not regenerated from source. No third-party repositories were modified or
   executed.
10. **pytest entrypoint is pre-existing/misconfigured.** `backend/pytest.ini` sets
    `testpaths = tests`, but no `backend/tests/` directory exists. The repository's
    intended entrypoint is the script-style `python test_*.py` suites used above; this
    was not changed in Phase 1 to avoid collecting vendor/third-party tests.

---

## 8. Manual UAT checklist — PENDING USER CONFIRMATION

Do not mark these passed until the user has run/confirmed them.

| # | Check | Expected result | Status |
|---|---|---|---|
| 1 | Run `cd backend && venv/bin/python report_counts.py` | All suites pass; 732 checks; 106 rules; 49 corpus cases; 10 fixtures | PENDING USER CONFIRMATION |
| 2 | Open `backend/cbom_fixtures/04_fndsa_in_development.json` | `specVersion: "1.7"`; FN-DSA component; `piquachu:standard_lifecycle: "in_development"`; no "finalized" claim | PENDING USER CONFIRMATION |
| 3 | Run `cipher_cli.py cbom test_samples --output /tmp/cbom.json` and validate | CycloneDX 1.7; schema validation succeeds; no absolute host paths; no source/key text | PENDING USER CONFIRMATION |
| 4 | Start API, scan a zip, GET `/api/v1/scans/{id}/cbom` | `200`; `specVersion: "1.7"`; cryptographic-asset components; policy findings not in `vulnerabilities` | PENDING USER CONFIRMATION |
| 5 | Run `cipher_cli.py selfcheck` | Registry valid; FIPS 206 printed as `in_development` with the evidence caveat | PENDING USER CONFIRMATION |
| 6 | Start frontend and scan `backend/test_samples` zip | Matrix shows FIPS 203/204/205 and FIPS 206 as "STANDARD IN DEVELOPMENT"; labels use discovery/evidence language | PENDING USER CONFIRMATION |
| 7 | Scan a no-crypto directory | Project verdict `not_assessed`; neutral "No matching cryptographic evidence observed" alert; no "compliant" claim | PENDING USER CONFIRMATION |
| 8 | Read README "Scope and limitations" and standards table | Three finalized standards + FN-DSA in development; no "four finalized" or "May 2025"; AI egress fields described | PENDING USER CONFIRMATION |
| 9 | Review a legacy-only CBOM | No CVE entries for ECB/MD5/RSA policy findings; only dependency advisories carry CVE IDs | PENDING USER CONFIRMATION |
| 10 | Run `cd frontend && npm run build && npm run lint` | Both exit 0 | PENDING USER CONFIRMATION |

---

## 9. Phase 1 acceptance gate

Phase 1 is complete when the user confirms:

1. The standards/lifecycle wording (three finalized NIST standards + FN-DSA in
   development) matches their intent.
2. The exported CycloneDX 1.7 fixture/inspection artifacts look correct.
3. The corrected status semantics (`detected_in_development`, `not_assessed`,
   `incomplete`; `not_detected` not a pass) are acceptable for existing consumers.
4. The recomputed counts and test evidence in this report match their run.
5. The known limitations/open issues are acceptable for entering Phase 2.

**Implementation stopped here. Phase 2 (detection expansion and external validation) was
not started.**
