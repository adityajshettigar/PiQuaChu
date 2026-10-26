# 09 · Validation Protocol

**Project:** PiQuaChu 🛡️
**Purpose:** The formal, repeatable procedure for validating that PiQuaChu's verdicts
are correct, its scores meaningful, and its release auditable.

---

## 1. Validation philosophy

1. **Labeled ground truth over vibes** — every reliability claim traces to the 49-case
   corpus with explicit expected labels.
2. **Both error directions matter** — a missed RSA (FN) is as bad as a false RSA alarm (FP);
   both are tracked and gated.
3. **Semantic, not textual, evidence** — corpus cases include obfuscation, wrappers,
   variable indirection, unreachable code and haystacks specifically to fail regex scanners.
4. **Honest limits are part of validation** — documented engine limitations are asserted,
   regression-guarded and never hidden (see §6).
5. **Zero-trust is testable** — the telemetry payload shape is an assertion, not a promise.

## 2. Validation gates

| Gate | Command | Pass criterion | Frequency |
|---|---|---|---|
| G1 Unit: compliance engine | `python3 test_compliance.py` | 62/62 checks | every change |
| G2 Unit: extras (rules, deps, keyfiles, patchers) | `python3 test_extras.py` | 59/59 checks | every change |
| G3 Integration: API | `python3 test_api.py` | 90/90 checks | every change |
| G4 Reliability benchmark | `python3 worker.py benchmark` | 49 cases; Acc/P/R/F1 = 1.0000; 0 FP, 0 FN | every change |
| G5 Ruleset schema | `semgrep --config rules.yaml --validate` | 0 configuration errors across every rule (count via `report_counts.py`) | ruleset changes |
| G6 Frontend build | `npm run build && npm run lint` | clean build + lint | frontend changes |
| G7 Engine selfcheck | `python3 cipher_cli.py selfcheck` | rules loaded; 3 finalized standards + FIPS 206 lifecycle tracked | release |
| G8 Celery parity | broker + worker round-trip (§5) | identical polling contract | job-queue changes |

A release is valid **only when G1–G8 are green in the same session**.

## 3. Reliability validation (G4) — detailed procedure

1. **Materialize:** for each of the 47 corpus specs, `build_case_dir()` writes the
   synthetic project into a fresh temp dir (hermetic, deterministic, offline).
2. **Scan:** `scanner.scan_directory(case_dir)` with the production engine chain
   (semgrep AST → Python ast → aux → deps → keyfiles). No test-only shortcuts.
3. **Predict:** risk present ⇔ (∃ non-PQC finding) ∨ verdict ∈ {non_compliant, at_risk,
   transitional}.
4. **Compare:** against `expected_risk(label)` → TP / FP / FN / TN.
5. **Compute:** Accuracy=(TP+TN)/N, Precision=TP/(TP+FP), Recall=TP/(TP+FN), F1.
6. **Report:** human table or `--json`; optional `--output metrics.json` for CI.

**Confusion-matrix acceptance:** any single FP or FN fails the gate — precision and
recall are both release-critical for a compliance product (false alarms destroy trust;
missed quantum-vulnerable crypto destroys security).

**Positive-detection control (closing a known blind spot):** COMPLIANT cases cannot
detect broken *positive* rules (no PQC usage expected → nothing to match). Therefore
dedicated tests assert literal positive matches:
`test_fips206_positive_detection`, `test_fips206_detection_all_standards`
(FN-DSA via liboqs Python, Bouncy Castle Java, liboqs C, PQClean, pqcrypto).

## 4. Security & privacy validation

| Control | Validation |
|---|---|
| Zero-trust telemetry | Test asserts the exact anonymized payload shape (algorithm/standard/severity/verdict only) — no paths, no source. |
| Upload hardening | 50 MB cap, 250 MB decompressed budget, 5000-entry cap, zip-slip + absolute-path + symlink rejection — all asserted in `test_api.py`. |
| Auth | Missing/invalid key → 401; env-key list (`PIQUACHU_API_KEYS`) honored. |
| CORS | Allow-list limited to dashboard origins (5173–5176 or env override). |
| Headers | nosniff, frame DENY, no-referrer, permissions-policy, no-store on all responses. |
| Rate limits | Per-IP limits asserted (incl. the endpoint that replaced the removed WAF route). |
| Job persistence | Explicit column selection regression test (guards the historic jobs-table 500). |
| Orphan recovery | Restart during ANALYSING → job marked FAILED on startup. |

## 5. Scaling-mode parity validation (G8)

1. Start Redis; export `PIQUACHU_BROKER_URL=redis://localhost:6379/0`.
2. `celery -A tasks worker --loglevel=info`; run `python app.py` with the same env.
3. Submit a scan; assert: job visible in `jobs` table → consumed by worker → status
   transitions PENDING→ANALYSING→SUCCESS → polled payload identical to thread mode
   (findings, matrix, plans, logs).
4. Kill worker mid-job → restart → orphan recovery marks it FAILED (no infinite poll).

## 6. Known-limit regression assertions

These limits are *documented and asserted*, not ignored:

| Limit | Current status | Guard |
|---|---|---|
| Semgrep metavariable rules match literal algorithm strings only | Accepted | Python variable-indirection covered by AST fallback; corpus cases 01–03 use indirection (documented); positive-literal tests exist |
| ~~4 Rust rules fail pattern validation~~ | **Fixed 2026-09** | Root cause: `use pqcrypto_X::...;` ellipsis form unparseable by semgrep's Rust tree-sitter; rewritten to `use pqcrypto_X::*;` glob + qualified-call forms. G5 now requires **0 errors across every loaded rule** |
| COMPLIANT corpus cases can't catch broken positive rules | Mitigated | Dedicated positive-detection tests (§3) |
| Legacy crypto libs are flagged regardless of CVE-patch status (node-forge, cryptography) | Accepted (by design) | A patched-version control case is therefore impossible for CVEs in legacy-capable libs — the CVE-specific finding fires only in-range, but the generic legacy advisory always fires. Documented in corpus.py |

## 7. External validation (E1 roadmap — ✅ implemented, run pending)

`benchmark/external.py` (wired as `worker.py external`) runs the production scanner
against a real application and emits a benchmark-shaped JSON report:

- **Implemented & smoke-tested:** `worker.py external --repo <path>` and
  `worker.py external --clone` (auto-clones OWASP Juice Shop, pinned ref for
  reproducibility); report keys mirror `worker.py benchmark` output with
  `fp/fn/tn = null` + explanatory note (observational run, no per-case ground truth).
- **Remaining (security-team action item):** execute the full Juice Shop run on a
  clean machine and publish the report alongside the corpus metrics.
- CVE-derived regression cases (node-forge CVE-2022-24771, cryptography
  CVE-2023-49083) are **permanent corpus cases** (cases 48–49) and gate on G4.
- Invite a security team to red-team the zero-trust claim (strace the CLI, audit egress).

## 8. Audit-trail requirements (product-level validation)

Every scan must be able to answer, from persisted data alone:
1. Which engine(s) ran (`engine` string), which rules fired (finding ids), file+line evidence.
2. The full 4-standard matrix + both scores at scan time.
3. Every remediation plan and its source (`local-rule-engine` vs `groq`).
4. A CBOM artifact (CycloneDX 1.7, schema-validated) exportable for auditors.

## 9. Release checklist

- [ ] G1–G8 green (same session, same commit)
- [ ] `summary.txt` health-check section updated
- [ ] README rule counts / test counts match reality
- [ ] No `CipherSentinel` strings (brand regression check)
- [ ] `piquachu.db` migrations idempotent on a fresh clone
- [ ] Known-limits section reviewed for new entries
