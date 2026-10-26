# Product Requirements Document (PRD)

**Product:** PiQuaChu 🛡️ — NIST Post-Quantum Cryptography Compliance Engine
**Version:** 2.1.0 · **Status:** Shipped (v1 scope complete; v1.1 roadmap below)
**Owner:** Aditya · **Last updated:** 2026-09

---

## 1. Vision

Every engineering organization will have to migrate its cryptography to the NIST
post-quantum standards. PiQuaChu is the fastest way to answer **"how quantum-vulnerable
is this codebase, standard by standard, and what exactly do I change?"** — with audit-grade
evidence, in seconds, without ever uploading source code to a third party.

> North star: *From zip upload to a defensible four-standard compliance verdict, with a
> migration plan for every finding, in under a minute, fully offline.*

## 2. Problem & opportunity

- Shor's algorithm breaks RSA/ECDSA/ECDH/DSA; "harvest now, decrypt later" makes the
  deadline *now* for long-lived secrets.
- FIPS 203/204/205 finalized Aug 2024; **FIPS 206 (FN-DSA/FALCON) May 2025**. Regulators
  (CISA/NSA) publish migration mandates; audit frameworks are following.
- Existing SAST tools report CVE noise, not NIST-native verdicts; regex tooling is
  semantically blind; manual audits don't scale or re-run.
- Opportunity: a deterministic, semantic, zero-trust compliance engine whose verdicts an
  auditor can trace to a rule and a line number.

## 3. Target users & personas

| Persona | Need | Success signal |
|---|---|---|
| **Security engineer (Priya)** | Per-standard verdict + evidence for audit | Exports CBOM + report; defends verdict line-by-line |
| **Developer (Marcus)** | Know what to change, exactly | Copies a drop-in replacement plan; applies a patch |
| **Compliance officer (Elena)** | Score trend across releases | Timeline chart shows pqc_score improving per scan |
| **Platform/SRE (Sam)** | Infra crypto posture pre-deploy | sshd_config/nginx.conf hybrid KEX detected statically |

## 4. Scope

### 4.1 In scope (v1 — shipped)
1. **Zip/directory ingestion** with hardening (50 MB / 250 MB decompressed / 5000 entries / zip-slip).
2. **Semantic discovery** against the authoritative standards registry (FIPS 203/204/205
   finalized; FIPS 206/FN-DSA in development): semgrep AST (rule count from
   `report_counts.py`, Python/Java/JS/TS/Go/C/C++/Rust/PHP) + Python-ast fallback
   engine + aux/config scanner + dependency & lockfile scanner + key-material scanner.
3. **Discovery matrix** per standard (`compliant/partial/non_compliant/not_detected`,
   + `transitional` for hybrids, + `detected_in_development` for FIPS 206) with
   `evidence_status`/lifecycle/confidence, project verdict, `pqc_score` readiness,
   weighted `risk_score`/`risk_level`.
4. **Remediation plans** for every legacy finding — deterministic local engine;
   optional Groq enrichment on anonymized metadata only.
5. **AST remediation patches** (Python + Java): md5/sha1→sha256, ECB→GCM,
   random→secrets, java.util.Random→SecureRandom, weak sig→SHA256withRSA; diffs,
   in-place apply, GitHub PR.
6. **CBOM** export (CycloneDX 1.7 `cryptographic-asset` components + genuine CVE advisories).
7. **Dashboard**: matrix cards, readiness gauge, threat map, timeline, live terminal logs,
   sortable/filterable findings, onboarding empty state, JSON/PDF report, AI assistant.
8. **Zero-trust CLI**: `scan / telemetry / remediate / patch / cbom / selfcheck / benchmark`.
9. **Dual execution**: in-process threads (default) or Celery+Redis workers.
10. **Reliability benchmark**: 49-case labeled regression corpus, Accuracy/Precision/Recall/F1.

### 4.2 Out of scope
- WAF/payload inspection (reviewed and **dropped** — focus is 100% PQC).
- Runtime network traffic analysis (static transport-config evidence only).
- Automated non-mechanical migrations (DES→AES, RSA→ML-KEM) — flagged `manual`, never auto-applied.
- Multi-tenant RBAC (roadmap; env API-key list is the production path).
- Training/ML-based vulnerability prediction.

## 5. Functional requirements

| ID | Requirement | Priority | Status |
|---|---|---|---|
| FR-1 | Accept zip/dir; harden extraction (slip/bomb/entry/symlink) | P0 | ✅ |
| FR-2 | AST-based detection with per-rule NIST metadata, 4 standards | P0 | ✅ |
| FR-3 | Python semantic fallback engine (aliases, secrets, AES-128, toy RSA, FALCON literals) | P0 | ✅ |
| FR-4 | Transport-config evidence: hybrid SSH KEX + TLS groups; classical-only suites warned | P1 | ✅ |
| FR-5 | Dependency + lockfile scan with bundled CVE version matching | P1 | ✅ |
| FR-6 | Key-material detection: PEM/OpenSSH/PuTTY/PKCS#12 w/ OID classification | P1 | ✅ |
| FR-7 | Registry-mapped matrix + evidence semantics + pqc_score + weighted risk_score/level | P0 | ✅ |
| FR-8 | Async jobs: 202+task_id, pollable status, live streamed logs, restart-safe persistence | P0 | ✅ |
| FR-9 | Remediation plan per finding: replacement code, deps, justification, skip-risk, source | P0 | ✅ |
| FR-10 | Optional LLM enrichment with anonymized-metadata-only contract | P2 | ✅ |
| FR-11 | AST patcher (py+java) w/ re-parse guard; diff/apply/PR flows | P1 | ✅ |
| FR-12 | CBOM (CycloneDX 1.7, schema-validated) per scan | P1 | ✅ |
| FR-13 | DevSecOps assistant grounded in latest scan + NIST knowledge | P2 | ✅ |
| FR-14 | Scan history timeline + reliability metrics endpoint | P2 | ✅ |
| FR-15 | CLI parity with API pipelines; telemetry subcommand prints exact permitted payload | P0 | ✅ |

## 6. Non-functional requirements

| ID | Requirement | Target | Status |
|---|---|---|---|
| NFR-1 | Reliability | F1 = 1.0, 0 FP, 0 FN on 49-case corpus (incl. CVE-derived regression cases) | ✅ verified |
| NFR-2 | Privacy | No source egress in zero-trust path; telemetry schema asserted | ✅ |
| NFR-3 | Performance | Typical repo verdict in seconds; LLM-free default path offline | ✅ |
| NFR-4 | Auditability | Every verdict → rule id + file/line + persisted history + CBOM | ✅ |
| NFR-5 | Security of the product itself | API-key auth, CORS allow-list, security headers, rate limits, zip hardening | ✅ |
| NFR-6 | Resilience | WAL SQLite, orphan recovery, corrupt-row-safe JSON parsing, engine fallbacks | ✅ |
| NFR-7 | Deployability | Single-host default; optional Celery/Redis scaling; air-gapped CLI mode | ✅ |
| NFR-8 | Explainability | No ML opacity — deterministic, documented scoring formulas | ✅ |

## 7. User flows

**Flow A — Dashboard scan:** drag zip → 202 → live terminal logs stream → matrix + gauge +
threat map + table → click finding → remediation plan → export report/CBOM.
**Flow B — Zero-trust audit:** `cipher_cli.py telemetry repo/` → copy printed payload →
`POST /api/v1/compliance/check` → verdict + async audit job.
**Flow C — Auto-remediation:** `cipher_cli.py patch repo/ --output patches/` → review
unified diffs → `apply_patches` in place → re-scan shows score improvement (timeline).

## 8. Metrics of success

| Metric | Target | Current |
|---|---|---|
| Benchmark F1 | Report actual; never edit labels | 0.9846 (49 cases, 1 FN, 2026-10-18) |
| False positives on compliant code | 0 | 0 |
| Standards covered | 3 finalized + FIPS 206 lifecycle tracked | 4 tracked; FIPS 206 in development |
| Unit + integration checks green | Run `report_counts.py` | Generated, not hard-coded |
| Ruleset size / validity | All tagged rules validate | Count via `report_counts.py`; 0 validation errors |
| Zero source-egress violations | 0 | 0 ✅ |

## 9. Risks & mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Rule gaps → missed crypto (FN) | Compliance blind spot | Corpus regression gate; positive-detection tests; ecosystem-aligned rule additions |
| False alarms erode trust (FP) | Tool abandonment | 0-FP gate; severity discipline (INFO for positive evidence) |
| Quantum-algorithm landscape shifts | Verdicts stale | Standards encoded as data (`STANDARDS`, rules.yaml metadata) — new standard = new entries |
| LLM hallucinated migration code | Broken remediation | Local deterministic templates primary; LLM optional + validated; source labeled in every plan |
| Product-scope creep (WAF-style) | Loss of focus | Explicit out-of-scope list; WAF removal precedent |

## 10. Roadmap

| Quarter | Item | Status |
|---|---|---|
| Next | **Run + publish** the external validation report (runner implemented: `worker.py external`; the Juice Shop execution + write-up remains) | runner ✅ / publication pending |
| Next | Multi-tenant auth: **Phase 4 shipped** (`authz.py`: tenants, hashed/rotating keys, owner/admin/analyst/developer/viewer RBAC, tenant-scoped scans/jobs/exports, audit events; `tenants.py` is a deprecated shim) | ✅ (Phase 4, awaiting user sign-off) |
| Next | Redis-backed rate limiting for multi-worker deployments | ✅ Phase 4 (real cross-instance test; deployment run pending) |
| ~~Later~~ | ~~Java patcher DES/3DES→AES-GCM~~ → **shipped 2026-09** (`patcher.py` Java path; key-replacement flagged in audit detail). Remaining: full ML-DSA/FN-DSA signature swaps | ✅ (partial) |
| ~~Later~~ | ~~Rust semgrep rule fix~~ → **fixed 2026-09** (`use pqcrypto_X::*;` glob form validates on pinned build; 0 rule errors). Remaining: variable-indirection heuristics beyond Python | ✅ |
| Later | CI plugin: PR comment bot posting pqc_score delta | pending |

## 11. Open questions

1. Should `transitional` hybrids count toward `pqc_score` as +5 compliant uses (current) or a separate +2 tier?
2. Publishing benchmark methodology externally — full corpus open-source vs metrics-only?
3. Assistant grounding: restrict to latest scan (current) or allow selecting any historical scan id?

## 12. Approval & traceability

- Product review decisions tracked in `summary.txt` §9 (verdict-by-verdict resolution).
- Architecture detail: `10 Product Architecture.md` · `sysarch` (Graphviz diagram).
- Data contract detail: `04 Data Dictionary.md`.
