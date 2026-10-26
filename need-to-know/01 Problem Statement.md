# 01 · Problem Statement

**Project:** PiQuaChu 🛡️ — NIST Post-Quantum Cryptography Compliance Engine
**Version:** 2.1.0 · **Status:** Verified (all tests green)
**Last updated:** 2026-09

---

## 1. The one-liner

Upload any source archive and get standards-mapped **discovery evidence** for the three
finalized NIST PQC standards — FIPS 203 (ML-KEM), 204 (ML-DSA) and 205 (SLH-DSA) — plus
lifecycle-aware FN-DSA/FALCON evidence while FIPS 206 remains **in development**, with
optional metadata-only AI migration plans, reviewable AST remediation patches (Python
**and** Java), a CycloneDX 1.7 Cryptographic Bill of Materials, and a SOC-grade dashboard.

---

## 2. The problem

### 2.1 The quantum deadline

A cryptographically-relevant quantum computer running **Shor's algorithm** breaks every
public-key scheme deployed at scale today: RSA, ECDSA, ECDH, DSA, EdDSA, Diffie–Hellman.
Unlike classical bugs, this threat has a *negative lead time*:

> **"Harvest now, decrypt later"** — adversaries record encrypted traffic today and
> decrypt it the day a quantum computer exists. Data with a long secrecy lifetime
> (health records, state secrets, IP, financial archives) is *already compromised in
> expectation*, years before the machine is built.

### 2.2 The regulatory response

NIST finalized the migration targets as formal standards:

| Standard | Algorithm | Former name | Role | Finalized |
|---|---|---|---|---|
| **FIPS 203** | ML-KEM | CRYSTALS-Kyber | Key Encapsulation — general encryption | Aug 2024 |
| **FIPS 204** | ML-DSA | CRYSTALS-Dilithium | Digital Signatures — primary | Aug 2024 |
| **FIPS 205** | SLH-DSA | SPHINCS+ | Digital Signatures — hash-based backup | Aug 2024 |
| **FIPS 206** | FN-DSA | FALCON | Digital Signatures — lattice (NTRU), hash-and-sign | May 2025 |

CISA, NSA and NIST have since published migration timelines. Enterprises are now
**required to know where their quantum-vulnerable cryptography lives** — and most do not.

### 2.3 Why existing tooling fails

| Existing approach | Why it is not enough |
|---|---|
| Generic SAST / CVE scanners | Report *CVE dumps*, not NIST-standard-native verdicts. "You use RSA" is not actionable; "migrate this RSA use to ML-KEM per FIPS 203" is. |
| Regex grep for crypto keywords | Cryptography is semantics, not text. Variable indirection (`alg = "ML-KEM-768"; oqs.Signature(alg)`), wrappers, obfuscation and unreachable code defeat text matching and produce both false positives and false negatives. |
| Manual audit spreadsheets | Do not scale, are stale the day they are finished, and cannot produce a re-runnable audit trail. |
| Network-flow analyzers (e.g. pqc-flow) | See only runtime traffic; miss code-level and config-level surface, and cannot scan a repo you have not deployed. |

### 2.4 The gap PiQuaChu fills

Organizations need a **deterministic, semantic, zero-trust engine** that answers four
questions for every codebase:

1. **Where** is cryptography used — down to file and line?
2. **Which** of the four NIST PQC standards does each usage satisfy or violate?
3. **How bad** is it — a weighted, category-aware risk score, not a flat count?
4. **What do I change it to** — a drop-in replacement plan, and where safe, the patch itself?

---

## 3. Solution statement

PiQuaChu is a full-stack compliance engine:

- **Semantic detection** — semgrep AST rules (106 rules, 9 languages) + a zero-dependency
  Python `ast` fallback, plus dependency/lockfile scanning and key-material detection.
- **Four-standard verdict matrix** — `compliant / partial / non_compliant / not_detected`
  per standard, plus `pqc_score` (readiness), weighted `risk_score`/`risk_level`, and a
  project `verdict`.
- **Migration plans** — deterministic local rule engine with optional Groq LLM enrichment
  (metadata only, never source).
- **AST remediation patches** — mechanical rewrites (md5→sha256, ECB→GCM,
  `random`→`secrets`, `java.util.Random`→`SecureRandom`) as unified diffs, in-place
  apply, or GitHub PR.
- **Zero-trust privacy** — the CLI never uploads source; only anonymized algorithm
  telemetry leaves the machine.

---

## 4. Users

| User | Job-to-be-done |
|---|---|
| **Security engineer / CISO** | Prove PQC readiness to auditors; get a per-standard verdict + CBOM + PDF/JSON report. |
| **Developer** | Know exactly which line to fix and what to replace it with (finding → plan → patch). |
| **Compliance officer** | Track scores across scans on a timeline; export audit-ready artifacts. |
| **Platform/SRE** | Detect PQC (or lack of it) in transport configs (`sshd_config`, `nginx.conf`). |

---

## 5. Success criteria

1. Reliability benchmark: **49-case labeled corpus** with measured metrics reported
   honestly (2026-10-18 baseline: precision 1.0000, recall 0.9697, F1 0.9846, one known
   FN). Corpus scores are regression evidence, not external validation.
2. Every legacy finding maps to a category-appropriate migration target (or an explicit
   manual-review note where no safe mechanical mapping exists).
3. Zero source code egress in the zero-trust path (`telemetry` payload is the contract).
4. Full verdict produced for a typical repo zip in seconds, offline, with no LLM cost
   (LLM is strictly optional enrichment).

---

## 6. Out of scope (explicit)

- A WAF / payload inspection (was reviewed and **dropped** — PiQuaChu is 100% PQC).
- Runtime/network traffic analysis (static config evidence only).
- Automated migration of non-mechanical rewrites (DES→AES, RSA→ML-KEM) — those are
  emitted as human-review "manual" changes, never silently applied.
- Multi-tenant RBAC (roadmap; current production path is `PIQUACHU_API_KEYS` env list).

---

## 7. Honest known limits

- Semgrep metavariable rules match **literal** algorithm strings; variable indirection is
  caught by the Python AST fallback for Python but not for all languages.
- The 4 Rust semgrep rules fail pattern validation in the pinned semgrep build and are
  skipped with a parse error; Rust positive detection relies on INFO rules when they parse.
- COMPLIANT corpus cases cannot catch broken *positive* rules by construction — closed by
  dedicated positive-detection tests (`test_fips206_positive_detection`, etc.).
