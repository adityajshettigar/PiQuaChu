# 07 · Model Architecture

**Project:** PiQuaChu 🛡️
**Purpose:** How the "intelligence" of PiQuaChu is structured — the detection model, the
scoring model, and the LLM-augmented generation layer.

> PiQuaChu ships **no trained ML weights**. Its model is a *deterministic, interpretable
> semantic-analysis pipeline*: AST rule matching → finding enrichment → decision-matrix
> scoring. The only neural components are optional LLM calls (Groq) that never see source.

---

## 1. Layered model overview

```
┌────────────────────────────────────────────────────────────────┐
│ L1  INGEST      safe_extract_zip (zip-slip/bomb/entry guards)  │
├────────────────────────────────────────────────────────────────┤
│ L2  DETECTION   5 engines, merged & deduplicated into findings │
│      E1 semgrep (AST, 106 rules, 9 languages)                  │
│      E2 Python ast walker (semantic fallback)                  │
│      E3 aux scan (odd extensions + transport configs)          │
│      E4 deps.py (manifests + lockfiles + CVE matching)         │
│      E5 keyfiles.py (PEM/OpenSSH/PKCS#12/PuTTY OIDs)           │
├────────────────────────────────────────────────────────────────┤
│ L3 ENRICHMENT   NIST metadata attach + snippet extraction      │
├────────────────────────────────────────────────────────────────┤
│ L4 DECISION     compliance.py: 4-standard matrix, verdicts,    │
│                 pqc_score, weighted risk_score/risk_level      │
├────────────────────────────────────────────────────────────────┤
│ L5 GENERATION   remediation.py (rule engine + optional Groq),  │
│                 patcher.py (AST rewrites → diffs), cbom.py     │
└────────────────────────────────────────────────────────────────┘
```

## 2. L2 — Detection engines (the core "model")

### E1 · Semgrep AST engine
- Patterns in `rules.yaml` match **syntax trees**, not text — immune to whitespace,
  comments and formatting.
- Each rule carries NIST metadata (standard, category, `pqc_compliant`, `target_algorithm`).
- Self-healing launcher: verifies the semgrep binary with `--version`, repairs broken venv
  console-script shebangs via an in-process `pysemgrep` launcher (mkstemp + chmod 700).

### E2 · Python AST fallback (zero-dependency)
Built-in `ast` module over `.py/.pyx/.pyi`. Adds *semantic* detection that patterns
cannot express:
- import-alias resolution (`from cryptography...as rsa` still resolved),
- hardcoded-secret heuristics (variable names key/secret/token/nonce/salt/iv),
- key-length-aware AES-128 flagging,
- textbook/toy RSA (modular exponentiation without library imports),
- `oqs.Signature("Falcon-512")` literal + pqcrypto module usage (FIPS 206 evidence).

### E3 · Auxiliary scanner
- Unusual extensions (`.java.bak`, `.pyx`, …) forced through semgrep with `--lang`.
- **Transport-config evidence**: `sshd_config`/`ssh_config` hybrid KEX
  (`sntrup761x25519-sha512@openssh.com`, `mlkem768x25519-sha256`), TLS hybrid groups
  (`X25519MLKEM768`, `X25519Kyber768Draft00`, `X25519MLKEM1024`) → FIPS 203
  `transitional`; classical-only suites → advisory WARNING.

### E4 · Dependency scanner (`deps.py`)
- Manifests: requirements.txt, package.json, go.mod, Cargo.toml, pom.xml, composer.json, Gemfile.
- Lockfiles (transitive): package-lock.json, Pipfile.lock, poetry.lock, Cargo.lock, go.sum, yarn.lock.
- Classification: legacy lib → WARNING; PQC lib → INFO positive; version match against
  bundled advisories → per-CVE severity; lockfile-only legacy → transitive WARNING.

### E5 · Key-material scanner (`keyfiles.py`)
- PEM/.key/.cer/.crt/.pub/.ppk + containers .p12/.pfx; `authorized_keys`/`known_hosts`.
- Algorithm via PEM headers and DER OID sniffing: RSA `1.2.840.113549.1.1.1`,
  EC `1.2.840.10045.2.1`, Ed25519 `1.3.101.112`, Ed448 `1.3.101.113`.

**Merge policy:** all engine findings are concatenated, enriched, and sorted; the
reported engine string (e.g. `semgrep+ast+aux`) records which engines fired for auditability.

## 3. L4 — Decision model (compliance.py)

### 3.1 Rule-metadata binding
`load_rule_metadata()` parses rules.yaml (ruamel → PyYAML → minimal manual parser
fallback chain) so every finding inherits its rule's NIST metadata.

### 3.2 Per-standard status state machine

For each of FIPS 203/204/205/206, over the findings mapped to it:

```
compliant uses = 0 AND legacy uses = 0        → not_detected
legacy = 0 AND compliant > 0                  → compliant
compliant > 0 AND legacy > 0                  → partial
legacy > 0 AND compliant = 0                  → non_compliant
hybrid evidence (X25519MLKEM768, sntrup761…)  → transitional (FIPS 203)
```

Project verdict = worst of standard statuses (ordering: `non_compliant > at_risk >
transitional > compliant > not_detected`).

### 3.3 Scoring formulas

**pqc_score (readiness):**
```
score = clamp(100
              − 20 × ERROR_legacy
              − 10 × WARNING_legacy
              +  5 × compliant_usages, 0, 100)
```

**risk_score (weighted danger):**
```
risk = clamp(round( Σ_legacy  weight(category) × factor(severity)  × 100/5 ), 0, 100)

weight: key-encapsulation 1.0 · signatures 1.0 · symmetric 0.8 · secrets 0.7
        randomness 0.7 · hashing 0.6 · kdf 0.5 · tls 0.5 · dependencies 0.4
        hybrid 0.1 · unknown 0.3
factor: ERROR 1.0 · WARNING 0.5 · INFO 0.0
```
Rationale: one max-weight critical finding contributes 20 points → 5 Shor-broken uses
saturate at 100. RSA (1.0) hurts more than SHA-1 (0.6); a dependency hint (0.4) less.
Bands: ≥80 critical · ≥50 high · ≥20 medium · else low.

## 4. L5 — Generation models

### 4.1 Remediation plan generator (remediation.py)
- **Local rule engine (default, deterministic):** a template per `(standard, language)`
  — Python/Java/Go/JS/C/Rust × FIPS 203/204/205/206 — each a complete runnable snippet
  (imports + function), plus dependency changes and skip-risk rating.
- **Groq enrichment (optional, when `GROQ_API_KEY`):** prompt receives **anonymized
  metadata only** (algorithm, severity, standard, language — never source); model default
  `llama-3.3-70b-versatile`; response validated, with the local plan as fallback.
- Assistant chat (`assistant_answer`) grounds answers in the latest scan's matrix +
  findings + a NIST knowledge base, same privacy rule.

### 4.2 AST patcher (patcher.py) — "the model that edits code"
- **Python (`ast` NodeTransformer):** `hashlib.md5/sha1→sha256`, `hashlib.new("md5")→
  "sha256"`, `AES.MODE_ECB→MODE_GCM`, `random.*→secrets.token_bytes(32)` (+`import secrets`).
- **Java (`javalang`, optional):** `MessageDigest.getInstance("MD5"/"SHA-1")→"SHA-256"`,
  `Cipher.getInstance("AES/ECB/…")→"AES/GCM/NoPadding"`,
  `Signature.getInstance("MD5withRSA"…)→"SHA256withRSA"`,
  `new Random(…)→new java.security.SecureRandom(…)`.
- Guardrails: only `.py`/`.java`; rewritten file must re-parse (ast.unparse round-trip /
  javalang re-parse); unsafe migrations (DES→AES, RSA→ML-KEM, static salts) recorded as
  `manual` review items, never auto-applied; unified diffs, in-place apply, or GitHub PR.

### 4.3 CBOM generator (cbom.py)
Compliance matrix + findings → CycloneDX 1.7 `cryptographic-asset` components with
evidence occurrences; `vulnerabilities` is reserved for genuine CVE advisories (see
04 · Data Dictionary §6).

## 5. Why this architecture (design rationale)

| Choice | Reason |
|---|---|
| Deterministic rules over ML classifier | Auditability: every verdict is explainable to its rule + line; no training data drift; offline; zero inference cost. |
| Two engines (semgrep + Python ast) | Graceful degradation: full coverage without external deps; semgrep when available for 9 languages. |
| Category-weighted dual scores | Readiness (pqc_score) and danger (risk_score) answer different audit questions and must not collapse into one number. |
| LLM strictly optional, metadata-only | Keeps zero-trust guarantee; deterministic path works air-gapped. |
| Patch-generation with re-parse guard | Mechanical-only rewrites, honest `manual` ledger → no silent semantic breakage. |

## 6. Model boundaries & limitations

- No statistical learning → recall bounded by rule corpus; measured on the 49-case
  benchmark (2026-10-18: F1 0.9846, one known FN) and extensible by adding rules/cases,
  not retraining.
- Variable-indirection detection only in Python fallback (documented limit).
- Rust semgrep rules skip on the pinned build (positive INFO rules still fire when parsed).
