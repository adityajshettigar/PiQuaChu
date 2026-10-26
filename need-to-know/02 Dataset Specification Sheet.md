# 02 · Dataset Specification Sheet

**Project:** PiQuaChu 🛡️ · PQC Compliance Engine
**Purpose:** Specify every dataset/corpus the engine consumes or is graded against.

---

## 1. Dataset overview

PiQuaChu is a *rule-based semantic analyzer*, not a trained model — its "datasets" are
(1) the labeled **benchmark corpus** used to measure reliability, (2) the **ruleset**
that drives detection, (3) the bundled **CVE advisory table**, and (4) the labeled
**test fixtures** used in the test suite.

| # | Dataset | Location | Format | Size |
|---|---------|----------|--------|------|
| D1 | Labeled reliability corpus | `backend/benchmark/corpus.py` | Python dict of synthetic file-trees | **49 labeled cases** (run `report_counts.py`) |
| D2 | Semgrep detection ruleset | `backend/rules.yaml` | semgrep YAML + NIST metadata | count via `report_counts.py` |
| D3 | CVE advisory database | `backend/deps.py` (`ADVISORIES`) | Python dict (offline) | curated (node-forge, cryptography, openssl, …) |
| D4 | Known-vulnerable test fixtures | `backend/test_samples/` | Real source files, 5+ languages | LegacyAuth.java, BadCrypto.java, PQCCompliant.java, pqc_compliant.py, bad_hash.py, fndsa_sign.py … |
| D5 | Vulnerable demo project | `backend/vulnerable_project/` (+ `.zip`) | Sample repo tree | demo corpus for CLI |

---

## 2. D1 — Benchmark corpus (primary evaluation dataset)

### 2.1 Label taxonomy

Each case is a self-contained synthetic project with an `expected` label:

| Label | Meaning | Risk expected? (POSITIVE/NEGATIVE) |
|---|---|---|
| `COMPLIANT` | PQC usage only (ML-KEM / ML-DSA / SLH-DSA / FN-DSA) | ❌ negative |
| `COMPLIANT_SYMMETRIC_ONLY` | Safe symmetric crypto only (AES-256-GCM etc.) | ❌ negative |
| `NO_CRYPTO_DETECTED` | No cryptography at all | ❌ negative |
| `NO_FILES_ERROR_HANDLING` | Empty archive — exercises error path | ❌ negative |
| `NON_COMPLIANT` | Classical/weak crypto (RSA, ECDSA, DES, MD5, SHA-1…) | ✅ positive |
| `NON_COMPLIANT_UNREACHABLE` | Legacy code behind a dead flag (still flagged) | ✅ positive |
| `NON_COMPLIANT_SEMANTIC` | Textbook/toy RSA via modular exponentiation, no imports | ✅ positive |
| `MIXED` | PQC and legacy coexisting | ✅ positive |
| `TRANSITIONAL_COMPLIANT` | Hybrid classical+PQC (X25519MLKEM768, sntrup761x25519) | ✅ positive |
| `NO_CODE_USAGE_DEPENDENCY_RISK` | Manifest-only legacy crypto libraries | ✅ positive |

### 2.2 Coverage categories (47 cases)

PQC-compliant KEM and signatures (incl. **FN-DSA/FALCON** Python + Java Bouncy Castle),
classical asymmetric, deprecated/weak primitives, hybrid/transitional, PEM/OpenSSH/
PKCS#12 key material, dependency-only risk, lockfile (transitive) risk, infra config
(hybrid SSH KEX / TLS groups), obfuscation, wrappers, unreachable code, mixed-verdict
repos, toy RSA (semantic), haystack (one RSA call buried among 70 helper functions),
empty/malformed archives.

### 2.3 Case construction rules

- Cases are **hermetic**: built on the fly into a temp dir by `build_case_dir()` — no
  network, no external fixtures, deterministic.
- Anti-shortcut controls: a "haystack" case buries a single `rsa.generate_private_key`
  in the middle of a large module to prove the engine reads *all* code, not just headers.
- Obfuscation/wrapper cases ensure plain regex scanners would fail (semantic requirement).

### 2.4 Grading protocol (see 09 · Validation Protocol)

`runner.py` maps labels to risk expectation:

```
risk_case   = expected ∈ POSITIVE_EXPECTED
prediction  = (any non-PQC finding) OR (verdict ∈ {non_compliant, at_risk, transitional})
confusion   = TP | FP | FN | TN
metrics     = Accuracy, Precision, Recall, F1   → verified: all 1.0000 (0 FP / 0 FN)
```

---

## 3. D2 — Ruleset as data (`rules.yaml`)

Every rule is a semgrep pattern **plus NIST metadata** consumed by `compliance.py`:

| Field | Values |
|---|---|
| `nist_standard` | FIPS 203 / 204 / 205 / 206 / FIPS 202 (hashing) / Advisory |
| `category` | key-encapsulation, signatures, hashing, symmetric, tls, secrets, kdf, randomness, dependencies, hybrid |
| `pqc_compliant` | true (PASS evidence) / false (migration required) |
| `target_algorithm` | exact migration target, e.g. `ML-KEM (hybrid X25519MLKEM768)` |
| `severity` | ERROR (Shor-broken/defunct: RSA, ECDH, ECDSA, DES…) / WARNING (MD5, SHA-1, TLS defaults) |

Rule distribution: **FIPS 203: 27 · FIPS 204: 16 · FIPS 205: 9 · FIPS 206: 6 ·
FIPS 202 + Advisory: 48**. Languages: Python, Java, JS/TS, Go, C/C++, Rust, PHP —
both positive (PQC usage) and negative (legacy) rules.

---

## 4. D3 — CVE advisory table (`deps.py`)

- Offline, bundled, version-constrained: each advisory = `{id, severity,
  constraints:[{op, version}], description}`; constraints are AND-ed.
- Examples wired in: node-forge CVE-2022-24771 (<1.3.0, ERROR), CVE-2020-7720 (<0.10.0);
  cryptography CVE-2023-49083 (<42.0.2); openssl CVE-2022-3602 (<3.0.7).
- Matched against declared manifest versions **and** lockfile (transitive) entries.

---

## 5. D4 — Test fixtures

`backend/test_samples/` holds known-vulnerable and PQC-compliant files across
Python/Java/JS/Go/C — used by the suite (211 checks) and as a live demo:
`python cipher_cli.py scan backend/test_samples`.

---

## 6. Data handling rules

1. **No user data is collected.** Uploaded zips are extracted to temp dirs and deleted in
   a `finally` block after each scan (`shutil.rmtree`).
2. **Zero-trust telemetry**: only `{algorithm, standard, severity, verdict}` tuples leave
   the machine; `cipher_cli.py telemetry` prints the exact permitted payload.
3. Persistence is limited to scan metadata + findings (SQLite `piquachu.db`).
4. All datasets are synthetic/bundled — no third-party data ingestion, fully offline.
