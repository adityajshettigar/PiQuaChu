# 03 · Domain Notes

**Project:** PiQuaChu 🛡️ · NIST PQC Compliance Engine
**Purpose:** The post-quantum cryptography domain knowledge the team must know to work on this codebase.

---

## 1. Why post-quantum, why now

- **Shor's algorithm** (1994) factors integers and computes discrete logarithms in
  polynomial time on a quantum computer → breaks **RSA, DH, ECDH, ECDSA, DSA, EdDSA**.
- **Grover's algorithm** only *halves* symmetric security → AES-256 stays safe; AES-128
  has reduced margin; hashes lose 2^n → 2^(n/2) preimage security.
- **Harvest now, decrypt later:** encrypted traffic recorded today is decryptable later.
  Migration is urgent for data whose secrecy lifetime exceeds time-to-quantum-computer.
- **Standardization status matters:** FIPS 203/204/205 were finalized in August 2024;
  FIPS 206 (FN-DSA/FALCON) is still **in development** at the registry review date.
  CISA/NSA/NIST publish migration timelines; auditors are beginning to ask.

## 2. The NIST PQC standards

| Standard | Algorithm | Former name | Role | Family / hardness |
|---|---|---|---|---|
| **FIPS 203** | **ML-KEM** | CRYSTALS-Kyber | Key Encapsulation Mechanism — general encryption | Module-LWE lattice problem |
| **FIPS 204** | **ML-DSA** | CRYSTALS-Dilithium | Digital signatures — primary | Module-LWE / Module-SIS |
| **FIPS 205** | **SLH-DSA** | SPHINCS+ | Digital signatures — hash-based backup | Hash-based (conservative) |
| **FIPS 206** | **FN-DSA** | FALCON | Digital signatures — lattice (NTRU), hash-and-sign | NTRU lattice / FFT over NTRU |

Parameter tiers: ML-KEM-512/768/1024 (NIST levels 1/3/5), ML-DSA-44/65/87,
SLH-DSA-128/192/256, FALCON-512/1024. ML-KEM-768 ≈ AES-256-equivalent security
(level 3). FN-DSA/FALCON remains a selected algorithm; do not report it as a
finalized FIPS pass.

**Hybrid migration:** TLS/SSH support *classical+PQC combined* schemes —
`X25519MLKEM768`, `X25519Kyber768Draft00`, `sntrup761x25519-sha512@openssh.com`,
`mlkem768x25519-sha256`, `mlkem1024x25519-sha512` — security holds if **either**
component holds. These count as "transitional" (migration in progress), not legacy.

## 3. What PiQuaChu flags as non-compliant

| Primitive | Broken by | Severity in engine | FIPS migration target |
|---|---|---|---|
| RSA (all uses: KEX, sigs, PKCS#1 v1.5) | Shor | ERROR | ML-KEM (203) / ML-DSA (204) |
| ECDH / X25519 key agreement | Shor | ERROR | ML-KEM (hybrid X25519MLKEM768) |
| ECDSA / EdDSA / Ed25519 / DSA | Shor | ERROR | ML-DSA / SLH-DSA |
| DES / 3DES / RC4 | Classical | ERROR | AES-256-GCM |
| MD5 / SHA-1 | Classical collision | WARNING | SHA-256 / SHA3-256 |
| TLS 1.0/1.1, classical-only suites | Weak config | WARNING | TLS 1.3 + hybrid groups |
| Static IVs / ECB mode | Semantic misuse | WARNING/ERROR | AES-GCM w/ random IV |
| Hardcoded secrets, weak randomness (`random` vs `secrets`) | Key-recovery | WARNING | `secrets` / CSPRNG |
| Static KDF salts | Rainbow tables | WARNING | Random per-derivation salt |

## 4. The PQC library ecosystem (detection + remediation targets)

First-class, name-resolved in `deps.py`/`rules.yaml`:

- **Python:** `liboqs-python` (`oqs.KeyEncapsulation`, `oqs.Signature`), `pqcrypto`,
  `crystals-kyber`, `pqcrypto-falcon`
- **Java:** Bouncy Castle PQC — `bcpqc-jdk18on`, `KyberKeyPairGenerator`,
  `DilithiumSigner`, `Falcon512Signer`/`Falcon1024Signer`, `SPHINCSPlusSigner`
- **C:** `liboqs` (`OQS_KEM_alg_ml_kem_768`, `OQS_SIG_alg_falcon_512`),
  `mlkem-native`, `mldsa-native`, `slhdsa-c` (PQClean successors), PQClean
  (`PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair`)
- **Go:** Cloudflare `circl` (`kem/mlkem`, `sign/mldsa`)
- **JS/TS:** `@noble/post-quantum`
- **Rust:** `pqcrypto-*` crates, Cloudflare `circl` Rust

Ecosystem alignment references: `itzmeanjan/falcon` (FALCON reference impl — the reason
FN-DSA is tracked), `CipherIQ/pqc-flow` (runtime PQC detection surface mirrored
statically here), `PQClean/PQClean` (archived legacy reference; maintained successors
include `mlkem-native`, `mldsa-native`, `slhdsa-c` and `liboqs`).

## 5. Cryptographic Bill of Materials (CBOM)

CycloneDX 1.7 supports `type: cryptographic-asset` components with
`cryptoProperties`. A CBOM is the crypto analogue of an SBOM: *which algorithms, where,
with what evidence*. PiQuaChu emits aggregated algorithm/material/protocol assets with
source evidence occurrences, and adds `vulnerabilities` only for genuine advisories
(e.g. matched CVEs). Policy findings such as "AES/ECB detected" remain in PiQuaChu's
native findings report and are not mislabelled as CVEs.

## 6. Compliance verdict semantics

Per standard: `compliant` / `partial` / `non_compliant` / `not_detected` (+ project
`transitional` when hybrid evidence exists). Overall verdict ordering (worst→best):
`non_compliant > at_risk > transitional > compliant > not_detected`.

Two orthogonal scores (see 07 · Model Architecture for formulas):
- `pqc_score` — readiness, starts at 100, subtracts for legacy, adds for PQC.
- `risk_score` — weighted danger of legacy crypto present, category-weighted
  (RSA/ECDH 1.0 > SHA-1 0.6 > dependencies 0.4), saturating, banded low/medium/high/critical.

## 7. Zero-trust analysis principle

The CLI agent **never uploads source code**. Two deployment modes exist:
1. Full scan (zip uploaded to *your own* local backend), or
2. Telemetry-only: `cipher_cli.py telemetry` computes locally and prints the anonymized
   payload `{algorithm_telemetry: [{algorithm, standard, severity, verdict}], summary}`
   that is permitted to leave the machine — POST it to `/api/v1/compliance/check`.
No file paths, variable names, or source snippets are ever in the telemetry channel.
LLM enrichment (Groq) receives the same anonymized metadata only.

## 8. Static-analysis domain notes

- **AST over regex:** crypto APIs are called through aliases, wrappers and indirection;
  only syntax-tree matching (semgrep) plus a semantic Python `ast` walker (alias
  resolution, key-length-aware AES, textbook-RSA math patterns) gets reliable results.
- **Known engine limitations (documented, not hidden):** metavariable rules match literal
  algorithm strings; Rust rules skip on this semgrep build; obfuscation is a best effort.
- **Transport configs are part of the crypto surface:** `sshd_config` KEX lines and
  `nginx.conf` TLS groups are scanned statically — same detection surface as network
  flow analyzers, usable before deployment.

## 9. Standards & references

- NIST FIPS 203 (ML-KEM) · 204 (ML-DSA) · 205 (SLH-DSA) · 206 (FN-DSA/FALCON)
- NIST SP 1800-38 (Migration to PQC) · CNSA 2.0 suite (NSA)
- CycloneDX 1.7 specification (`cryptographic-asset` components)
- OWASP ASVS §6 (cryptography controls) for advisory framing
