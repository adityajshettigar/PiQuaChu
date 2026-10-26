# backend/cbom_cases.py
"""
cbom_cases.py — deterministic CBOM fixture scenarios
====================================================
Builds a CycloneDX 1.7 CBOM for each representative evidence shape used by
``test_cbom.py`` and ``generate_cbom_fixtures.py``.  The cases are synthetic
findings so they exercise serialization semantics, not scanner detection.
"""

from __future__ import annotations

import compliance
import cbom


def _finding(rule: str, file: str, line: int, severity: str = "WARNING",
             recommendation: str = "", line_text: str = "") -> dict:
    return {
        "vulnerability": rule,
        "file": file,
        "line": line,
        "severity": severity,
        "recommendation": recommendation,
        "line_text": line_text,
    }


CASES: dict[str, list[dict]] = {
    "01_legacy_only": [
        _finding("deprecated-rsa-python-cryptography", "src/legacy/rsa.py", 14,
                 "ERROR", "RSA key generation is quantum-vulnerable.",
                 "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)"),
        _finding("weak-crypto-python-md5", "src/legacy/hash.py", 8,
                 "WARNING", "MD5 is broken for collision resistance.",
                 "digest = hashlib.md5(payload).hexdigest()"),
    ],
    "02_pqc_kem": [
        _finding("pqc-mlkem-python", "src/pqc/kem.py", 11, "INFO",
                 "ML-KEM evidence detected.",
                 'kem = oqs.KeyEncapsulation("ML-KEM-768")'),
    ],
    "03_pqc_signature": [
        _finding("pqc-mldsa-python", "src/pqc/sign.py", 19, "INFO",
                 "ML-DSA evidence detected.",
                 'signer = oqs.Signature("ML-DSA-65")'),
    ],
    "04_fndsa_in_development": [
        _finding("pqc-fndsa-python", "src/pqc/falcon.py", 7, "INFO",
                 "FN-DSA (FALCON) algorithm evidence detected. FIPS 206 is still in development.",
                 'signer = oqs.Signature("Falcon-512")'),
    ],
    "05_mixed_legacy_pqc": [
        _finding("pqc-mlkem-python", "src/pqc/kem.py", 11, "INFO",
                 "ML-KEM evidence detected.", 'oqs.KeyEncapsulation("ML-KEM-768")'),
        _finding("deprecated-rsa-python-cryptography", "src/legacy/rsa.py", 14,
                 "ERROR", "RSA key generation is quantum-vulnerable."),
        _finding("deprecated-ecdsa-python-cryptography", "src/legacy/sign.py", 22,
                 "ERROR", "ECDSA signatures are quantum-vulnerable."),
    ],
    "06_duplicate_evidence": [
        _finding("pqc-mlkem-python", "src/a/kem.py", 5, "INFO",
                 "ML-KEM evidence detected.", 'oqs.KeyEncapsulation("ML-KEM-768")'),
        _finding("pqc-mlkem-python", "src/b/kem.py", 9, "INFO",
                 "ML-KEM evidence detected.", 'oqs.KeyEncapsulation("ML-KEM-768")'),
    ],
    "07_dependency_cve": [
        _finding("dependency-vulnerable-version", "requirements.txt", 1, "ERROR",
                 "CVE-2022-24771: RSA signature verification bypass in node-forge "
                 "(CVE-2022-24771). Declared node-forge 1.2.9 — upgrade."),
        _finding("dependency-legacy-crypto-lib", "requirements.txt", 1, "WARNING",
                 "Classical-crypto library declared: node-forge."),
    ],
    "08_key_material": [
        _finding("key-file-rsa", "keys/deploy_id_rsa", 1, "ERROR",
                 "RSA private key material found. Key bytes are never serialized."),
    ],
    "09_no_crypto": [],
    "10_unknown_input": [
        _finding("unknown-rule-not-in-registry", "/etc/shadow", 1, "WARNING",
                 "Unclassified pattern.", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        _finding("", "../../outside.py", 0, "INFO", "Malformed finding."),
    ],
}


def build_case(name: str, scan_id: int | None = None) -> dict:
    findings = CASES[name]
    matrix = compliance.analyze_compliance([dict(f) for f in findings])
    return cbom.build_cbom(matrix, findings, scan_id=scan_id, filename=f"{name}.zip")


def build_all() -> dict[str, dict]:
    return {name: build_case(name, scan_id=i + 1)
            for i, name in enumerate(CASES)}
