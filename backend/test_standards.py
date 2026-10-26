#!/usr/bin/env python3
# backend/test_standards.py
"""
test_standards.py — Phase 1 registry integrity + verdict-semantics tests.

Run:  venv/bin/python test_standards.py     (no pytest required)
"""

import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import compliance
import standards

PASSED = []


def check(name, condition, detail=""):
    if not condition:
        raise AssertionError(f"FAILED: {name} {detail}")
    PASSED.append(name)
    print(f"  ✓ {name}")


def expect_registry_error(label, registry):
    try:
        standards.validate_registry(registry)
    except standards.RegistryError:
        PASSED.append(label)
        print(f"  ✓ {label}")
        return
    raise AssertionError(f"FAILED: {label} (no RegistryError raised)")


# ---------------------------------------------------------------------------
# Registry integrity / lifecycle provenance
# ---------------------------------------------------------------------------

def test_registry_integrity():
    print("Registry integrity:")
    standards.validate_registry()
    check("registry validates", True)
    ids = standards.standard_ids()
    check("four canonical entries", ids == ["FIPS 203", "FIPS 204", "FIPS 205", "FIPS 206"], ids)
    check("no duplicate ids", len(ids) == len(set(ids)))

    for entry in standards.STANDARDS:
        sid = entry["id"]
        check(f"{sid} official source", entry["source"].startswith("https://"))
        check(f"{sid} review date present", bool(entry["reviewed"]))
        check(f"{sid} primitive valid", entry["primitive"] in standards.CYCLONEDX_PRIMITIVES)
        check(f"{sid} category valid", entry["category"] in standards.CATEGORIES)

    for sid in ("FIPS 203", "FIPS 204", "FIPS 205"):
        std = standards.get_standard(sid)
        check(f"{sid} finalized", std["lifecycle"] == "final")
        check(f"{sid} publication date", std["publication_date"] == "2024-08-13")

    fips206 = standards.get_standard("FIPS 206")
    check("FIPS 206 in development", fips206["lifecycle"] == "in_development")
    check("FIPS 206 has no publication date", fips206["publication_date"] is None)
    check("FIPS 206 source is NIST PQC project page",
          "post-quantum-cryptography" in fips206["source"])

    # Alias resolution is data-driven and case-insensitive.
    check("Kyber -> FIPS 203", standards.by_alias("Kyber")["id"] == "FIPS 203")
    check("CRYSTALS-Dilithium -> FIPS 204",
          standards.by_alias("CRYSTALS-Dilithium")["id"] == "FIPS 204")
    check("SPHINCS+ -> FIPS 205", standards.by_alias("SPHINCS+")["id"] == "FIPS 205")
    check("FALCON -> FIPS 206", standards.by_alias("Falcon")["id"] == "FIPS 206")
    check("unknown alias -> None", standards.by_alias("not-an-algorithm") is None)


def test_registry_rejects_bad_data():
    print("Registry validation negatives:")
    base = copy.deepcopy(standards.STANDARDS)

    bad = copy.deepcopy(base)
    bad[0]["aliases"].append("FALCON")
    expect_registry_error("alias collision rejected", bad)

    bad = copy.deepcopy(base)
    bad[3]["publication_date"] = "2025-05-01"
    expect_registry_error("in-development publication claim rejected", bad)

    bad = copy.deepcopy(base)
    bad[0]["primitive"] = "totally-bogus"
    expect_registry_error("invalid primitive rejected", bad)

    bad = copy.deepcopy(base)
    bad[1]["category"] = "not-a-category"
    expect_registry_error("invalid category rejected", bad)

    bad = copy.deepcopy(base)
    bad[0]["source"] = "http://example.invalid"
    expect_registry_error("non-https source rejected", bad)

    bad = copy.deepcopy(base)
    bad.append(copy.deepcopy(base[0]))
    bad[-1]["aliases"] = ["Another-Kyber-Alias"]
    expect_registry_error("duplicate canonical id rejected", bad)

    bad = copy.deepcopy(base)
    bad[0]["reviewed"] = "18-10-2026"
    expect_registry_error("non-ISO review date rejected", bad)

    check("original registry still valid", standards.validate_registry() is None)


def test_quantum_security_levels():
    print("NIST quantum security levels:")
    check("ML-KEM-768 -> 3", standards.nist_quantum_security_level("ML-KEM-768") == 3)
    check("ML-KEM-1024 -> 5", standards.nist_quantum_security_level("ML-KEM-1024") == 5)
    check("SLH-DSA-SHA2-128s -> 1",
          standards.nist_quantum_security_level("SLH-DSA-SHA2-128s") == 1)
    check("family name has no single level",
          standards.nist_quantum_security_level("ML-KEM") is None)
    check("unknown parameter set -> None",
          standards.nist_quantum_security_level("ML-KEM-999") is None)


def test_category_aware_guidance():
    print("Category-aware migration guidance:")
    hashing = standards.migration_guidance("hashing")
    check("hash guidance names SHA-256", "SHA-256" in hashing)
    check("hash guidance is not PQC signature migration",
          "ML-KEM" not in hashing and "not a post-quantum signature" in hashing.lower())
    symmetric = standards.migration_guidance("symmetric")
    check("symmetric guidance names AES-256-GCM", "AES-256-GCM" in symmetric)
    check("symmetric guidance says Shor does not break AES",
          "not broken by Shor" in symmetric)
    signatures = standards.migration_guidance("signatures")
    check("signature guidance names ML-DSA and SLH-DSA",
          "ML-DSA" in signatures and "SLH-DSA" in signatures)
    check("signature guidance flags FIPS 206 in development",
          "in development" in signatures)
    check("unknown category degrades safely",
          "review manually" in standards.migration_guidance("nonsense"))


# ---------------------------------------------------------------------------
# Verdict / evidence semantics
# ---------------------------------------------------------------------------

def _analyze(rule_id, severity="WARNING", file="src/a.py", line=1, **extra):
    finding = {"vulnerability": rule_id, "severity": severity,
               "file": file, "line": line}
    finding.update(extra)
    return compliance.analyze_compliance([finding])


def test_no_evidence_is_not_compliance():
    print("No-evidence semantics:")
    matrix = compliance.analyze_compliance([])
    check("empty verdict not_assessed", matrix["verdict"] == "not_assessed", matrix["verdict"])
    check("empty assessment status", matrix["assessment"]["status"] == "not_assessed")
    check("score stays readiness heuristic",
          matrix["pqc_score"] == 100 and matrix["risk_score"] == 0)
    for std, info in matrix["standards"].items():
        check(f"{std} evidence not_detected", info["evidence_status"] == "not_detected")
        check(f"{std} status not_detected", info["status"] == "not_detected")
        check(f"{std} confidence none", info["confidence"] == "none")
        check(f"{std} rationale says not compliant", "not compliant" in info["rationale"])


def test_role_separation():
    print("Role / category separation:")
    kem = _analyze("pqc-mlkem-python", "INFO", line_text='oqs.KeyEncapsulation("ML-KEM-768")')
    check("KEM does not satisfy FIPS 204", kem["standards"]["FIPS 204"]["status"] == "not_detected")
    check("KEM does not satisfy FIPS 205", kem["standards"]["FIPS 205"]["status"] == "not_detected")
    check("KEM satisfies FIPS 203", kem["standards"]["FIPS 203"]["status"] == "compliant")
    check("partial coverage is not project-compliant", kem["verdict"] == "incomplete", kem["verdict"])

    sig = _analyze("pqc-mldsa-python", "INFO", line_text='oqs.Signature("ML-DSA-65")')
    check("signature does not satisfy FIPS 203", sig["standards"]["FIPS 203"]["status"] == "not_detected")
    check("signature satisfies FIPS 204", sig["standards"]["FIPS 204"]["status"] == "compliant")

    md5 = _analyze("weak-crypto-python-md5", "WARNING")
    check("MD5 is advisory only", md5["standards"]["FIPS 203"]["status"] == "not_detected")
    check("MD5 does not map to ML-KEM", md5["standards"]["FIPS 205"]["status"] == "not_detected")
    check("MD5 advisory hashing count", md5["advisory"]["hashing"] == 1)
    check("MD5-only verdict at_risk", md5["verdict"] == "at_risk", md5["verdict"])

    aes = _analyze("deprecated-aes128-python", "WARNING")
    check("AES-128 is not a PQC standard finding",
          all(info["status"] == "not_detected" for info in aes["standards"].values()))
    check("AES-128 advisory symmetric count", aes["advisory"]["symmetric"] == 1)

    # A PQC-capable dependency is evidence, not a legacy risk and not a pass.
    dep = _analyze("dependency-pqc-lib", "INFO")
    check("PQC dependency alone is incomplete, not at_risk",
          dep["verdict"] == "incomplete", dep["verdict"])
    check("PQC dependency adds no standard evidence",
          all(info["status"] == "not_detected" for info in dep["standards"].values()))


def test_fips206_semantics():
    print("FIPS 206 / FN-DSA semantics:")
    matrix = _analyze("pqc-fndsa-python", "INFO", line_text='oqs.Signature("Falcon-512")')
    fips206 = matrix["standards"]["FIPS 206"]
    check("status detected_in_development", fips206["status"] == "detected_in_development")
    check("evidence status detected", fips206["evidence_status"] == "detected")
    check("lifecycle in_development", fips206["standard_lifecycle"] == "in_development")
    check("not a finalized pass", "not a finalized" in fips206["rationale"])
    check("finding carries lifecycle", matrix["findings_count"] == 1)
    check("verdict incomplete (no final standards detected)",
          matrix["verdict"] == "incomplete", matrix["verdict"])


def test_status_vocabulary():
    print("Status vocabulary:")
    cases = [
        _analyze("pqc-mlkem-python", "INFO"),
        _analyze("deprecated-rsa-python-cryptography", "ERROR"),
        _analyze("weak-crypto-python-md5", "WARNING"),
    ]
    for matrix in cases:
        for std, info in matrix["standards"].items():
            check(f"{std} public status vocabulary",
                  info["status"] in {"compliant", "partial", "non_compliant",
                                     "not_detected", "transitional",
                                     "detected_in_development"})
            check(f"{std} evidence vocabulary",
                  info["evidence_status"] in compliance.EVIDENCE_STATUSES)
            check(f"{std} rationale present", bool(info["rationale"]))
            check(f"{std} coverage present", bool(info["evidence_coverage"]))


def test_evidence_provenance():
    print("Finding evidence provenance:")
    matrix = compliance.analyze_compliance([
        {"vulnerability": "deprecated-rsa-python-cryptography", "severity": "ERROR",
         "file": "src/rsa.py", "line": 4},
    ])
    check("finding count", matrix["findings_count"] == 1)
    enriched = compliance.enrich_finding(
        {"vulnerability": "deprecated-rsa-python-cryptography", "severity": "ERROR",
         "file": "src/rsa.py", "line": 4},
        compliance.load_rule_metadata(),
    )
    check("evidence kind", enriched["evidence_kind"] == "legacy_usage")
    check("confidence high with location", enriched["confidence"] == "high")
    check("lifecycle attached", enriched["standard_lifecycle"] == "final")
    check("limitations attached", "not prove" in enriched["limitations"].lower()
          or "does not prove" in enriched["limitations"].lower())
    check("rationale attached", bool(enriched["rationale"]))


def test_score_and_risk_bounds():
    print("Score / risk behavior:")
    meta = compliance.load_rule_metadata()
    idle = compliance.analyze_compliance([])
    one_error = compliance.analyze_compliance([
        {"vulnerability": "deprecated-rsa-python-cryptography", "severity": "ERROR",
         "file": "a.py", "line": 1}], metadata=meta)
    two_errors = compliance.analyze_compliance([
        {"vulnerability": "deprecated-rsa-python-cryptography", "severity": "ERROR",
         "file": "a.py", "line": i} for i in (1, 2)], metadata=meta)
    check("score in range", 0 <= one_error["pqc_score"] <= 100)
    check("risk in range", 0 <= one_error["risk_score"] <= 100)
    check("more legacy findings do not increase readiness",
          two_errors["pqc_score"] <= one_error["pqc_score"] < idle["pqc_score"])
    check("more legacy findings do not decrease risk",
          two_errors["risk_score"] >= one_error["risk_score"] >= idle["risk_score"])

    duplicate = compliance.analyze_compliance([
        {"vulnerability": "deprecated-rsa-python-cryptography", "severity": "ERROR",
         "file": "a.py", "line": 1},
        {"vulnerability": "deprecated-rsa-python-cryptography", "severity": "ERROR",
         "file": "a.py", "line": 1}], metadata=meta)
    check("duplicate findings deterministic",
          duplicate["pqc_score"] == one_error["pqc_score"] - 20)
    check("semantics version", one_error["assessment"]["semantics_version"] == "evidence-v1")
    check("score formula version", one_error["assessment"]["score_formula_version"] == "readiness-v1")
    check("risk formula version", one_error["assessment"]["risk_formula_version"] == "risk-v1")


def test_telemetry_privacy():
    print("Telemetry privacy / lifecycle:")
    tel = compliance.build_telemetry([
        {"vulnerability": "pqc-fndsa-python", "severity": "INFO",
         "file": "/home/alice/secret/falcon.py", "line": 3},
    ])
    blob = str(tel)
    check("no file path", "alice" not in blob and "falcon.py" not in blob)
    check("lifecycle included", tel["algorithm_telemetry"][0]["standard_lifecycle"]
          == "in_development")
    check("no source text", "oqs.Signature" not in blob)


def main():
    print("=" * 68)
    print("PiQuaChu standards registry + verdict semantics tests")
    print("=" * 68)
    test_registry_integrity()
    test_registry_rejects_bad_data()
    test_quantum_security_levels()
    test_category_aware_guidance()
    test_no_evidence_is_not_compliance()
    test_role_separation()
    test_fips206_semantics()
    test_status_vocabulary()
    test_evidence_provenance()
    test_score_and_risk_bounds()
    test_telemetry_privacy()
    print("=" * 68)
    print(f"ALL {len(PASSED)} CHECKS PASSED ✅")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    sys.exit(main())
