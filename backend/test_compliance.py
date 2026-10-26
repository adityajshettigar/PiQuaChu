#!/usr/bin/env python3
# backend/test_compliance.py
"""
test_compliance.py — unit tests for the NIST PQC compliance engine.
Run:  python3 test_compliance.py   (no pytest required)
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import compliance
import remediation

PASSED = []


def check(name, condition, detail=""):
    if not condition:
        raise AssertionError(f"FAILED: {name} {detail}")
    PASSED.append(name)
    print(f"  ✓ {name}")


def rule_id(metadata, standard, compliant, category=None):
    """Pick a sample rule id matching the criteria."""
    for rid, meta in metadata.items():
        if meta.get("nist_standard") == standard and meta.get("pqc_compliant") == compliant:
            if category and meta.get("category") != category:
                continue
            return rid
    return None


def test_rule_metadata():
    print("Rule metadata (rules.yaml):")
    meta = compliance.load_rule_metadata()
    check("rules loaded", len(meta) >= 40, f"got {len(meta)}")
    for std in ("FIPS 203", "FIPS 204", "FIPS 205", "FIPS 206"):
        pos = rule_id(meta, std, True)
        check(f"{std} has positive rule", pos is not None, f"missing for {std}")
    # Legacy signatures map to FIPS 204 (primary); FIPS 205 / 206 are alternatives.
    for std in ("FIPS 203", "FIPS 204"):
        neg = rule_id(meta, std, False)
        check(f"{std} has negative rule", neg is not None, f"missing for {std}")
    # Legacy rules must carry a migration target
    for rid, m in meta.items():
        if not m.get("pqc_compliant") and m.get("nist_standard") in ("FIPS 203", "FIPS 204", "FIPS 205"):
            check(f"migration target for {rid}", bool(m.get("target_algorithm")))


def test_empty_scan():
    print("Empty scan:")
    matrix = compliance.analyze_compliance([])
    check("score 100 on clean code", matrix["pqc_score"] == 100)
    # No matching evidence is NOT a compliance pass.
    check("verdict not_assessed", matrix["verdict"] == "not_assessed", matrix["verdict"])
    check("assessment not_assessed", matrix["assessment"]["status"] == "not_assessed")
    for std in compliance.STANDARDS:
        check(f"{std} not_detected", matrix["standards"][std]["status"] == "not_detected")
        check(f"{std} evidence not_detected",
              matrix["standards"][std]["evidence_status"] == "not_detected")


def test_legacy_findings():
    print("Legacy (non-compliant) findings:")
    meta = compliance.load_rule_metadata()
    findings = [
        {"vulnerability": rule_id(meta, "FIPS 203", False), "severity": "ERROR", "file": "a.py", "line": 1},
        {"vulnerability": rule_id(meta, "FIPS 204", False), "severity": "ERROR", "file": "b.java", "line": 2},
        {"vulnerability": rule_id(meta, "FIPS 202", False), "severity": "WARNING", "file": "c.js", "line": 3},
    ]
    matrix = compliance.analyze_compliance(findings)
    check("score penalized", matrix["pqc_score"] == 50, f"got {matrix['pqc_score']}")
    check("FIPS 203 non_compliant", matrix["standards"]["FIPS 203"]["status"] == "non_compliant")
    check("FIPS 204 non_compliant", matrix["standards"]["FIPS 204"]["status"] == "non_compliant")
    check("verdict non_compliant", matrix["verdict"] == "non_compliant")
    check("advisory hashing count", matrix["advisory"]["hashing"] == 1)


def test_pqc_findings():
    print("PQC-compliant findings:")
    meta = compliance.load_rule_metadata()
    findings = [
        {"vulnerability": rule_id(meta, "FIPS 203", True), "severity": "INFO", "file": "a.py", "line": 1},
        {"vulnerability": rule_id(meta, "FIPS 204", True), "severity": "INFO", "file": "b.java", "line": 2},
        {"vulnerability": rule_id(meta, "FIPS 205", True), "severity": "INFO", "file": "c.go", "line": 3},
        {"vulnerability": rule_id(meta, "FIPS 206", True), "severity": "INFO", "file": "d.rs", "line": 4},
    ]
    matrix = compliance.analyze_compliance(findings)
    check("bonus applied", matrix["pqc_score"] == 100, f"got {matrix['pqc_score']}")
    for std in ("FIPS 203", "FIPS 204", "FIPS 205"):
        check(f"{std} compliant", matrix["standards"][std]["status"] == "compliant")
    # FIPS 206 is still in development: evidence, never a finalized pass.
    check("FIPS 206 detected_in_development",
          matrix["standards"]["FIPS 206"]["status"] == "detected_in_development",
          matrix["standards"]["FIPS 206"])
    check("verdict compliant for finalized standards", matrix["verdict"] == "compliant",
          matrix["verdict"])


def test_fips206_fndsa():
    print("FIPS 206 (FN-DSA/FALCON):")
    meta = compliance.load_rule_metadata()
    findings = [
        {"vulnerability": "pqc-fndsa-python", "severity": "INFO", "file": "sign.py", "line": 3},
        {"vulnerability": "deprecated-ecdsa-python-cryptography", "severity": "ERROR",
         "file": "legacy.py", "line": 9},
    ]
    matrix = compliance.analyze_compliance(findings, metadata=meta)
    check("FIPS 206 detected_in_development",
          matrix["standards"]["FIPS 206"]["status"] == "detected_in_development")
    check("FIPS 206 lifecycle in_development",
          matrix["standards"]["FIPS 206"]["standard_lifecycle"] == "in_development")
    check("FIPS 204 non_compliant (legacy ECDSA)",
          matrix["standards"]["FIPS 204"]["status"] == "non_compliant")
    check("FIPS 206 in standards matrix", "FIPS 206" in matrix["standards"])
    check("FN-DSA algorithm name", matrix["standards"]["FIPS 206"]["algorithm"] == "FN-DSA")


def test_mixed_findings():
    print("Mixed findings (PQC + legacy):")
    meta = compliance.load_rule_metadata()
    findings = [
        {"vulnerability": rule_id(meta, "FIPS 203", True), "severity": "INFO", "file": "a.py", "line": 1},
        {"vulnerability": rule_id(meta, "FIPS 203", False), "severity": "ERROR", "file": "a.py", "line": 2},
    ]
    matrix = compliance.analyze_compliance(findings)
    check("FIPS 203 partial", matrix["standards"]["FIPS 203"]["status"] == "partial")
    check("verdict at_risk", matrix["verdict"] == "at_risk")


def test_score_caps():
    meta = compliance.load_rule_metadata()
    many = [
        {"vulnerability": rule_id(meta, "FIPS 203", False), "severity": "ERROR", "file": "x.py", "line": i}
        for i in range(20)
    ]
    check("score floor at 0", compliance.compute_score(many) == 0)


def test_telemetry_anonymized():
    meta = compliance.load_rule_metadata()
    findings = [
        {"vulnerability": rule_id(meta, "FIPS 203", False), "severity": "ERROR",
         "file": "secret_project/src/auth/key_management.py", "line": 42},
        {"vulnerability": rule_id(meta, "FIPS 204", True), "severity": "INFO",
         "file": "secret_project/src/auth/signing.py", "line": 7},
    ]
    tel = compliance.build_telemetry(findings, metadata=meta)
    blob = str(tel)
    check("no file paths in telemetry", "secret_project" not in blob and "key_management" not in blob)
    check("telemetry has algorithm_telemetry", "algorithm_telemetry" in tel)
    check("telemetry counts", tel["algorithm_telemetry"][0].get("count") == 1)


def test_remediation_plan():
    print("Remediation plans:")
    meta = compliance.load_rule_metadata()
    finding = compliance.enrich_finding(
        {"vulnerability": rule_id(meta, "FIPS 203", False), "severity": "ERROR",
         "file": "src/auth.py", "line": 10}, meta)
    plan = remediation.build_plan(finding)
    check("replacement code present", bool(plan.get("replacement_code")))
    check("dependencies present", bool(plan.get("dependencies")))
    check("justification present", bool(plan.get("justification")))
    check("risk present", plan.get("risk") in ("low", "medium", "high"))
    check("local source by default", plan.get("source") == "local-rule-engine")


def test_assistant():
    meta = compliance.load_rule_metadata()
    findings = [
        {"vulnerability": rule_id(meta, "FIPS 203", False), "severity": "ERROR",
         "file": "src/auth.py", "line": 10},
    ]
    matrix = compliance.analyze_compliance(findings, metadata=meta)
    ans = remediation.assistant_answer("Show me all RSA findings in the last scan", matrix, findings)
    check("assistant RSA intent", "RSA" in ans["answer"])
    ans2 = remediation.assistant_answer("What is the recommended Dilithium parameter set?", matrix, findings)
    check("assistant ML-DSA knowledge", "ML-DSA-65" in ans2["answer"])
    ans3 = remediation.assistant_answer("Generate an executive summary", matrix, findings)
    check("assistant exec summary", "Executive summary" in ans3["answer"])


def main():
    print("=" * 60)
    print("PiQuaChu compliance engine unit tests")
    print("=" * 60)
    test_rule_metadata()
    test_empty_scan()
    test_legacy_findings()
    test_pqc_findings()
    test_mixed_findings()
    test_score_caps()
    test_telemetry_anonymized()
    test_remediation_plan()
    test_fips206_fndsa()
    test_assistant()
    print("=" * 60)
    print(f"ALL {len(PASSED)} CHECKS PASSED ✅")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
