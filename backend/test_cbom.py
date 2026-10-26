#!/usr/bin/env python3
# backend/test_cbom.py
"""
test_cbom.py — CycloneDX 1.7 CBOM schema + semantic fixture tests.

Run:  venv/bin/python test_cbom.py     (no pytest required)

Schema validation uses the bundled official CycloneDX 1.7 schema.  If the
jsonschema dependency is unavailable the suite reports BLOCKED (exit 2) and
prints the exact command to complete validation — it never fakes a pass.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cbom
import cbom_cases

PASSED = []
FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "cbom_fixtures")


def check(name, condition, detail=""):
    if not condition:
        raise AssertionError(f"FAILED: {name} {detail}")
    PASSED.append(name)
    print(f"  ✓ {name}")


def _json(bom):
    return json.dumps(bom)


def _component(bom, name):
    for component in bom["components"]:
        if component["name"] == name:
            return component
    return None


def _props(component):
    return {p["name"]: p.get("value") for p in component.get("properties", [])}


def test_schema_validation():
    print("Official CycloneDX 1.7 schema validation:")
    try:
        for name, bom in cbom_cases.build_all().items():
            cbom.validate_cbom(bom)
            check(f"schema valid: {name}", True)
    except cbom.CbomValidationUnavailable as exc:
        print(f"  BLOCKED: {exc}")
        print("  Complete validation with: "
              "venv/bin/python -c \"import cbom, cbom_cases; "
              "[cbom.validate_cbom(b) for b in cbom_cases.build_all().values()]\"")
        return 2
    return 0


def test_envelope():
    print("BOM envelope:")
    bom = cbom_cases.build_case("05_mixed_legacy_pqc", scan_id=7)
    check("bomFormat", bom["bomFormat"] == "CycloneDX")
    check("specVersion 1.7", bom["specVersion"] == "1.7")
    check("serialNumber urn:uuid",
          re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", bom["serialNumber"]) is not None)
    check("version integer", bom["version"] == 1)
    check("tools.components", isinstance(bom["metadata"]["tools"]["components"], list))
    check("tool name", bom["metadata"]["tools"]["components"][0]["name"] == "PiQuaChu")
    check("project component bom-ref", bom["metadata"]["component"]["bom-ref"] == "piquachu-project")
    props = {p["name"]: p.get("value") for p in bom["metadata"]["properties"]}
    check("registry review date in metadata",
          props["piquachu:standards_registry_reviewed"] == "2026-10-18")
    check("policy findings are not CVEs",
          int(props["piquachu:policy_findings_not_in_vulnerabilities"]) >= 1)


def test_components_and_evidence():
    print("Cryptographic-asset components + evidence:")
    all_refs = set()
    for name, bom in cbom_cases.build_all().items():
        refs = [c["bom-ref"] for c in bom["components"]]
        check(f"unique bom-refs: {name}", len(refs) == len(set(refs)))
        all_refs.update(refs)
        for component in bom["components"]:
            check(f"{name}: component type", component["type"] == "cryptographic-asset")
            check(f"{name}: cryptoProperties present", "cryptoProperties" in component)
            check(f"{name}: assetType present",
                  component["cryptoProperties"].get("assetType") in
                  {"algorithm", "related-crypto-material", "protocol", "certificate"})
    # Uniqueness is required within each BOM, not across independently
    # serialized documents.  Assert the fixtures still cover several assets.
    check("fixtures cover multiple asset refs", len(all_refs) >= 5, sorted(all_refs))


def test_paths_and_secrets():
    print("Path / secret hygiene:")
    for name, bom in cbom_cases.build_all().items():
        blob = _json(bom)
        check(f"no absolute unix paths: {name}",
              not re.search(r'"/[A-Za-z0-9_.-]+/', blob))
        check(f"no Windows drive paths: {name}",
              not re.search(r'"[A-Za-z]:\\\\', blob))
        check(f"no PEM key material: {name}", "BEGIN " not in blob)
        check(f"no source snippets: {name}",
              "oqs.Signature" not in blob and "hashlib.md5" not in blob
              and "AAAAAAAA" not in blob)
        for component in bom["components"]:
            for occurrence in component.get("evidence", {}).get("occurrences", []):
                check(f"{name}: relative occurrence",
                      not occurrence["location"].startswith(("/", "\\"))
                      and ".." not in occurrence["location"].split("/"))


def test_policy_findings_are_not_cves():
    print("Policy findings vs vulnerabilities:")
    for name in ("01_legacy_only", "02_pqc_kem", "03_pqc_signature",
                 "04_fndsa_in_development", "05_mixed_legacy_pqc",
                 "06_duplicate_evidence", "08_key_material",
                 "09_no_crypto", "10_unknown_input"):
        bom = cbom_cases.build_case(name)
        check(f"no CVE entries: {name}", bom["vulnerabilities"] == [])
    dep = cbom_cases.build_case("07_dependency_cve")
    check("one genuine CVE entry", len(dep["vulnerabilities"]) == 1)
    check("CVE id preserved", dep["vulnerabilities"][0]["id"] == "CVE-2022-24771")
    check("CVE source NVD", dep["vulnerabilities"][0]["source"]["name"] == "NVD")


def test_pqc_assets():
    print("PQC asset properties:")
    kem = _component(cbom_cases.build_case("02_pqc_kem"), "ML-KEM")
    check("ML-KEM component present", kem is not None)
    check("ML-KEM primitive kem",
          kem["cryptoProperties"]["algorithmProperties"]["primitive"] == "kem")
    check("ML-KEM-768 NIST level 3",
          kem["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3)
    check("ML-KEM standard property", _props(kem)["piquachu:nist_standard"] == "FIPS 203")
    check("ML-KEM lifecycle final", _props(kem)["piquachu:standard_lifecycle"] == "final")

    sig = _component(cbom_cases.build_case("03_pqc_signature"), "ML-DSA")
    check("ML-DSA component present", sig is not None)
    check("ML-DSA primitive signature",
          sig["cryptoProperties"]["algorithmProperties"]["primitive"] == "signature")
    check("ML-DSA-65 NIST level 3",
          sig["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3)

    # No exact parameter set observed -> no fabricated NIST level.
    matrix = cbom_cases.compliance.analyze_compliance([
        {"vulnerability": "pqc-mlkem-python", "severity": "INFO",
         "file": "src/kem.py", "line": 1},
    ])
    bom = cbom.build_cbom(matrix, [{"vulnerability": "pqc-mlkem-python",
                                    "severity": "INFO", "file": "src/kem.py",
                                    "line": 1}])
    kem_unknown = _component(bom, "ML-KEM")
    check("unknown parameter set omits NIST level",
          "nistQuantumSecurityLevel" not in kem_unknown["cryptoProperties"]["algorithmProperties"])


def test_fips206_is_not_finalized():
    print("FIPS 206 asset semantics:")
    bom = cbom_cases.build_case("04_fndsa_in_development")
    component = _component(bom, "FN-DSA")
    check("FN-DSA asset present", component is not None)
    props = _props(component)
    check("FN-DSA lifecycle in_development",
          props["piquachu:standard_lifecycle"] == "in_development")
    check("FN-DSA standard property", props["piquachu:nist_standard"] == "FIPS 206")
    check("FN-DSA Falcon-512 level 1",
          component["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 1)
    blob = _json(bom).lower()
    check("no finalized-FIPS-206 claim",
          "finalized" not in blob and "nist-approved" not in blob)


def test_duplicate_and_empty_inputs():
    print("Deduplication / empty / malformed inputs:")
    dup = cbom_cases.build_case("06_duplicate_evidence")
    mlkem = [c for c in dup["components"] if c["name"] == "ML-KEM"]
    check("duplicate evidence aggregated to one component", len(mlkem) == 1)
    occurrences = mlkem[0]["evidence"]["occurrences"]
    check("both source locations retained", len(occurrences) == 2)
    check("occurrences sorted", occurrences == sorted(
        occurrences, key=lambda o: (o["location"], o.get("line") or 0)))

    empty = cbom_cases.build_case("09_no_crypto")
    check("empty scan has no manufactured components", empty["components"] == [])
    check("empty scan has no vulnerabilities", empty["vulnerabilities"] == [])

    unknown = cbom_cases.build_case("10_unknown_input")
    check("malformed finding does not crash", isinstance(unknown, dict))
    check("unknown rule not fabricated into asset", unknown["components"] == [])

    key = cbom_cases.build_case("08_key_material")
    material = _component(key, "RSA key material")
    check("key material asset present", material is not None)
    check("key material asset type",
          material["cryptoProperties"]["assetType"] == "related-crypto-material")
    check("key material has no key bytes", "BEGIN " not in _json(key))


def test_no_module_validation_claim():
    print("No fabricated certification claim:")
    bom = cbom_cases.build_case("02_pqc_kem")
    component = _component(bom, "ML-KEM")
    algorithm = component["cryptoProperties"]["algorithmProperties"]
    check("no certificationLevel field", "certificationLevel" not in algorithm)
    check("no certification claim in properties",
          "fips140" not in _json(bom).lower())
    check("limitations explicitly disclaim module validation",
          "fips 140" in _props(component)["piquachu:limitations"].lower())


def test_cli_cbom_consistency():
    print("CLI CBOM output:")
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        source = os.path.join(tmp, "kem.py")
        with open(source, "w", encoding="utf-8") as fh:
            fh.write('import oqs\nkem = oqs.KeyEncapsulation("ML-KEM-768")\n')
        out = os.path.join(tmp, "cbom.json")
        proc = subprocess.run(
            [sys.executable, "cipher_cli.py", "cbom", tmp, "--output", out],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            capture_output=True, text=True, timeout=120,
        )
        check("CLI cbom exit 0", proc.returncode == 0, proc.stderr[-400:])
        with open(out, encoding="utf-8") as fh:
            bom = json.load(fh)
        check("CLI cbom specVersion", bom["specVersion"] == "1.7")
        check("CLI cbom ML-KEM asset", _component(bom, "ML-KEM") is not None)
        check("CLI cbom schema valid", cbom.validate_cbom(bom) is None)


def test_committed_fixtures():
    print("Committed fixture BOMs:")
    if not os.path.isdir(FIXTURE_DIR):
        check("fixture directory exists", False, FIXTURE_DIR)
    files = sorted(f for f in os.listdir(FIXTURE_DIR) if f.endswith(".json"))
    check("fixture BOMs present", len(files) >= len(cbom_cases.CASES), files)
    for filename in files:
        path = os.path.join(FIXTURE_DIR, filename)
        with open(path, encoding="utf-8") as fh:
            bom = json.load(fh)
        check(f"fixture schema valid: {filename}", cbom.validate_cbom(bom) is None)
        check(f"fixture specVersion: {filename}", bom["specVersion"] == "1.7")


def main():
    print("=" * 68)
    print("PiQuaChu CycloneDX 1.7 CBOM tests")
    print("=" * 68)
    blocked = test_schema_validation()
    if blocked:
        return blocked
    test_envelope()
    test_components_and_evidence()
    test_paths_and_secrets()
    test_policy_findings_are_not_cves()
    test_pqc_assets()
    test_fips206_is_not_finalized()
    test_duplicate_and_empty_inputs()
    test_no_module_validation_claim()
    test_cli_cbom_consistency()
    test_committed_fixtures()
    print("=" * 68)
    print(f"ALL {len(PASSED)} CHECKS PASSED ✅")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    sys.exit(main())
