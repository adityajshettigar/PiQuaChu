#!/usr/bin/env python3
# backend/test_extras.py
"""
test_extras.py — tests for the roadmap batch: expanded detection rules,
weighted risk scoring, taint tracking, version-aware dependency scanning,
SSH/PKCS#12 key material, the AST-based remediation patcher (Python + Java),
and FIPS 206 (FN-DSA) detection.

Run:  venv/bin/python test_extras.py   (no pytest required)
"""

import base64
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import compliance  # noqa: E402
import deps  # noqa: E402
import keyfiles  # noqa: E402
import patcher  # noqa: E402
import scanner  # noqa: E402

PASSED = []


def check(name, condition, detail=""):
    if not condition:
        raise AssertionError(f"FAILED: {name} {detail}")
    PASSED.append(name)
    print(f"  ✓ {name}")


def _write_tree(root: str, files: dict):
    for rel, content in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(rel) else None
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)


# ---------------------------------------------------------------------------
# Rule metadata growth
# ---------------------------------------------------------------------------

def test_rule_metadata_growth():
    meta = compliance.load_rule_metadata()
    check("rule count grew to >= 90", len(meta) >= 90, f"got {len(meta)}")
    for rid in ("deprecated-ecb-python", "deprecated-cbc-static-iv-python",
                "deprecated-static-salt-python", "weak-randomness-python",
                "taint-secret-weak-algorithm-python", "deprecated-ecb-java",
                "deprecated-static-iv-js", "weak-randomness-js", "weak-randomness-go",
                "deprecated-c-ecb", "deprecated-ecb-php", "deprecated-pkcs1v15-python",
                "deprecated-tls-protocols-config", "dependency-vulnerable-version",
                "dependency-transitive-legacy-crypto-lib",
                "pqc-fndsa-python", "pqc-hybrid-ssh-kex-config",
                "deprecated-ssh-kex-config"):
        check(f"rule present: {rid}", rid in meta, meta.keys())
    # New advisory buckets must be tracked.
    check("kdf bucket tracked", "kdf" in compliance.ADVISORY_BUCKETS)
    check("randomness bucket tracked", "randomness" in compliance.ADVISORY_BUCKETS)


# ---------------------------------------------------------------------------
# Weighted risk score
# ---------------------------------------------------------------------------

def test_risk_score():
    empty = compliance.analyze_compliance([])
    check("empty scan risk 0/low", empty["risk_score"] == 0 and empty["risk_level"] == "low")

    meta = compliance.load_rule_metadata()
    rsa = compliance.analyze_compliance([
        {"vulnerability": "deprecated-rsa-java", "severity": "ERROR",
         "file": "a.java", "line": 1}], metadata=meta)
    sha1 = compliance.analyze_compliance([
        {"vulnerability": "weak-crypto-java-sha1", "severity": "WARNING",
         "file": "a.java", "line": 1}], metadata=meta)
    check("RSA risk > SHA-1 risk (weighting)",
          rsa["risk_score"] > sha1["risk_score"], f"{rsa['risk_score']} vs {sha1['risk_score']}")
    check("RSA single finding is high risk",
          rsa["risk_score"] >= 10 and rsa["risk_level"] in ("medium", "high", "critical"),
          f"{rsa['risk_score']} {rsa['risk_level']}")
    check("risk score present in summary", "weighted risk" in rsa["summary"])


# ---------------------------------------------------------------------------
# New Python AST rules + taint
# ---------------------------------------------------------------------------

def test_new_ast_rules():
    with tempfile.TemporaryDirectory() as tmp:
        _write_tree(tmp, {"misuse.py": (
            "import hashlib\nimport random\n"
            "from Crypto.Cipher import AES\n"
            "def ecb(key):\n"
            "    return AES.new(key, AES.MODE_ECB)\n"
            "def cbc(key):\n"
            "    iv = b'0123456789abcdef'\n"
            "    return AES.new(key, AES.MODE_CBC, iv)\n"
            "def derive(pw):\n"
            "    return hashlib.pbkdf2_hmac('sha256', pw, b'static-salt', 100000)\n"
            "def rng_key():\n"
            "    key = random.random()\n"
            "    return hashlib.md5(str(key).encode()).hexdigest()\n"
        )})
        vulns = {f["vulnerability"] for f in scanner.run_python_ast_scan(tmp)}
        for rid in ("deprecated-ecb-python", "deprecated-cbc-static-iv-python",
                    "deprecated-static-salt-python", "weak-randomness-python",
                    "weak-crypto-python-md5"):
            check(f"AST rule fired: {rid}", rid in vulns, vulns)
        # taint: md5(secret-key-derived value)
        check("taint rule fired", "taint-secret-weak-algorithm-python" in vulns, vulns)


# ---------------------------------------------------------------------------
# Version-aware dependency scanning
# ---------------------------------------------------------------------------

def test_deps_version_and_transitive():
    with tempfile.TemporaryDirectory() as tmp:
        _write_tree(tmp, {
            "requirements.txt": "node-forge==1.2.9\ncryptography==42.0.5\nliboqs-python>=0.10\n",
            "package-lock.json": (
                '{"name":"app","lockfileVersion":3,"packages":{'
                '"node_modules/node-forge":{"version":"1.2.9"},'
                '"node_modules/circl":{"version":"1.0.0"}}}'),
        })
        findings = deps.scan_target(tmp)
        vulns = {f["vulnerability"] for f in findings}
        check("vulnerable version flagged", "dependency-vulnerable-version" in vulns, vulns)
        check("transitive lockfile flagged", "dependency-transitive-legacy-crypto-lib" in vulns, vulns)
        check("PQC lib positive", "dependency-pqc-lib" in vulns, vulns)
        # cryptography 42.0.5 is >= 42.0.2 → NOT vulnerable
        vuln = [f for f in findings if f["vulnerability"] == "dependency-vulnerable-version"]
        check("cryptography 42.0.5 not flagged", all("cryptography" not in f["recommendation"] for f in vuln))


def test_deps_version_clean():
    with tempfile.TemporaryDirectory() as tmp:
        _write_tree(tmp, {"requirements.txt": "node-forge==1.3.1\n"})
        findings = deps.scan_target(tmp)
        check("patched version not flagged",
              not any(f["vulnerability"] == "dependency-vulnerable-version" for f in findings))


# ---------------------------------------------------------------------------
# Transport config evidence (pqc-flow-inspired SSH / TLS hybrid detection)
# ---------------------------------------------------------------------------

def test_ssh_hybrid_kex_detection():
    with tempfile.TemporaryDirectory() as tmp:
        _write_tree(tmp, {
            "sshd_config": "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256\n",
            "ssh_config": "KexAlgorithms curve25519-sha256\n",
        })
        findings = scanner.run_aux_scan(tmp)
        rules = {f["vulnerability"] for f in findings}
        check("ssh hybrid KEX detected", "pqc-hybrid-ssh-kex-config" in rules, rules)
        check("classical-only ssh KEX flagged", "deprecated-ssh-kex-config" in rules, rules)


def test_fips206_positive_detection():
    """Positive FIPS 206 (FN-DSA) detection through the full scanner — guards
    against silent rule breakage that the risk-only benchmark cannot catch."""
    with tempfile.TemporaryDirectory() as tmp:
        _write_tree(tmp, {
            "fndsa.py": (
                "import oqs\n\n"
                "def demo():\n"
                "    with oqs.Signature(\"Falcon-512\") as s:\n"
                "        return s.generate_keypair()\n"
            ),
        })
        result = scanner.scan_directory(tmp)
        findings = result.get("findings", [])
        rules = {f["vulnerability"] for f in findings}
        check("pqc-fndsa-python fired", "pqc-fndsa-python" in rules, rules)
        matrix = result.get("compliance", {})
        check("FIPS 206 detected_in_development in matrix",
              matrix.get("standards", {}).get("FIPS 206", {}).get("status")
              == "detected_in_development",
              matrix.get("standards", {}))


def test_fips206_detection_all_standards():
    """Positive rules for every standard (203/204/205/206) must fire on literal
    usage — the benchmark only requires no-risk for COMPLIANT cases, so this
    is the layer that actually proves detection."""
    with tempfile.TemporaryDirectory() as tmp:
        _write_tree(tmp, {
            "pq.py": (
                "import oqs\n"
                "with oqs.KeyEncapsulation(\"ML-KEM-768\") as kem:\n"
                "    kem.generate_keypair()\n"
                "with oqs.Signature(\"ML-DSA-65\") as s:\n"
                "    s.generate_keypair()\n"
                "with oqs.Signature(\"SLH-DSA-SHA2-128s\") as s2:\n"
                "    s2.generate_keypair()\n"
                "with oqs.Signature(\"Falcon-512\") as s3:\n"
                "    s3.generate_keypair()\n"
            ),
        })
        result = scanner.scan_directory(tmp)
        rules = {f["vulnerability"] for f in result.get("findings", [])}
        for rid in ("pqc-mlkem-python", "pqc-mldsa-python", "pqc-slhdsa-python",
                    "pqc-fndsa-python"):
            check(f"positive rule fired: {rid}", rid in rules, rules)


# ---------------------------------------------------------------------------
# SSH / PKCS#12 key material
# ---------------------------------------------------------------------------

def test_keyfiles_ssh_and_pkcs12():
    with tempfile.TemporaryDirectory() as tmp:
        openssh = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + base64.b64encode(b"openssh-key-v1\x00\x00\x00\x00ssh-rsa\x00\x00").decode()
            + "\n-----END OPENSSH PRIVATE KEY-----\n"
        )
        p12 = bytes.fromhex("30820305020103300d06092a864886f70d0101010500")
        _write_tree(tmp, {
            "id_rsa": openssh,
            "authorized_keys": "ssh-rsa AAAAB3NzaC1yc2E deploy@ci\n",
            "deploy.ppk": "PuTTY-User-Key-File-2: ssh-ed25519\n",
        })
        with open(os.path.join(tmp, "cert.p12"), "wb") as fh:
            fh.write(p12)
        findings = keyfiles.scan_target(tmp)
        rules = {f["vulnerability"] for f in findings}
        names = {os.path.basename(f["file"]) for f in findings}
        check("OpenSSH RSA private key", "id_rsa" in names and rules == rules, f"{names} {rules}")
        check("RSA key material present", "key-file-rsa" in rules, rules)
        check("EC key material present", "key-file-ec" in rules, rules)
        check("PKCS12 container detected", "cert.p12" in names, names)
        check("PuTTY key detected", "deploy.ppk" in names, names)
        check("authorized_keys detected", "authorized_keys" in names, names)


# ---------------------------------------------------------------------------
# AST patcher
# ---------------------------------------------------------------------------

def test_patcher_rewrites():
    """Phase 3 semantics: safe rewrites apply by default; digest swaps and
    type-changing RNG swaps are CONDITIONAL CANDIDATES (review-gated)."""
    src = (
        "import hashlib\nimport random\n"
        "def h(d):\n"
        "    return hashlib.md5(d).hexdigest()\n"
        "def k():\n"
        "    key = random.randbytes(16)\n"
        "    return key\n"
        "def t():\n"
        "    token = random.random()\n"
        "    return token\n"
    )
    # Default: only safe-mechanical edits are applied.
    new_src, changes = patcher.rewrite_python_source(src)
    check("default: md5 NOT rewritten (candidate)",
          "hashlib.md5(d)" in new_src and "sha256" not in new_src, new_src)
    check("default: randbytes -> token_bytes applied (safe)",
          "secrets.token_bytes(16)" in new_src, new_src)
    check("default: random.random NOT rewritten (candidate)",
          "random.random()" in new_src, new_src)
    check("secrets import added", "import secrets" in new_src)
    compile(new_src, "<patched>", "exec")
    check("default patched source compiles", True)
    check("safe change recorded",
          any(c["what"].startswith("key = secrets.token_bytes")
              and c["class"] == patcher.CLASS_SAFE for c in changes), str(changes))

    # With candidates included: md5 + type-changing RNG swap are applied and
    # still labelled as conditional candidates in the change records.
    new_src2, changes2 = patcher.rewrite_python_source(src, include_candidates=True)
    check("candidates: md5 rewritten", "hashlib.sha256(d)" in new_src2, new_src2)
    check("candidates: random.random rewritten", "secrets.token_bytes(32)" in new_src2)
    compile(new_src2, "<patched>", "exec")
    check("candidate patched source compiles", True)
    md5 = [c for c in changes2 if c["what"].startswith("hashlib.md5")]
    check("md5 labelled conditional-candidate",
          md5 and md5[0]["class"] == patcher.CLASS_CANDIDATE, str(md5))
    check("candidate records carry preconditions",
          md5 and bool(md5[0].get("preconditions")), str(md5))


def test_patcher_diff_and_apply():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "a.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("import hashlib\nx = hashlib.md5(b'a')\n")
        patch = patcher.build_patch(path, root=tmp, include_candidates=True)
        check("patch built", patch is not None)
        check("diff non-empty", patch and len(patch["diff"]) > 0)
        check("patch carries old/new hashes",
              patch and len(patch["old_sha256"]) == 64 and len(patch["new_sha256"]) == 64)
        modified = patcher.apply_patches([patch])
        check("applied in place", modified == ["a.py"])
        with open(path, encoding="utf-8") as fh:
            check("file rewritten on disk", "sha256" in fh.read())
        # Idempotence: a second build over the patched file yields no diff.
        again = patcher.build_patch(path, root=tmp, include_candidates=True)
        check("second run produces no further diff",
              again is None or not again["diff"], str(again and again["diff"]))


def test_java_patcher_rewrites():
    """Java AST patcher (javalang): digest / ECB / weak-signature / Random swaps."""
    if not patcher.JAVALANG_AVAILABLE:
        print("  (skipped — javalang not installed)")
        return
    src = (
        "import java.security.MessageDigest;\n"
        "import javax.crypto.Cipher;\n"
        "import java.security.Signature;\n"
        "import java.util.Random;\n"
        "public class A {\n"
        "  void f() throws Exception {\n"
        '    MessageDigest md = MessageDigest.getInstance("MD5");\n'
        '    Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");\n'
        '    Signature s = Signature.getInstance("SHA1withRSA");\n'
        "    Random r = new Random();\n"
        "  }\n"
        "}\n"
    )
    # Default: only safe-mechanical edits (Random -> SecureRandom).
    new_src, changes = patcher.rewrite_java_source(src)
    check("java default: md5 NOT rewritten (candidate)", '"MD5"' in new_src, new_src)
    check("java default: ECB NOT rewritten (manual-only)",
          '"AES/ECB/PKCS5Padding"' in new_src, new_src)
    check("java default: sha1withrsa NOT rewritten (candidate)",
          '"SHA1withRSA"' in new_src, new_src)
    check("java Random -> SecureRandom (safe)",
          "new java.security.SecureRandom(" in new_src, new_src)
    check("java changes recorded", len(changes) == 1, str(changes))

    # Candidates included: digest/signature swaps apply, ECB stays manual.
    new_src2, changes2 = patcher.rewrite_java_source(src, include_candidates=True)
    check("java candidates: md5 -> SHA-256", '"SHA-256"' in new_src2, new_src2)
    check("java candidates: sha1withrsa -> sha256withrsa",
          '"SHA256withRSA"' in new_src2, new_src2)
    check("java candidates: ECB still never rewritten",
          '"AES/GCM/NoPadding"' not in new_src2, new_src2)
    sig = [c for c in changes2 if c["what"].startswith("Signature")]
    check("sha256withrsa flagged as NOT a PQC migration",
          sig and "NOT" in sig[0]["detail"] and "PQC" in sig[0]["detail"], str(sig))


def test_java_patcher_des_rewrites():
    """Java AST patcher: DES/DESede/3DES transforms → AES/GCM/NoPadding."""
    if not patcher.JAVALANG_AVAILABLE:
        print("  (skipped — javalang not installed)")
        return
    src = (
        "import javax.crypto.Cipher;\n"
        "public class DesLegacy {\n"
        "  byte[] a(byte[] pt, java.security.Key k) throws Exception {\n"
        '    return Cipher.getInstance("DES/ECB/PKCS5Padding").doFinal(pt);\n'
        "  }\n"
        "  byte[] b(byte[] pt, java.security.Key k) throws Exception {\n"
        '    return Cipher.getInstance("DESede/CBC/PKCS5Padding").doFinal(pt);\n'
        "  }\n"
        "  byte[] c(byte[] pt, java.security.Key k) throws Exception {\n"
        '    return Cipher.getInstance("3DES/CBC/NoPadding").doFinal(pt);\n'
        "  }\n"
        "  byte[] bare(byte[] pt, java.security.Key k) throws Exception {\n"
        '    return Cipher.getInstance("DES").doFinal(pt);\n'
        "  }\n"
        "}\n"
    )
    # DES/3DES -> AES/GCM is MANUAL-ONLY: key material is incompatible, so a
    # textual substitution is deliberately refused — even with candidates on.
    new_src, changes = patcher.rewrite_java_source(src, include_candidates=True)
    check("des never rewritten (manual-only)", new_src == src, new_src)
    check("no AES/GCM substitution emitted", '"AES/GCM/NoPadding"' not in new_src)
    check("no changes applied", len(changes) == 0, str(changes))
    res = patcher.analyze_java_source(src, include_candidates=True)
    check("4 manual records produced", len(res["manual"]) == 4, str(res["manual"]))
    key_flags = [c for c in res["manual"] if "key material" in c.get("detail", "")]
    check("des key-incompatibility flagged", len(key_flags) == 4, str(key_flags))
    check("manual records carry follow-up steps",
          all(c.get("follow_up") for c in res["manual"]), str(res["manual"]))


def test_java_patcher_file_roundtrip():
    """End-to-end: .java file -> unified diff -> apply in place."""
    if not patcher.JAVALANG_AVAILABLE:
        print("  (skipped — javalang not installed)")
        return
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "Legacy.java")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("class L {\n"
                     "  void f() throws Exception {\n"
                     '    java.security.MessageDigest.getInstance("SHA-1");\n'
                     "  }\n"
                     "}\n")
        patch = patcher.build_patch(path, root=tmp, include_candidates=True)
        check("java patch built", patch is not None and len(patch["diff"]) > 0)
        modified = patcher.apply_patches([patch])
        check("java applied in place", modified == ["Legacy.java"])
        with open(path, encoding="utf-8") as fh:
            check("java file rewritten on disk", '"SHA-256"' in fh.read())
        again = patcher.build_patch(path, root=tmp, include_candidates=True)
        check("java idempotent (second run: no diff)",
              again is None or not again["diff"])


# ---------------------------------------------------------------------------

TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def main():
    print("=" * 64)
    print("PiQuaChu extras tests (roadmap batch)")
    print("=" * 64)
    failed = []
    for t in TESTS:
        print(f"\n[{t.__name__[5:].replace('_', ' ')}]")
        try:
            t()
        except AssertionError as exc:
            failed.append(exc)
        except Exception as exc:  # noqa: BLE001
            failed.append(f"{t.__name__} raised: {exc!r}")
    print("\n" + "=" * 64)
    if failed:
        for f in failed:
            print(f"  ✗ {f}")
        print(f"FAILED: {len(failed)} test(s)")
        print("=" * 64)
        return 1
    print(f"ALL {len(PASSED)} CHECKS PASSED ✅")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
