#!/usr/bin/env python3
# backend/test_api.py
"""
test_api.py — integration & edge-case test suite for the PiQuaChu Flask API.

Run:  venv/bin/python test_api.py   (no pytest required)

Covers: auth, zip upload scanning, zip-slip / zip-bomb / bad-archive
rejection, async remediation job polling, telemetry ingestion, assistant,
scan history, security headers, CORS policy, input caps and rate limiting.
"""

import io
import json
import os
import sqlite3
import stat
import sys
import tempfile
import time
import uuid
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import scanner  # noqa: E402
import compliance  # noqa: E402
import cbom  # noqa: E402
import baseline  # noqa: E402
import sarif  # noqa: E402
import app as api  # noqa: E402

# Point the API at a scratch database so the suite never pollutes real data.
_SCRATCH_DIR = tempfile.mkdtemp(prefix="piquachu-test-")
api.DB_PATH = os.path.join(_SCRATCH_DIR, "test.db")
api.init_db()

PASSED = []
FAILED = []

TEST_SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_samples")
AUTH = {"X-API-Key": "super-secret-key-123"}
CLIENT = api.app.test_client()


def check(name, condition, detail=""):
    if not condition:
        FAILED.append(name)
        raise AssertionError(f"FAILED: {name} {detail}")
    PASSED.append(name)
    print(f"  ✓ {name}")


def _reset_limits():
    try:
        api.limiter.reset()
    except Exception:
        pass


def _make_zip(entries: dict) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    buf.seek(0)
    return buf


def _upload_zip(entries: dict):
    return CLIENT.post(
        "/api/v1/sast-scan",
        headers=AUTH,
        data={"file": (_make_zip(entries), "sample.zip")},
        content_type="multipart/form-data",
    )


def _sample_zip() -> io.BytesIO:
    """Zip of the real test_samples fixture directory (all 5 languages)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(TEST_SAMPLES):
            for name in files:
                path = os.path.join(root, name)
                arc = os.path.relpath(path, os.path.dirname(TEST_SAMPLES))
                zf.write(path, arc)
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# Core HTTP surface
# ---------------------------------------------------------------------------

def test_home():
    _reset_limits()
    r = CLIENT.get("/")
    check("home 200", r.status_code == 200)
    check("home json service", r.get_json().get("service") == "PiQuaChu API")


def test_security_headers():
    _reset_limits()
    r = CLIENT.get("/")
    check("X-Content-Type-Options nosniff", r.headers.get("X-Content-Type-Options") == "nosniff")
    check("X-Frame-Options DENY", r.headers.get("X-Frame-Options") == "DENY")
    check("Referrer-Policy", r.headers.get("Referrer-Policy") == "no-referrer")
    check("Cache-Control no-store", r.headers.get("Cache-Control") == "no-store")


def test_cors_policy():
    _reset_limits()
    ok = CLIENT.get("/", headers={"Origin": "http://localhost:5173"})
    evil = CLIENT.get("/", headers={"Origin": "http://evil.example"})
    check("allowed origin gets ACAO", "Access-Control-Allow-Origin" in ok.headers)
    check("disallowed origin blocked", "Access-Control-Allow-Origin" not in evil.headers)


def test_auth():
    _reset_limits()
    check("no key -> 401", CLIENT.get("/api/v1/scans").status_code == 401)
    check("bad key -> 401", CLIENT.get("/api/v1/scans", headers={"X-API-Key": "nope"}).status_code == 401)
    check("good key -> 200", CLIENT.get("/api/v1/scans", headers=AUTH).status_code == 200)


def test_404_handler():
    _reset_limits()
    r = CLIENT.get("/definitely-not-a-route", headers=AUTH)
    check("404 handler", r.status_code == 404 and "Endpoint not found" in r.get_json()["error"])

# ---------------------------------------------------------------------------


# SAST zip upload
# ---------------------------------------------------------------------------

def _seed_scan():
    """Upload the fixture zip (all 5 languages). The API is async: returns 202
    with a task_id — the result arrives via polling. Returns the parsed body."""
    _reset_limits()
    r = CLIENT.post(
        "/api/v1/sast-scan", headers=AUTH,
        data={"file": (_sample_zip(), "sample.zip")},
        content_type="multipart/form-data",
    )
    check("sast 202 accepted", r.status_code == 202, r.get_json())
    check("task_id present", bool(r.get_json().get("task_id")))
    return r.get_json()


def _drain_jobs(timeout_s: float = 20.0) -> None:
    """Join background job threads before a test swaps api.DB_PATH.

    Job threads resolve api.DB_PATH at write time, so a still-running scan from
    an earlier test could otherwise write into the temporary schema while the
    migration test is asserting. Deterministic teardown, no sleeps.
    """
    deadline = time.time() + timeout_s
    for thread in list(getattr(api.job_manager, "_threads", {}).values()):
        thread.join(max(0.0, deadline - time.time()))


def _wait_scan(task_id: str, deadline_s: float = 90.0) -> dict:
    """Poll GET /api/v1/scan/<task_id> until SUCCESS/FAILED and return the result."""
    deadline = time.time() + deadline_s
    status, result = "PENDING", None
    while time.time() < deadline:
        r = CLIENT.get(f"/api/v1/scan/{task_id}", headers=AUTH)
        j = r.get_json()
        status = j["status"]
        if status in ("SUCCESS", "FAILED"):
            result = j
            break
        time.sleep(0.5)
    check("job reaches SUCCESS", status == "SUCCESS", f"final status {status}")
    return result or {}


def test_sast_scan_happy_path():
    body = _seed_scan()
    result = _wait_scan(body["task_id"])
    check("findings present", len(result.get("findings", [])) > 0)
    check("compliance matrix present", result.get("compliance", {}).get("pqc_score") is not None)
    check("scan_id present", isinstance(result.get("scan_id"), int))
    check("no temp paths leaked", not any(f.get("file", "").startswith("/") for f in result["findings"]))
    # samples contain real legacy crypto, so verdict must NOT be compliant
    check("legacy findings flagged", result["compliance"]["verdict"] in ("at_risk", "non_compliant"))
    return result


def test_sast_job_polling():
    body = _seed_scan()
    result = _wait_scan(body["task_id"])
    check("remediation plans generated", len(result.get("remediation_plans", [])) > 0)


def test_sast_unknown_job():
    _reset_limits()
    check("unknown task -> 404", CLIENT.get("/api/v1/scan/no-such-task", headers=AUTH).status_code == 404)


def test_job_column_order_migration():
    """Regression: /api/v1/scan/<id> used to 500 with "Extra data: line 1
    column 5 (char 4)" because get() did `SELECT *` and zipped it against a
    hardcoded column list. When the jobs table predates the `logs` column
    (added later via ALTER TABLE), the physical column order differs and
    every JSON field was misaligned. Explicit column selection must be
    order-independent."""
    _drain_jobs()
    scratch = tempfile.mkdtemp(prefix="piquachu-jobtest-")
    old_db = api.DB_PATH
    api.DB_PATH = os.path.join(scratch, "old_schema.db")
    try:
        conn = sqlite3.connect(api.DB_PATH)
        conn.execute(
            "CREATE TABLE jobs (id TEXT PRIMARY KEY, status TEXT, scan_id INTEGER, "
            "payload TEXT, result TEXT, created_at TEXT, updated_at TEXT)"
        )
        conn.commit()
        conn.close()
        api._migrate_jobs_logs_column()  # appends `logs` at the END of the physical order
        # The real upgrade path (init_db -> migrations) must add the Phase 4
        # tenant columns additively, keeping the legacy physical order.
        api.init_db()

        job_id = str(uuid.uuid4())
        api.job_manager.submit(job_id, 7, lambda: {"ok": True}, payload={"type": "sast"})
        deadline = time.time() + 10
        while time.time() < deadline:
            job = api.job_manager.get(job_id)
            if job and job["status"] == "SUCCESS":
                break
            time.sleep(0.2)
        job = api.job_manager.get(job_id)
        check("migrated table: no 500, job retrievable", job is not None and job["status"] == "SUCCESS", str(job)[:120])
        check("migrated table: logs parses as list", isinstance(job["logs"], list))
        check("migrated table: payload parses as dict", isinstance(job["payload"], dict))
        check("migrated table: result parses as dict", isinstance(job["result"], dict))
        check("migrated table: updated_at is a timestamp",
              isinstance(job["updated_at"], str) and "T" in job["updated_at"])
    finally:
        api.DB_PATH = old_db


def test_sast_bad_archives():
    _reset_limits()
    r = CLIENT.post(
        "/api/v1/sast-scan", headers=AUTH,
        data={"file": (io.BytesIO(b"definitely not a zip"), "junk.zip")},
        content_type="multipart/form-data",
    )
    check("garbage zip -> 400", r.status_code == 400)

    r2 = CLIENT.post(
        "/api/v1/sast-scan", headers=AUTH,
        data={"file": (io.BytesIO(b"hello"), "notes.txt")},
        content_type="multipart/form-data",
    )
    check("non-zip extension -> 400", r2.status_code == 400)

    r3 = CLIENT.post("/api/v1/sast-scan", headers=AUTH, data={}, content_type="multipart/form-data")
    check("no file -> 400", r3.status_code == 400)


def test_sast_zip_slip_rejected():
    _reset_limits()
    r = _upload_zip({"../../escape.txt": "pwned", "safe.py": "import hashlib\nhashlib.md5(b'x')\n"})
    # Rejection happens during pre-extraction validation, so nothing escapes
    # the temp extraction root; the direct safe_extract_zip unit test above
    # additionally proves no file is written outside the destination dir.
    check("zip-slip -> 413", r.status_code == 413, r.get_json())


def test_sast_entry_flood_rejected():
    _reset_limits()
    entries = {f"f{i}.py": "x = 1\n" for i in range(5001)}
    r = _upload_zip(entries)
    check("entry flood -> 413", r.status_code == 413, r.get_json())


def test_sast_unauthorized():
    _reset_limits()
    r = CLIENT.post("/api/v1/sast-scan", data={}, content_type="multipart/form-data")
    check("sast without key -> 401", r.status_code == 401)


# ---------------------------------------------------------------------------
# Telemetry ingestion
# ---------------------------------------------------------------------------

def test_compliance_check():
    _reset_limits()
    tel = {"algorithm_telemetry": [
        {"nist_standard": "FIPS 203", "category": "key-encapsulation",
         "severity": "ERROR", "verdict": "FAIL", "count": 2},
    ]}
    r = CLIENT.post("/api/v1/compliance/check", headers=AUTH, json={"telemetry": tel})
    check("telemetry accepted", r.status_code == 200 and r.get_json()["status"] == "accepted")
    check("telemetry verdict review", r.get_json()["verdict"] == "review")

    r2 = CLIENT.post("/api/v1/compliance/check", headers=AUTH, json={"telemetry": {}})
    check("bad telemetry -> 400", r2.status_code == 400)

    big = {"algorithm_telemetry": [{"verdict": "WARN", "count": 1}] * 501}
    r3 = CLIENT.post("/api/v1/compliance/check", headers=AUTH, json={"telemetry": big})
    check("telemetry cap -> 400", r3.status_code == 400)


# ---------------------------------------------------------------------------
# Assistant
# ---------------------------------------------------------------------------

def test_assistant():
    _reset_limits()
    # Seed a completed scan first — the assistant answers from the latest scan context.
    body = _seed_scan()
    _wait_scan(body["task_id"])
    r = CLIENT.post("/api/v1/assistant/query", headers=AUTH,
                    json={"question": "What is the recommended Dilithium parameter set?"})
    check("assistant 200", r.status_code == 200)
    check("assistant has ML-DSA knowledge", "ML-DSA-65" in r.get_json()["answer"])
    check("empty question -> 400",
          CLIENT.post("/api/v1/assistant/query", headers=AUTH, json={"question": "  "}).status_code == 400)
    check("oversized question -> 413",
          CLIENT.post("/api/v1/assistant/query", headers=AUTH,
                      json={"question": "x" * 3000}).status_code == 413)


# ---------------------------------------------------------------------------
# Scanner engine & archive hardening units
# ---------------------------------------------------------------------------

def test_semgrep_binary_located():
    path = scanner.find_semgrep_binary()
    check("semgrep binary located", path is not None and os.path.isfile(path))


def test_language_detection_and_templates():
    import remediation
    check("js -> javascript", remediation.detect_language("src/a.js") == "javascript")
    check("ts -> typescript", remediation.detect_language("src/a.ts") == "typescript")
    check("py -> python", remediation.detect_language("src/a.py") == "python")
    check("java -> java", remediation.detect_language("src/A.java") == "java")
    check("go -> go", remediation.detect_language("src/a.go") == "go")
    check("c -> c", remediation.detect_language("src/a.c") == "c")
    check("no ext -> unknown", remediation.detect_language("Makefile") == "unknown")

    meta = compliance.load_rule_metadata()
    f = compliance.enrich_finding(
        {"vulnerability": "nodejs-ecdsa-keypair", "severity": "ERROR",
         "file": "src/signer.js", "line": 4}, meta)
    plan = remediation.build_plan(f)
    check("JS FIPS 204 finding uses ML-DSA template",
          "mldsa65" in plan["replacement_code"] or "@noble/post-quantum" in plan["replacement_code"],
          plan["replacement_code"][:80])
    check("template risk is high", plan["risk"] == "high")


def test_safe_extract_benign():
    with tempfile.TemporaryDirectory() as tmp:
        zf = zipfile.ZipFile(_make_zip({"a.py": "x=1", "sub/b.py": "y=2"}), "r")
        scanner.safe_extract_zip(zf, tmp)
        check("benign zip extracted", os.path.exists(os.path.join(tmp, "sub", "b.py")))


def test_safe_extract_traversal():
    with tempfile.TemporaryDirectory() as tmp:
        zf = zipfile.ZipFile(_make_zip({"../../evil.py": "boom"}), "r")
        try:
            scanner.safe_extract_zip(zf, tmp)
            check("traversal rejected", False)
        except scanner.ZipExtractionError:
            check("traversal rejected", True)


def test_safe_extract_symlink():
    with tempfile.TemporaryDirectory() as tmp:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("link")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")
        buf.seek(0)
        try:
            scanner.safe_extract_zip(zipfile.ZipFile(buf, "r"), tmp)
            check("symlink rejected", False)
        except scanner.ZipExtractionError:
            check("symlink rejected", True)


def test_scan_all_languages():
    """Regression: with the semgrep engine active, every language fixture must
    be detected and the C positive rules must not cross-match SLH-DSA."""
    result = scanner.scan_directory(TEST_SAMPLES)
    check("engine uses semgrep", result.get("engine", "").startswith("semgrep"),
          f"got {result.get('engine')}")
    findings = result.get("findings", [])
    vulns = [f["vulnerability"] for f in findings]

    for rule in ("weak-crypto-python-md5", "deprecated-tlsv1-python",
                 "weak-crypto-java-sha1", "deprecated-des-java",
                 "nodejs-weak-crypto", "nodejs-rsa-keypair",
                 "deprecated-go-rsa", "deprecated-go-ecdsa",
                 "deprecated-c-openssl-md5", "deprecated-c-openssl-rsa"):
        check(f"negative rule fired: {rule}", rule in vulns)

    for rule in ("pqc-mlkem-python", "pqc-mldsa-python", "pqc-slhdsa-python",
                 "pqc-mlkem-java", "pqc-mldsa-java", "pqc-slhdsa-java",
                 "pqc-mlkem-js", "pqc-mldsa-js", "pqc-slhdsa-js",
                 "pqc-mlkem-go", "pqc-mldsa-go", "pqc-slhdsa-go",
                 "pqc-mlkem-c", "pqc-mldsa-c", "pqc-slhdsa-c"):
        check(f"positive rule fired: {rule}", rule in vulns, vulns)

    c_findings = [f for f in findings if "pqc_usage.c" in f.get("file", "")]
    c_mldsa = [f for f in c_findings if f["vulnerability"] == "pqc-mldsa-c"]
    c_slhdsa = [f for f in c_findings if f["vulnerability"] == "pqc-slhdsa-c"]
    check("SLH-DSA in C not miscounted as ML-DSA", len(c_mldsa) == 1 and len(c_slhdsa) == 1,
          f"mldsa={len(c_mldsa)} slhdsa={len(c_slhdsa)}")

    fips205 = [f for f in findings if f.get("nist_standard") == "FIPS 205"]
    check("FIPS 205 evidence only from SLH-DSA rules",
          all("slh" in f["vulnerability"] or "sphincs" in f["vulnerability"] for f in fips205))


def test_telemetry_privacy():
    meta = compliance.load_rule_metadata()
    tel = compliance.build_telemetry([
        {"vulnerability": "deprecated-rsa-java", "severity": "ERROR",
         "file": "secret_project/src/keys/KeyStore.java", "line": 9},
    ], metadata=meta)
    check("no source paths in telemetry",
          "secret_project" not in str(tel) and "KeyStore" not in str(tel))


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def test_cbom_endpoint():
    """GET /api/v1/scans/{id}/cbom returns a schema-valid CycloneDX 1.7 BOM."""
    findings = [
        {"vulnerability": "pqc-mlkem-python", "severity": "INFO",
         "file": "src/kem.py", "line": 4,
         "line_text": 'oqs.KeyEncapsulation("ML-KEM-768")'},
        {"vulnerability": "deprecated-rsa-python-cryptography", "severity": "ERROR",
         "file": "src/rsa.py", "line": 9},
    ]
    matrix = compliance.analyze_compliance(findings)
    conn = api._connect()
    cur = conn.execute(
        "INSERT INTO scan_history (timestamp, filename, pqc_score, verdict, "
        "compliance_json, findings_json) VALUES (?, ?, ?, ?, ?, ?)",
        ("2026-10-18T00:00:00", "sample.zip", matrix["pqc_score"],
         matrix["verdict"], json.dumps(matrix), json.dumps(findings)),
    )
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()

    r = CLIENT.get(f"/api/v1/scans/{scan_id}/cbom", headers=AUTH)
    check("cbom 200", r.status_code == 200, r.status_code)
    bom = r.get_json()
    check("cbom specVersion 1.7", bom.get("specVersion") == "1.7", bom.get("specVersion"))
    check("cbom asset components",
          all(c.get("type") == "cryptographic-asset" for c in bom.get("components", [])))
    check("cbom has PQC asset",
          any(c.get("name") == "ML-KEM" for c in bom.get("components", [])))
    check("cbom has no absolute paths",
          "/home/" not in json.dumps(bom) and "/tmp/" not in json.dumps(bom))
    try:
        cbom.validate_cbom(bom)
        check("cbom endpoint artifact schema valid", True)
    except cbom.CbomValidationUnavailable as exc:
        print(f"  (skipped schema validation — {exc})")

    unauth = CLIENT.get(f"/api/v1/scans/{scan_id}/cbom")
    check("cbom unauthorized", unauth.status_code == 401, unauth.status_code)
    missing = CLIENT.get("/api/v1/scans/999999/cbom", headers=AUTH)
    check("cbom unknown scan", missing.status_code == 404, missing.status_code)


def test_rate_limit():
    _reset_limits()
    codes = []
    for _ in range(31):
        codes.append(CLIENT.post("/api/v1/compliance/check", headers=AUTH,
                                 json={"telemetry": {"algorithm_telemetry": []}}).status_code)
    check("compliance/check rate limited after 30/hour", 429 in codes, str(codes))

    # The new SARIF endpoint declares its own limit; prove it is enforced.
    _reset_limits()
    conn = api._connect()
    cur = conn.execute(
        "INSERT INTO scan_history (timestamp, filename, pqc_score, verdict, "
        "compliance_json, findings_json) VALUES (?, ?, ?, ?, ?, ?)",
        ("2026-10-20T00:00:00", "rate.zip", 90, "compliant", "{}", "[]"),
    )
    sarif_scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    sarif_codes = [CLIENT.get(f"/api/v1/scans/{sarif_scan_id}/sarif",
                              headers=AUTH).status_code for _ in range(61)]
    check("sarif endpoint serves a valid scan", sarif_codes[0] == 200, sarif_codes[:3])
    check("sarif endpoint rate limited", 429 in sarif_codes,
          f"429 never returned in {len(sarif_codes)} calls")
    _reset_limits()


# ---------------------------------------------------------------------------
# Phase 3: baseline upload -> delta + gate, SARIF export
# ---------------------------------------------------------------------------

LEGACY_FIXTURE = {
    "src/crypto.py": (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "import hashlib\n"
        "\n"
        "\n"
        "def keypair():\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "\n"
        "\n"
        "def digest(data):\n"
        "    return hashlib.md5(data).hexdigest()\n"
    ),
}


def _upload_with(entries: dict, *, form: dict | None = None,
                 baseline_doc=None):
    data = {"file": (_make_zip(entries), "sample.zip")}
    if form:
        data.update(form)
    if baseline_doc is not None:
        raw = (baseline_doc if isinstance(baseline_doc, bytes)
               else json.dumps(baseline_doc).encode("utf-8"))
        data["baseline"] = (io.BytesIO(raw), "baseline.json")
    return CLIENT.post("/api/v1/sast-scan", headers=AUTH, data=data,
                       content_type="multipart/form-data")


def test_baseline_gate_and_sarif():
    """Baseline upload -> new/persistent delta -> deterministic gate; SARIF 2.1.0."""
    _reset_limits()

    # 1) No baseline, fail_on=new-high: the RSA (ERROR) finding must fail the gate.
    r = _upload_with(LEGACY_FIXTURE, form={"fail_on": "new-high"})
    check("baseline scan accepted", r.status_code == 202, r.get_json())
    first = _wait_scan(r.get_json()["task_id"])
    check("gate returned with result", isinstance(first.get("gate"), dict), list(first))
    check("no-baseline delta mode",
          first["baseline_delta"]["mode"] == "no-baseline", first["baseline_delta"]["mode"])
    check("new-high gate triggers on new ERROR finding",
          first["gate"]["triggered"] is True, first["gate"]["failures"])
    check("sarif_url published", first.get("sarif_url", "").endswith("/sarif"))
    check("baseline has no absolute paths",
          "/tmp/" not in json.dumps(first["baseline_delta"]))

    # 2) Same code + committed baseline: nothing is new, so a new-findings gate
    #    must pass even though the aggregate score is unchanged/bad.
    baseline_doc = baseline.build_baseline(first["findings"])
    _reset_limits()
    r = _upload_with(LEGACY_FIXTURE, form={"fail_on": "new-high"},
                     baseline_doc=baseline_doc)
    check("baseline re-scan accepted", r.status_code == 202, r.get_json())
    second = _wait_scan(r.get_json()["task_id"])
    counts = second["baseline_delta"]["counts"]
    check("baseline: zero new findings", counts["new"] == 0, counts)
    check("baseline: findings persist", counts["persistent"] >= 2, counts)
    check("baseline: existing issue does not fail gate",
          second["gate"]["triggered"] is False, second["gate"])

    # 3) Introduce SHA-1: one new WARNING. new-high stays green, new-warning fails.
    grown = dict(LEGACY_FIXTURE)
    grown["src/crypto.py"] = LEGACY_FIXTURE["src/crypto.py"] + (
        "\n\ndef weak(data):\n    return hashlib.sha1(data).hexdigest()\n")
    _reset_limits()
    r = _upload_with(grown, form={"fail_on": "new-high"}, baseline_doc=baseline_doc)
    check("grown scan accepted", r.status_code == 202, r.get_json())
    third = _wait_scan(r.get_json()["task_id"])
    check("grown code adds one new finding",
          third["baseline_delta"]["counts"]["new"] == 1,
          third["baseline_delta"]["counts"])
    check("new-high gate ignores new WARNING", third["gate"]["triggered"] is False)

    _reset_limits()
    r = _upload_with(grown, form={"fail_on": "new-warning"}, baseline_doc=baseline_doc)
    check("grown warning scan accepted", r.status_code == 202, r.get_json())
    fourth = _wait_scan(r.get_json()["task_id"])
    check("new-warning gate fails on new WARNING",
          fourth["gate"]["triggered"] is True, fourth["gate"])

    # 4) Suppression in the baseline: a waived finding is reported, not gated.
    suppressed_doc = dict(baseline_doc)
    suppressed_doc["suppressions"] = [{
        "kind": "rule-file",
        "rule_id": "weak-crypto-python-md5",
        "path": "src/crypto.py",
        "rationale": "Legacy cache key only; tracked in SEC-1042 for removal.",
        "expires": "2027-06-30",
    }]
    _reset_limits()
    r = _upload_with(LEGACY_FIXTURE, form={"fail_on": "new-warning"},
                     baseline_doc=suppressed_doc)
    check("suppressed scan accepted", r.status_code == 202, r.get_json())
    fifth = _wait_scan(r.get_json()["task_id"])
    check("suppressed finding is counted",
          fifth["baseline_delta"]["counts"]["suppressed"] == 1,
          fifth["baseline_delta"]["counts"])
    check("suppressed finding never fails the gate",
          fifth["gate"]["triggered"] is False and not any(
              f.get("rule_id") == "weak-crypto-python-md5"
              for f in fifth["gate"]["failures"]), fifth["gate"])

    # 5) SARIF export (persisted baseline status travels with the scan).
    scan_id = second["scan_id"]
    r = CLIENT.get(f"/api/v1/scans/{scan_id}/sarif", headers=AUTH)
    check("sarif 200", r.status_code == 200, r.status_code)
    check("sarif content type", "sarif" in r.headers.get("Content-Type", "").lower(),
          r.headers.get("Content-Type"))
    doc = r.get_json()
    errors = sarif.validate_sarif(doc)
    check("sarif schema valid", errors == [], errors[:3])
    check("sarif results present", len(doc["runs"][0]["results"]) >= 2)
    check("sarif driver is PiQuaChu",
          doc["runs"][0]["tool"]["driver"]["name"] == "PiQuaChu")
    check("sarif carries baseline status",
          any(res["properties"].get("baselineStatus")
              for res in doc["runs"][0]["results"]))
    blob = json.dumps(doc)
    check("sarif has no host paths", "/home/" not in blob and "/tmp/" not in blob)
    check("sarif has no source snippets",
          "hasattr" not in blob and "generate_private_key(public_exponent" not in blob)

    # 6) Auth / unknown scan / strict upload validation.
    check("sarif unauthorized",
          CLIENT.get(f"/api/v1/scans/{scan_id}/sarif").status_code == 401)
    check("sarif unknown scan",
          CLIENT.get("/api/v1/scans/999999/sarif", headers=AUTH).status_code == 404)
    _reset_limits()
    bad_json = _upload_with(LEGACY_FIXTURE, baseline_doc=b"{not json")
    check("corrupt baseline rejected 400", bad_json.status_code == 400, bad_json.status_code)
    _reset_limits()
    bad_schema = _upload_with(LEGACY_FIXTURE,
                              baseline_doc={"schema_version": 99, "findings": []})
    check("unsupported baseline schema rejected 400", bad_schema.status_code == 400,
          bad_schema.status_code)
    _reset_limits()
    broad = dict(baseline_doc)
    broad["suppressions"] = [{"kind": "rule-file", "rule_id": "weak-crypto-python-md5",
                              "path": "*", "rationale": "x" * 20,
                              "expires": "2027-01-01"}]
    too_broad = _upload_with(LEGACY_FIXTURE, baseline_doc=broad)
    check("wildcard suppression rejected 400", too_broad.status_code == 400,
          too_broad.status_code)
    _reset_limits()
    bad_policy = _upload_with(LEGACY_FIXTURE, form={"fail_on": "bogus-policy"})
    check("invalid fail_on rejected 400", bad_policy.status_code == 400,
          bad_policy.status_code)


def test_scan_history_baseline_column_migration():
    """Pre-Phase-3 scan_history tables gain baseline_json; legacy rows still
    produce SARIF (NULL baseline must not be treated as an empty/clean delta)."""
    _drain_jobs()
    scratch = tempfile.mkdtemp(prefix="piquachu-baseline-mig-")
    old_db = api.DB_PATH
    api.DB_PATH = os.path.join(scratch, "old_schema.db")
    try:
        conn = sqlite3.connect(api.DB_PATH)
        conn.execute(
            "CREATE TABLE scan_history (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "timestamp TEXT, filename TEXT, pqc_score INTEGER, verdict TEXT, "
            "compliance_json TEXT, findings_json TEXT)"
        )
        conn.execute(
            "INSERT INTO scan_history (timestamp, filename, pqc_score, verdict, "
            "compliance_json, findings_json) VALUES (?, ?, ?, ?, ?, ?)",
            ("2026-10-01T00:00:00", "legacy.zip", 40, "at_risk",
             json.dumps({"pqc_score": 40, "verdict": "at_risk"}),
             json.dumps([{"vulnerability": "weak-crypto-python-md5",
                          "severity": "WARNING", "file": "a.py", "line": 3,
                          "fingerprint": "h=0123456789ab"}])),
        )
        conn.commit()
        conn.close()

        api.init_db()  # additive upgrade path (tenant columns) — never recreates
        api._migrate_scan_baseline_column()
        api._migrate_scan_baseline_column()  # idempotent
        conn = api._connect()
        cols = [r[1] for r in conn.execute("PRAGMA table_info(scan_history)").fetchall()]
        conn.close()
        check("baseline_json column migrated", "baseline_json" in cols, cols)

        r = CLIENT.get("/api/v1/scans/1/sarif", headers=AUTH)
        check("legacy row sarif 200", r.status_code == 200, r.status_code)
        doc = r.get_json()
        check("legacy row sarif valid", sarif.validate_sarif(doc) == [])
        check("legacy row has no fabricated baseline status",
              all("baselineStatus" not in res.get("properties", {})
                  for res in doc["runs"][0]["results"]))
    finally:
        api.DB_PATH = old_db


# ---------------------------------------------------------------------------

TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def main():
    print("=" * 64)
    print("PiQuaChu API integration & edge-case tests")
    print("=" * 64)
    for t in TESTS:
        name = t.__name__[5:].replace("_", " ")
        print(f"\n[{name}]")
        try:
            t()
        except AssertionError as exc:
            print(f"  ✗ {exc}")
        except Exception as exc:  # noqa: BLE001
            FAILED.append(t.__name__)
            print(f"  ✗ {t.__name__} raised: {exc!r}")
    print("\n" + "=" * 64)
    if FAILED:
        print(f"FAILED: {len(FAILED)} test(s) — {FAILED}")
        print("=" * 64)
        return 1
    print(f"ALL {len(PASSED)} CHECKS PASSED ✅")
    print("=" * 64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
