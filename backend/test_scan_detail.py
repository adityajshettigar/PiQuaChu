#!/usr/bin/env python3
"""
test_scan_detail.py — stored scan retrieval + scan-scoped assistant

Covers the contract the frontend depends on:
  * GET /api/v1/scans/<id> returns the durable scan row (findings,
    compliance, remediation plans) rather than a transient job record.
  * The lookup is tenant-scoped: another tenant's id is a 404, never a leak.
  * POST /api/v1/assistant/query honours an explicit scan_id and rejects
    foreign or unknown ids instead of silently using the latest scan.
"""
import io
import json
import os
import sys
import tempfile
import time
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import app as api  # noqa: E402
import authz  # noqa: E402

_SCRATCH = tempfile.mkdtemp(prefix="piquachu-scan-detail-")


@pytest.fixture(scope="module", autouse=True)
def scratch_database():
    """Point the API at this module's database, then restore the previous path.

    Import-time mutation would break other suites that share the `app` module.
    """
    previous = api.DB_PATH
    api.DB_PATH = os.path.join(_SCRATCH, "test.db")
    api.init_db()
    try:
        yield
    finally:
        api.DB_PATH = previous


AUTH = {"X-API-Key": "super-secret-key-123"}
client = api.app.test_client()


SAMPLE = """\
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

def legacy(data):
    return hashlib.md5(data).hexdigest()

def keys():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
"""


def _zip_bytes() -> io.BytesIO:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("app/crypto.py", SAMPLE)
    buffer.seek(0)
    return buffer


@pytest.fixture(scope="module")
def completed_scan():
    api.limiter.reset()
    upload = client.post(
        "/api/v1/sast-scan",
        headers=AUTH,
        data={"file": (_zip_bytes(), "crypto.zip")},
        content_type="multipart/form-data",
    )
    assert upload.status_code == 202, upload.get_data(as_text=True)
    task_id = upload.get_json()["task_id"]

    deadline = time.time() + 90
    while time.time() < deadline:
        poll = client.get(f"/api/v1/scan/{task_id}", headers=AUTH)
        assert poll.status_code == 200
        body = poll.get_json()
        if body["status"] == "SUCCESS":
            assert body["scan_id"]
            return body
        if body["status"] in {"FAILED", "TIMEOUT"}:
            pytest.fail(f"scan failed: {body.get('error')}")
        time.sleep(0.4)
    pytest.fail("scan did not finish in 90s")


def test_requires_authentication():
    response = client.get("/api/v1/scans/1")
    assert response.status_code == 401


def test_returns_the_stored_scan(completed_scan):
    scan_id = completed_scan["scan_id"]
    response = client.get(f"/api/v1/scans/{scan_id}", headers=AUTH)
    assert response.status_code == 200
    body = response.get_json()

    assert body["scan_id"] == scan_id
    assert body["filename"] == "crypto.zip"
    assert isinstance(body["findings"], list) and body["findings"]
    # The remediation plans are joined through the persisted finding rows, which
    # is what makes them reachable after a reload.
    assert isinstance(body["remediation_plans"], list)
    assert body["counts"]["findings"] == len(body["findings"])
    assert body["counts"]["remediation_plans"] == len(body["remediation_plans"])
    assert body["compliance"]["verdict"]
    assert "risk_score" in body["compliance"]


def test_corrupt_json_does_not_500():
    scan_id = client.get("/api/v1/scans", headers=AUTH).get_json()["scans"][0]["id"]
    connection = api._connect()
    try:
        connection.execute(
            "UPDATE scan_history SET compliance_json='{not json' WHERE id=?", (scan_id,)
        )
        connection.commit()
    finally:
        connection.close()

    response = client.get(f"/api/v1/scans/{scan_id}", headers=AUTH)
    assert response.status_code == 200
    assert response.get_json()["compliance"] == {}


def test_unknown_scan_is_404():
    response = client.get("/api/v1/scans/999999", headers=AUTH)
    assert response.status_code == 404


def test_another_tenants_scan_is_indistinguishable_from_unknown():
    authz.create_tenant("detail-acme", "Detail ACME")
    other = authz.create_key("detail-acme", "reader", role="analyst")

    connection = api._connect()
    try:
        cursor = connection.execute(
            "INSERT INTO scan_history (timestamp, filename, pqc_score, verdict, "
            "compliance_json, findings_json, tenant_id) VALUES "
            "('2026-10-20T00:00:00Z', 'foreign.zip', 50, 'partial', '{}', '[]', ?)",
            ("detail-acme",),
        )
        foreign_id = cursor.lastrowid
        connection.commit()
    finally:
        connection.close()

    headers = {"X-API-Key": other["api_key"]}
    assert client.get(f"/api/v1/scans/{foreign_id}", headers=headers).status_code == 200

    # The local/legacy key belongs to the `local` tenant and must not see it.
    assert client.get(f"/api/v1/scans/{foreign_id}", headers=AUTH).status_code == 404


def test_assistant_uses_the_requested_scan(completed_scan):
    scan_id = completed_scan["scan_id"]
    response = client.post(
        "/api/v1/assistant/query",
        headers={**AUTH, "Content-Type": "application/json"},
        data=json.dumps({"question": "What should I fix first?", "scan_id": scan_id}),
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["has_context"] is True
    assert body["scan_id"] == scan_id
    assert isinstance(body["answer"], str) and body["answer"]


def test_assistant_rejects_unknown_scan():
    response = client.post(
        "/api/v1/assistant/query",
        headers={**AUTH, "Content-Type": "application/json"},
        data=json.dumps({"question": "hello", "scan_id": 999999}),
    )
    assert response.status_code == 404


def test_assistant_rejects_malformed_scan_id():
    response = client.post(
        "/api/v1/assistant/query",
        headers={**AUTH, "Content-Type": "application/json"},
        data=json.dumps({"question": "hello", "scan_id": "1; DROP TABLE scans"}),
    )
    assert response.status_code == 400
