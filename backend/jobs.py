# backend/jobs.py
"""
jobs.py — shared background job pipelines for PiQuaChu
=======================================================
Used by BOTH execution backends so the work is byte-identical:

  1. In-process thread dispatcher (default) — JobManager spawns a daemon
     thread per job.
  2. Optional Celery worker (production scaling) — set PIQUACHU_BROKER_URL
     (e.g. redis://localhost:6379/0) and run `celery -A tasks worker`.

Tenant safety (Phase 4)
-----------------------
A worker never trusts the message it receives. Before doing any work it loads
the persisted job row and:

  * refuses to run if the row does not exist,
  * takes the tenant from the ROW (DB is the source of truth),
  * refuses if the payload claims a different tenant (tampered broker message),
  * refuses payload paths outside the server-created upload directory,

and every write is attributed to that validated tenant. Status transitions and
log streaming are handled by app.job_manager (SQLite WAL).
"""

import json
import logging
import os
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone

import audit
import baseline
import metrics
import scanner

# app is imported at module load; it never imports this module at the top
# level (only lazily inside JobManager.submit), so there is no import cycle.
import app as _app

UPLOAD_PREFIX = "piquachu-upload-"


class JobFailure(Exception):
    """Raised inside a job to surface a clean error message to the client."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_job_context(job_id: str, payload: dict) -> tuple[str, str | None]:
    """Load the persisted row and derive the authoritative tenant context."""
    job = _app.job_manager.get(job_id)
    if job is None:
        raise JobFailure("Job record not found")
    tenant_id = job.get("tenant_id")
    if not tenant_id:
        raise JobFailure("Job has no tenant context")
    claimed = payload.get("tenant_id")
    if claimed and claimed != tenant_id:
        raise JobFailure("Tenant context mismatch — refusing to run this job")
    return tenant_id, job.get("principal_id")


def _validate_job_paths(payload: dict) -> tuple[str, str]:
    """Refuse payload paths that are not server-created upload directories.

    Protects against a tampered Celery message (or a corrupted row) pointing
    the worker at an arbitrary filesystem path.
    """
    temp_dir = payload.get("temp_dir")
    zip_path = payload.get("zip_path")
    if not temp_dir or not zip_path:
        raise JobFailure("Job is missing its upload paths")
    real_temp = os.path.realpath(temp_dir)
    real_zip = os.path.realpath(zip_path)
    root = os.path.realpath(tempfile.gettempdir())
    if os.path.dirname(real_temp) != root:
        raise JobFailure("Job temp directory is outside the upload root")
    if not os.path.basename(real_temp).startswith(UPLOAD_PREFIX):
        raise JobFailure("Job temp directory is not a PiQuaChu upload directory")
    if os.path.dirname(real_zip) != real_temp:
        raise JobFailure("Job archive is outside its upload directory")
    return real_temp, real_zip


def resume_if_complete(job_id: str) -> dict | None:
    """Return the stored result of an already-successful job, else None.

    Celery uses at-least-once delivery (`acks_late`): if the worker dies after
    writing the scan but before (or while) the acknowledgement is sent, the
    broker redelivers the same message. Re-running the pipeline would insert a
    second scan row, so a completed job is answered from its persisted row.
    """
    job = _app.job_manager.get(job_id)
    if not job or job.get("status") != "SUCCESS":
        return None
    result = job.get("result")
    if isinstance(result, dict) and result.get("scan_id"):
        return result
    return None


def resume_committed_scan(job_id: str, payload: dict) -> dict | None:
    """Resume a job whose scan row was committed but never marked SUCCESS.

    The scan-history insert and the ``jobs.scan_id`` update happen in ONE
    SQLite transaction, so ``scan_id IS NOT NULL`` proves the scan row exists.
    A redelivery in that window must reuse it instead of scanning again — the
    upload directory may already be gone (the worker was killed), and a second
    row would be a duplicate durable side effect.
    """
    job = _app.job_manager.get(job_id)
    if not job:
        return None
    scan_id = job.get("scan_id")
    if not scan_id or job.get("status") == "SUCCESS":
        return None
    tenant_id, principal_id = _validate_job_context(job_id, payload)
    conn = _app._connect()
    try:
        row = conn.execute(
            "SELECT filename, compliance_json, findings_json, tenant_id "
            "FROM scan_history WHERE id=?", (scan_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    filename, matrix_json, findings_json, row_tenant = row
    if row_tenant != tenant_id:
        # Never resume another tenant's scan, even if the row is malformed.
        raise JobFailure("Scan ownership mismatch — refusing to resume this job")
    findings = json.loads(findings_json or "[]")
    matrix = json.loads(matrix_json or "{}")
    _app.job_manager.append_log(
        job_id, "warning",
        "Worker restart detected — resuming the already-persisted scan "
        f"(scan {scan_id}); no second scan row will be created")
    _app._persist_scan(scan_id, findings)
    plans = _app._remediate_findings_job(scan_id, findings)
    audit.record("scan.resumed", actor_type="worker", actor_id=principal_id,
                 tenant_id=tenant_id, object_type="scan", object_id=str(scan_id),
                 correlation_id=job_id,
                 detail={"reason": "redelivery after worker loss"})
    return {
        "scan_id": scan_id,
        "engine": "resumed",
        "filename": filename,
        "findings": findings,
        "compliance": matrix,
        "remediation_plans": plans.get("remediation_plans", []),
        "count": plans.get("count", 0),
        "resumed": True,
    }


def run_sast_job(job_id: str, payload: dict) -> dict:
    """Full scan pipeline: extract -> multi-engine scan -> persist -> plans."""
    tenant_id, principal_id = _validate_job_context(job_id, payload)
    # Idempotency first: a redelivered message must never re-run committed work
    # (and must not need the upload directory, which a crash may have removed).
    resumed = resume_if_complete(job_id) or resume_committed_scan(job_id, payload)
    if resumed is not None:
        return resumed
    temp_dir, zip_path = _validate_job_paths(payload)
    filename = os.path.basename(payload.get("filename") or "upload.zip")

    def log(level: str, msg: str) -> None:
        _app.job_manager.append_log(job_id, level, msg)

    try:
        log("info", f"Task accepted — analysing {filename}")
        archive = payload.get("archive") or {}
        if archive.get("nested_archive_count"):
            log("warning", f"{archive['nested_archive_count']} nested archive(s) "
                           f"are stored as opaque files and not expanded")
        log("info", "Validating archive safety (zip-slip / zip-bomb / symlink guards)…")
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                scanner.safe_extract_zip(
                    zf, temp_dir,
                    max_entries=_app.MAX_ZIP_ENTRIES,
                    max_bytes=_app.MAX_DECOMPRESSED_BYTES,
                    max_file_bytes=_app.MAX_ZIP_FILE_BYTES,
                    max_compression_ratio=_app.MAX_COMPRESSION_RATIO,
                )
        except scanner.ZipExtractionError as exc:
            raise JobFailure(str(exc))
        log("info", "Archive validated & extracted")

        result = scanner.scan_directory(temp_dir, logger=lambda lvl, msg: log(lvl, msg))
        findings = result.get("findings", []) or []
        matrix = result.get("compliance", {}) or {}

        # Clean temp paths from findings (keep snippets — they are relocatable text)
        for finding in findings:
            if "file" in finding:
                finding["file"] = finding["file"].replace(temp_dir + "/", "")

        # Phase 3: baseline delta + gate. Same semantics as `cipher-cli scan
        # --baseline/--fail-on`, so a CI result is reproducible locally.
        stored_baseline = None
        upload_baseline = payload.get("baseline")
        fail_on = payload.get("fail_on")
        if upload_baseline is not None or fail_on:
            try:
                ruleset_sha = metrics.ruleset_fingerprint().get("sha256")
            except Exception as exc:  # noqa: BLE001 — provenance is best-effort
                log("warning", f"Ruleset fingerprint unavailable: {type(exc).__name__}")
                ruleset_sha = None
            delta = baseline.compare(
                findings, upload_baseline,
                baseline_path=payload.get("baseline_filename"),
                ruleset_sha256=ruleset_sha,
            )
            gate = None
            if fail_on or upload_baseline is not None:
                policy = baseline.parse_policy(fail_on or "new-error")
                gate = baseline.evaluate_gate(delta, policy)
            stored_baseline = {"delta": delta, "gate": gate}
            counts = delta.get("counts") or {}
            log("info", "Baseline comparison — new {new}, persistent {persistent}, "
                        "changed {changed}, resolved {resolved}, suppressed {suppressed}"
                        .format(**{k: counts.get(k, 0) for k in
                                   ("new", "persistent", "changed", "resolved", "suppressed")}))
            if delta.get("uncertain", {}).get("is_uncertain"):
                reasons = (delta.get("uncertain") or {}).get("reasons") or []
                log("warning", f"Comparison is uncertain: {'; '.join(reasons[:3])}")
            if gate is not None:
                if gate.get("triggered"):
                    log("error", f"Gate {gate.get('policy')}: {len(gate.get('failures') or [])} "
                                  f"finding(s) exceed the configured threshold")
                else:
                    log("info", f"Gate {gate.get('policy')}: passed")

        log("info", "Persisting scan history + findings…")
        # ONE transaction: the scan row and the job -> scan linkage commit
        # together, so `jobs.scan_id IS NOT NULL` always means "the scan row
        # exists". That is what makes redelivery recovery (resume) safe.
        conn = _app._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO scan_history (timestamp, filename, pqc_score, verdict, "
                "compliance_json, findings_json, baseline_json, tenant_id, principal_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (_now(), filename, matrix.get("pqc_score", 0),
                 matrix.get("verdict", "unknown"), json.dumps(matrix),
                 json.dumps(findings),
                 json.dumps(stored_baseline) if stored_baseline else None,
                 tenant_id, principal_id),
            )
            scan_id = cur.lastrowid
            cur.execute("UPDATE jobs SET scan_id=?, updated_at=? WHERE id=?",
                        (scan_id, _now(), job_id))
            conn.commit()
        finally:
            conn.close()
        _app._persist_scan(scan_id, findings)

        log("info", "Generating remediation / migration plans…")
        plans = _app._remediate_findings_job(scan_id, findings)
        log("info", f"Remediation complete — {plans['count']} plan(s) generated")

        job_result = {
            "scan_id": scan_id,
            "engine": result.get("engine", "?"),
            "findings": findings,
            "compliance": matrix,
            "remediation_plans": plans.get("remediation_plans", []),
            "count": plans.get("count", 0),
        }
        # Additive contract: baseline keys only appear when a baseline or a
        # gate policy was requested, so existing clients are unaffected.
        if stored_baseline:
            job_result["baseline_delta"] = stored_baseline["delta"]
            if stored_baseline["gate"] is not None:
                job_result["gate"] = stored_baseline["gate"]
            job_result["sarif_url"] = f"/api/v1/scans/{scan_id}/sarif"
        audit.record("scan.complete", actor_type="worker", actor_id=principal_id,
                     tenant_id=tenant_id, object_type="scan", object_id=str(scan_id),
                     correlation_id=job_id,
                     detail={"findings": len(findings),
                             "gate_triggered": bool(
                                 (stored_baseline or {}).get("gate", {}).get("triggered"))})
        return job_result
    except JobFailure as exc:
        audit.record("scan.failure", result="failed", actor_type="worker",
                     actor_id=principal_id, tenant_id=tenant_id,
                     object_type="job", object_id=job_id,
                     detail={"reason": str(exc)[:180]})
        raise RuntimeError(str(exc))
    except Exception as exc:  # noqa: BLE001 - audited then surfaced as failed
        audit.record("scan.failure", result="error", actor_type="worker",
                     actor_id=principal_id, tenant_id=tenant_id,
                     object_type="job", object_id=job_id,
                     detail={"reason": type(exc).__name__})
        raise
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def run_telemetry_job(job_id: str, payload: dict) -> dict:
    """Audit-job pipeline for CLI telemetry ingestion (zero-trust)."""
    tenant_id, _principal_id = _validate_job_context(job_id, payload)
    return {
        "telemetry": payload.get("telemetry", {}),
        "summary": payload.get("summary", {}),
        "tenant_id": tenant_id,
    }


def run_job(job_id: str, payload: dict) -> dict:
    """Dispatch a persisted job row by payload['type']."""
    kind = payload.get("type")
    if kind == "sast":
        return run_sast_job(job_id, payload)
    if kind == "telemetry-audit":
        return run_telemetry_job(job_id, payload)
    logging.error("Unknown job type received: %r", kind)
    raise ValueError(f"Unknown job type: {kind!r}")
