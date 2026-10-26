#!/usr/bin/env python3
# backend/test_celery_integration.py
"""
test_celery_integration.py — real Celery + Redis integration (Phase 4)
======================================================================
Run:  venv/bin/python test_celery_integration.py     (no pytest required)

The Phase 4 acceptance suite (test_phase4.py) covers tenant isolation in
*thread* mode and the Redis-backed rate limiter against a real
`redis-server`.  This suite closes the remaining gap: the **Celery**
execution backend, with a real broker and a real worker *process*.

What it proves (nothing here is mocked):
  1. A scan submitted over HTTP is executed by the Celery worker process
     (the worker log contains the job id; the API process ran no thread).
  2. The persisted job row and the resulting scan row carry the submitting
     tenant/principal — the worker's writes are tenant-scoped.
  3. A tampered broker message (payload claims a different tenant than the
     persisted job row) is REFUSED by the worker: the job fails and no scan
     row is written.  The worker never trusts the message.
  4. The polling API is identical in both backends (same job/scan ids).

Requirements: `redis-server` on PATH and `celery` importable in the venv.
If either is missing the suite reports BLOCKED with a reproducible command
instead of pretending to pass.
"""

import io
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

PYTHON = sys.executable
PASSED = []
FAILED = []
BLOCKED = []


def check(name, condition, detail=""):
    if not condition:
        FAILED.append(name)
        raise AssertionError(f"FAILED: {name} {detail}")
    PASSED.append(name)
    print(f"  ✓ {name}")


def blocked(name, reason, command):
    BLOCKED.append({"check": name, "reason": reason, "command": command})
    print(f"  ⊘ BLOCKED: {name} — {reason}\n    run: {command}")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _start_redis():
    """Start a private redis-server (no external service required)."""
    binary = shutil.which("redis-server")
    if not binary:
        return None, None
    port = _free_port()
    workdir = tempfile.mkdtemp(prefix="piquachu-celery-redis-")
    proc = subprocess.Popen(
        [binary, "--port", str(port), "--save", "", "--appendonly", "no",
         "--bind", "127.0.0.1", "--dir", workdir],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import redis
    client = redis.Redis(host="127.0.0.1", port=port, socket_timeout=2)
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            if client.ping():
                return proc, port
        except Exception:
            time.sleep(0.15)
    proc.terminate()
    return None, None


def _start_worker(broker_url, db_path, audit_log, log_path,
                  visibility_timeout=None):
    """Start a real `celery -A tasks worker` subprocess.

    The worker runs in its own session/process group so a test can hard-kill
    the parent *and* its prefork children (a lone SIGKILL of the parent would
    leave a child finishing the task, which is not a crash).
    """
    env = dict(os.environ)
    env.update({
        "PIQUACHU_BROKER_URL": broker_url,
        "PIQUACHU_DB_PATH": db_path,
        "PIQUACHU_AUDIT_LOG": audit_log,
        "PIQUACHU_ENV": "development",
        "PYTHONPATH": HERE + os.pathsep + env.get("PYTHONPATH", ""),
        "PYTHONUNBUFFERED": "1",
    })
    if visibility_timeout is not None:
        env["PIQUACHU_CELERY_VISIBILITY_TIMEOUT"] = str(visibility_timeout)
    handle = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [PYTHON, "-m", "celery", "-A", "tasks", "worker",
         "--loglevel=INFO", "--concurrency=1",
         "--without-gossip", "--without-mingle", "--without-heartbeat"],
        cwd=HERE, env=env, stdout=handle, stderr=subprocess.STDOUT,
        start_new_session=True)
    return proc, handle


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _job_logs(db_path, job_id):
    import sqlite3
    conn = sqlite3.connect(db_path, timeout=10)
    try:
        row = conn.execute("SELECT logs FROM jobs WHERE id=?", (job_id,)).fetchone()
    finally:
        conn.close()
    if not row or not row[0]:
        return []
    try:
        return json.loads(row[0])
    except ValueError:
        return []


def _wait_for_job_log(db_path, job_id, needle, timeout_s=180.0):
    """Wait until the *pipeline itself* reports a stage (no sleep-race)."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        for entry in _job_logs(db_path, job_id):
            if needle in str(entry.get("message") or ""):
                return True
        time.sleep(0.1)
    return False


def _wait_worker_ready(log_path, proc, timeout_s=90.0):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with open(log_path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            text = ""
        if "celery@" in text and "ready" in text:
            return True
        time.sleep(0.4)
    return False


def _make_zip(entries: dict) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    buf.seek(0)
    return buf


def _row(db_path, sql, params=()):
    import sqlite3
    conn = sqlite3.connect(db_path, timeout=10)
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        return conn.execute(sql, params).fetchone()
    finally:
        conn.close()


def _count(db_path, sql, params=()):
    row = _row(db_path, sql, params)
    return int(row[0]) if row else 0


def main() -> int:
    print("=" * 68)
    print("Phase 4 — Celery + Redis integration (real broker, real worker)")
    print("=" * 68)

    # ---- service availability -------------------------------------------
    if not shutil.which("redis-server"):
        blocked("celery integration",
                "redis-server not found on PATH",
                "apt-get install redis-server && ./venv/bin/python test_celery_integration.py")
        return 0
    try:
        import celery  # noqa: F401
    except Exception:
        blocked("celery integration",
                "celery is not installed in the venv",
                "./venv/bin/pip install -r requirements.txt && "
                "./venv/bin/python test_celery_integration.py")
        return 0

    redis_proc, redis_port = _start_redis()
    if redis_proc is None:
        blocked("celery integration", "could not start a local redis-server",
                "redis-server --port 6379 --save '' & "
                "./venv/bin/python test_celery_integration.py")
        return 0

    scratch = tempfile.mkdtemp(prefix="piquachu-celery-it-")
    db_path = os.path.join(scratch, "celery-it.db")
    audit_log = os.path.join(scratch, "audit.jsonl")
    worker_log = os.path.join(scratch, "worker.log")
    broker_url = f"redis://127.0.0.1:{redis_port}/0"

    worker = None
    worker_handle = None
    try:
        # Environment must be set before the app module is imported: the app
        # reads the broker URL and the DB path at import time.
        os.environ["PIQUACHU_DB_PATH"] = db_path
        os.environ["PIQUACHU_AUDIT_LOG"] = audit_log
        os.environ["PIQUACHU_BROKER_URL"] = broker_url
        os.environ["PIQUACHU_RATE_LIMIT_STORAGE_URI"] = broker_url
        os.environ["PIQUACHU_ENV"] = "development"
        os.environ.pop("GROQ_API_KEY", None)

        import app as api
        import authz
        import tasks

        check("celery backend is enabled in the API process",
              api._celery_enabled() is True)

        worker, worker_handle = _start_worker(broker_url, db_path, audit_log,
                                              worker_log)
        ready = _wait_worker_ready(worker_log, worker)
        if not ready:
            with open(worker_log, encoding="utf-8", errors="replace") as fh:
                tail = fh.read()[-2000:]
            blocked("celery worker startup",
                    f"worker did not report ready\n{tail}",
                    "PIQUACHU_BROKER_URL=redis://127.0.0.1:6379/0 "
                    "celery -A tasks worker --loglevel=INFO")
            return 0
        check("celery worker process is ready", True)

        # ---- fixtures ---------------------------------------------------
        authz.create_tenant("acme", "ACME Corp", actor="integration-test")
        key = authz.create_key("acme", "ci-bot", role="owner",
                                created_by="integration-test")
        raw_key = key["api_key"]
        headers = {"X-API-Key": raw_key}

        client = api.app.test_client()

        # ---- 1. a real scan executed by the worker ----------------------
        buf = _make_zip({
            "src/weak.py": "import hashlib\n"
                           "def f(x):\n"
                           "    return hashlib.md5(x).hexdigest()\n",
        })
        resp = client.post("/api/v1/sast-scan", headers=headers,
                           data={"file": (buf, "sample.zip")},
                           content_type="multipart/form-data")
        check("scan accepted in celery mode", resp.status_code == 202,
              f"{resp.status_code} {resp.get_data(as_text=True)[:200]}")
        task_id = resp.get_json()["task_id"]

        check("the API process did not run the job in a thread",
              task_id not in getattr(api.job_manager, "_threads", {}),
              "job must be dispatched to the broker")

        body = {}
        deadline = time.time() + 180
        while time.time() < deadline:
            body = client.get(f"/api/v1/scan/{task_id}",
                              headers=headers).get_json() or {}
            if body.get("status") in ("SUCCESS", "FAILED"):
                break
            time.sleep(0.5)

        check("scan completed successfully in celery mode",
              body.get("status") == "SUCCESS",
              f"status={body.get('status')} error={(body.get('result') or {}).get('error')}")

        with open(worker_log, encoding="utf-8", errors="replace") as fh:
            worker_text = fh.read()
        # The worker logs the Celery task id (not our job id) — the evidence
        # that a *separate worker process* ran the pipeline is: the API
        # process started no thread, the job row reached SUCCESS, and the
        # worker log shows the named task being received and succeeding.
        check("the Celery worker process received the task",
              "piquachu.sast_scan" in worker_text, worker_text[-800:])
        check("the Celery worker process completed the task",
              "succeeded" in worker_text, worker_text[-800:])
        check("the worker process is a different PID from the API process",
              worker.pid != os.getpid(), f"worker={worker.pid} api={os.getpid()}")

        scan_id = body.get("scan_id") or (body.get("result") or {}).get("scan_id")
        job_row = _row(db_path,
                       "SELECT tenant_id, principal_id, status FROM jobs WHERE id=?",
                       (task_id,))
        check("job row carries the submitting tenant",
              job_row and job_row[0] == "acme", job_row)
        check("job row carries the submitting principal",
              job_row and job_row[1] == key["key_id"], job_row)
        check("job row is terminal", job_row and job_row[2] == "SUCCESS", job_row)

        scan_row = _row(db_path,
                        "SELECT tenant_id, filename FROM scan_history WHERE id=?",
                        (scan_id,))
        check("scan row is attributed to the same tenant",
              scan_row and scan_row[0] == "acme", scan_row)
        check("the scan is readable by the submitting tenant only",
              client.get(f"/api/v1/scans/{scan_id}/cbom",
                         headers=headers).status_code == 200)

        # ---- 2. tampered broker message is refused ----------------------
        before = _count(db_path, "SELECT COUNT(*) FROM scan_history")
        evil_id = str(uuid.uuid4())
        payload = {"type": "sast", "filename": "evil.zip",
                   "zip_path": "/tmp/does-not-exist.zip",
                   "temp_dir": "/tmp", "tenant_id": "evil-tenant"}
        conn = api._connect()
        try:
            conn.execute(
                "INSERT INTO jobs (id, status, scan_id, payload, logs, created_at, "
                "updated_at, tenant_id, principal_id) "
                "VALUES (?, 'PENDING', NULL, ?, '[]', ?, ?, ?, ?)",
                (evil_id, json.dumps(payload),
                 api._now_iso(), api._now_iso(), "acme", key["key_id"]))
            conn.commit()
        finally:
            conn.close()

        tasks.app.send_task("piquachu.sast_scan", args=[evil_id, payload])

        deadline = time.time() + 90
        status = None
        while time.time() < deadline:
            row = _row(db_path, "SELECT status FROM jobs WHERE id=?", (evil_id,))
            status = row[0] if row else None
            if status in ("FAILED", "SUCCESS"):
                break
            time.sleep(0.5)

        check("a tampered tenant claim fails the job",
              status == "FAILED", f"status={status}")
        after = _count(db_path, "SELECT COUNT(*) FROM scan_history")
        check("the refused job wrote no scan row", after == before,
              f"{before} -> {after}")

        # ---- 3. cross-tenant polling is denied in celery mode -----------
        authz.create_tenant("other", "Other Co", actor="integration-test")
        other = authz.create_key("other", "analyst", role="analyst",
                                 created_by="integration-test")
        other_headers = {"X-API-Key": other["api_key"]}
        denied = client.get(f"/api/v1/scan/{task_id}", headers=other_headers)
        check("another tenant cannot poll the job", denied.status_code == 404,
              denied.status_code)
        denied_logs = client.get(f"/api/v1/scan/{task_id}/logs",
                                 headers=other_headers)
        check("another tenant cannot read the job logs",
              denied_logs.status_code == 404, denied_logs.status_code)

        # ---- 4. hard-kill an ACTIVE task -> broker redelivery -------------
        # Kill the worker (parent + prefork children) while the task is inside
        # the scan. The broker must redeliver the *same* job after the
        # visibility timeout, and the pipeline must recover exactly once.
        scans_before_kill = _count(db_path, "SELECT COUNT(*) FROM scan_history")
        files = {f"src/m{i}.py": ("import hashlib\n\n\ndef h(x):\n"
                                  "    return hashlib.md5(x).hexdigest()\n")
                 for i in range(400)}
        resp = client.post("/api/v1/sast-scan", headers=headers,
                           data={"file": (_make_zip(files), "slow.zip")},
                           content_type="multipart/form-data")
        check("slow scan accepted", resp.status_code == 202,
              resp.get_data(as_text=True)[:200])
        kill_id = resp.get_json()["task_id"]

        reached = _wait_for_job_log(db_path, kill_id,
                                    "Archive validated & extracted")
        check("the active task reached the extraction/scan stage", reached,
              "job never started scanning — cannot test an in-flight kill")

        killed_pid = worker.pid
        os.killpg(os.getpgid(killed_pid), signal.SIGKILL)
        worker.wait(timeout=30)
        worker_handle.close()
        worker, worker_handle = None, None
        time.sleep(0.3)

        mid_status = _row(db_path, "SELECT status FROM jobs WHERE id=?", (kill_id,))
        check("the hard-killed job is not recorded as successful",
              mid_status and mid_status[0] != "SUCCESS", mid_status)
        check("the hard-killed job committed no scan row",
              _count(db_path, "SELECT COUNT(*) FROM scan_history") == scans_before_kill,
              "a scan row was written before the kill — cannot isolate redelivery")
        check("the killed worker process is really gone",
              not _pid_alive(killed_pid), killed_pid)

        # A replacement worker restores the unacked message after the
        # (test-only) 2s visibility timeout and re-runs the same job id.
        worker_log2 = os.path.join(scratch, "worker-restart.log")
        worker, worker_handle = _start_worker(broker_url, db_path, audit_log,
                                              worker_log2, visibility_timeout=2)
        restarted = _wait_worker_ready(worker_log2, worker)
        check("replacement worker is ready", restarted,
              open(worker_log2, encoding="utf-8", errors="replace").read()[-2000:])

        deadline = time.time() + 300
        body = {}
        while time.time() < deadline:
            body = client.get(f"/api/v1/scan/{kill_id}",
                              headers=headers).get_json() or {}
            if body.get("status") in ("SUCCESS", "FAILED"):
                break
            time.sleep(0.5)
        check("the redelivered job reaches a terminal SUCCESS state",
              body.get("status") == "SUCCESS",
              f"status={body.get('status')} result={(body.get('result') or {})}")
        check("redelivery created exactly ONE scan row",
              _count(db_path, "SELECT COUNT(*) FROM scan_history") ==
              scans_before_kill + 1,
              f"expected {scans_before_kill + 1}, got "
              f"{_count(db_path, 'SELECT COUNT(*) FROM scan_history')}")
        dup_findings = _count(
            db_path,
            "SELECT COUNT(*) FROM (SELECT scan_id, file_path, line_number, "
            "algorithm, COUNT(*) c FROM findings GROUP BY 1,2,3,4 HAVING c>1)")
        check("redelivery created no duplicate finding rows", dup_findings == 0,
              f"{dup_findings} duplicated finding group(s)")
        dup_plans = _count(
            db_path,
            "SELECT COUNT(*) FROM (SELECT finding_id, suggested_code, "
            "COUNT(*) c FROM remediation_plans GROUP BY 1,2 HAVING c>1)")
        check("redelivery created no duplicate remediation plans",
              dup_plans == 0, f"{dup_plans} duplicated plan group(s)")

        # ---- 5. crash AFTER the scan commit -> resume, never re-scan ------
        # This is the dangerous window: the scan row is committed, the job is
        # still ANALYSING. The upload dir is gone (the worker was killed), so
        # a re-scan would fail or duplicate; the worker must resume instead.
        row = _row(db_path, "SELECT payload, scan_id FROM jobs WHERE id=?",
                   (kill_id,))
        check("the recovered job is linked to its scan",
              row and row[1] is not None, row)
        payload = json.loads(row[0])
        committed_scan_id = row[1]
        scans_now = _count(db_path, "SELECT COUNT(*) FROM scan_history")
        findings_now = _count(db_path,
                              "SELECT COUNT(*) FROM findings WHERE scan_id=?",
                              (committed_scan_id,))
        plans_now = _count(
            db_path,
            "SELECT COUNT(*) FROM remediation_plans WHERE finding_id IN "
            "(SELECT id FROM findings WHERE scan_id=?)", (committed_scan_id,))
        check("the recovered scan has persisted findings", findings_now > 0,
              findings_now)

        conn = api._connect()
        try:
            conn.execute("UPDATE jobs SET status='ANALYSING', result=NULL "
                         "WHERE id=?", (kill_id,))
            conn.commit()
        finally:
            conn.close()
        check("upload directory is already gone (re-scan is impossible)",
              not os.path.isdir(payload.get("temp_dir") or "/nonexistent"),
              payload.get("temp_dir"))

        tasks.app.send_task("piquachu.sast_scan", args=[kill_id, payload])
        deadline = time.time() + 180
        body = {}
        while time.time() < deadline:
            body = client.get(f"/api/v1/scan/{kill_id}",
                              headers=headers).get_json() or {}
            if body.get("status") in ("SUCCESS", "FAILED"):
                break
            time.sleep(0.5)
        check("a redelivery after the scan commit succeeds (resume)",
              body.get("status") == "SUCCESS",
              f"status={body.get('status')} result={(body.get('result') or {})}")
        check("resume keeps exactly ONE scan row",
              _count(db_path, "SELECT COUNT(*) FROM scan_history") == scans_now,
              f"expected {scans_now}, got "
              f"{_count(db_path, 'SELECT COUNT(*) FROM scan_history')}")
        check("resume does not duplicate findings",
              _count(db_path, "SELECT COUNT(*) FROM findings WHERE scan_id=?",
                     (committed_scan_id,)) == findings_now)
        check("resume does not duplicate remediation plans",
              _count(db_path,
                     "SELECT COUNT(*) FROM remediation_plans WHERE finding_id IN "
                     "(SELECT id FROM findings WHERE scan_id=?)",
                     (committed_scan_id,)) == plans_now)
        result = body.get("result") or {}
        check("the resumed result points at the already-committed scan",
              (body.get("scan_id") or result.get("scan_id")) == committed_scan_id,
              f"{body.get('scan_id')} / {result.get('scan_id')} vs {committed_scan_id}")
        check("the resume is logged, not silent",
              any("resuming the already-persisted scan" in str(e.get("message"))
                  for e in _job_logs(db_path, kill_id)),
              _job_logs(db_path, kill_id)[-3:])

    finally:
        if worker is not None:
            try:
                worker.send_signal(signal.SIGTERM)
                worker.wait(timeout=30)
            except Exception:
                try:
                    worker.kill()
                except Exception:
                    pass
        if worker_handle is not None:
            try:
                worker_handle.close()
            except Exception:
                pass
        if redis_proc is not None:
            try:
                redis_proc.terminate()
                redis_proc.wait(timeout=10)
            except Exception:
                try:
                    redis_proc.kill()
                except Exception:
                    pass
        shutil.rmtree(scratch, ignore_errors=True)

    print()
    print("=" * 68)
    if BLOCKED:
        print(f"BLOCKED: {len(BLOCKED)} check group(s) require a service:")
        for item in BLOCKED:
            print(f"  ⊘ {item['check']} — {item['reason']}")
    if FAILED:
        print(f"FAILED: {len(FAILED)} check(s) — {FAILED}")
        print("=" * 68)
        return 1
    print(f"ALL {len(PASSED)} CHECKS PASSED ✅")
    if BLOCKED:
        print("(blocked checks were not counted as passed)")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    sys.exit(main())
