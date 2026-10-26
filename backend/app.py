# backend/app.py
import json
import logging
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, g, jsonify, redirect, request
from flask_limiter import Limiter
from werkzeug.utils import secure_filename
from flask_cors import CORS

import audit
import authz
import baseline
import cbom
import compliance
import config
import migrations
import metrics
import oidc
import remediation
import sarif
import scanner

APP_VERSION = config.APP_VERSION

app = Flask(__name__)
_HERE = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(_HERE, "piquachu.log")),
        logging.StreamHandler(),
    ]
)

# --- Boot-time security validation (fail closed on unsafe production config) --
_STARTUP = config.validate_startup()
for _warning in _STARTUP["warnings"]:
    logging.warning("Config: %s", _warning)
for _note in _STARTUP["info"]:
    logging.info("Config: %s", _note)
if _STARTUP["errors"]:
    _message = ("Refusing to start with unsafe configuration:\n  - "
                + "\n  - ".join(_STARTUP["errors"]))
    logging.error(_message)
    raise RuntimeError(_message)

# Upload hardening + input caps, all env-configurable (see config.py).
app.config["MAX_CONTENT_LENGTH"] = config.max_upload_bytes()
MAX_DECOMPRESSED_BYTES = config.max_uncompressed_bytes()
MAX_ZIP_ENTRIES = config.max_zip_entries()
MAX_ZIP_FILE_BYTES = config.max_zip_file_bytes()
MAX_COMPRESSION_RATIO = config.max_compression_ratio()
MAX_QUESTION_LENGTH = config.max_question_length()
MAX_TELEMETRY_ITEMS = config.max_telemetry_items()
MAX_BASELINE_BYTES = config.max_baseline_bytes()
# Reliability benchmark cache TTL (seconds)
RELIABILITY_TTL = 300

# --- API keys ---------------------------------------------------------------
# Local/single-user mode keeps the frictionless path: PIQUACHU_API_KEYS (or the
# built-in development keys) authenticate as owner of the `local` tenant.
# Team mode requires tenant keys; the shared-key path is only enabled with an
# explicit PIQUACHU_LEGACY_ENV_KEYS=1 and never with dev defaults in production.
_DEV_DEFAULT_KEYS = {"super-secret-key-123", "piquachu-admin"}
_ENV_KEYS = {k.strip() for k in (os.environ.get("PIQUACHU_API_KEYS") or "").split(",") if k.strip()}
_LEGACY_KEYS = set(_ENV_KEYS)
if config.dev_default_keys_allowed():
    _LEGACY_KEYS |= _DEV_DEFAULT_KEYS
if not config.legacy_env_keys_allowed():
    _LEGACY_KEYS = set()
VALID_API_KEYS = frozenset(_LEGACY_KEYS)  # import-compatible alias

CORS(app, origins=config.cors_origins(), supports_credentials=False,
     allow_headers=["Content-Type", "X-API-Key"],
     methods=["GET", "POST", "OPTIONS"])

DB_PATH = os.environ.get("PIQUACHU_DB_PATH") or os.path.join(_HERE, "piquachu.db")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- Rate limiting -----------------------------------------------------------
_RATE_LIMIT_STORAGE = config.rate_limit_storage_uri()
_RATE_LIMIT_FAILURE_MODE = config.rate_limit_failure_mode()


def _current_principal():
    """Resolve + cache the request principal (one DB lookup per request).

    An API key always wins. Otherwise a verified OIDC session cookie is accepted
    (same-origin deployments only), and the tenant/role come from the signed
    session — never from a query string or header the browser could set.
    """
    if "_piquachu_principal" in g:
        return g._piquachu_principal
    principal = authz.principal_for_key(request.headers.get("X-API-Key"), _LEGACY_KEYS)
    if principal is None:
        principal = oidc.principal_from_session(
            oidc.read_session(request.cookies.get(oidc.SESSION_COOKIE))
        )
    g._piquachu_principal = principal
    return principal


def _rate_limit_key() -> str:
    """Bucket by tenant+principal, else trusted-proxy-aware client IP.

    The raw API key and scan content are never part of a storage key.
    """
    principal = _current_principal()
    if principal is not None:
        return config.rate_limit_identity(None, None, principal.tenant_id, principal.id)
    return config.rate_limit_identity(request.remote_addr,
                                      request.headers.get("X-Forwarded-For"))


limiter = Limiter(
    _rate_limit_key,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=_RATE_LIMIT_STORAGE,
    # `closed` => storage failures propagate and are mapped to 503 below;
    # `degraded` => requests are allowed while the outage is logged.
    swallow_errors=(_RATE_LIMIT_FAILURE_MODE == "degraded"),
    headers_enabled=True,
)


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def _connect():
    """Connection with WAL journaling + busy timeout so the request threads
    (findings) and JobManager threads (remediation) don't deadlock on write
    locks during concurrent scans."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _secure_local_files():
    """Best-effort 0600 on the local database and its WAL/SHM sidecars."""
    for suffix in ("", "-wal", "-shm"):
        path = DB_PATH + suffix
        try:
            if os.path.exists(path):
                os.chmod(path, 0o600)
        except OSError:
            pass


def init_db():
    """Create/upgrade schema: scan_history (SAST), findings,
    remediation_plans, jobs (with live logs) plus the Phase 4 tenant schema.

    Additive only: `migrations.migrate` never drops or recreates a table and
    takes a one-time pre-upgrade backup of a populated database.
    """
    conn = _connect()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            filename TEXT,
            pqc_score INTEGER,
            verdict TEXT,
            compliance_json TEXT,
            findings_json TEXT,
            baseline_json TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            file_path TEXT,
            line_number INTEGER,
            algorithm TEXT,
            key_size TEXT,
            severity TEXT,
            status TEXT,
            nist_standard TEXT,
            created_at TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS remediation_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER,
            suggested_code TEXT,
            migration_notes TEXT,
            llm_response TEXT,
            source TEXT,
            created_at TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            status TEXT,
            scan_id INTEGER,
            payload TEXT,
            result TEXT,
            logs TEXT,
            created_at TEXT,
            updated_at TEXT
        )
    ''')
    conn.commit()
    try:
        upgrade = migrations.migrate(conn, db_path=DB_PATH)
        if upgrade.get("applied"):
            logging.info("Schema upgrade applied: %s (backup: %s)",
                         ", ".join(upgrade["applied"]), upgrade.get("backup"))
    finally:
        conn.close()
    _secure_local_files()
    logging.info("Database initialized successfully.")


# One shared connection provider: authz owns identity tables, audit owns the
# event stream, and both follow app.DB_PATH (including in tests).
authz.set_connection_provider(_connect)


init_db()

# Leftovers from a crash/restart cannot accumulate or be reused.
try:
    _removed = scanner.cleanup_stale_upload_dirs(config.stale_upload_seconds())
    if _removed:
        logging.info("Removed %d stale upload director(ies).", len(_removed))
except Exception as _exc:  # noqa: BLE001 - startup must continue
    logging.warning("Stale upload cleanup failed: %s", _exc)
try:
    audit.prune()
except Exception as _exc:  # noqa: BLE001
    logging.warning("Audit retention prune failed: %s", _exc)


def _migrate_jobs_logs_column():
    """Add the `logs` column to pre-existing jobs tables (idempotent)."""
    try:
        conn = _connect()
        cols = [r[1] for r in conn.execute("PRAGMA table_info(jobs)").fetchall()]
        if "logs" not in cols:
            conn.execute("ALTER TABLE jobs ADD COLUMN logs TEXT")
            conn.commit()
        conn.close()
    except Exception as exc:
        logging.error(f"jobs.logs migration failed: {exc}")


_migrate_jobs_logs_column()


def _migrate_scan_baseline_column():
    """Add `baseline_json` to pre-existing scan_history tables (idempotent)."""
    try:
        conn = _connect()
        cols = [r[1] for r in conn.execute("PRAGMA table_info(scan_history)").fetchall()]
        if "baseline_json" not in cols:
            conn.execute("ALTER TABLE scan_history ADD COLUMN baseline_json TEXT")
            conn.commit()
        conn.close()
    except Exception as exc:
        logging.error(f"scan_history.baseline_json migration failed: {exc}")


_migrate_scan_baseline_column()


def _safe_json_loads(value, default):
    """Parse a JSON-typed DB column defensively so one corrupt or misaligned
    row can never take an endpoint down — falls back to `default` instead of
    raising a JSONDecodeError (the source of the /api/v1/scan/<id> 500s)."""
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Background job manager (thread-based, SQLite-persisted, log-enabled)
# ---------------------------------------------------------------------------

def _ensure_job_columns(conn):
    """Additive safety net: a jobs table created by an older release gets the
    Phase 4 tenant columns through the same versioned migration (no drop)."""
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(jobs)")}
        if "tenant_id" not in cols or "principal_id" not in cols:
            migrations.migrate(conn, db_path=DB_PATH)
    except sqlite3.Error as exc:
        logging.error("jobs schema upgrade failed: %s", type(exc).__name__)


class JobManager:
    """Minimal async job queue. Jobs are persisted to SQLite so polling works
    even across restarts; stale PENDING/ANALYSING rows are failed at startup.
    Every job carries an append-only `logs` array streamed to the dashboard's
    live terminal console and an immutable tenant/principal context."""

    def __init__(self):
        self._threads = {}
        self._lock = threading.Lock()
        self._recover_orphans()

    def _recover_orphans(self):
        """Fail only *stale* jobs.

        Startup in a second API process must never fail a job that another
        process is actively running, so recovery is age-based (heartbeat on
        every log append) rather than "every non-terminal row at boot".
        """
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(
                seconds=config.orphan_grace_seconds())).isoformat()
            conn = _connect()
            cursor = conn.execute(
                "UPDATE jobs SET status='FAILED', result=?, updated_at=? "
                "WHERE status IN ('PENDING','ANALYSING') "
                "AND (updated_at IS NULL OR updated_at < ?)",
                (json.dumps({"error": "Job interrupted by server restart"}),
                 _now_iso(), cutoff),
            )
            conn.commit()
            recovered = cursor.rowcount
            conn.close()
            if recovered:
                logging.warning("Recovered %d stale job(s) as FAILED.", recovered)
        except Exception as exc:
            logging.error(f"Job recovery failed: {exc}")

    def submit(self, job_id: str, scan_id, fn=None, payload: dict = None,
               tenant_id: str | None = None,
               principal_id: str | None = None) -> str:
        """Dispatch a job row and run it on the active execution backend.

        Default: a daemon thread runs `fn` (or the shared pipeline from
        jobs.py when fn is None). When PIQUACHU_BROKER_URL is set and the job
        has a serializable payload['type'], the job is routed to the Celery
        worker instead — the polling API is identical in both modes.

        The tenant context is written to the row (source of truth) and mirrored
        into the payload for the worker; the worker re-validates the row rather
        than trusting the message. Duplicate job ids are ignored, so a retried
        request cannot restart or duplicate a running scan.
        """
        payload = dict(payload or {})
        tenant_id = tenant_id or payload.get("tenant_id") or authz.LEGACY_TENANT
        principal_id = principal_id or payload.get("principal_id")
        payload["tenant_id"] = tenant_id
        payload["principal_id"] = principal_id
        with self._lock:
            conn = _connect()
            _ensure_job_columns(conn)
            cursor = conn.execute(
                "INSERT INTO jobs (id, status, scan_id, payload, logs, created_at, "
                "updated_at, tenant_id, principal_id) "
                "VALUES (?, 'PENDING', ?, ?, '[]', ?, ?, ?, ?) "
                "ON CONFLICT(id) DO NOTHING",
                (job_id, scan_id, json.dumps(payload), _now_iso(), _now_iso(),
                 tenant_id, principal_id),
            )
            conn.commit()
            inserted = cursor.rowcount > 0
            conn.close()
            if not inserted:
                logging.info("Duplicate job submission ignored: %s", job_id)
                return job_id

            try:
                if fn is None and payload.get("type") and _celery_enabled():
                    task = _celery_tasks().get(payload["type"])
                    if task is not None:
                        task.delay(job_id, payload)   # worker process runs it
                        return job_id

                if fn is None:
                    fn = _job_pipeline_runner(job_id, payload)
                thread = threading.Thread(target=self._run, args=(job_id, fn), daemon=True)
                self._threads[job_id] = thread
                thread.start()
            except Exception as exc:
                # Never leave an accepted job stuck in PENDING.
                logging.error("Job dispatch failed for %s: %s", job_id, exc)
                self._set_status(job_id, "FAILED", {"error": "Dispatch failed"})
        return job_id

    def append_log(self, job_id: str, level: str, message: str) -> None:
        """Append a terminal-style log line to a job's log stream."""
        entry = {"t": _now_iso(), "level": level, "message": message}
        try:
            conn = _connect()
            row = conn.execute("SELECT logs FROM jobs WHERE id=?", (job_id,)).fetchone()
            logs = _safe_json_loads(row[0] if row else None, [])
            if not isinstance(logs, list):
                logs = []
            logs.append(entry)
            conn.execute(
                "UPDATE jobs SET logs=?, updated_at=? WHERE id=?",
                (json.dumps(logs[-500:]), _now_iso(), job_id),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            logging.error(f"append_log failed for {job_id}: {exc}")

    def _run(self, job_id: str, fn):
        self._set_status(job_id, "ANALYSING")
        try:
            result = fn()
            self._set_status(job_id, "SUCCESS", result)
        except Exception as exc:
            logging.error(f"Job {job_id} failed: {exc}")
            self._set_status(job_id, "FAILED", {"error": str(exc)[:500]})
        finally:
            with self._lock:
                self._threads.pop(job_id, None)  # keep the registry bounded

    def _set_status(self, job_id: str, status: str, result: dict = None):
        conn = _connect()
        conn.execute(
            "UPDATE jobs SET status=?, result=?, updated_at=? WHERE id=?",
            (status, json.dumps(result) if result is not None else None,
             _now_iso(), job_id),
        )
        conn.commit()
        conn.close()

    def mark_analysing(self, job_id: str) -> None:
        """Transition a job to ANALYSING (used by the Celery tasks)."""
        self._set_status(job_id, "ANALYSING")

    def set_scan_id(self, job_id: str, scan_id: int) -> None:
        """Attach the persisted scan id to the job row (both backends)."""
        conn = _connect()
        conn.execute("UPDATE jobs SET scan_id=?, updated_at=? WHERE id=?",
                     (scan_id, _now_iso(), job_id))
        conn.commit()
        conn.close()

    def get(self, job_id: str, tenant_id: str | None = None) -> dict | None:
        """Read a job, optionally tenant-scoped.

        Explicit column list — never `SELECT *`. A jobs table whose `logs`
        column was appended by an ALTER TABLE migration has a different
        physical column order, so a hardcoded zip would misalign every field
        and hand a raw timestamp to json.loads() (the reported
        "Extra data: line 1 column 5 (char 4)" 500 on job polling).
        """
        conn = _connect()
        _ensure_job_columns(conn)
        sql = ("SELECT id, status, scan_id, payload, result, logs, created_at, "
               "updated_at, tenant_id, principal_id FROM jobs WHERE id=?")
        params: tuple = (job_id,)
        if tenant_id is not None:
            sql += " AND tenant_id=?"
            params = (job_id, tenant_id)
        row = conn.execute(sql, params).fetchone()
        conn.close()
        if not row:
            return None
        cols = ["id", "status", "scan_id", "payload", "result", "logs",
                "created_at", "updated_at", "tenant_id", "principal_id"]
        job = dict(zip(cols, row))
        job["payload"] = _safe_json_loads(job["payload"], {})
        job["result"] = _safe_json_loads(job["result"], None)
        job["logs"] = _safe_json_loads(job["logs"], [])
        return job


job_manager = JobManager()


# ---------------------------------------------------------------------------
# Remediation background task
# ---------------------------------------------------------------------------

def _remediate_findings_job(scan_id: int, findings: list) -> dict:
    """Generate a remediation plan for every legacy finding and persist it.
    Capped to keep background work bounded (esp. with Groq-enabled plans)."""
    plans = []
    conn = _connect()
    c = conn.cursor()
    # Idempotent: a redelivered/restarted job regenerates this scan's plans
    # instead of appending a second copy of each one.
    c.execute("DELETE FROM remediation_plans WHERE finding_id IN "
              "(SELECT id FROM findings WHERE scan_id=?)", (scan_id,))
    for f in findings[:60]:
        if f.get("pqc_compliant"):
            continue
        try:
            plan = remediation.build_plan(f)
            finding_id = None
            # Persist finding (reuse row inserted by _persist_scan if line matches)
            row = c.execute(
                "SELECT id FROM findings WHERE scan_id=? AND file_path=? AND line_number=? AND algorithm=?",
                (scan_id, f.get("file"), f.get("line"), f.get("vulnerability")),
            ).fetchone()
            if row:
                finding_id = row[0]
            c.execute(
                "INSERT INTO remediation_plans "
                "(finding_id, suggested_code, migration_notes, llm_response, source, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (finding_id, plan.get("replacement_code"), plan.get("justification"),
                 json.dumps(plan), plan.get("source"), _now_iso()),
            )
            plans.append({
                "file": f.get("file"), "line": f.get("line"),
                "rule": f.get("vulnerability"), "standard": f.get("nist_standard"),
                "plan": plan,
            })
        except Exception as exc:
            logging.error(f"Remediation plan failed for {f.get('vulnerability')}: {exc}")
    conn.commit()
    conn.close()
    return {"remediation_plans": plans, "count": len(plans)}


def _persist_scan(scan_id: int, findings: list):
    """Persist the per-finding rows for a scan (idempotent per scan id)."""
    conn = _connect()
    try:
        c = conn.cursor()
        # A redelivered job may re-persist the same scan; never duplicate rows.
        c.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        _insert_findings(c, scan_id, findings)
        conn.commit()
    finally:
        conn.close()


def _insert_findings(c, scan_id: int, findings: list):
    for f in findings:
        c.execute(
            "INSERT INTO findings (scan_id, file_path, line_number, algorithm, key_size, "
            "severity, status, nist_standard, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, f.get("file"), f.get("line"), f.get("vulnerability"), None,
             f.get("severity"), f.get("verdict"), f.get("nist_standard"),
             _now_iso()),
        )


# ---------------------------------------------------------------------------
# Authentication + authorization (centralized middleware)
# ---------------------------------------------------------------------------
# Authentication happens once in `before_request`; routes declare a *permission*
# with @requires(...). Object ownership is checked in the query itself
# (WHERE tenant_id=?) — never by trusting an ID or a route-level role alone.

PUBLIC_PATHS = {
    "/", "/api/v1/health", "/api/v1/ready",
    # Authentication endpoints are reachable without a session by definition;
    # they resolve identity themselves and never expose scan data.
    "/api/v1/auth/providers", "/api/v1/auth/login", "/api/v1/auth/callback",
    "/api/v1/auth/session", "/api/v1/auth/logout",
}


def _authorized() -> bool:
    """Compatibility helper: True when the request carries a valid principal."""
    return _current_principal() is not None


@app.before_request
def _authenticate_request():
    if request.method == "OPTIONS":
        return None
    path = request.path
    if path in PUBLIC_PATHS or not path.startswith("/api/"):
        return None
    principal = _current_principal()
    if principal is None:
        audit.record_from_request(
            "auth.failure", result="denied",
            detail={"path": path, "reason": "missing_or_invalid_key"})
        return jsonify({"error": "Unauthorized."}), 401
    g.principal = principal
    return None


def requires(permission: str):
    """Route guard: authenticated principal AND an explicit permission.

    Unknown roles/scopes deny by default (authz.has_permission).
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            principal = getattr(g, "principal", None)
            if principal is None:
                return jsonify({"error": "Unauthorized."}), 401
            if not authz.has_permission(principal.role, permission):
                audit.record_from_request(
                    "authz.denied", result="denied",
                    detail={"permission": permission, "path": request.path})
                return jsonify({"error": "Forbidden."}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Async SAST job
# ---------------------------------------------------------------------------
# The scan pipeline (extract → multi-engine scan → persist → remediation plans)
# lives in jobs.py so the in-process thread dispatcher and the optional Celery
# worker run byte-identical work. See JobManager.submit() for dispatch.


def _celery_enabled() -> bool:
    """True when the operator opted into Celery (PIQUACHU_BROKER_URL set) and
    celery is importable. Falls back to in-process threads otherwise."""
    if not os.environ.get("PIQUACHU_BROKER_URL"):
        return False
    try:
        import celery  # noqa: F401
        return True
    except Exception:
        logging.warning("PIQUACHU_BROKER_URL is set but celery is not installed — "
                        "using in-process threads.")
        return False


def _celery_tasks() -> dict:
    """Lazily import the Celery task map (imports tasks.py only when used)."""
    import tasks
    return {"sast": tasks.sast_scan_task, "telemetry-audit": tasks.telemetry_audit_task}


def _job_pipeline_runner(job_id: str, payload: dict):
    """Thread-mode runner for payload-driven jobs — mirrors the Celery tasks."""
    def run():
        from jobs import run_job
        return run_job(job_id, payload)
    return run


# ---------------------------------------------------------------------------
# Reliability benchmark cache (background computation)
# ---------------------------------------------------------------------------

_reliability_cache = {"at": 0.0, "report": None, "last_error": None,
                     "last_success": None, "running": False}
_reliability_lock = threading.Lock()


def _start_reliability_compute():
    """Start one background benchmark run, at most one at a time.

    Without the guard every poll of an empty cache started another full corpus
    scan, so concurrent requests starved each other and the metrics never
    became available.
    """
    with _reliability_lock:
        if _reliability_cache["running"]:
            return
        _reliability_cache["running"] = True
    threading.Thread(target=_compute_reliability, daemon=True).start()


def _compute_reliability():
    """Recompute the hermetic metric report.

    A failed run must not destroy the last *successful* report: the cache keeps
    the previous good result (with its real timestamp, so it stays visibly
    stale) and records the failure separately. Otherwise a broken run would
    look like a fresh, current metric.
    """
    try:
        from benchmark import runner as benchmark_runner
        report = benchmark_runner.run_all()
    except Exception as exc:  # noqa: BLE001 - reported, never swallowed silently
        logging.error(f"Reliability benchmark failed: {exc}")
        with _reliability_lock:
            _reliability_cache["last_error"] = {
                "at": datetime.now(timezone.utc).isoformat(),
                "error": str(exc),
            }
        return
    finally:
        with _reliability_lock:
            _reliability_cache["running"] = False
    with _reliability_lock:
        _reliability_cache["at"] = time.time()
        _reliability_cache["report"] = report
        _reliability_cache["last_success"] = report.get("generated_at")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "status": "online",
        "service": "PiQuaChu API",
        "version": APP_VERSION,
        "message": ("PQC discovery API (FIPS 203/204/205 finalized; FIPS 206 in "
                    "development) — static discovery evidence, not a compliance certificate."),
    }), 200


# ---- SAST scan: async zip upload -> compliance matrix + live logs + plans ----

def _upload_reject(message: str, status: int, tmpdir: str | None = None):
    """Reject an upload and always clean the temporary directory it created."""
    if tmpdir:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return jsonify({"error": message}), status


@app.route('/api/v1/sast-scan', methods=['POST'])
@limiter.limit(config.rate_limit("scan"))
@requires("scan:create")
def sast_scan():
    """Accept the archive, run fast pre-checks synchronously, then dispatch the
    full analysis as a background job. Poll GET /api/v1/scan/<task_id> (+ /logs)
    for status, live terminal logs and final results."""
    principal = g.principal

    if 'file' not in request.files:
        return _upload_reject("No file part in the request", 400)
    file = request.files['file']
    if file.filename == '':
        return _upload_reject("No selected file", 400)
    if not file.filename.lower().endswith('.zip'):
        return _upload_reject("Only .zip files are supported", 400)

    filename = secure_filename(file.filename)
    if not filename:
        return _upload_reject("Unsupported upload filename", 400)

    # Fast synchronous pre-checks (400/413 for obviously-bad uploads): entry
    # count, zip-slip / absolute-path / symlink / collision entries, per-file
    # and compression-ratio budgets are validated BEFORE dispatch.
    tmpdir = tempfile.mkdtemp(prefix="piquachu-upload-")
    zip_path = os.path.join(tmpdir, filename)
    try:
        file.save(zip_path)
        with zipfile.ZipFile(zip_path, 'r') as zf:
            try:
                scanner.validate_zip_entries(
                    zf, max_entries=MAX_ZIP_ENTRIES,
                    max_bytes=MAX_DECOMPRESSED_BYTES,
                    max_file_bytes=MAX_ZIP_FILE_BYTES,
                    max_compression_ratio=MAX_COMPRESSION_RATIO,
                )
            except scanner.ZipExtractionError as exc:
                return _upload_reject(str(exc), 413, tmpdir)
            archive_info = scanner.archive_diagnostics(zf)
    except zipfile.BadZipFile:
        return _upload_reject("The uploaded file is not a valid ZIP archive.", 400, tmpdir)
    except OSError:
        logging.error("Upload could not be stored for tenant %s", principal.tenant_id)
        return _upload_reject("Upload could not be stored.", 500, tmpdir)

    # Phase 3: optional baseline + gate policy. Validated STRICTLY here so a
    # malformed baseline is a 400 at upload time — never a silently-clean scan.
    baseline_data = None
    baseline_filename = None
    bfile = request.files.get("baseline")
    if bfile is not None and bfile.filename:
        raw = bfile.read(MAX_BASELINE_BYTES + 1)
        if len(raw) > MAX_BASELINE_BYTES:
            return _upload_reject(
                f"Baseline file too large (max {MAX_BASELINE_BYTES} bytes).", 413, tmpdir)
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _upload_reject(
                "The uploaded baseline is not valid UTF-8 JSON.", 400, tmpdir)
        try:
            baseline_data = baseline.validate_baseline(
                decoded, source=secure_filename(bfile.filename) or "baseline")
        except baseline.BaselineError as exc:
            return _upload_reject(f"Invalid baseline: {exc}", 400, tmpdir)
        baseline_filename = secure_filename(bfile.filename) or None

    fail_on = (request.form.get("fail_on") or "").strip() or None
    if fail_on is not None:
        try:
            baseline.parse_policy(fail_on)
        except baseline.BaselineError as exc:
            return _upload_reject(str(exc), 400, tmpdir)

    job_id = str(uuid.uuid4())
    job_manager.submit(
        job_id, None,
        payload={"type": "sast", "filename": filename,
                 "zip_path": zip_path, "temp_dir": tmpdir,
                 "archive": archive_info,
                 "baseline": baseline_data,
                 "baseline_filename": baseline_filename,
                 "fail_on": fail_on},
        tenant_id=principal.tenant_id,
        principal_id=principal.id,
    )
    audit.record_from_request("scan.submit", result="accepted",
                              object_type="job", object_id=job_id,
                              detail={"filename": filename,
                                      "entries": archive_info.get("entries")})
    logging.info("SAST job dispatched: %s (tenant=%s)", job_id, principal.tenant_id)
    return jsonify({
        "status": "accepted",
        "task_id": job_id,
        "message": "Analysis dispatched. Poll /api/v1/scan/{task_id} for status and live logs.",
    }), 202


# ---- Job polling -------------------------------------------------------------

@app.route('/api/v1/scan/<job_id>', methods=['GET'])
@limiter.limit(config.rate_limit("poll"))
@requires("scan:read")
def scan_status(job_id):
    # Tenant-scoped lookup: another tenant's job id is indistinguishable from
    # an unknown one (404), so no existence oracle is offered.
    job = job_manager.get(job_id, tenant_id=g.principal.tenant_id)
    if not job:
        return jsonify({"error": "Unknown task_id"}), 404

    response = {
        "task_id": job_id,
        "status": job["status"],
        "scan_id": job["scan_id"],
        "updated_at": job["updated_at"],
        "logs": job["logs"],
    }
    if job["status"] == "SUCCESS" and job.get("result"):
        response.update(job["result"])
    if job["status"] == "FAILED":
        # Error text is bounded at write time; no host paths or secrets.
        response["error"] = (job.get("result") or {}).get("error", "Job failed")
    return jsonify(response), 200


@app.route('/api/v1/scan/<job_id>/logs', methods=['GET'])
@limiter.limit(config.rate_limit("logs"))
@requires("scan:read")
def scan_logs(job_id):
    """Live terminal-log stream for a job (lightweight — no results payload)."""
    job = job_manager.get(job_id, tenant_id=g.principal.tenant_id)
    if not job:
        return jsonify({"error": "Unknown task_id"}), 404
    return jsonify({
        "task_id": job_id,
        "status": job["status"],
        "logs": job["logs"],
    }), 200


# ---- Compliance check (CLI telemetry ingestion) -----------------------------

@app.route('/api/v1/compliance/check', methods=['POST'])
@limiter.limit(config.rate_limit("telemetry"))
@requires("telemetry:write")
def compliance_check():
    """Accepts anonymized telemetry from the CLI agent (zero-trust) and returns
    an initial verdict; dispatches an audit job."""
    principal = g.principal
    data = request.get_json(silent=True) or {}
    telemetry = data.get("telemetry") or data

    if not telemetry or "algorithm_telemetry" not in telemetry:
        return jsonify({"error": "Expected telemetry payload with 'algorithm_telemetry' "
                                 "(see `python cipher_cli.py telemetry <target>`)"}), 400

    algo_telemetry = telemetry["algorithm_telemetry"]
    if not isinstance(algo_telemetry, list) or len(algo_telemetry) > MAX_TELEMETRY_ITEMS:
        return jsonify({"error": f"algorithm_telemetry must be a list of at most "
                                 f"{MAX_TELEMETRY_ITEMS} items"}), 400
    summary = {
        "PASS": 0, "WARN": 0, "FAIL": 0,
        "standards": {std: 0 for std in compliance.STANDARDS},
    }
    for item in algo_telemetry:
        verdict = item.get("verdict", "WARN")
        summary[verdict if verdict in summary else "WARN"] += item.get("count", 1)
        std = item.get("nist_standard")
        if std in summary["standards"]:
            summary["standards"][std] += item.get("count", 1)

    job_id = str(uuid.uuid4())
    job_manager.submit(
        job_id, None,
        payload={"type": "telemetry-audit", "telemetry": telemetry, "summary": summary},
        tenant_id=principal.tenant_id,
        principal_id=principal.id,
    )
    audit.record_from_request("telemetry.ingest", result="accepted",
                              object_type="job", object_id=job_id,
                              detail={"items": len(algo_telemetry)})

    return jsonify({
        "status": "accepted",
        "task_id": job_id,
        "verdict": "review" if summary["FAIL"] else ("warn" if summary["WARN"] else "ok"),
        "telemetry_summary": summary,
        "note": "Initial local verdict from anonymized telemetry. No source code was uploaded.",
    }), 200


# ---- Scan history (timeline / audit) ----------------------------------------

@app.route('/api/v1/scans', methods=['GET'])
@limiter.limit(config.rate_limit("exports"))
@requires("scan:read")
def scan_history():
    conn = _connect()
    rows = conn.execute(
        "SELECT id, timestamp, filename, pqc_score, verdict FROM scan_history "
        "WHERE tenant_id=? ORDER BY id DESC LIMIT 50",
        (g.principal.tenant_id,),
    ).fetchall()
    conn.close()
    return jsonify({
        "scans": [
            {"id": r[0], "timestamp": r[1], "filename": r[2],
             "pqc_score": r[3], "verdict": r[4]}
            for r in rows
        ]
    }), 200


# ---- Stored scan detail -------------------------------------------------------

@app.route('/api/v1/scans/<int:scan_id>', methods=['GET'])
@limiter.limit(config.rate_limit("poll"))
@requires("scan:read")
def scan_detail(scan_id):
    """One stored scan, addressed by its numeric scan id.

    The job endpoint is keyed by task id and a job record is not permanent
    runtime state, so results, findings, remediation, CBOM and exports all read
    from this durable row. Ownership is part of the query: another tenant's
    scan id is indistinguishable from an unknown one (404).
    """
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT id, timestamp, filename, pqc_score, verdict, compliance_json, "
            "findings_json, baseline_json FROM scan_history "
            "WHERE id=? AND tenant_id=?",
            (scan_id, g.principal.tenant_id),
        ).fetchone()
        if not row:
            return jsonify({"error": "Unknown scan_id"}), 404

        plan_rows = conn.execute(
            "SELECT f.file_path, f.line_number, f.algorithm, f.nist_standard, "
            "p.llm_response, p.created_at FROM remediation_plans p "
            "JOIN findings f ON f.id = p.finding_id "
            "WHERE f.scan_id=? ORDER BY f.id",
            (scan_id,),
        ).fetchall()
    finally:
        conn.close()

    findings = _safe_json_loads(row[6], [])
    plans = []
    for file_path, line_number, algorithm, standard, response, created_at in plan_rows:
        plan = _safe_json_loads(response, None)
        if not isinstance(plan, dict):
            continue
        plans.append({
            "file": file_path,
            "line": line_number,
            "rule": algorithm,
            "standard": standard,
            "plan": plan,
            "created_at": created_at,
        })

    return jsonify({
        "scan_id": row[0],
        "timestamp": row[1],
        "filename": row[2],
        "pqc_score": row[3],
        "verdict": row[4],
        "compliance": _safe_json_loads(row[5], {}),
        "findings": findings if isinstance(findings, list) else [],
        "remediation_plans": plans,
        "baseline": _safe_json_loads(row[7], None),
        "counts": {
            "findings": len(findings) if isinstance(findings, list) else 0,
            "remediation_plans": len(plans),
        },
    }), 200


# ---- CBOM export -------------------------------------------------------------

@app.route('/api/v1/scans/<int:scan_id>/cbom', methods=['GET'])
@limiter.limit(config.rate_limit("exports"))
@requires("report:read")
def scan_cbom(scan_id):
    """CycloneDX 1.7 Cryptographic Bill of Materials for a completed scan."""
    conn = _connect()
    row = conn.execute(
        "SELECT filename, compliance_json, findings_json FROM scan_history "
        "WHERE id=? AND tenant_id=?",
        (scan_id, g.principal.tenant_id),
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Unknown scan_id"}), 404

    matrix = _safe_json_loads(row[1], {})
    findings = _safe_json_loads(row[2], [])
    bom = cbom.build_cbom(matrix, findings, scan_id=scan_id, filename=row[0])
    audit.record_from_request("report.export", object_type="scan",
                              object_id=str(scan_id), detail={"format": "cbom"})
    return jsonify(bom), 200


# ---- SARIF 2.1.0 export ------------------------------------------------------

@app.route('/api/v1/scans/<int:scan_id>/sarif', methods=['GET'])
@limiter.limit(config.rate_limit("exports"))
@requires("report:read")
def scan_sarif(scan_id):
    """SARIF 2.1.0 for a completed scan (validated against the official schema).

    Contains no source snippets, no secrets and no host paths — safe to upload
    as a CI artifact. Baseline status/gate from the scan is carried in result
    properties so code scanning shows new vs. persistent.
    """
    conn = _connect()
    row = conn.execute(
        "SELECT findings_json, baseline_json FROM scan_history "
        "WHERE id=? AND tenant_id=?",
        (scan_id, g.principal.tenant_id),
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Unknown scan_id"}), 404

    findings = _safe_json_loads(row[0], [])
    stored = _safe_json_loads(row[1], None)
    delta = gate = None
    if isinstance(stored, dict):
        delta = stored.get("delta")
        gate = stored.get("gate")

    doc = sarif.build_sarif({"findings": findings},
                            baseline_delta=delta, gate=gate)
    errors = sarif.validate_sarif(doc)
    if errors:
        logging.error(f"SARIF validation failed for scan {scan_id}: {errors[:5]}")
        return jsonify({"error": "SARIF generation failed schema validation",
                        "details": errors[:10]}), 500

    response = jsonify(doc)
    response.headers["Content-Type"] = "application/sarif+json"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="piquachu-scan-{scan_id}.sarif"')
    audit.record_from_request("report.export", object_type="scan",
                              object_id=str(scan_id), detail={"format": "sarif"})
    return response, 200


# ---- Reliability metrics -----------------------------------------------------

@app.route('/api/v1/reliability', methods=['GET'])
@limiter.limit(config.rate_limit("exports"))
@requires("reliability:read")
def reliability():
    """Detection metrics (Accuracy / Precision / Recall / F1) over the labeled
    hermetic corpus.

    The response always carries provenance (ruleset + corpus fingerprint,
    metric source) and true freshness (``generated_at`` + ``age_seconds``).
    A cached report is never presented as current: once older than
    ``RELIABILITY_TTL`` it is flagged ``stale`` and a background refresh starts.
    """
    with _reliability_lock:
        fresh = _reliability_cache["report"] is not None and \
            (time.time() - _reliability_cache["at"]) < RELIABILITY_TTL
        report = _reliability_cache["report"]
        last_error = _reliability_cache["last_error"]
        last_success = (_reliability_cache["last_success"]
                        or (report or {}).get("generated_at"))

    if report is None:
        # first request — kick off background computation, report computing state
        _start_reliability_compute()
        return jsonify({
            "status": "computing",
            "metric_source": metrics.NOT_RUN,
            "note": ("Benchmark corpus is being scanned in the background. "
                     "Poll again shortly."),
        }), 202

    payload = dict(report)
    payload["generated_at"] = payload.get("generated_at")
    payload["last_successful_run"] = last_success
    if last_error:
        payload["last_attempt_failed"] = last_error
    age = metrics.age_seconds(payload.get("generated_at"))
    payload["age_seconds"] = age
    payload["max_age_seconds"] = RELIABILITY_TTL
    # Staleness is a property of the metric, not of the cache slot: an old
    # generated_at is stale even if the cache entry was just touched.
    payload["stale"] = bool(not fresh or age is None or age > RELIABILITY_TTL)
    payload["metric_source"] = payload.get("metric_source", metrics.HERMETIC)
    payload.setdefault("ruleset", metrics.ruleset_fingerprint())
    payload.setdefault("corpus", metrics.corpus_fingerprint())
    payload["external_validation"] = _external_metrics_status()
    payload["release_gates"] = payload.get("release_gates") or metrics.release_gates()
    if not fresh:
        # Refresh in the background; the stale report stays visible meanwhile.
        _start_reliability_compute()
        payload["refreshing"] = True
    return jsonify({"status": "ready", **payload}), 200


def _external_metrics_status() -> dict:
    """External ground-truth metrics are only published when a run exists.

    Never fabricate them: no report file means ``not-run``, which is honest and
    distinct from a passing external baseline.
    """
    path = os.environ.get("PIQUACHU_EXTERNAL_REPORT", "").strip()
    if not path or not os.path.isfile(path):
        return {"metric_source": metrics.NOT_RUN,
                "note": "No external ground-truth run has been published."}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        return {"metric_source": metrics.EXTERNAL, "status": "unreadable",
                "error": str(exc)}
    metric_values = data.get("metrics") or {}
    micro = metric_values.get("micro") or metric_values
    return {
        "metric_source": metrics.EXTERNAL,
        "status": "ready",
        "generated_at": data.get("generated_at"),
        "age_seconds": metrics.age_seconds(data.get("generated_at")),
        "targets": data.get("targets"),
        "confusion": data.get("confusion"),
        "micro": micro,
        "macro": metric_values.get("macro"),
        "per_target": data.get("per_target"),
    }


# ---- AI Assistant (DevSecOps engineer) --------------------------------------

@app.route('/api/v1/assistant/query', methods=['POST'])
@limiter.limit(config.rate_limit("assistant"))
@requires("assist:query")
def assistant_query():
    data = request.get_json(silent=True) or {}
    question = (data.get("question") or "").strip()
    if not question:
        return jsonify({"error": "Missing 'question'"}), 400
    if len(question) > MAX_QUESTION_LENGTH:
        return jsonify({"error": f"question exceeds {MAX_QUESTION_LENGTH} characters"}), 413

    # Context is one specific stored scan when the caller supplies `scan_id`
    # (tenant-scoped; unknown ids are a 404, not a silent fallback). Without it
    # the most recent scan for THIS tenant is used.
    compliance_matrix, findings = {}, []
    scan_id = data.get("scan_id")
    conn = _connect()
    if scan_id is not None:
        if not isinstance(scan_id, int) or isinstance(scan_id, bool):
            conn.close()
            return jsonify({"error": "scan_id must be an integer"}), 400
        row = conn.execute(
            "SELECT compliance_json, findings_json FROM scan_history "
            "WHERE id=? AND tenant_id=?",
            (scan_id, g.principal.tenant_id),
        ).fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Unknown scan_id"}), 404
    else:
        row = conn.execute(
            "SELECT compliance_json, findings_json FROM scan_history "
            "WHERE tenant_id=? ORDER BY id DESC LIMIT 1",
            (g.principal.tenant_id,),
        ).fetchone()
    conn.close()
    if row:
        compliance_matrix = _safe_json_loads(row[0], {})
        findings = _safe_json_loads(row[1], [])

    answer = remediation.assistant_answer(question, compliance_matrix, findings)
    return jsonify({
        "question": question,
        "answer": answer.get("answer", ""),
        "code": answer.get("code"),
        "has_context": bool(row),
        "scan_id": scan_id,
        "remote_ai": bool(os.environ.get("GROQ_API_KEY")),
        "privacy_note": remediation.ASSISTANT_PRIVACY_NOTE,
    }), 200


# ---- Authentication (OIDC Authorization Code + PKCE) ------------------------
#
# The API key path above remains valid for local/CI use. These routes add an
# identity-provider login whose client secret never leaves this process. When
# the provider is not configured they report that state; there is no mock
# "logged in" fallback.

def _app_origin() -> str:
    """Public origin of the web application, used only for post-login redirects."""
    return (config.env("PIQUACHU_APP_URL", "") or "").rstrip("/")


def _same_origin_request() -> bool:
    """Cheap CSRF belt for cookie-authenticated state changes.

    SameSite=Lax already stops cross-site POSTs from carrying the session
    cookie; this additionally rejects a mismatched Origin when one is sent.
    """
    origin = request.headers.get("Origin")
    if not origin:
        return True
    allowed = {request.host_url.rstrip("/")}
    if _app_origin():
        allowed.add(_app_origin())
    return origin.rstrip("/") in allowed


@app.route('/api/v1/auth/providers', methods=['GET'])
@limiter.limit(config.rate_limit("auth"))
def auth_providers():
    status = oidc.public_status()
    return jsonify({"providers": oidc.providers(), **status}), 200


@app.route('/api/v1/auth/login', methods=['GET'])
@limiter.limit(config.rate_limit("auth"))
def auth_login():
    """Start the flow. `return_to` is restricted to same-application paths."""
    try:
        url, flow_cookie, max_age = oidc.begin_login(request.args.get("return_to"))
    except oidc.OidcError as exc:
        logging.warning("OIDC login could not start: %s", exc)
        return jsonify({"error": str(exc)}), 503

    response = redirect(url, code=302)
    response.set_cookie(
        oidc.FLOW_COOKIE, flow_cookie, max_age=max_age,
        httponly=True, secure=oidc.should_use_secure_cookie(), samesite="Lax",
        path="/api/v1/auth",
    )
    return response


@app.route('/api/v1/auth/callback', methods=['GET'])
@limiter.limit(config.rate_limit("auth"))
def auth_callback():
    """Provider callback: verify state/nonce/signature, then set a session."""
    code = request.args.get("code", "")
    state = request.args.get("state", "")
    flow_cookie = request.cookies.get(oidc.FLOW_COOKIE)

    def fail(reason: str):
        logging.warning("OIDC callback rejected: %s", reason)
        audit.record_from_request("auth.oidc.callback", result="denied",
                                  detail={"reason": reason})
        target = f"{_app_origin() or ''}/login?error=sso_failed"
        response = redirect(target, code=302)
        response.delete_cookie(oidc.FLOW_COOKIE, path="/api/v1/auth")
        return response

    try:
        payload, return_to = oidc.complete_login(code, state, flow_cookie)
    except oidc.OidcError as exc:
        return fail(str(exc))

    principal = oidc.principal_from_session(payload)
    if principal is None or not authz.tenant_active(principal.tenant_id):
        return fail("tenant or role is not usable")

    # Session rotation: the session id is minted fresh for this login.
    response = redirect(f"{_app_origin()}{return_to}", code=302)
    response.set_cookie(
        oidc.SESSION_COOKIE, oidc.issue_session(payload),
        max_age=oidc.session_ttl(), **oidc.session_cookie_settings(),
    )
    response.delete_cookie(oidc.FLOW_COOKIE, path="/api/v1/auth")
    audit.record_from_request("auth.login", result="success",
                             object_type="principal", object_id=principal.id,
                             detail={"method": "oidc", "tenant": principal.tenant_id,
                                     "role": principal.role})
    return response


@app.route('/api/v1/auth/session', methods=['GET'])
@limiter.limit(config.rate_limit("auth"))
def auth_session():
    """Who is this request? API key, verified session, or nobody."""
    raw_session = request.cookies.get(oidc.SESSION_COOKIE)
    session_payload = oidc.read_session(raw_session)
    principal = _current_principal()
    base = {"providers": oidc.providers(), **oidc.public_status()}

    if principal is None:
        return jsonify({
            "authenticated": False,
            "method": None,
            "principal": None,
            "permissions": [],
            **base,
        }), 200

    return jsonify({
        "authenticated": True,
        "method": "session" if session_payload else "api_key",
        "principal": principal.as_public_dict(),
        "permissions": authz.permissions_for(principal.role),
        "expires_at": session_payload.get("exp") if session_payload else None,
        **base,
    }), 200


@app.route('/api/v1/auth/logout', methods=['POST'])
@limiter.limit(config.rate_limit("auth"))
def auth_logout():
    if not _same_origin_request():
        return jsonify({"error": "Forbidden."}), 403
    principal = getattr(g, "principal", None)
    response = jsonify({"authenticated": False})
    response.delete_cookie(oidc.SESSION_COOKIE, path="/")
    if principal is not None:
        audit.record_from_request("auth.logout", result="success",
                                 object_type="principal", object_id=principal.id)
    return response, 200


# ---- Health / readiness -----------------------------------------------------

def _limit_ready_state(storage_uri: str) -> bool:
    """Probe an arbitrary limiter storage URI (readiness + tests).

    Never raises and never includes the URI in an error response.
    """
    try:
        from limits.storage import storage_from_string
        return bool(storage_from_string(storage_uri).check())
    except Exception:  # noqa: BLE001 - unavailable is the answer, not a traceback
        return False


def _limiter_storage_ok() -> bool | None:
    """Cheap liveness probe of the limiter backend (None when in-memory)."""
    if _RATE_LIMIT_STORAGE.startswith("memory://"):
        return None
    try:
        return bool(limiter.storage.check())
    except Exception:  # noqa: BLE001 - surfaced as unavailable, never a stack trace
        return False


@app.route('/api/v1/health', methods=['GET'])
@limiter.limit(config.rate_limit("health"))
def health():
    """Liveness + configuration summary. No secrets, no internal stack traces."""
    return jsonify({
        "status": "ok",
        "service": "PiQuaChu API",
        "version": APP_VERSION,
        "checks": {
            "database": {"status": "ok"},
            "rate_limiter": {
                "backend": ("redis" if config.distributed_rate_limiting()
                            else "in-memory"),
                "failure_mode": _RATE_LIMIT_FAILURE_MODE,
            },
            "job_backend": ("celery" if _celery_enabled() else "threads"),
        },
        "configuration": {
            "environment": _STARTUP["environment"],
            "tenancy_mode": _STARTUP["tenancy_mode"],
            "warnings": _STARTUP["warnings"],
        },
    }), 200


@app.route('/api/v1/ready', methods=['GET'])
@limiter.limit(config.rate_limit("health"))
def ready():
    """Readiness: DB reachable + limiter backend usable when distributed."""
    database_ok = True
    try:
        conn = _connect()
        conn.execute("SELECT 1").fetchone()
        conn.close()
    except Exception:  # noqa: BLE001
        database_ok = False
    limiter_ok = _limiter_storage_ok()
    ready_now = database_ok and limiter_ok is not False
    status = "ready" if ready_now else "not_ready"
    return jsonify({
        "status": status,
        "version": APP_VERSION,
        "checks": {
            "database": "ok" if database_ok else "unavailable",
            "rate_limiter": ("ok" if limiter_ok else
                             ("in-memory" if limiter_ok is None else "unavailable")),
        },
    }), (200 if ready_now else 503)


# ---- Administration (tenant / key / audit) ----------------------------------

@app.route('/api/v1/admin/tenants', methods=['GET'])
@limiter.limit(config.rate_limit("admin"))
@requires("tenant:admin")
def admin_list_tenants():
    return jsonify({"tenants": authz.list_tenants()}), 200


@app.route('/api/v1/admin/tenants', methods=['POST'])
@limiter.limit(config.rate_limit("admin"))
@requires("tenant:admin")
def admin_create_tenant():
    data = request.get_json(silent=True) or {}
    try:
        created = authz.create_tenant((data.get("tenant_id") or "").strip(),
                                      data.get("name"),
                                      actor=g.principal.id)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    audit.record_from_request("tenant.create", object_type="tenant",
                              object_id=created["tenant_id"], tenant_id=created["tenant_id"])
    return jsonify(created), 201


@app.route('/api/v1/admin/keys', methods=['GET'])
@limiter.limit(config.rate_limit("admin"))
@requires("key:admin")
def admin_list_keys():
    tenant = request.args.get("tenant") or g.principal.tenant_id
    if tenant != g.principal.tenant_id and g.principal.role not in {"owner", "admin"}:
        return jsonify({"error": "Forbidden."}), 403
    return jsonify({"keys": authz.list_keys(tenant)}), 200


@app.route('/api/v1/admin/keys', methods=['POST'])
@limiter.limit(config.rate_limit("admin"))
@requires("key:admin")
def admin_create_key():
    data = request.get_json(silent=True) or {}
    tenant = (data.get("tenant_id") or g.principal.tenant_id).strip()
    # A key admin may only mint keys for their own tenant unless they are an
    # owner/admin of the *target* tenant — cross-tenant key minting is denied.
    if tenant != g.principal.tenant_id and g.principal.role not in {"owner"}:
        return jsonify({"error": "Forbidden."}), 403
    try:
        created = authz.create_key(tenant, data.get("name") or "api-key",
                                   role=data.get("role") or "analyst",
                                   expires_days=data.get("expires_days"),
                                   created_by=g.principal.id)
    except (ValueError, RuntimeError) as exc:
        return jsonify({"error": str(exc)}), 400
    audit.record_from_request("key.create", object_type="principal",
                              object_id=created["key_id"], tenant_id=tenant,
                              detail={"role": created["role"]})
    return jsonify(created), 201


@app.route('/api/v1/admin/keys/<key_id>/rotate', methods=['POST'])
@limiter.limit(config.rate_limit("admin"))
@requires("key:admin")
def admin_rotate_key(key_id):
    try:
        rotated = authz.rotate_key(key_id, actor=g.principal.id)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    audit.record_from_request("key.rotate", object_type="principal",
                              object_id=rotated["key_id"],
                              tenant_id=rotated["tenant_id"],
                              detail={"replaced": key_id})
    return jsonify(rotated), 201


@app.route('/api/v1/admin/keys/<key_id>', methods=['DELETE'])
@limiter.limit(config.rate_limit("admin"))
@requires("key:admin")
def admin_revoke_key(key_id):
    revoked = authz.revoke_key(key_id, actor=g.principal.id)
    audit.record_from_request("key.revoke", object_type="principal",
                              object_id=key_id, result="ok" if revoked else "not_found")
    if not revoked:
        return jsonify({"error": "Unknown key"}), 404
    return jsonify({"revoked": True, "key_id": key_id}), 200


@app.route('/api/v1/admin/audit', methods=['GET'])
@limiter.limit(config.rate_limit("admin"))
@requires("audit:read")
def admin_audit():
    try:
        limit = int(request.args.get("limit") or 50)
    except ValueError:
        limit = 50
    return jsonify({"events": audit.recent(g.principal.tenant_id, limit=limit)}), 200


# ---- Misc -------------------------------------------------------------------

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found. Check your URL."}), 404


@app.errorhandler(413)
def too_large(error):
    return jsonify({"error": f"Upload too large (max {config.max_upload_bytes()} bytes)."}), 413


def _is_limiter_storage_error(exc: BaseException) -> bool:
    module = type(exc).__module__ or ""
    name = type(exc).__name__
    return (module.startswith(("redis", "limits"))
            or name in {"ConnectionError", "TimeoutError", "RedisError"})


@app.errorhandler(500)
def internal_error(error):
    """Fail closed when the distributed limiter is unavailable.

    In `closed` mode a limiter storage outage must not silently disable the
    abuse control, so the request is refused with 503. Everything else gets a
    generic 500 with no stack trace or internal path.
    """
    original = getattr(error, "original_exception", None) or error
    if _is_limiter_storage_error(original) and _RATE_LIMIT_FAILURE_MODE == "closed":
        logging.error("Rate-limiter storage unavailable (%s); failing closed.",
                      type(original).__name__)
        return jsonify({"error": "Rate limiter unavailable; request refused."}), 503
    logging.error("Unhandled error: %s", type(original).__name__)
    return jsonify({"error": "Internal server error."}), 500


@app.after_request
def _apply_security_headers(response):
    """Baseline hardening headers for all API responses."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Content-Security-Policy",
                                "default-src 'none'; frame-ancestors 'none'")
    if config.is_production():
        response.headers.setdefault("Strict-Transport-Security",
                                    "max-age=31536000; includeSubDomains")
    return response


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting PiQuaChu API on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
