# backend/tasks.py
"""
tasks.py — optional Celery worker for PiQuaChu background jobs
===============================================================
Production scaling path for the job queue (see README "Production scaling").

The default deployment keeps jobs in-process (daemon threads + SQLite WAL),
which is perfect for single-host / self-hosted use. When you need multiple
workers, horizontal scaling or crash isolation, run the Celery worker:

    export PIQUACHU_BROKER_URL=redis://localhost:6379/0
    cd backend
    celery -A tasks worker --loglevel=info

The Flask app auto-detects PIQUACHU_BROKER_URL and routes new jobs to this
worker instead of spawning threads. Results and logs are still persisted to
SQLite (the jobs table), so the polling API is identical in both modes.
"""

import os

from celery import Celery

from jobs import run_job

_BROKER = os.environ.get("PIQUACHU_BROKER_URL", "redis://localhost:6379/0")

app = Celery("piquachu", broker=_BROKER, backend=_BROKER)
app.conf.update(
    task_track_started=True,      # report started tasks to the broker
    worker_prefetch_multiplier=1, # one job per worker at a time (bounded memory)
    task_time_limit=1800,
    # A worker crash must not silently drop an accepted job: the task is
    # re-queued (at-least-once). The pipeline is idempotent per job row — the
    # worker re-reads the row and refuses a tenant-context mismatch.
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    broker_connection_retry_on_startup=True,
    # How long an unacked message may stay invisible before Redis redelivers it
    # after a hard worker kill. Default is 1 hour; lower values recover scans
    # faster but risk duplicate execution of a slow scan (the pipeline is
    # idempotent per job row, and a duplicate is refused once the row is done).
    broker_transport_options={
        "visibility_timeout": int(os.environ.get(
            "PIQUACHU_CELERY_VISIBILITY_TIMEOUT", "3600"))},
)


@app.task(name="piquachu.sast_scan", bind=True)
def sast_scan_task(self, job_id: str, payload: dict):
    """Celery task mirror of the thread-mode sast pipeline.

    `run_job` validates the persisted job row (tenant + upload paths) before
    any work; a tampered message fails the job instead of writing data.
    """
    from app import job_manager
    from jobs import resume_if_complete

    existing = resume_if_complete(job_id)
    if existing is not None:
        return existing
    job_manager.mark_analysing(job_id)
    try:
        result = run_job(job_id, payload)
        job_manager._set_status(job_id, "SUCCESS", result)
        return result
    except Exception as exc:  # noqa: BLE001 — always mark the job row failed
        job_manager._set_status(job_id, "FAILED", {"error": str(exc)})
        raise


@app.task(name="piquachu.telemetry_audit", bind=True)
def telemetry_audit_task(self, job_id: str, payload: dict):
    """Celery task for the zero-trust telemetry audit job."""
    from app import job_manager
    from jobs import resume_if_complete

    existing = resume_if_complete(job_id)
    if existing is not None:
        return existing
    job_manager.mark_analysing(job_id)
    try:
        result = run_job(job_id, payload)
        job_manager._set_status(job_id, "SUCCESS", result)
        return result
    except Exception as exc:  # noqa: BLE001
        job_manager._set_status(job_id, "FAILED", {"error": str(exc)})
        raise
