# backend/audit.py
"""
audit.py — structured security audit events
===========================================
A dedicated, append-only event stream for security-relevant actions. This is
**not** an immutable/WORM compliance ledger and the documentation says so; the
guarantee implemented here is:

  * one structured record per security event (DB row + JSONL file),
  * append-only application semantics (no update/delete API),
  * CR/LF/control-character injection cannot forge a line, and every
    attacker-controlled field is length-bounded,
  * secrets, source snippets and key material are never written,
  * file is created 0600 and rotated with a bounded number of backups,
  * retention pruning is explicit and counted.

Failure to write an audit event never crashes a request; it is logged as an
error so the operator can see the audit path is broken.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import config

# Fields that must never reach the audit stream, whatever the caller passes.
_FORBIDDEN_KEYS = {
    "api_key", "apikey", "key", "secret", "token", "password", "passwd",
    "authorization", "cookie", "set-cookie", "private_key", "privatekey",
    "snippet", "snippets", "source", "source_code", "code", "content",
    "payload", "question", "key_material", "pepper", "hash", "key_hash",
}

MAX_FIELD_CHARS = 200
MAX_DETAIL_CHARS = 2000
MAX_DETAIL_KEYS = 24

_CONNECT = None


def set_connection_provider(provider) -> None:
    """Let the Flask app supply its own connection (respects a swapped DB path)."""
    global _CONNECT
    _CONNECT = provider


def _connect() -> sqlite3.Connection:
    if _CONNECT is not None:
        return _CONNECT()
    path = os.environ.get("PIQUACHU_DB_PATH") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "piquachu.db")
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sanitize(value, *, limit: int = MAX_FIELD_CHARS) -> str | None:
    """Strip control characters (incl. CR/LF) and bound the length.

    An attacker-controlled finding message or header value must not be able to
    inject a new JSONL line or a fake `action` field.
    """
    if value is None:
        return None
    text = str(value)
    cleaned = "".join(
        ch if (ch.isprintable() and ch not in "\r\n\t") else " "
        for ch in text
    )
    cleaned = " ".join(cleaned.split())
    return cleaned[:limit]


def _sanitize_detail(detail: dict | None) -> dict:
    if not isinstance(detail, dict):
        return {}
    out: dict = {}
    for key, value in list(detail.items())[:MAX_DETAIL_KEYS]:
        name = sanitize(key, limit=48) or "field"
        if name.lower() in _FORBIDDEN_KEYS:
            out[name] = "<redacted>"
            continue
        if isinstance(value, bool) or value is None:
            out[name] = value
        elif isinstance(value, (int, float)):
            out[name] = value
        elif isinstance(value, (list, tuple)):
            out[name] = [sanitize(item, limit=80) for item in list(value)[:8]]
        elif isinstance(value, dict):
            out[name] = {sanitize(k, limit=32) or "k": sanitize(v, limit=80)
                         for k, v in list(value.items())[:8]
                         if str(k).lower() not in _FORBIDDEN_KEYS}
        else:
            out[name] = sanitize(value, limit=120)
    encoded = json.dumps(out, ensure_ascii=True, separators=(",", ":"))
    while len(encoded) > MAX_DETAIL_CHARS and out:
        out.popitem()
        encoded = json.dumps(out, ensure_ascii=True, separators=(",", ":"))
    return out


def _rotate_if_needed(path: str) -> None:
    try:
        if not os.path.exists(path):
            return
        if os.path.getsize(path) < config.audit_max_bytes():
            return
        backups = config.audit_backups()
        if backups <= 0:
            os.replace(path, path + ".1")
            return
        oldest = f"{path}.{backups}"
        if os.path.exists(oldest):
            os.remove(oldest)
        for index in range(backups - 1, 0, -1):
            src = f"{path}.{index}"
            if os.path.exists(src):
                os.replace(src, f"{path}.{index + 1}")
        os.replace(path, f"{path}.1")
    except OSError as exc:  # rotation is best-effort; never break the request
        logging.error("Audit log rotation failed: %s", exc)


def _write_file(event: dict) -> None:
    path = config.audit_log_path()
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        _rotate_if_needed(path)
        line = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
        # `open` honours an existing file's mode; create with 0600 explicitly.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except OSError as exc:
        logging.error("Audit log write failed: %s", exc)


def _write_db(event: dict) -> None:
    try:
        conn = _connect()
        try:
            conn.execute(
                "INSERT INTO audit_events (timestamp, actor_type, actor_id, tenant_id, "
                "action, result, object_type, object_id, correlation_id, detail, client_ip) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (event["timestamp"], event["actor_type"], event["actor_id"],
                 event["tenant_id"], event["action"], event["result"],
                 event["object_type"], event["object_id"],
                 event["correlation_id"],
                 json.dumps(event["detail"], ensure_ascii=True),
                 event["client_ip"]),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001 - audit must not break the request
        logging.error("Audit DB write failed: %s", exc)


def record(action: str, *, result: str = "success",
           actor_type: str = "system", actor_id: str | None = None,
           tenant_id: str | None = None,
           object_type: str | None = None, object_id: str | None = None,
           correlation_id: str | None = None,
           detail: dict | None = None,
           client_ip: str | None = None) -> dict:
    """Record one security event. Returns the sanitized event that was written."""
    event = {
        "timestamp": _now(),
        "actor_type": sanitize(actor_type, limit=24) or "system",
        "actor_id": sanitize(actor_id, limit=64),
        "tenant_id": sanitize(tenant_id, limit=64),
        "action": sanitize(action, limit=64) or "unknown",
        "result": sanitize(result, limit=16) or "unknown",
        "object_type": sanitize(object_type, limit=32),
        "object_id": sanitize(object_id, limit=64),
        "correlation_id": sanitize(correlation_id, limit=64),
        "detail": _sanitize_detail(detail),
        "client_ip": sanitize(client_ip, limit=64),
    }
    if not config.audit_enabled():
        return event
    _write_db(event)
    _write_file(event)
    return event


def record_from_request(action: str, **kwargs) -> dict:
    """Convenience wrapper for HTTP callers (never raises outside a request)."""
    try:
        from flask import g, request
    except Exception:  # pragma: no cover - flask is a hard dependency
        return record(action, **kwargs)
    principal = getattr(g, "principal", None)
    kwargs.setdefault("actor_type", "principal" if principal else "anonymous")
    if principal:
        kwargs.setdefault("actor_id", principal.id)
        kwargs.setdefault("tenant_id", principal.tenant_id)
        if getattr(principal, "legacy", False):
            kwargs.setdefault("actor_type", "legacy-env")
    try:
        kwargs.setdefault("client_ip", config.client_ip(
            request.remote_addr, request.headers.get("X-Forwarded-For")))
    except RuntimeError:
        pass
    return record(action, **kwargs)


def prune(retention_days: int | None = None) -> int:
    """Delete DB events older than the retention window. Returns rows removed."""
    days = config.audit_retention_days() if retention_days is None else retention_days
    if days <= 0:
        return 0
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    try:
        conn = _connect()
        try:
            cursor = conn.execute("DELETE FROM audit_events WHERE timestamp < ?", (cutoff,))
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001
        logging.error("Audit retention prune failed: %s", exc)
        return 0


def recent(tenant_id: str | None = None, limit: int = 50) -> list[dict]:
    """Read recent events (tenant-scoped when given). Metadata only."""
    limit = max(1, min(int(limit), 200))
    conn = _connect()
    try:
        if tenant_id is None:
            rows = conn.execute(
                "SELECT timestamp, actor_type, actor_id, tenant_id, action, result, "
                "object_type, object_id, correlation_id, detail FROM audit_events "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT timestamp, actor_type, actor_id, tenant_id, action, result, "
                "object_type, object_id, correlation_id, detail FROM audit_events "
                "WHERE tenant_id=? ORDER BY id DESC LIMIT ?", (tenant_id, limit)).fetchall()
        keys = ["timestamp", "actor_type", "actor_id", "tenant_id", "action",
                "result", "object_type", "object_id", "correlation_id"]
        events = []
        for row in rows:
            item = dict(zip(keys, row[:9]))
            try:
                item["detail"] = json.loads(row[9]) if row[9] else {}
            except (TypeError, ValueError):
                item["detail"] = {}
            events.append(item)
        return events
    finally:
        conn.close()


def count(action: str | None = None) -> int:
    conn = _connect()
    try:
        if action:
            return conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE action=?", (action,)).fetchone()[0]
        return conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    finally:
        conn.close()
