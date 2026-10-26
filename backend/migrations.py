# backend/migrations.py
"""
migrations.py — versioned, data-preserving schema upgrades
==========================================================
Phase 4 introduces tenants, principals, audit events and tenant columns on
existing tables. The upgrade is **additive only**:

  * no table is dropped, renamed or recreated,
  * scan / finding / remediation / job rows keep their primary keys and values,
  * a one-time SQLite backup is written before the first upgrade,
  * the version is recorded in `schema_migrations`, so the upgrade is idempotent.

Rollback is explicit (`python migrations.py rollback --yes`) or a manual file
restore with the service stopped. There is no automatic destructive path — a
setup script, test or deploy must never drop a user's database.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone

import config

SCHEMA_VERSION = 1

_NEW_TABLES = {
    "schema_migrations": """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL,
            app_version TEXT,
            notes TEXT
        )
    """,
    "tenants": """
        CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            disabled INTEGER NOT NULL DEFAULT 0
        )
    """,
    "principals": """
        CREATE TABLE IF NOT EXISTS principals (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            key_prefix TEXT UNIQUE,
            key_hash TEXT,
            created_at TEXT NOT NULL,
            created_by TEXT,
            expires_at TEXT,
            revoked_at TEXT,
            last_used_at TEXT,
            rotated_from TEXT
        )
    """,
    "audit_events": """
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor_type TEXT,
            actor_id TEXT,
            tenant_id TEXT,
            action TEXT NOT NULL,
            result TEXT NOT NULL,
            object_type TEXT,
            object_id TEXT,
            correlation_id TEXT,
            detail TEXT,
            client_ip TEXT
        )
    """,
    "settings": """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """,
}

_COLUMNS = {
    "scan_history": [
        ("tenant_id", "TEXT NOT NULL DEFAULT 'local'"),
        ("principal_id", "TEXT"),
    ],
    "jobs": [
        ("tenant_id", "TEXT NOT NULL DEFAULT 'local'"),
        ("principal_id", "TEXT"),
    ],
}

_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_scan_history_tenant ON scan_history(tenant_id, id)",
    "CREATE INDEX IF NOT EXISTS idx_jobs_tenant ON jobs(tenant_id, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_principals_tenant ON principals(tenant_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_events_tenant ON audit_events(tenant_id, id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action, id)",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    return bool(row)


def columns(conn: sqlite3.Connection, table: str) -> set[str]:
    if not table_exists(conn, table):
        return set()
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def current_version(conn: sqlite3.Connection) -> int:
    if not table_exists(conn, "schema_migrations"):
        return 0
    row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    return int(row[0] or 0)


def _backup(conn: sqlite3.Connection, db_path: str) -> str | None:
    """One-time pre-upgrade backup via the SQLite backup API (no shell copy)."""
    if not db_path or not os.path.isfile(db_path):
        return None
    target = db_path + ".pre-phase4.bak"
    if os.path.exists(target):
        return target  # never overwrite the first, known-good snapshot
    try:
        dest = sqlite3.connect(target)
        try:
            conn.backup(dest)
        finally:
            dest.close()
        os.chmod(target, 0o600)
        return target
    except (OSError, sqlite3.Error):
        return None


def migrate(conn: sqlite3.Connection, *, db_path: str | None = None) -> dict:
    """Upgrade the connected database in place. Idempotent, additive only."""
    freshest = not table_exists(conn, "scan_history")
    version = current_version(conn)
    applied: list[str] = []
    backup = None

    if version < SCHEMA_VERSION and not freshest:
        backup = _backup(conn, db_path or "")
        applied.append("backup")

    for name, ddl in _NEW_TABLES.items():
        conn.execute(ddl)
    if version < SCHEMA_VERSION:
        applied.append("tables")

    for table, additions in _COLUMNS.items():
        if not table_exists(conn, table):
            continue
        existing = columns(conn, table)
        for name, ddl in additions:
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
                applied.append(f"{table}.{name}")

    for statement in _INDEXES:
        try:
            conn.execute(statement)
        except sqlite3.OperationalError:
            # The index targets a table that does not exist yet in a partial
            # schema; skip it rather than failing the whole upgrade.
            pass

    conn.execute(
        "INSERT INTO tenants (id, name, created_at, disabled) VALUES ('local', ?, ?, 0) "
        "ON CONFLICT(id) DO NOTHING",
        ("Local workspace", _now()),
    )

    if version < SCHEMA_VERSION:
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at, app_version, notes) "
            "VALUES (?, ?, ?, ?)",
            (SCHEMA_VERSION, _now(), config.APP_VERSION,
             "tenant scope + principals + audit events (additive)"),
        )
    conn.commit()

    return {
        "schema_version": SCHEMA_VERSION,
        "previous_version": version,
        "fresh_database": freshest,
        "applied": applied,
        "backup": backup,
    }


def preflight(conn: sqlite3.Connection, db_path: str | None = None) -> dict:
    """Report what an upgrade would do without writing anything."""
    version = current_version(conn)
    changes: list[str] = []
    for name in _NEW_TABLES:
        if not table_exists(conn, name):
            changes.append(f"create table {name}")
    for table, additions in _COLUMNS.items():
        existing = columns(conn, table)
        for name, _ddl in additions:
            if table_exists(conn, table) and name not in existing:
                changes.append(f"add column {table}.{name}")
    backup_exists = bool(db_path and os.path.exists(db_path + ".pre-phase4.bak"))
    return {"current_version": version, "target_version": SCHEMA_VERSION,
            "pending_changes": changes,
            "backup_exists": backup_exists,
            "needs_upgrade": version < SCHEMA_VERSION}


def restore_backup(db_path: str, backup_path: str | None = None) -> dict:
    """Rollback: copy the pre-upgrade snapshot back over the live database.

    Explicit operation only. The service must be stopped first; this function
    verifies the snapshot's integrity before overwriting anything.
    """
    backup_path = backup_path or (db_path + ".pre-phase4.bak")
    if not os.path.isfile(backup_path):
        raise FileNotFoundError(
            f"No pre-upgrade backup at {backup_path}; restore your own copy.")
    source = sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True)
    try:
        check = source.execute("PRAGMA integrity_check").fetchone()
        if not check or check[0] != "ok":
            raise ValueError("Backup failed integrity_check; refusing to restore.")
        dest = sqlite3.connect(db_path)
        try:
            source.backup(dest)
            dest.execute("PRAGMA journal_mode=WAL")
        finally:
            dest.close()
    finally:
        source.close()
    return {"restored_from": backup_path, "db_path": db_path,
            "schema_version": schema_version_of(db_path)}


def schema_version_of(db_path: str) -> int:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        return current_version(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        prog="migrations", description="PiQuaChu schema migration helper")
    parser.add_argument("command", choices=["status", "upgrade", "rollback"])
    parser.add_argument("--db", default=os.environ.get(
        "PIQUACHU_DB_PATH",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "piquachu.db")))
    parser.add_argument("--backup", help="explicit backup file for rollback")
    parser.add_argument("--yes", action="store_true",
                        help="confirm the destructive rollback")
    args = parser.parse_args()

    if args.command == "status":
        conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
        try:
            print(json.dumps(preflight(conn, args.db), indent=2))
        finally:
            conn.close()
        sys.exit(0)

    if args.command == "upgrade":
        conn = sqlite3.connect(args.db, timeout=10)
        try:
            print(json.dumps(migrate(conn, db_path=args.db), indent=2))
        finally:
            conn.close()
        sys.exit(0)

    if not args.yes:
        print("Refusing to roll back without --yes (stop the API first).", file=sys.stderr)
        sys.exit(2)
    # Operator-facing failure: report the reason, never a stack trace (the
    # rollback runbook in docs/operations/release-checklist.md runs this
    # command by hand, and a missing/failed snapshot is an expected state).
    try:
        result = restore_backup(args.db, args.backup)
    except (FileNotFoundError, ValueError, OSError, sqlite3.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    print(json.dumps(result, indent=2))
    sys.exit(0)
