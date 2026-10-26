# backend/authz.py
"""
authz.py — tenant-scoped identity, RBAC and API-key lifecycle
=============================================================
The smallest secure model that fits this product:

  tenant/workspace  ── principals (API keys) ── role ── permission matrix

Design decisions
----------------
* Keys look like ``pqk_<8 hex prefix>_<secret>``. Only the prefix is stored in
  clear (it is the lookup index); the secret is verified against
  ``HMAC-SHA256(pepper, key)`` in constant time. The raw key is returned once
  from ``create_key``/``rotate_key`` and never persisted or logged.
* Unknown roles deny every permission (default deny), and tenant ownership is
  checked separately from the role — an unguessable UUID is never authorization.
* Revocation is a timestamp (audit trail preserved); rotation creates a new
  key and revokes the old one in one step.
* The hard-coded/single-user path keeps working: in local mode a shared
  ``PIQUACHU_API_KEYS`` key authenticates as the owner of the ``local``
  tenant. In team mode that compatibility path is opt-in only
  (``PIQUACHU_LEGACY_ENV_KEYS=1``) and never covers production dev defaults.
* No auth header, token or query string is ever written to a log or audit row.

CLI (run from ``backend/``):

    python authz.py create-tenant acme --name "ACME"
    python authz.py create-key acme ci-bot --role developer --expires-days 90
    python authz.py list-keys --tenant acme
    python authz.py rotate-key <key_id>
    python authz.py revoke-key <key_id>
    python authz.py check-key <raw-key>          # never echoes the key
"""

from __future__ import annotations

import argparse
import hmac
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import audit
import config

# ---------------------------------------------------------------------------
# Permission matrix
# ---------------------------------------------------------------------------

PERMISSIONS = frozenset({
    "scan:create",       # submit a scan
    "scan:read",         # poll jobs, list history, read logs
    "report:read",       # CBOM / SARIF / report downloads
    "remediation:read",  # remediation plans
    "patch:dry_run",     # render patches without writing
    "patch:apply",       # apply patches (CLI; owner-grantable)
    "baseline:read",     # read baseline metadata / deltas
    "baseline:write",    # update/accept a baseline
    "telemetry:write",   # CLI telemetry ingestion
    "assist:query",      # assistant questions
    "reliability:read",  # detection metrics
    "runtime:read",      # runtime evidence (read-only, opt-in)
    "tenant:admin",      # create/disable tenants
    "key:admin",         # create/rotate/revoke keys
    "audit:read",        # read audit events
})

_ANALYST = frozenset({
    "scan:create", "scan:read", "report:read", "remediation:read",
    "baseline:read", "baseline:write", "telemetry:write", "assist:query",
    "reliability:read", "runtime:read",
})

_DEVELOPER = frozenset({
    "scan:create", "scan:read", "report:read", "remediation:read",
    "baseline:read", "patch:dry_run", "patch:apply", "assist:query",
    "reliability:read",
})

_VIEWER = frozenset({
    "scan:read", "report:read", "reliability:read",
})

ROLE_PERMISSIONS: dict[str, frozenset] = {
    "owner": PERMISSIONS,
    "admin": PERMISSIONS,
    "analyst": _ANALYST,
    "developer": _DEVELOPER,
    "viewer": _VIEWER,
}

ROLES = tuple(ROLE_PERMISSIONS)

LEGACY_TENANT = "local"
LEGACY_PRINCIPAL_ID = "legacy-env"
LEGACY_ROLE = "owner"

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
_KEY_RE = re.compile(r"^pqk_([0-9a-f]{8})_([A-Za-z0-9_-]{20,})$")

_CONNECT = None


# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------

def set_connection_provider(provider) -> None:
    """Use the Flask app's connection function (honours a swapped DB path)."""
    global _CONNECT
    _CONNECT = provider
    audit.set_connection_provider(provider)


def _connect() -> sqlite3.Connection:
    if _CONNECT is not None:
        return _CONNECT()
    path = os.environ.get("PIQUACHU_DB_PATH") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "piquachu.db")
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime | None = None) -> str:
    return (moment or _now()).isoformat()


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


# ---------------------------------------------------------------------------
# Principal
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Principal:
    id: str
    tenant_id: str
    name: str
    role: str
    legacy: bool = False
    key_prefix: str | None = None

    def as_public_dict(self) -> dict:
        return {"principal_id": self.id, "tenant_id": self.tenant_id,
                "name": self.name, "role": self.role,
                "legacy_shared_key": self.legacy}


def has_permission(role: str | None, permission: str) -> bool:
    """Default deny: an unknown role or permission grants nothing."""
    if not role or not permission:
        return False
    return permission in ROLE_PERMISSIONS.get(role, frozenset())


def permissions_for(role: str | None) -> list[str]:
    return sorted(ROLE_PERMISSIONS.get(role or "", frozenset()))


def matrix() -> dict:
    return {role: sorted(perms) for role, perms in ROLE_PERMISSIONS.items()}


def authorize(principal: Principal | None, permission: str) -> bool:
    return bool(principal) and has_permission(principal.role, permission)


# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------

def _pepper(conn: sqlite3.Connection) -> str:
    """HMAC pepper: env-provided, else generated once and stored locally.

    The DB-stored fallback is documented honestly: someone holding a full DB
    copy holds the pepper too, so a DB dump still cannot be used to derive a
    key from the verifier alone, but an env-held pepper is stronger.
    """
    configured = config.env("PIQUACHU_KEY_PEPPER")
    if configured:
        return configured
    row = conn.execute("SELECT value FROM settings WHERE key='key_pepper'").fetchone()
    if row:
        return row[0]
    generated = secrets.token_hex(32)
    conn.execute("INSERT INTO settings (key, value) VALUES ('key_pepper', ?) "
                 "ON CONFLICT(key) DO NOTHING", (generated,))
    conn.commit()
    stored = conn.execute("SELECT value FROM settings WHERE key='key_pepper'").fetchone()
    return stored[0] if stored else generated


def hash_key(raw_key: str, pepper: str) -> str:
    return hmac.new(pepper.encode("utf-8"), raw_key.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def generate_key() -> tuple[str, str]:
    """Return (raw_key, prefix). Cryptographically secure random material."""
    prefix = secrets.token_hex(4)
    raw = f"pqk_{prefix}_{secrets.token_urlsafe(32)}"
    return raw, prefix


def key_prefix_of(raw_key: str | None) -> str | None:
    match = _KEY_RE.match(raw_key or "")
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# Tenants
# ---------------------------------------------------------------------------

def create_tenant(tenant_id: str, name: str | None = None, *,
                  actor: str | None = None) -> dict:
    tenant_id = (tenant_id or "").strip()
    if not _SLUG_RE.match(tenant_id):
        raise ValueError("tenant id must be 2-64 chars: lowercase letters, digits, - or _")
    conn = _connect()
    try:
        exists = conn.execute("SELECT 1 FROM tenants WHERE id=?", (tenant_id,)).fetchone()
        if exists:
            raise ValueError(f"tenant already exists: {tenant_id}")
        conn.execute(
            "INSERT INTO tenants (id, name, created_at, disabled) VALUES (?, ?, ?, 0)",
            (tenant_id, (name or tenant_id).strip()[:80], _iso()))
        conn.commit()
    finally:
        conn.close()
    audit.record("tenant.create", actor_type="cli" if actor else "system",
                 actor_id=actor, tenant_id=tenant_id,
                 object_type="tenant", object_id=tenant_id)
    return {"tenant_id": tenant_id, "name": name or tenant_id}


def list_tenants() -> list[dict]:
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, name, created_at, disabled FROM tenants ORDER BY id").fetchall()
    finally:
        conn.close()
    return [{"tenant_id": r[0], "name": r[1], "created_at": r[2],
             "disabled": bool(r[3])} for r in rows]


def set_tenant_disabled(tenant_id: str, disabled: bool = True, *,
                        actor: str | None = None) -> bool:
    conn = _connect()
    try:
        cursor = conn.execute("UPDATE tenants SET disabled=? WHERE id=?",
                              (1 if disabled else 0, tenant_id))
        conn.commit()
        changed = cursor.rowcount > 0
    finally:
        conn.close()
    if changed:
        audit.record("tenant.disable" if disabled else "tenant.enable",
                     actor_type="cli" if actor else "system", actor_id=actor,
                     tenant_id=tenant_id, object_type="tenant", object_id=tenant_id)
    return changed


def tenant_active(tenant_id: str | None) -> bool:
    if not tenant_id:
        return False
    conn = _connect()
    try:
        row = conn.execute("SELECT disabled FROM tenants WHERE id=?",
                           (tenant_id,)).fetchone()
    finally:
        conn.close()
    return bool(row) and not row[0]


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

def create_key(tenant_id: str, name: str, role: str = "analyst", *,
               expires_days: int | None = None,
               created_by: str | None = None) -> dict:
    if role not in ROLE_PERMISSIONS:
        raise ValueError(f"unknown role: {role!r} (expected one of {', '.join(ROLES)})")
    if not tenant_active(tenant_id):
        raise ValueError(f"unknown or disabled tenant: {tenant_id}")
    name = (name or "").strip()
    if not name:
        raise ValueError("key name is required")
    expires_at = None
    if expires_days is not None:
        if int(expires_days) <= 0:
            raise ValueError("expires_days must be positive")
        expires_at = _iso(_now() + timedelta(days=int(expires_days)))

    conn = _connect()
    try:
        pepper = _pepper(conn)
        raw = prefix = None
        for _ in range(5):
            candidate_raw, candidate_prefix = generate_key()
            taken = conn.execute("SELECT 1 FROM principals WHERE key_prefix=?",
                                 (candidate_prefix,)).fetchone()
            if not taken:
                raw, prefix = candidate_raw, candidate_prefix
                break
        if raw is None:
            raise RuntimeError("could not allocate a unique key prefix")
        key_id = "key_" + secrets.token_hex(8)
        conn.execute(
            "INSERT INTO principals (id, tenant_id, name, role, key_prefix, key_hash, "
            "created_at, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (key_id, tenant_id, name[:64], role, prefix, hash_key(raw, pepper),
             _iso(), created_by, expires_at))
        conn.commit()
    finally:
        conn.close()

    audit.record("key.create", actor_type="cli" if created_by else "system",
                 actor_id=created_by, tenant_id=tenant_id,
                 object_type="principal", object_id=key_id,
                 detail={"role": role, "key_prefix": prefix,
                         "expires_at": expires_at})
    return {"key_id": key_id, "tenant_id": tenant_id, "name": name[:64],
            "role": role, "key_prefix": prefix, "api_key": raw,
            "created_at": _iso(), "expires_at": expires_at,
            "note": "This secret is shown once and is not stored in plaintext."}


def import_key(raw_key: str, tenant_id: str, name: str, role: str = "analyst", *,
               expires_days: int | None = None,
               created_by: str | None = None) -> dict:
    """Register an externally generated key (must use the pqk_<prefix>_<secret>
    format so the prefix lookup index exists). The key is hashed, never stored."""
    if role not in ROLE_PERMISSIONS:
        raise ValueError(f"unknown role: {role!r}")
    prefix = key_prefix_of(raw_key)
    if not prefix:
        raise ValueError("key must match pqk_<8 hex chars>_<secret>")
    if not tenant_active(tenant_id):
        raise ValueError(f"unknown or disabled tenant: {tenant_id}")
    expires_at = None
    if expires_days is not None:
        expires_at = _iso(_now() + timedelta(days=int(expires_days)))
    conn = _connect()
    try:
        if conn.execute("SELECT 1 FROM principals WHERE key_prefix=?",
                        (prefix,)).fetchone():
            raise ValueError("a key with this prefix already exists")
        pepper = _pepper(conn)
        key_id = "key_" + secrets.token_hex(8)
        conn.execute(
            "INSERT INTO principals (id, tenant_id, name, role, key_prefix, key_hash, "
            "created_at, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (key_id, tenant_id, (name or "imported")[:64], role, prefix,
             hash_key(raw_key, pepper), _iso(), created_by, expires_at))
        conn.commit()
    finally:
        conn.close()
    audit.record("key.import", actor_type="cli" if created_by else "system",
                 actor_id=created_by, tenant_id=tenant_id,
                 object_type="principal", object_id=key_id,
                 detail={"key_prefix": prefix, "role": role})
    return {"key_id": key_id, "tenant_id": tenant_id, "name": name[:64],
            "role": role, "key_prefix": prefix, "created_at": _iso(),
            "expires_at": expires_at}


def revoke_key(key_id: str, *, actor: str | None = None) -> bool:
    conn = _connect()
    try:
        row = conn.execute("SELECT tenant_id, key_prefix FROM principals WHERE id=?",
                           (key_id,)).fetchone()
        if not row:
            return False
        cursor = conn.execute(
            "UPDATE principals SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
            (_iso(), key_id))
        conn.commit()
        changed = cursor.rowcount > 0
    finally:
        conn.close()
    if not changed:
        return False
    audit.record("key.revoke", actor_type="cli" if actor else "system", actor_id=actor,
                 tenant_id=row[0], object_type="principal", object_id=key_id,
                 detail={"key_prefix": row[1]})
    return True


def rotate_key(key_id: str, *, expires_days: int | None = None,
               actor: str | None = None) -> dict:
    """Create a replacement and revoke the old key atomically (single step)."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT tenant_id, name, role, revoked_at FROM principals WHERE id=?",
            (key_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        raise ValueError(f"unknown key: {key_id}")
    if row[3]:
        raise ValueError(f"key {key_id} is already revoked")
    created = create_key(row[0], row[1], role=row[2], expires_days=expires_days,
                         created_by=actor)
    revoke_key(key_id, actor=actor)
    conn = _connect()
    try:
        conn.execute("UPDATE principals SET rotated_from=? WHERE id=?",
                     (key_id, created["key_id"]))
        conn.commit()
    finally:
        conn.close()
    created["rotated_from"] = key_id
    audit.record("key.rotate", actor_type="cli" if actor else "system",
                 actor_id=actor, tenant_id=created["tenant_id"],
                 object_type="principal", object_id=created["key_id"],
                 detail={"replaced_key_id": key_id})
    return created


def list_keys(tenant_id: str | None = None) -> list[dict]:
    conn = _connect()
    try:
        base = ("SELECT id, tenant_id, name, role, key_prefix, created_at, expires_at, "
                "revoked_at, last_used_at, rotated_from FROM principals")
        if tenant_id:
            rows = conn.execute(base + " WHERE tenant_id=? ORDER BY created_at DESC",
                                (tenant_id,)).fetchall()
        else:
            rows = conn.execute(base + " ORDER BY created_at DESC").fetchall()
    finally:
        conn.close()
    keys = ["key_id", "tenant_id", "name", "role", "key_prefix", "created_at",
            "expires_at", "revoked_at", "last_used_at", "rotated_from"]
    return [dict(zip(keys, row)) for row in rows]


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def _dummy_verify(raw_key: str, pepper: str) -> None:
    """Spend the same work for an unknown prefix (no prefix-existence oracle)."""
    hmac.compare_digest(hash_key(raw_key, pepper), "0" * 64)


def authenticate(raw_key: str | None, *, touch: bool = True) -> Principal | None:
    """Verify a tenant API key. Returns None for unknown/revoked/expired keys.

    Verification is constant-time over the secret; the prefix lookup is a
    public index, not the secret.
    """
    if not raw_key:
        return None
    match = _KEY_RE.match(raw_key)
    try:
        conn = _connect()
    except sqlite3.Error as exc:
        logging.warning("Identity database unavailable: %s", type(exc).__name__)
        return None
    try:
        pepper = _pepper(conn)
        if not match:
            _dummy_verify(raw_key, pepper)
            return None
        prefix = match.group(1)
        row = conn.execute(
            "SELECT p.id, p.tenant_id, p.name, p.role, p.key_hash, p.revoked_at, "
            "p.expires_at, t.disabled, p.last_used_at FROM principals p "
            "LEFT JOIN tenants t ON t.id = p.tenant_id WHERE p.key_prefix=?",
            (prefix,)).fetchone()
        if not row:
            _dummy_verify(raw_key, pepper)
            return None
        stored = row[4] or ""
        candidate = hash_key(raw_key, pepper)
        matched = hmac.compare_digest(candidate, stored)
        if not matched:
            return None
        if row[5] or row[7] or not row[1]:
            return None
        expires = _parse_iso(row[6])
        if expires is not None and expires <= _now():
            return None
        # Throttle the last-used write: polling endpoints would otherwise turn
        # every request into a SQLite write (lock contention without value).
        last_used = _parse_iso(row[8])
        if touch and (last_used is None or
                      (_now() - last_used).total_seconds() > 60):
            conn.execute("UPDATE principals SET last_used_at=? WHERE id=?",
                         (_iso(), row[0]))
            conn.commit()
        return Principal(id=row[0], tenant_id=row[1], name=row[2],
                         role=row[3], key_prefix=prefix)
    except sqlite3.OperationalError as exc:
        # Missing identity tables must fail closed (401), not 500.
        logging.warning("Tenant-key lookup unavailable: %s", type(exc).__name__)
        return None
    finally:
        conn.close()


def authenticate_legacy(raw_key: str | None, allowed_keys) -> Principal | None:
    """Shared-key compatibility path (local mode / explicit team opt-in)."""
    if not raw_key or not allowed_keys:
        return None
    matched = False
    for candidate in allowed_keys:
        if hmac.compare_digest(str(candidate), str(raw_key)):
            matched = True
    if not matched:
        return None
    return Principal(id=LEGACY_PRINCIPAL_ID, tenant_id=LEGACY_TENANT,
                     name="shared environment key", role=LEGACY_ROLE, legacy=True)


def principal_for_key(raw_key: str | None, legacy_keys=()) -> Principal | None:
    return authenticate(raw_key) or authenticate_legacy(raw_key, legacy_keys)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_CLI_READY = False


def _cli_connect() -> sqlite3.Connection:
    global _CLI_READY
    import migrations
    path = os.environ.get("PIQUACHU_DB_PATH") or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "piquachu.db")
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    if not _CLI_READY:
        migrations.migrate(conn, db_path=path)
        _CLI_READY = True
    return conn


def _configure_cli() -> None:
    set_connection_provider(_cli_connect)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="authz", description="PiQuaChu tenant / API-key administration")
    sub = parser.add_subparsers(dest="command", required=True)

    p_t = sub.add_parser("create-tenant", help="create a tenant/workspace")
    p_t.add_argument("tenant_id")
    p_t.add_argument("--name")

    sub.add_parser("list-tenants", help="list tenants")

    p_td = sub.add_parser("disable-tenant", help="disable a tenant (all keys rejected)")
    p_td.add_argument("tenant_id")

    p_k = sub.add_parser("create-key", help="create an API key (shown once)")
    p_k.add_argument("tenant_id")
    p_k.add_argument("name")
    p_k.add_argument("--role", default="analyst", choices=list(ROLES))
    p_k.add_argument("--expires-days", type=int)

    p_l = sub.add_parser("list-keys", help="list key metadata (prefix only)")
    p_l.add_argument("--tenant")

    p_r = sub.add_parser("revoke-key", help="revoke a key")
    p_r.add_argument("key_id")

    p_rot = sub.add_parser("rotate-key", help="rotate a key (new secret shown once)")
    p_rot.add_argument("key_id")
    p_rot.add_argument("--expires-days", type=int)

    p_c = sub.add_parser("check-key", help="validate a key without echoing it")
    p_c.add_argument("raw_key")

    sub.add_parser("matrix", help="print the role/permission matrix")

    args = parser.parse_args(argv)
    _configure_cli()

    try:
        if args.command == "create-tenant":
            print(json.dumps(create_tenant(args.tenant_id, args.name, actor="cli"),
                             indent=2))
        elif args.command == "list-tenants":
            print(json.dumps(list_tenants(), indent=2))
        elif args.command == "disable-tenant":
            print(json.dumps({"disabled": set_tenant_disabled(args.tenant_id,
                                                              actor="cli")}))
        elif args.command == "create-key":
            print(json.dumps(create_key(args.tenant_id, args.name, role=args.role,
                                        expires_days=args.expires_days,
                                        created_by="cli"), indent=2))
        elif args.command == "list-keys":
            print(json.dumps(list_keys(args.tenant), indent=2))
        elif args.command == "revoke-key":
            print(json.dumps({"revoked": revoke_key(args.key_id, actor="cli")}))
        elif args.command == "rotate-key":
            print(json.dumps(rotate_key(args.key_id, expires_days=args.expires_days,
                                        actor="cli"), indent=2))
        elif args.command == "check-key":
            principal = authenticate(args.raw_key)
            if principal is None:
                print(json.dumps({"valid": False}), file=sys.stderr)
                return 1
            print(json.dumps({"valid": True, **principal.as_public_dict()}, indent=2))
        elif args.command == "matrix":
            print(json.dumps(matrix(), indent=2))
    except (ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
