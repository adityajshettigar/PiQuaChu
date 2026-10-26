# backend/tenants.py
"""
tenants.py — DEPRECATED compatibility shim (Phase 2 scaffold)
=============================================================
The Phase 2 scaffold kept team keys in a separate `api_tenants` table with a
boolean `active` flag and no roles, ownership checks or audit events. Phase 4
replaced it with `authz.py` (tenants + principals + RBAC + rotation + audit).

This module now only forwards the old function names so an existing script does
not crash, and emits a deprecation warning. There is **no second auth model**:
every call lands in the same `principals` table the API uses, so a key created
through this shim has a role and is tenant-scoped like any other.

Prefer:
    python authz.py create-tenant acme
    python authz.py create-key acme ci-bot --role developer
    python authz.py list-keys --tenant acme
    python authz.py revoke-key <key_id>
"""

import logging

import authz

_WARNED = False


def _warn() -> None:
    global _WARNED
    if _WARNED:
        return
    _WARNED = True
    logging.warning(
        "tenants.py is deprecated: use authz.py (tenant-scoped keys with RBAC, "
        "rotation and audit). The old api_tenants table is no longer read.")


def enable_multi_tenant() -> None:
    """No-op: Phase 4 creates the tenant schema through migrations at startup."""
    _warn()


def create_team(team_id: str, api_key: str | None = None) -> dict:
    """Create (or reuse) a tenant and issue one owner key. Secret shown once."""
    _warn()
    try:
        authz.create_tenant(team_id, team_id, actor="tenants-shim")
    except ValueError:
        pass  # tenant already exists — issuing one more key is still valid
    if api_key:
        created = authz.import_key(api_key, team_id, "legacy-team-key", role="owner",
                                   created_by="tenants-shim")
        return {"team_id": team_id, "api_key": api_key,
                "key_id": created["key_id"], "role": "owner"}
    created = authz.create_key(team_id, "legacy-team-key", role="owner",
                               created_by="tenants-shim")
    return {"team_id": team_id, "api_key": created["api_key"],
            "key_id": created["key_id"], "role": "owner"}


def validate_tenant_key(key: str) -> bool:
    _warn()
    return authz.authenticate(key) is not None


def revoke_team(team_id: str) -> int:
    """Revoke every active key of a tenant (audited per key)."""
    _warn()
    count = 0
    for key in authz.list_keys(team_id):
        if not key.get("revoked_at") and authz.revoke_key(key["key_id"],
                                                         actor="tenants-shim"):
            count += 1
    return count


def list_teams() -> list[dict]:
    _warn()
    tenants = []
    for tenant in authz.list_tenants():
        keys = authz.list_keys(tenant["tenant_id"])
        tenants.append({
            "team_id": tenant["tenant_id"],
            "name": tenant["name"],
            "active": not tenant["disabled"],
            "created_at": tenant["created_at"],
            "key_count": len(keys),
            "active_key_count": sum(1 for k in keys if not k.get("revoked_at")),
            "key_fingerprints": [k["key_prefix"] for k in keys],
        })
    return tenants


if __name__ == "__main__":
    import sys

    print("tenants.py is deprecated — use authz.py instead.", file=sys.stderr)
    print("  python authz.py create-tenant <id> | create-key <tenant> <name> "
          "--role <role> | list-keys | revoke-key <id>", file=sys.stderr)
    sys.exit(2)
