# backend/config.py
"""
config.py — one place for security-relevant runtime configuration
=================================================================
Every security setting is read here (never scattered through routes) so it can
be validated, documented and tested:

  * deployment environment / tenancy mode / legacy-key compatibility
  * API CORS allow-list and trusted-proxy handling for client IP resolution
  * rate-limiter storage backend and degradation mode
  * upload / audit budget knobs
  * startup validation (fail closed when a security-critical setting is unsafe)

Environment variables are read at call time (not import time) where a test or a
long-running process may adjust them, except for the few values documented as
boot-time constants in the Phase 4 report.
"""

from __future__ import annotations

import ipaddress
import os

APP_VERSION = "2.4.0"

ENV_DEVELOPMENT = "development"
ENV_PRODUCTION = "production"

MODE_LOCAL = "local"
MODE_TEAM = "team"

DEFAULT_LIMITS = {
    # name: (default limit, rationale)
    "scan": ("10 per hour", "scan submission"),
    "poll": ("120 per minute", "job status polling"),
    "logs": ("120 per minute", "job log streaming"),
    "telemetry": ("30 per hour", "CLI telemetry ingestion"),
    "exports": ("60 per minute", "CBOM / SARIF / report downloads"),
    "assistant": ("30 per minute", "assistant queries"),
    "admin": ("30 per hour", "tenant / key / audit administration"),
    "auth": ("60 per minute", "authenticated request baseline"),
    "health": ("120 per minute", "health and readiness probes"),
}


def _env(environ: dict | None = None) -> dict:
    return os.environ if environ is None else environ


def env(name: str, default: str | None = None, environ: dict | None = None) -> str | None:
    value = _env(environ).get(name)
    if value is None:
        return default
    value = value.strip()
    return value if value else default


def flag(name: str, default: bool = False, environ: dict | None = None) -> bool:
    raw = _env(environ).get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def integer(name: str, default: int, environ: dict | None = None) -> int:
    raw = _env(environ).get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def environment(environ: dict | None = None) -> str:
    value = (env("PIQUACHU_ENV", ENV_DEVELOPMENT, environ) or ENV_DEVELOPMENT).lower()
    return ENV_PRODUCTION if value in {"production", "prod"} else ENV_DEVELOPMENT


def is_production(environ: dict | None = None) -> bool:
    return environment(environ) == ENV_PRODUCTION


def tenancy_mode(environ: dict | None = None) -> str:
    """`local` (single-user / self-hosted default) or `team` (tenant keys).

    `PIQUACHU_MULTI_TENANT=1` is kept as a backward-compatible alias for the
    Phase 2/3 scaffold so an existing deployment does not silently change mode.
    """
    raw = (env("PIQUACHU_TENANCY_MODE", "", environ) or "").lower()
    if raw in {MODE_LOCAL, MODE_TEAM}:
        return raw
    if flag("PIQUACHU_MULTI_TENANT", False, environ):
        return MODE_TEAM
    return MODE_LOCAL


def legacy_env_keys_allowed(environ: dict | None = None) -> bool:
    """Whether shared `PIQUACHU_API_KEYS` are still accepted.

    Local mode: yes (frictionless single-user path).
    Team mode: only with an explicit `PIQUACHU_LEGACY_ENV_KEYS=1` opt-in, and
    never for the hard-coded development keys.
    """
    if tenancy_mode(environ) == MODE_LOCAL:
        return True
    return flag("PIQUACHU_LEGACY_ENV_KEYS", False, environ)


def dev_default_keys_allowed(environ: dict | None = None) -> bool:
    """The hard-coded local keys exist only for non-production local use."""
    return (not is_production(environ)) and tenancy_mode(environ) == MODE_LOCAL


def require_tenant_keys(environ: dict | None = None) -> bool:
    """True when shared env keys must NOT be the production boundary."""
    return tenancy_mode(environ) == MODE_TEAM and not flag(
        "PIQUACHU_LEGACY_ENV_KEYS", False, environ)


def worker_count(environ: dict | None = None) -> int:
    """Best-effort worker count for the in-memory-limiter warning.

    `PIQUACHU_WORKERS` is authoritative; WEB_CONCURRENCY and GUNICORN_CMD_ARGS
    are read as hints because that is how gunicorn deployments usually set it.
    """
    explicit = integer("PIQUACHU_WORKERS", 0, environ)
    if explicit > 0:
        return explicit
    hint = integer("WEB_CONCURRENCY", 0, environ)
    if hint > 0:
        return hint
    args = env("GUNICORN_CMD_ARGS", "", environ) or ""
    for token in args.replace("=", " ").split():
        if token.isdigit():
            return int(token)
    return 1


def redis_broker_url(environ: dict | None = None) -> str | None:
    return env("PIQUACHU_BROKER_URL", None, environ)


def rate_limit_storage_uri(environ: dict | None = None) -> str:
    """Explicit limiter storage, else the Redis broker, else in-memory.

    Memory storage is only safe for a single process; the startup validator
    refuses (production) or warns (development) when multiple workers are
    configured on top of it.
    """
    explicit = env("PIQUACHU_RATE_LIMIT_STORAGE_URI", None, environ)
    if explicit:
        return explicit
    broker = redis_broker_url(environ)
    if broker and broker.startswith(("redis://", "rediss://", "unix://")):
        return broker
    return "memory://"


def distributed_rate_limiting(environ: dict | None = None) -> bool:
    return not rate_limit_storage_uri(environ).startswith("memory://")


def rate_limit_failure_mode(environ: dict | None = None) -> str:
    """`closed` (refuse the request, 503) or `degraded` (allow, 429 unaware).

    Default is fail-closed: an unavailable limiter must not silently remove a
    brute-force/abuse control. Documented in the Phase 4 report.
    """
    value = (env("PIQUACHU_RATE_LIMIT_FAILURE_MODE", "closed", environ) or "closed").lower()
    if value not in {"closed", "degraded"}:
        return "closed"
    return value


def rate_limit(name: str, environ: dict | None = None) -> str:
    default = DEFAULT_LIMITS.get(name, ("60 per minute", ""))[0]
    override = env(f"PIQUACHU_RATE_LIMIT_{name.upper()}", None, environ)
    return override or default


def cors_origins(environ: dict | None = None) -> list[str]:
    default = ",".join(
        f"http://{host}:{port}"
        for host in ("localhost", "127.0.0.1")
        for port in range(5173, 5177)
    )
    raw = env("PIQUACHU_CORS_ORIGINS", default, environ) or default
    return [item.strip() for item in raw.split(",") if item.strip()]


def trusted_proxies(environ: dict | None = None) -> list[str]:
    """IPs/CIDRs whose X-Forwarded-For header may be believed.

    Empty by default: `request.remote_addr` is used, so a client cannot spoof
    its rate-limit identity through a forwarded header.
    """
    raw = env("PIQUACHU_TRUSTED_PROXIES", "", environ) or ""
    return [item.strip() for item in raw.split(",") if item.strip()]


def _ip_in_networks(ip: str, networks: list[str]) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for item in networks:
        try:
            if address in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False


def client_ip(remote_addr: str | None, forwarded_for: str | None,
              environ: dict | None = None) -> str:
    """Resolve the client IP for rate limiting.

    X-Forwarded-For is only honoured when the direct peer is an explicitly
    trusted proxy; the left-most address is then the original client. A
    forwarded header from an untrusted peer is ignored entirely.
    """
    peer = remote_addr or "unknown"
    networks = trusted_proxies(environ)
    if not networks or not _ip_in_networks(peer, networks):
        return peer
    if not forwarded_for:
        return peer
    first = forwarded_for.split(",")[0].strip()
    try:
        return str(ipaddress.ip_address(first))
    except ValueError:
        return peer


def rate_limit_identity(remote_addr: str | None, forwarded_for: str | None,
                        tenant_id: str | None = None,
                        principal_id: str | None = None,
                        environ: dict | None = None) -> str:
    """Rate-limit bucket identity — never the API key itself.

    Authenticated requests are bucketed by tenant + principal; unauthenticated
    requests by client IP (trusted-proxy aware).
    """
    if tenant_id and principal_id:
        return f"tenant:{tenant_id}:principal:{principal_id}"
    return "ip:" + client_ip(remote_addr, forwarded_for, environ)


# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------

def max_upload_bytes(environ: dict | None = None) -> int:
    return max(1, integer("PIQUACHU_MAX_UPLOAD_BYTES", 50 * 1024 * 1024, environ))


def max_uncompressed_bytes(environ: dict | None = None) -> int:
    return max(1, integer("PIQUACHU_MAX_UNCOMPRESSED_BYTES", 250 * 1024 * 1024, environ))


def max_zip_entries(environ: dict | None = None) -> int:
    return max(1, integer("PIQUACHU_MAX_ZIP_ENTRIES", 5000, environ))


def max_zip_file_bytes(environ: dict | None = None) -> int:
    return max(1, integer("PIQUACHU_MAX_ZIP_FILE_BYTES", 25 * 1024 * 1024, environ))


def max_compression_ratio(environ: dict | None = None) -> int:
    return max(2, integer("PIQUACHU_MAX_COMPRESSION_RATIO", 200, environ))


def max_baseline_bytes(environ: dict | None = None) -> int:
    return max(1, integer("PIQUACHU_MAX_BASELINE_BYTES", 8 * 1024 * 1024, environ))


def max_question_length(environ: dict | None = None) -> int:
    return max(1, integer("PIQUACHU_MAX_QUESTION_LENGTH", 2000, environ))


def max_telemetry_items(environ: dict | None = None) -> int:
    return max(1, integer("PIQUACHU_MAX_TELEMETRY_ITEMS", 500, environ))


def orphan_grace_seconds(environ: dict | None = None) -> int:
    """Age after which a PENDING/ANALYSING row is considered orphaned.

    A second API worker process must never fail another process's live job, so
    recovery is age-based rather than startup-based.
    """
    return max(0, integer("PIQUACHU_ORPHAN_GRACE_SECONDS", 3600, environ))


def stale_upload_seconds(environ: dict | None = None) -> int:
    return max(60, integer("PIQUACHU_STALE_UPLOAD_SECONDS", 6 * 3600, environ))


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def audit_log_path(environ: dict | None = None) -> str:
    default = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "piquachu-audit.jsonl")
    return env("PIQUACHU_AUDIT_LOG", default, environ) or default


def audit_enabled(environ: dict | None = None) -> bool:
    return not flag("PIQUACHU_AUDIT_DISABLED", False, environ)


def audit_max_bytes(environ: dict | None = None) -> int:
    return max(64 * 1024, integer("PIQUACHU_AUDIT_MAX_BYTES", 5 * 1024 * 1024, environ))


def audit_backups(environ: dict | None = None) -> int:
    return max(0, integer("PIQUACHU_AUDIT_BACKUPS", 3, environ))


def audit_retention_days(environ: dict | None = None) -> int:
    return max(0, integer("PIQUACHU_AUDIT_RETENTION_DAYS", 90, environ))


# ---------------------------------------------------------------------------
# Startup validation
# ---------------------------------------------------------------------------

MIN_KEY_LENGTH = 16


def _split_keys(raw: str | None) -> list[str]:
    return [item.strip() for item in (raw or "").split(",") if item.strip()]


def validate_startup(environ: dict | None = None) -> dict:
    """Validate security-critical configuration.

    Returns {"errors": [...], "warnings": [...], "info": [...]}. Errors must
    abort startup (fail closed); warnings are logged and surfaced in the health
    payload's `configuration` block.
    """
    environ = _env(environ)
    errors: list[str] = []
    warnings: list[str] = []
    info: list[str] = []

    env_name = environment(environ)
    mode = tenancy_mode(environ)
    keys = _split_keys(env("PIQUACHU_API_KEYS", "", environ))
    using_dev_defaults = not keys

    raw_failure_mode = (env("PIQUACHU_RATE_LIMIT_FAILURE_MODE", "", environ) or "").strip().lower()
    if raw_failure_mode and raw_failure_mode not in {"closed", "degraded"}:
        errors.append("PIQUACHU_RATE_LIMIT_FAILURE_MODE must be 'closed' or 'degraded'.")

    storage = rate_limit_storage_uri(environ)
    workers = worker_count(environ)
    if storage.startswith("memory://") and workers > 1:
        message = (f"PIQUACHU_WORKERS={workers} with in-memory rate limiting — "
                   f"limits are per-process, not deployment-wide.")
        (errors if is_production(environ) else warnings).append(message)

    if "*" in cors_origins(environ):
        (errors if is_production(environ) else warnings).append(
            "CORS wildcard origin is not allowed with API keys.")

    if is_production(environ):
        if using_dev_defaults and mode == MODE_LOCAL:
            errors.append(
                "Production mode requires PIQUACHU_API_KEYS (the built-in "
                "development keys are never accepted in production).")
        if not env("PIQUACHU_KEY_PEPPER", "", environ):
            warnings.append(
                "PIQUACHU_KEY_PEPPER is not set; a generated pepper is stored in "
                "the local database (a DB copy then contains the verifier material).")
        if storage.startswith("memory://") and workers <= 1:
            warnings.append("Production mode with in-memory rate limiting (single process only).")
        if env("GROQ_API_KEY", "", environ):
            info.append("Remote AI enrichment is enabled (metadata-only egress allowlist).")
    else:
        info.append(f"{env_name}/{mode} mode: shared keys and in-memory "
                    "services are acceptable for local/development use.")

    if mode == MODE_TEAM and flag("PIQUACHU_LEGACY_ENV_KEYS", False, environ):
        warnings.append(
            "Team mode with PIQUACHU_LEGACY_ENV_KEYS=1 keeps the shared-key "
            "compatibility path enabled; disable it once tenant keys are provisioned.")

    for key in keys:
        if len(key) < MIN_KEY_LENGTH:
            warnings.append("A PIQUACHU_API_KEYS entry is shorter than "
                            f"{MIN_KEY_LENGTH} characters.")
        if key in {"changeme", "password", "secret"}:
            warnings.append("A PIQUACHU_API_KEYS entry is a well-known placeholder.")

    if not env("PIQUACHU_AUDIT_LOG", "", environ):
        info.append(f"Audit events are written to {audit_log_path(environ)}.")

    storage_scheme = storage.split(":", 1)[0]
    if storage_scheme in {"redis", "rediss"}:
        try:
            import redis  # noqa: F401
        except Exception:
            errors.append("Redis rate-limit storage is configured but the 'redis' "
                          "package is not installed.")

    return {"environment": env_name, "tenancy_mode": mode,
            "errors": errors, "warnings": warnings, "info": info}
