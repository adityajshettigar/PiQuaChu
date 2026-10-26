# backend/oidc.py
"""
oidc.py — server-side OpenID Connect login for PiQuaChu
=======================================================
The browser never sees a client secret or an identity token payload it could
forge a session from. The flow is:

    GET /api/v1/auth/login
        -> build state + nonce + PKCE verifier, store them in a signed, short
           lived HttpOnly cookie, redirect to the provider's authorization URL
    GET /api/v1/auth/callback?code=...&state=...
        -> compare `state` with the signed flow cookie (single use)
        -> exchange the code at the token endpoint (client secret stays here)
        -> verify the ID token signature against the issuer's JWKS and check
           iss / aud / exp / iat / nonce
        -> optional server-side email-domain restriction
    session cookie
        -> signed (itsdangerous), HttpOnly, SameSite=Lax, Secure in production

Deliberate choices
------------------
* The identity is ``issuer + subject`` — an email address is never the account
  key, and a user-supplied email is never proof of identity.
* Roles are never escalated by logging in: the configured default role is
  assigned, and an unknown role is refused.
* When the provider is not configured, every auth route reports that honestly
  (503 / ``configured: false``); there is no mock "logged in" path.
* Tokens are kept out of URLs after the callback, out of logs and out of the
  browser's storage. Only the signed session cookie is sent back.

Configuration (server-side only):

    PIQUACHU_OIDC_ISSUER                 https://idp.example.com
    PIQUACHU_OIDC_CLIENT_ID              client id
    PIQUACHU_OIDC_CLIENT_SECRET          confidential clients only
    PIQUACHU_OIDC_REDIRECT_URI           https://piquachu.example.com/api/v1/auth/callback
    PIQUACHU_OIDC_SCOPES                 default: "openid profile email"
    PIQUACHU_OIDC_PROVIDER_NAME          default: "Single sign-on"
    PIQUACHU_OIDC_ALLOWED_EMAIL_DOMAINS  comma separated, optional
    PIQUACHU_OIDC_TENANT                 tenant new sessions belong to (default local)
    PIQUACHU_OIDC_DEFAULT_ROLE           default: "analyst"
    PIQUACHU_OIDC_ALLOW_INSECURE         allow http issuer (local test only)
    PIQUACHU_SESSION_SECRET              required in production
    PIQUACHU_SESSION_TTL_SECONDS         default: 28800 (8h)
    PIQUACHU_COOKIE_SECURE               default: true in production
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

import config

try:  # PyJWT is a declared runtime dependency; a missing install degrades to
    import jwt  # type: ignore  # "provider not configured", never a bypass.
    from jwt import PyJWKClient  # type: ignore
    _JWT_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only on a broken install
    jwt = None  # type: ignore
    PyJWKClient = None  # type: ignore
    _JWT_AVAILABLE = False

try:
    from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
except Exception:  # pragma: no cover
    BadSignature = SignatureExpired = Exception  # type: ignore
    URLSafeTimedSerializer = None  # type: ignore

SESSION_COOKIE = "piquachu_session"
FLOW_COOKIE = "piquachu_oidc_flow"
FLOW_TTL_SECONDS = 600
SESSION_TTL_SECONDS = 8 * 60 * 60
DISCOVERY_TTL_SECONDS = 60 * 60
ALLOWED_ALGORITHMS = ("RS256", "PS256", "ES256", "EdDSA")

_ISSUER_KEYS = {"openid", "profile", "email"}

# Ephemeral fallback so a development install still runs. It is logged once and
# reported by /api/v1/auth/providers; it is refused outright in production.
_EPHEMERAL_SECRET = secrets.token_urlsafe(48)
_secret_warned = False


class OidcError(Exception):
    """A provider/configuration problem safe to show to the operator."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def issuer() -> str:
    return (config.env("PIQUACHU_OIDC_ISSUER", "") or "").rstrip("/")


def client_id() -> str:
    return config.env("PIQUACHU_OIDC_CLIENT_ID", "") or ""


def client_secret() -> str:
    return config.env("PIQUACHU_OIDC_CLIENT_SECRET", "") or ""


def redirect_uri() -> str:
    return config.env("PIQUACHU_OIDC_REDIRECT_URI", "") or ""


def scopes() -> str:
    raw = config.env("PIQUACHU_OIDC_SCOPES", "openid profile email") or "openid profile email"
    parts = [scope for scope in raw.split() if scope]
    if "openid" not in parts:
        parts.insert(0, "openid")
    return " ".join(parts)


def provider_name() -> str:
    return config.env("PIQUACHU_OIDC_PROVIDER_NAME", "Single sign-on") or "Single sign-on"


def allowed_email_domains() -> list[str]:
    raw = config.env("PIQUACHU_OIDC_ALLOWED_EMAIL_DOMAINS", "") or ""
    return [item.strip().lower().lstrip("@") for item in raw.split(",") if item.strip()]


def session_tenant() -> str:
    return config.env("PIQUACHU_OIDC_TENANT", "local") or "local"


def default_role() -> str:
    return config.env("PIQUACHU_OIDC_DEFAULT_ROLE", "analyst") or "analyst"


def session_ttl() -> int:
    value = config.integer("PIQUACHU_SESSION_TTL_SECONDS", SESSION_TTL_SECONDS)
    return max(300, min(value, 7 * 24 * 60 * 60))


def cookie_secure() -> bool:
    return config.flag("PIQUACHU_COOKIE_SECURE", config.is_production())


def _insecure_issuer_allowed() -> bool:
    return config.flag("PIQUACHU_OIDC_ALLOW_INSECURE", False)


def session_secret() -> str:
    global _secret_warned
    configured = config.env("PIQUACHU_SESSION_SECRET", "") or ""
    if configured and len(configured) >= 32:
        return configured
    if config.is_production():
        raise OidcError(
            "PIQUACHU_SESSION_SECRET is required in production (32+ characters)."
        )
    if not _secret_warned:
        logging.warning(
            "PIQUACHU_SESSION_SECRET is not set; using an ephemeral development "
            "secret. Sessions will not survive a restart."
        )
        _secret_warned = True
    return _EPHEMERAL_SECRET


def configuration_problems() -> list[str]:
    """Everything that prevents a real login, in operator-readable terms."""
    problems: list[str] = []
    if not _JWT_AVAILABLE or URLSafeTimedSerializer is None:
        problems.append("PyJWT/itsdangerous are not installed on the server.")
        return problems
    if not issuer():
        problems.append("PIQUACHU_OIDC_ISSUER is not set.")
    elif not issuer().startswith("https://") and not _insecure_issuer_allowed():
        problems.append(
            "PIQUACHU_OIDC_ISSUER must use https (set PIQUACHU_OIDC_ALLOW_INSECURE=1 "
            "only for a local test provider)."
        )
    if not client_id():
        problems.append("PIQUACHU_OIDC_CLIENT_ID is not set.")
    if not redirect_uri():
        problems.append("PIQUACHU_OIDC_REDIRECT_URI is not set.")
    elif not redirect_uri().startswith(("https://", "http://")):
        problems.append("PIQUACHU_OIDC_REDIRECT_URI must be an absolute http(s) URL.")
    if not config.env("PIQUACHU_SESSION_SECRET", ""):
        if config.is_production():
            problems.append("PIQUACHU_SESSION_SECRET is required in production.")
        else:
            problems.append(
                "PIQUACHU_SESSION_SECRET is not set — sessions use an ephemeral "
                "development secret and end on restart."
            )
    return problems


def configured() -> bool:
    """True only when a login attempt could succeed."""
    fatal = [p for p in configuration_problems() if "ephemeral" not in p]
    return not fatal


def providers() -> list[dict[str, Any]]:
    if not configured():
        return []
    return [
        {
            "id": "oidc",
            "name": provider_name(),
            "issuer": issuer(),
            "scopes": scopes(),
        }
    ]


def public_status() -> dict[str, Any]:
    """Non-secret status for the login page and the header."""
    problems = configuration_problems()
    return {
        "configured": configured(),
        "provider": provider_name() if issuer() else None,
        "issuer": issuer() or None,
        "problems": problems,
        "session_cookie_secure": cookie_secure(),
        "session_ttl_seconds": session_ttl(),
        "tenant": session_tenant(),
        "default_role": default_role(),
        # A cross-origin API cannot receive the HttpOnly session cookie; the
        # deployment must proxy /api on the same origin as the app.
        "same_origin_required": True,
    }


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only; no extra dependency for discovery)
# ---------------------------------------------------------------------------


def _http_json(url: str, *, data: bytes | None = None, timeout: float = 8.0) -> dict:
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Accept": "application/json",
            "User-Agent": "PiQuaChu-OIDC/1.0",
            **({"Content-Type": "application/x-www-form-urlencoded"} if data else {}),
        },
        method="POST" if data else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(512 * 1024)
    except urllib.error.HTTPError as exc:
        # Never echo a provider error body back to the browser (it can contain
        # the code or a token); log the status only.
        logging.warning("OIDC endpoint returned HTTP %s", exc.code)
        raise OidcError("The identity provider rejected the request.") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logging.warning("OIDC endpoint unreachable: %s", type(exc).__name__)
        raise OidcError("The identity provider could not be reached.") from exc
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OidcError("The identity provider returned an unreadable response.") from exc
    if not isinstance(parsed, dict):
        raise OidcError("The identity provider returned an unexpected response.")
    return parsed


@dataclass
class _Metadata:
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    issuer: str


_metadata_cache: dict[str, Any] = {"at": 0.0, "value": None}
_jwks_cache: dict[str, Any] = {"at": 0.0, "client": None, "uri": None}


def metadata() -> _Metadata:
    """Discovery document, cached for an hour (key rotation is handled by the
    JWKS client's own refresh, not by re-discovering per request)."""
    now = time.time()
    cached = _metadata_cache.get("value")
    if cached and now - float(_metadata_cache.get("at") or 0) < DISCOVERY_TTL_SECONDS:
        return cached

    base = issuer()
    if not base:
        raise OidcError("The provider is not configured.")
    document = _http_json(f"{base}/.well-known/openid-configuration")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        value = document.get(field)
        if not isinstance(value, str) or not value.startswith("https://") and not _insecure_issuer_allowed():
            raise OidcError("The provider discovery document is missing a required endpoint.")
    advertised = document.get("issuer")
    if isinstance(advertised, str) and advertised.rstrip("/") != base:
        raise OidcError("The provider issuer does not match the configured issuer.")

    value = _Metadata(
        authorization_endpoint=document["authorization_endpoint"],
        token_endpoint=document["token_endpoint"],
        jwks_uri=document["jwks_uri"],
        issuer=base,
    )
    _metadata_cache["value"] = value
    _metadata_cache["at"] = now
    return value


def _jwks_client(uri: str) -> Any:
    now = time.time()
    client = _jwks_cache.get("client")
    if client and _jwks_cache.get("uri") == uri and now - float(_jwks_cache.get("at") or 0) < DISCOVERY_TTL_SECONDS:
        return client
    client = PyJWKClient(uri, cache_keys=True, lifespan=DISCOVERY_TTL_SECONDS)
    _jwks_cache.update({"client": client, "uri": uri, "at": now})
    return client


# ---------------------------------------------------------------------------
# Flow state (signed cookie, single use via the state parameter)
# ---------------------------------------------------------------------------


def _flow_serializer():
    return URLSafeTimedSerializer(session_secret(), salt="piquachu-oidc-flow-v1")


def _session_serializer():
    return URLSafeTimedSerializer(session_secret(), salt="piquachu-session-v1")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def safe_return_to(value: str | None) -> str:
    """Only same-application absolute paths. Blocks `//evil`, `/\\evil`,
    schemes and anything that a browser could read as another origin."""
    if not value:
        return "/"
    candidate = value.strip()
    if not candidate.startswith("/") or candidate.startswith("//") or candidate.startswith("/\\"):
        return "/"
    if "\\" in candidate or "\r" in candidate or "\n" in candidate:
        return "/"
    return candidate[:512]


def begin_login(return_to: str | None) -> tuple[str, str, int]:
    """Return (authorization URL, flow cookie value, cookie max-age)."""
    if not configured():
        raise OidcError("Single sign-on is not configured on this server.")
    meta = metadata()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())

    params = {
        "response_type": "code",
        "client_id": client_id(),
        "redirect_uri": redirect_uri(),
        "scope": scopes(),
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    url = f"{meta.authorization_endpoint}?{urllib.parse.urlencode(params)}"
    flow = _flow_serializer().dumps({
        "state": hashlib.sha256(state.encode("ascii")).hexdigest(),
        "nonce": nonce,
        "verifier": verifier,
        "return_to": safe_return_to(return_to),
        "redirect_uri": redirect_uri(),
    })
    return url, flow, FLOW_TTL_SECONDS


def _load_flow(raw: str | None) -> dict:
    if not raw:
        raise OidcError("The sign-in attempt has no state cookie. Start again.")
    try:
        payload = _flow_serializer().loads(raw, max_age=FLOW_TTL_SECONDS)
    except SignatureExpired as exc:
        raise OidcError("The sign-in attempt expired. Start again.") from exc
    except BadSignature as exc:
        raise OidcError("The sign-in attempt could not be verified. Start again.") from exc
    except OidcError:
        raise
    except Exception as exc:  # noqa: BLE001 - unknown secret/format
        raise OidcError("The sign-in attempt could not be verified. Start again.") from exc
    if not isinstance(payload, dict):
        raise OidcError("The sign-in attempt could not be verified. Start again.")
    return payload


def complete_login(code: str, state: str, flow_cookie: str | None) -> tuple[dict, str]:
    """Verify the callback and return (session payload, return_to path)."""
    if not configured():
        raise OidcError("Single sign-on is not configured on this server.")
    if not code or not state:
        raise OidcError("The identity provider did not return a usable authorization code.")

    flow = _load_flow(flow_cookie)
    expected_state = flow.get("state")
    supplied = hashlib.sha256(state.encode("ascii")).hexdigest()
    if not isinstance(expected_state, str) or not secrets.compare_digest(expected_state, supplied):
        raise OidcError("The sign-in state did not match. Start again.")

    meta = metadata()
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": flow.get("redirect_uri") or redirect_uri(),
        "client_id": client_id(),
        "code_verifier": flow.get("verifier") or "",
    }
    if client_secret():
        form["client_secret"] = client_secret()
    tokens = _http_json(meta.token_endpoint, data=urllib.parse.urlencode(form).encode("utf-8"))

    id_token = tokens.get("id_token")
    if not isinstance(id_token, str) or not id_token:
        raise OidcError("The identity provider did not return an identity token.")

    claims = verify_id_token(id_token, expected_nonce=flow.get("nonce"))
    enforce_email_domain(claims)
    return build_session_claims(claims), safe_return_to(flow.get("return_to"))


def verify_id_token(id_token: str, *, expected_nonce: str | None = None) -> dict:
    """Signature + claim validation against the issuer's published keys."""
    if not _JWT_AVAILABLE:
        raise OidcError("Server-side JWT verification is unavailable.")
    meta = metadata()
    try:
        header = jwt.get_unverified_header(id_token)
    except Exception as exc:  # noqa: BLE001
        raise OidcError("The identity token is malformed.") from exc
    algorithm = header.get("alg")
    if algorithm not in ALLOWED_ALGORITHMS:
        raise OidcError("The identity token uses an unsupported signing algorithm.")
    try:
        signing_key = _jwks_client(meta.jwks_uri).get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=[algorithm],
            audience=client_id(),
            issuer=meta.issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except OidcError:
        raise
    except Exception as exc:  # noqa: BLE001 - invalid signature/claims
        logging.warning("OIDC ID token rejected: %s", type(exc).__name__)
        raise OidcError("The identity token could not be verified.") from exc

    token_nonce = claims.get("nonce")
    if not expected_nonce or not isinstance(token_nonce, str):
        raise OidcError("The identity token is missing a matching nonce.")
    if not secrets.compare_digest(token_nonce, str(expected_nonce)):
        raise OidcError("The identity token nonce did not match. Start again.")

    # Reject tokens issued in the future (clock skew already handled by PyJWT).
    issued = claims.get("iat")
    if isinstance(issued, (int, float)) and issued > time.time() + 120:
        raise OidcError("The identity token is not valid yet.")
    return claims


def enforce_email_domain(claims: dict) -> None:
    domains = allowed_email_domains()
    if not domains:
        return
    email = claims.get("email")
    if not isinstance(email, str) or "@" not in email:
        raise OidcError("This deployment requires a verified email address.")
    if claims.get("email_verified") is False:
        raise OidcError("The identity provider has not verified this email address.")
    domain = email.rsplit("@", 1)[1].lower()
    if domain not in domains:
        raise OidcError("This account's email domain is not allowed to sign in.")


def build_session_claims(claims: dict) -> dict:
    issuer_value = str(claims.get("iss") or "")
    subject = str(claims.get("sub") or "")
    if not issuer_value or not subject:
        raise OidcError("The identity token has no stable subject.")
    digest = hashlib.sha256(f"{issuer_value}\n{subject}".encode("utf-8")).hexdigest()
    now = int(time.time())
    return {
        "sub": f"oidc:{digest[:32]}",
        "iss": issuer_value,
        "email": claims.get("email") if isinstance(claims.get("email"), str) else None,
        "name": (
            claims.get("name")
            or claims.get("preferred_username")
            or claims.get("email")
            or "Signed-in user"
        ),
        "tenant": session_tenant(),
        "role": default_role(),
        "iat": now,
        "exp": now + session_ttl(),
        "sid": secrets.token_urlsafe(16),
    }


# ---------------------------------------------------------------------------
# Session cookie
# ---------------------------------------------------------------------------


def issue_session(payload: dict) -> str:
    return _session_serializer().dumps(payload)


def read_session(raw: str | None) -> dict | None:
    """Return verified session claims, or None. Never raises."""
    if not raw or URLSafeTimedSerializer is None:
        return None
    try:
        payload = _session_serializer().loads(raw, max_age=session_ttl())
    except Exception:  # noqa: BLE001 - bad signature, expiry, secret rotation
        return None
    if not isinstance(payload, dict):
        return None
    if not payload.get("sub") or not payload.get("tenant") or not payload.get("role"):
        return None
    try:
        if int(payload.get("exp") or 0) <= int(time.time()):
            return None
    except (TypeError, ValueError):
        return None
    return payload


def principal_from_session(payload: dict | None):
    """Build the authz principal for a verified session (import kept local to
    avoid a circular import at module load)."""
    if not payload:
        return None
    import authz

    role = str(payload.get("role") or "")
    if role not in authz.ROLE_PERMISSIONS:
        return None
    tenant = str(payload.get("tenant") or "")
    if not tenant:
        return None
    return authz.Principal(
        id=str(payload["sub"]),
        tenant_id=tenant,
        name=str(payload.get("name") or "Signed-in user")[:64],
        role=role,
    )


def reset_caches() -> None:
    """Test hook: forget discovery/JWKS documents."""
    _metadata_cache.update({"at": 0.0, "value": None})
    _jwks_cache.update({"at": 0.0, "client": None, "uri": None})


def should_use_secure_cookie() -> bool:
    return cookie_secure()


def environment_is_production() -> bool:
    return config.is_production()


def session_cookie_settings() -> dict:
    return {
        "httponly": True,
        "secure": cookie_secure(),
        "samesite": "Lax",
        "path": "/",
    }


def log_configuration() -> None:
    if configured():
        logging.info("OIDC login configured for issuer %s", issuer())
    else:
        logging.info("OIDC login not configured: %s", "; ".join(configuration_problems()))
