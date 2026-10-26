#!/usr/bin/env python3
"""
test_oidc.py — OpenID Connect login, token validation and session cookies

These tests use a locally generated RSA key and a stubbed discovery/JWKS
endpoint: they prove the server-side verification logic (state, nonce, PKCE,
issuer, audience, expiry, signature, domain restriction, session tampering),
not a live provider integration.
"""
import hashlib
import os
import sys
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import app as api  # noqa: E402
import oidc  # noqa: E402

ISSUER = "https://idp.test.example"
CLIENT_ID = "piquachu-test"
REDIRECT_URI = "https://app.test.example/api/v1/auth/callback"


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _SigningKey:
    def __init__(self, key):
        self.key = key


class _JwksClient:
    def __init__(self, key):
        self._key = key

    def get_signing_key_from_jwt(self, _token):
        return _SigningKey(self._key)


@pytest.fixture
def configured(monkeypatch, signing_key):
    env = {
        "PIQUACHU_OIDC_ISSUER": ISSUER,
        "PIQUACHU_OIDC_CLIENT_ID": CLIENT_ID,
        "PIQUACHU_OIDC_CLIENT_SECRET": "server-only-secret",
        "PIQUACHU_OIDC_REDIRECT_URI": REDIRECT_URI,
        "PIQUACHU_SESSION_SECRET": "x" * 48,
        "PIQUACHU_OIDC_TENANT": "local",
        "PIQUACHU_OIDC_DEFAULT_ROLE": "analyst",
        "PIQUACHU_COOKIE_SECURE": "1",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("PIQUACHU_OIDC_ALLOWED_EMAIL_DOMAINS", raising=False)
    monkeypatch.delenv("PIQUACHU_OIDC_ALLOW_INSECURE", raising=False)

    metadata = oidc._Metadata(
        authorization_endpoint=f"{ISSUER}/authorize",
        token_endpoint=f"{ISSUER}/token",
        jwks_uri=f"{ISSUER}/jwks",
        issuer=ISSUER,
    )
    monkeypatch.setattr(oidc, "metadata", lambda: metadata)
    monkeypatch.setattr(
        oidc, "_jwks_client", lambda _uri: _JwksClient(signing_key.public_key())
    )
    oidc.reset_caches()
    return metadata


@pytest.fixture
def unconfigured(monkeypatch):
    for key in (
        "PIQUACHU_OIDC_ISSUER",
        "PIQUACHU_OIDC_CLIENT_ID",
        "PIQUACHU_OIDC_CLIENT_SECRET",
        "PIQUACHU_OIDC_REDIRECT_URI",
        "PIQUACHU_SESSION_SECRET",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("PIQUACHU_OIDC_ALLOW_INSECURE", raising=False)


def _id_token(signing_key, nonce, *, issuer=ISSUER, audience=CLIENT_ID, ttl=3600, sub="user-1"):
    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": sub,
        "iat": now,
        "exp": now + ttl,
        "nonce": nonce,
        "email": "ada@example.com",
        "email_verified": True,
        "name": "Ada Lovelace",
    }
    return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "test-key"})


def _flow_from_login(return_to="/results/12"):
    _url, flow_cookie, _max_age = oidc.begin_login(return_to)
    return oidc._load_flow(flow_cookie), flow_cookie


# ---------------------------------------------------------------------------
# Configuration / providers
# ---------------------------------------------------------------------------


def test_unconfigured_provider_is_reported_honestly(unconfigured):
    client = api.app.test_client()
    response = client.get("/api/v1/auth/providers")
    assert response.status_code == 200
    body = response.get_json()
    assert body["configured"] is False
    assert body["providers"] == []
    assert body["problems"]


def test_login_refuses_when_unconfigured(unconfigured):
    client = api.app.test_client()
    response = client.get("/api/v1/auth/login?return_to=/")
    assert response.status_code == 503
    assert "error" in response.get_json()


def test_providers_list_when_configured(configured):
    client = api.app.test_client()
    body = client.get("/api/v1/auth/providers").get_json()
    assert body["configured"] is True
    assert body["providers"][0]["issuer"] == ISSUER


# ---------------------------------------------------------------------------
# Authorization request
# ---------------------------------------------------------------------------


def test_begin_login_uses_pkce_and_encodes_a_safe_return(configured):
    url, flow_cookie, max_age = oidc.begin_login("/results/12")
    assert "code_challenge_method=S256" in url
    assert "response_type=code" in url
    assert f"client_id={CLIENT_ID}" in url
    assert max_age == oidc.FLOW_TTL_SECONDS

    flow = oidc._load_flow(flow_cookie)
    assert flow["return_to"] == "/results/12"
    assert flow["verifier"]
    assert flow["nonce"]


def test_safe_return_to_rejects_other_origins():
    assert oidc.safe_return_to("//evil.example") == "/"
    assert oidc.safe_return_to("https://evil.example") == "/"
    assert oidc.safe_return_to("/\\evil.example") == "/"
    assert oidc.safe_return_to("/results/1") == "/results/1"


# ---------------------------------------------------------------------------
# Callback validation
# ---------------------------------------------------------------------------


def test_complete_login_verifies_state_nonce_and_returns_a_session(configured, signing_key, monkeypatch):
    flow, flow_cookie = _flow_from_login()

    # The state value the provider echoes is the raw one from the authorization
    # URL; recover it by generating a fresh flow and using its hash.
    raw_state = "raw-state-value"
    flow["state"] = hashlib.sha256(raw_state.encode("ascii")).hexdigest()
    flow_cookie = oidc._flow_serializer().dumps(flow)

    token = _id_token(signing_key, flow["nonce"])
    monkeypatch.setattr(oidc, "_http_json", lambda *_a, **_k: {"id_token": token})

    session, return_to = oidc.complete_login("code-123", raw_state, flow_cookie)
    assert return_to == "/results/12"
    assert session["sub"].startswith("oidc:")
    assert session["tenant"] == "local"
    assert session["role"] == "analyst"
    assert session["email"] == "ada@example.com"
    assert session["exp"] > time.time()


def test_state_mismatch_is_rejected(configured, signing_key, monkeypatch):
    flow, _ = _flow_from_login()
    token = _id_token(signing_key, flow["nonce"])
    monkeypatch.setattr(oidc, "_http_json", lambda *_a, **_k: {"id_token": token})
    flow_cookie = oidc._flow_serializer().dumps(flow)

    with pytest.raises(oidc.OidcError, match="state"):
        oidc.complete_login("code", "wrong-state", flow_cookie)


def test_missing_flow_cookie_is_rejected(configured):
    with pytest.raises(oidc.OidcError):
        oidc.complete_login("code", "state", None)


def test_nonce_mismatch_is_rejected(configured, signing_key, monkeypatch):
    raw_state = "state-abc"
    flow, _ = _flow_from_login()
    flow["state"] = hashlib.sha256(raw_state.encode("ascii")).hexdigest()
    token = _id_token(signing_key, "a-different-nonce")
    monkeypatch.setattr(oidc, "_http_json", lambda *_a, **_k: {"id_token": token})

    with pytest.raises(oidc.OidcError, match="nonce"):
        oidc.complete_login(
            "code", raw_state, oidc._flow_serializer().dumps(flow)
        )


def test_wrong_issuer_is_rejected(configured, signing_key):
    with pytest.raises(oidc.OidcError):
        oidc.verify_id_token(
            _id_token(signing_key, "n", issuer="https://attacker.example"),
            expected_nonce="n",
        )


def test_wrong_audience_is_rejected(configured, signing_key):
    with pytest.raises(oidc.OidcError):
        oidc.verify_id_token(
            _id_token(signing_key, "n", audience="another-client"), expected_nonce="n"
        )


def test_expired_token_is_rejected(configured, signing_key):
    with pytest.raises(oidc.OidcError):
        oidc.verify_id_token(_id_token(signing_key, "n", ttl=-60), expected_nonce="n")


def test_token_signed_by_another_key_is_rejected(configured):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(oidc.OidcError):
        oidc.verify_id_token(_id_token(other, "n"), expected_nonce="n")


def test_unsupported_algorithm_is_rejected(configured):
    unsigned = jwt.encode({"sub": "x"}, "secret", algorithm="HS256")
    with pytest.raises(oidc.OidcError):
        oidc.verify_id_token(unsigned, expected_nonce="n")


def test_email_domain_restriction_is_enforced(configured, monkeypatch):
    monkeypatch.setenv("PIQUACHU_OIDC_ALLOWED_EMAIL_DOMAINS", "corp.example")
    with pytest.raises(oidc.OidcError, match="domain"):
        oidc.enforce_email_domain({"email": "ada@example.com", "email_verified": True})

    # Allowed domain passes.
    oidc.enforce_email_domain({"email": "ada@corp.example", "email_verified": True})


def test_unverified_email_is_rejected_when_domains_are_configured(configured, monkeypatch):
    monkeypatch.setenv("PIQUACHU_OIDC_ALLOWED_EMAIL_DOMAINS", "corp.example")
    with pytest.raises(oidc.OidcError, match="verified"):
        oidc.enforce_email_domain({"email": "ada@corp.example", "email_verified": False})


# ---------------------------------------------------------------------------
# Session cookies
# ---------------------------------------------------------------------------


def test_session_round_trip_and_tampering(configured):
    payload = {
        "sub": "oidc:abc",
        "iss": ISSUER,
        "tenant": "local",
        "role": "analyst",
        "name": "Ada",
        "iat": int(time.time()),
        "exp": int(time.time()) + 600,
        "sid": "sid-1",
    }
    cookie = oidc.issue_session(payload)
    assert oidc.read_session(cookie)["sub"] == "oidc:abc"
    assert oidc.read_session(cookie + "x") is None
    assert oidc.read_session(None) is None

    principal = oidc.principal_from_session(oidc.read_session(cookie))
    assert principal is not None
    assert principal.tenant_id == "local"
    assert principal.role == "analyst"


def test_expired_session_is_refused(configured):
    payload = {
        "sub": "oidc:abc",
        "tenant": "local",
        "role": "analyst",
        "exp": int(time.time()) - 5,
    }
    assert oidc.read_session(oidc.issue_session(payload)) is None


def test_unknown_role_is_refused(configured):
    payload = {
        "sub": "oidc:abc",
        "tenant": "local",
        "role": "superuser",
        "exp": int(time.time()) + 600,
    }
    assert oidc.principal_from_session(payload) is None


def test_session_endpoint_reports_no_credential():
    client = api.app.test_client()
    body = client.get("/api/v1/auth/session").get_json()
    assert body["authenticated"] is False
    assert body["method"] is None


def test_logout_clears_the_session_cookie():
    client = api.app.test_client()
    response = client.post("/api/v1/auth/logout")
    assert response.status_code == 200
    cookies = response.headers.getlist("Set-Cookie")
    assert any("piquachu_session=" in cookie for cookie in cookies)
