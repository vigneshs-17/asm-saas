"""Unit tests for Supabase token verification and JWKS key management."""

import logging
import time
import uuid
from typing import Any
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from asm.auth.config import AuthSettings
from asm.auth.jwks import JWKSManager
from asm.auth.token import (
    AuthServiceUnavailableError,
    ExpiredTokenError,
    InvalidTokenError,
    MissingTokenError,
    extract_bearer_token,
    verify_access_token,
)

SUPABASE_URL = "https://mockproject.supabase.co"
AUDIENCE = "authenticated"


@pytest.fixture(scope="module")
def ec_key_pair():
    """Generate an ephemeral EC (SECP256R1) key pair for ES256 tests."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    jwk_dict = jwt.algorithms.ECAlgorithm.to_jwk(public_key, as_dict=True)
    jwk_dict["kid"] = "test-ec-kid"
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "ES256"
    return private_key, public_key, jwk_dict


@pytest.fixture(scope="module")
def rsa_key_pair():
    """Generate an ephemeral RSA (2048-bit) key pair for RS256 tests."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk_dict = jwt.algorithms.RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk_dict["kid"] = "test-rsa-kid"
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"
    return private_key, public_key, jwk_dict


@pytest.fixture
def auth_settings():
    """Return standard test auth settings."""
    return AuthSettings(supabase_url=SUPABASE_URL, jwt_audience=AUDIENCE)


@pytest.fixture
def mock_jwks_manager(ec_key_pair, rsa_key_pair, auth_settings):
    """Provide a JWKSManager loaded with the test EC and RSA keys without network calls."""
    _, _, ec_jwk = ec_key_pair
    _, _, rsa_jwk = rsa_key_pair
    jwks_data = {"keys": [ec_jwk, rsa_jwk]}

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = jwks_data
    mock_client.get.return_value = mock_resp

    manager = JWKSManager(
        jwks_url=auth_settings.jwks_url,
        fetch_timeout=5.0,
        min_refresh_interval=10.0,
        http_client=mock_client,
    )
    # Trigger initial load
    manager.get_signing_key("test-ec-kid")
    return manager


def create_token(
    private_key,
    headers: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
    algorithm: str = "ES256",
) -> str:
    """Helper to craft signed test JWTs."""
    now = int(time.time())
    default_headers = {"kid": "test-ec-kid", "alg": algorithm}
    if headers is not None:
        default_headers.update(headers)

    default_payload = {
        "sub": str(uuid.uuid4()),
        "email": "user@example.com",
        "iss": f"{SUPABASE_URL}/auth/v1",
        "aud": AUDIENCE,
        "exp": now + 3600,
        "iat": now,
    }
    if payload is not None:
        default_payload.update(payload)

    return jwt.encode(default_payload, private_key, algorithm=algorithm, headers=default_headers)


def test_extract_bearer_token():
    """extract_bearer_token properly extracts token and rejects invalid formats."""
    assert extract_bearer_token("Bearer secret-token") == "secret-token"
    assert extract_bearer_token("bearer secret-token") == "secret-token"

    with pytest.raises(MissingTokenError):
        extract_bearer_token(None)
    with pytest.raises(MissingTokenError):
        extract_bearer_token("")
    with pytest.raises(InvalidTokenError):
        extract_bearer_token("Basic dXNlcjpwYXNz")
    with pytest.raises(InvalidTokenError):
        extract_bearer_token("Bearer")


def test_valid_es256_token(ec_key_pair, auth_settings, mock_jwks_manager):
    """Valid ES256 token passes cryptographic verification and extracts sub & email."""
    ec_priv, _, _ = ec_key_pair
    user_id = uuid.uuid4()
    token = create_token(ec_priv, payload={"sub": str(user_id), "email": "test@example.com"})

    result = verify_access_token(token, auth_settings, mock_jwks_manager)
    assert result["user_id"] == user_id
    assert result["email"] == "test@example.com"
    assert result["claims"]["aud"] == AUDIENCE


def test_valid_rs256_token(rsa_key_pair, auth_settings, mock_jwks_manager):
    """Valid RS256 token passes cryptographic verification with RSA key."""
    rsa_priv, _, _ = rsa_key_pair
    user_id = uuid.uuid4()
    token = create_token(
        rsa_priv,
        headers={"kid": "test-rsa-kid", "alg": "RS256"},
        payload={"sub": str(user_id), "email": "rsa@example.com"},
        algorithm="RS256",
    )

    result = verify_access_token(token, auth_settings, mock_jwks_manager)
    assert result["user_id"] == user_id
    assert result["email"] == "rsa@example.com"


def test_expired_token_rejected(ec_key_pair, auth_settings, mock_jwks_manager):
    """Token with exp timestamp in the past is rejected with ExpiredTokenError."""
    ec_priv, _, _ = ec_key_pair
    token = create_token(ec_priv, payload={"exp": int(time.time()) - 60})

    with pytest.raises(ExpiredTokenError):
        verify_access_token(token, auth_settings, mock_jwks_manager)


def test_wrong_issuer_rejected(ec_key_pair, auth_settings, mock_jwks_manager):
    """Token with wrong iss claim is rejected with InvalidTokenError."""
    ec_priv, _, _ = ec_key_pair
    token = create_token(ec_priv, payload={"iss": "https://evil.attacker.com/auth/v1"})

    with pytest.raises(InvalidTokenError, match="Invalid token signature or claims"):
        verify_access_token(token, auth_settings, mock_jwks_manager)


def test_wrong_audience_rejected(ec_key_pair, auth_settings, mock_jwks_manager):
    """Token with mismatched aud claim is rejected with InvalidTokenError."""
    ec_priv, _, _ = ec_key_pair
    token = create_token(ec_priv, payload={"aud": "wrong-audience"})

    with pytest.raises(InvalidTokenError, match="Invalid token signature or claims"):
        verify_access_token(token, auth_settings, mock_jwks_manager)


def test_hs256_algorithm_confusion_rejected(ec_key_pair, auth_settings, mock_jwks_manager):
    """Token signed with HS256 using arbitrary key is rejected (algorithm confusion defense)."""
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "email": "attacker@example.com",
            "iss": f"{SUPABASE_URL}/auth/v1",
            "aud": AUDIENCE,
            "exp": now + 3600,
        },
        key=b"secret-hmac-key-attempt-32bytes!!",
        algorithm="HS256",
        headers={"kid": "test-ec-kid", "alg": "HS256"},
    )

    with pytest.raises(InvalidTokenError, match="Unsupported signing algorithm: HS256"):
        verify_access_token(token, auth_settings, mock_jwks_manager)



def test_alg_none_rejected(ec_key_pair, auth_settings, mock_jwks_manager):
    """Unsigned token with alg: none is rejected."""
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "email": "attacker@example.com",
            "iss": f"{SUPABASE_URL}/auth/v1",
            "aud": AUDIENCE,
            "exp": now + 3600,
        },
        key="",
        algorithm=None,
        headers={"alg": "none"},
    )
    with pytest.raises(InvalidTokenError, match="Unsupported signing algorithm"):
        verify_access_token(token, auth_settings, mock_jwks_manager)


def test_anonymous_token_rejected(ec_key_pair, auth_settings, mock_jwks_manager):
    """Token with is_anonymous: true claim is rejected with InvalidTokenError."""
    ec_priv, _, _ = ec_key_pair
    token = create_token(ec_priv, payload={"is_anonymous": True})

    with pytest.raises(InvalidTokenError, match="Anonymous tokens are not allowed"):
        verify_access_token(token, auth_settings, mock_jwks_manager)


def test_missing_sub_rejected(ec_key_pair, auth_settings, mock_jwks_manager):
    """Token missing sub claim is rejected."""
    ec_priv, _, _ = ec_key_pair
    now = int(time.time())
    token = jwt.encode(
        {
            "email": "user@example.com",
            "iss": f"{SUPABASE_URL}/auth/v1",
            "aud": AUDIENCE,
            "exp": now + 3600,
        },
        ec_priv,
        algorithm="ES256",
        headers={"kid": "test-ec-kid", "alg": "ES256"},
    )

    with pytest.raises(InvalidTokenError):
        verify_access_token(token, auth_settings, mock_jwks_manager)


def test_tampered_payload_rejected(ec_key_pair, auth_settings, mock_jwks_manager):
    """Token with altered payload fails signature verification."""
    ec_priv, _, _ = ec_key_pair
    token = create_token(ec_priv)
    parts = token.split(".")
    # Tamper payload part
    tampered_token = f"{parts[0]}.eyJzdWIiOiAiZXZpbCJ9.{parts[2]}"

    with pytest.raises(InvalidTokenError):
        verify_access_token(tampered_token, auth_settings, mock_jwks_manager)


def test_unknown_kid_refreshes_once_then_fails(ec_key_pair, auth_settings):
    """Token with unknown kid triggers refresh; if still unknown, returns InvalidTokenError."""
    ec_priv, _, ec_jwk = ec_key_pair
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"keys": [ec_jwk]}
    mock_client.get.return_value = mock_resp

    manager = JWKSManager(
        jwks_url=auth_settings.jwks_url,
        fetch_timeout=5.0,
        min_refresh_interval=10.0,
        http_client=mock_client,
    )

    token = create_token(ec_priv, headers={"kid": "non-existent-kid"})
    with pytest.raises(InvalidTokenError, match="Unknown key ID 'non-existent-kid'"):
        verify_access_token(token, auth_settings, manager)

    # Verify mock_client was called exactly once to refresh
    assert mock_client.get.call_count == 1


def test_unknown_kid_refresh_throttling(ec_key_pair, auth_settings):
    """Consecutive unknown kids within min_refresh_interval do not trigger multiple HTTP calls."""
    ec_priv, _, ec_jwk = ec_key_pair
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"keys": [ec_jwk]}
    mock_client.get.return_value = mock_resp

    manager = JWKSManager(
        jwks_url=auth_settings.jwks_url,
        fetch_timeout=5.0,
        min_refresh_interval=10.0,
        http_client=mock_client,
    )

    # First unknown kid -> triggers fetch
    token1 = create_token(ec_priv, headers={"kid": "random-kid-1"})
    with pytest.raises(InvalidTokenError):
        verify_access_token(token1, auth_settings, manager)
    assert mock_client.get.call_count == 1

    # Second unknown kid immediately after -> throttled, no new fetch
    token2 = create_token(ec_priv, headers={"kid": "random-kid-2"})
    with pytest.raises(InvalidTokenError):
        verify_access_token(token2, auth_settings, manager)
    assert mock_client.get.call_count == 1


def test_jwks_outage_raises_service_unavailable(ec_key_pair, auth_settings):
    """JWKS endpoint 500 error raises AuthServiceUnavailableError."""
    ec_priv, _, _ = ec_key_pair
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 503
    mock_client.get.return_value = mock_resp

    manager = JWKSManager(
        jwks_url=auth_settings.jwks_url,
        fetch_timeout=5.0,
        min_refresh_interval=10.0,
        http_client=mock_client,
    )

    token = create_token(ec_priv, headers={"kid": "any-kid"})
    with pytest.raises(AuthServiceUnavailableError):
        verify_access_token(token, auth_settings, manager)


def test_token_never_logged_on_error(ec_key_pair, auth_settings, mock_jwks_manager, caplog):
    """Raw token string must never appear in log records."""
    ec_priv, _, _ = ec_key_pair
    secret_token = create_token(ec_priv, payload={"exp": int(time.time()) - 100})

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(ExpiredTokenError):
            verify_access_token(secret_token, auth_settings, mock_jwks_manager)

    for record in caplog.records:
        assert secret_token not in record.message


def test_verify_access_token_unconfigured(ec_key_pair, mock_jwks_manager):
    """verify_access_token fails closed with AuthMisconfiguredError when SUPABASE_URL is empty."""
    ec_priv, _, _ = ec_key_pair
    token = create_token(ec_priv)
    unconfigured_settings = AuthSettings(supabase_url="")

    with pytest.raises(AuthServiceUnavailableError) as exc_info:
        verify_access_token(token, unconfigured_settings, mock_jwks_manager)
    assert "not configured" in str(exc_info.value).lower()

