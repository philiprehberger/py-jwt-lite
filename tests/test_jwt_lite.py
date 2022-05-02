"""Tests for philiprehberger_jwt_lite."""

from __future__ import annotations

import time
import uuid

import pytest

from philiprehberger_jwt_lite import (
    ExpiredTokenError,
    InvalidTokenError,
    TokenRevokedError,
    create_token,
    decode_token,
    decode_unverified,
    verify_token,
)


def test_create_and_verify_roundtrip() -> None:
    """Token created with create_token should be verifiable with verify_token."""
    payload = {"sub": "user123", "role": "admin"}
    secret = "my-secret-key"

    token = create_token(payload, secret)
    result = verify_token(token, secret)

    assert result["sub"] == "user123"
    assert result["role"] == "admin"


def test_expired_token_raises() -> None:
    """A token with an expired exp claim should raise ExpiredTokenError."""
    payload = {"sub": "user123"}
    secret = "my-secret-key"

    token = create_token(payload, secret, expires_in=-1)

    with pytest.raises(ExpiredTokenError):
        verify_token(token, secret)


def test_invalid_signature_raises() -> None:
    """A token verified with the wrong secret should raise InvalidTokenError."""
    payload = {"sub": "user123"}
    token = create_token(payload, "correct-secret")

    with pytest.raises(InvalidTokenError):
        verify_token(token, "wrong-secret")


def test_decode_without_verification() -> None:
    """decode_token should return the payload without checking the signature."""
    payload = {"sub": "user123", "data": "value"}
    token = create_token(payload, "secret")

    result = decode_token(token)

    assert result["sub"] == "user123"
    assert result["data"] == "value"


def test_custom_algorithm_hs512() -> None:
    """Tokens should work with the HS512 algorithm."""
    payload = {"sub": "user123"}
    secret = "my-secret-key"

    token = create_token(payload, secret, algorithm="HS512")
    result = verify_token(token, secret, algorithm="HS512")

    assert result["sub"] == "user123"


def test_valid_token_with_future_expiry() -> None:
    """A token with a future exp claim should verify successfully."""
    payload = {"sub": "user123"}
    secret = "my-secret-key"

    token = create_token(payload, secret, expires_in=3600)
    result = verify_token(token, secret)

    assert result["sub"] == "user123"
    assert "exp" in result


def test_malformed_token_raises() -> None:
    """A token with fewer than three parts should raise InvalidTokenError."""
    with pytest.raises(InvalidTokenError):
        verify_token("not.a-valid-token", "secret")

    with pytest.raises(InvalidTokenError):
        decode_token("invalid")


# --- JTI auto-generation ---


def test_include_jti_adds_uuid4() -> None:
    """create_token with include_jti=True should add a valid UUID4 jti claim."""
    token = create_token({"sub": "user1"}, "secret", include_jti=True)
    payload = decode_token(token)

    assert "jti" in payload
    jti = payload["jti"]
    assert isinstance(jti, str)
    # Should be a valid UUID4
    parsed = uuid.UUID(jti, version=4)
    assert str(parsed) == jti


def test_include_jti_false_no_jti() -> None:
    """create_token with include_jti=False (default) should not add a jti claim."""
    token = create_token({"sub": "user1"}, "secret")
    payload = decode_token(token)

    assert "jti" not in payload


def test_include_jti_does_not_overwrite_existing() -> None:
    """create_token with include_jti=True should overwrite any existing jti in payload."""
    token = create_token({"sub": "user1", "jti": "custom-id"}, "secret", include_jti=True)
    payload = decode_token(token)

    # include_jti=True generates a new UUID, overwriting the provided one
    assert payload["jti"] != "custom-id"
    uuid.UUID(str(payload["jti"]), version=4)


# --- Token revocation ---


def test_revoked_token_raises() -> None:
    """verify_token should raise TokenRevokedError when is_revoked returns True."""
    revoked_jtis = set()
    token = create_token({"sub": "user1"}, "secret", include_jti=True)
    jti = str(decode_token(token)["jti"])
    revoked_jtis.add(jti)

    with pytest.raises(TokenRevokedError):
        verify_token(token, "secret", is_revoked=lambda j: j in revoked_jtis)


def test_non_revoked_token_passes() -> None:
    """verify_token should pass when is_revoked returns False."""
    token = create_token({"sub": "user1"}, "secret", include_jti=True)

    result = verify_token(token, "secret", is_revoked=lambda j: False)
    assert result["sub"] == "user1"


def test_revocation_without_jti_passes() -> None:
    """verify_token with is_revoked but no jti claim should not raise."""
    token = create_token({"sub": "user1"}, "secret")

    result = verify_token(token, "secret", is_revoked=lambda j: True)
    assert result["sub"] == "user1"


# --- decode_unverified ---


def test_decode_unverified_returns_header_and_payload() -> None:
    """decode_unverified should return both header and payload dicts."""
    token = create_token({"sub": "user1", "role": "admin"}, "secret", algorithm="HS384")

    header, payload = decode_unverified(token)

    assert header["alg"] == "HS384"
    assert header["typ"] == "JWT"
    assert payload["sub"] == "user1"
    assert payload["role"] == "admin"


def test_decode_unverified_does_not_check_signature() -> None:
    """decode_unverified should succeed even with a tampered signature."""
    token = create_token({"sub": "user1"}, "secret")
    # Tamper with the signature part
    parts = token.split(".")
    tampered = f"{parts[0]}.{parts[1]}.invalid-signature"

    header, payload = decode_unverified(tampered)
    assert payload["sub"] == "user1"


def test_decode_unverified_malformed_raises() -> None:
    """decode_unverified should raise InvalidTokenError for malformed tokens."""
    with pytest.raises(InvalidTokenError):
        decode_unverified("not-a-token")
