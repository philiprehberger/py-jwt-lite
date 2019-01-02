"""Tests for philiprehberger_jwt_lite."""

from __future__ import annotations

import time

import pytest

from philiprehberger_jwt_lite import (
    ExpiredTokenError,
    InvalidTokenError,
    create_token,
    decode_token,
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
