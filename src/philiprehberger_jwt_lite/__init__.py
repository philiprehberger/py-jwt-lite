"""Minimal JWT creation and validation with zero dependencies."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Callable

__all__ = [
    "create_token",
    "verify_token",
    "decode_token",
    "refresh_token",
    "ExpiredTokenError",
    "InvalidTokenError",
]

_ALGORITHMS = {"HS256": "sha256", "HS384": "sha384", "HS512": "sha512"}


class ExpiredTokenError(Exception):
    """Raised when a token's exp claim is in the past."""


class InvalidTokenError(Exception):
    """Raised when a token's signature is invalid or the token is malformed."""


def _b64url_encode(data: bytes) -> str:
    """Base64url-encode bytes, stripping padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url-decode a string, restoring padding."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def create_token(
    payload: dict[str, object],
    secret: str,
    algorithm: str = "HS256",
    expires_in: int | float | None = None,
) -> str:
    """Create a signed JWT token.

    Args:
        payload: Claims to include in the token.
        secret: Shared secret used for HMAC signing.
        algorithm: Signing algorithm (HS256, HS384, or HS512).
        expires_in: Optional expiration time in seconds from now.

    Returns:
        A signed JWT string.

    Raises:
        ValueError: If the algorithm is not supported.
    """
    if algorithm not in _ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    header = {"alg": algorithm, "typ": "JWT"}

    if expires_in is not None:
        payload = {**payload, "exp": time.time() + expires_in}

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        secret.encode(),
        signing_input.encode(),
        _ALGORITHMS[algorithm],
    ).digest()
    signature_b64 = _b64url_encode(signature)

    return f"{signing_input}.{signature_b64}"


def verify_token(
    token: str,
    secret: str,
    algorithm: str = "HS256",
    validators: dict[str, Callable[[Any], bool]] | None = None,
) -> dict[str, object]:
    """Verify a JWT token's signature and expiration.

    Args:
        token: The JWT string to verify.
        secret: Shared secret used for HMAC verification.
        algorithm: Expected signing algorithm.
        validators: Optional mapping of claim names to validator functions.
            Each function receives the claim value and must return True for
            the token to be considered valid.

    Returns:
        The decoded payload as a dictionary.

    Raises:
        InvalidTokenError: If the token is malformed, the signature is invalid,
            or any custom validator fails.
        ExpiredTokenError: If the token has expired.
        ValueError: If the algorithm is not supported.
    """
    if algorithm not in _ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidTokenError("Token must have three parts")

    header_b64, payload_b64, signature_b64 = parts

    signing_input = f"{header_b64}.{payload_b64}"
    expected_signature = hmac.new(
        secret.encode(),
        signing_input.encode(),
        _ALGORITHMS[algorithm],
    ).digest()

    actual_signature = _b64url_decode(signature_b64)

    if not hmac.compare_digest(expected_signature, actual_signature):
        raise InvalidTokenError("Invalid signature")

    payload: dict[str, object] = json.loads(_b64url_decode(payload_b64))

    exp = payload.get("exp")
    if exp is not None and isinstance(exp, (int, float)) and exp < time.time():
        raise ExpiredTokenError("Token has expired")

    if validators is not None:
        for claim_name, validator_fn in validators.items():
            claim_value = payload.get(claim_name)
            if claim_value is None:
                raise InvalidTokenError(
                    f"Missing required claim: {claim_name}"
                )
            if not validator_fn(claim_value):
                raise InvalidTokenError(
                    f"Validation failed for claim: {claim_name}"
                )

    return payload


def refresh_token(
    token: str,
    secret: str,
    extends_by: int = 3600,
    algorithm: str = "HS256",
) -> str:
    """Refresh a JWT token by re-signing with a new expiration time.

    The existing token is verified first, then a new token is created
    with the same payload but a fresh ``exp`` claim.

    Args:
        token: The JWT string to refresh.
        secret: Shared secret used for HMAC signing.
        extends_by: New expiration time in seconds from now (default 3600).
        algorithm: Signing algorithm (HS256, HS384, or HS512).

    Returns:
        A new signed JWT string with an updated expiration.

    Raises:
        InvalidTokenError: If the original token is invalid.
        ExpiredTokenError: If the original token has expired.
        ValueError: If the algorithm is not supported.
    """
    payload = verify_token(token, secret, algorithm=algorithm)
    payload["exp"] = time.time() + extends_by
    return create_token(payload, secret, algorithm=algorithm)


def decode_token(token: str) -> dict[str, object]:
    """Decode a JWT token's payload without verifying the signature.

    Args:
        token: The JWT string to decode.

    Returns:
        The decoded payload as a dictionary.

    Raises:
        InvalidTokenError: If the token is malformed.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidTokenError("Token must have three parts")

    try:
        payload: dict[str, object] = json.loads(_b64url_decode(parts[1]))
    except (json.JSONDecodeError, Exception) as exc:
        raise InvalidTokenError("Invalid payload") from exc

    return payload
