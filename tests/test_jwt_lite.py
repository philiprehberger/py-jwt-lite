"""Tests for philiprehberger_jwt_lite."""

from __future__ import annotations

import subprocess
import time
import uuid

import pytest

from philiprehberger_jwt_lite import (
    ClaimValidationError,
    ExpiredTokenError,
    InvalidTokenError,
    JWKSet,
    TokenRevokedError,
    create_token,
    decode_header,
    decode_token,
    decode_unverified,
    refresh_token,
    verify_token,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _generate_rsa_keypair() -> tuple[str, str]:
    """Generate a 2048-bit RSA key pair using openssl CLI.

    Returns (private_pem, public_pem).
    """
    private_pem = subprocess.check_output(
        ["openssl", "genrsa", "2048"],
        stderr=subprocess.DEVNULL,
    ).decode()
    public_pem = subprocess.check_output(
        ["openssl", "rsa", "-pubout"],
        input=private_pem.encode(),
        stderr=subprocess.DEVNULL,
    ).decode()
    return private_pem, public_pem


@pytest.fixture(scope="module")
def rsa_keys() -> tuple[str, str]:
    """Module-scoped RSA key pair fixture."""
    return _generate_rsa_keypair()


@pytest.fixture(scope="module")
def rsa_keys_alt() -> tuple[str, str]:
    """A second RSA key pair for mismatch tests."""
    return _generate_rsa_keypair()


# ---------------------------------------------------------------------------
# Basic HMAC round-trip
# ---------------------------------------------------------------------------


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


def test_unsupported_algorithm_raises() -> None:
    """An unsupported algorithm should raise ValueError."""
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        create_token({"sub": "u"}, "s", algorithm="NONE")

    with pytest.raises(ValueError, match="Unsupported algorithm"):
        verify_token("a.b.c", "s", algorithm="NONE")


# ---------------------------------------------------------------------------
# JTI auto-generation
# ---------------------------------------------------------------------------


def test_include_jti_adds_uuid4() -> None:
    """create_token with include_jti=True should add a valid UUID4 jti claim."""
    token = create_token({"sub": "user1"}, "secret", include_jti=True)
    payload = decode_token(token)

    assert "jti" in payload
    jti = payload["jti"]
    assert isinstance(jti, str)
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

    assert payload["jti"] != "custom-id"
    uuid.UUID(str(payload["jti"]), version=4)


# ---------------------------------------------------------------------------
# Token revocation
# ---------------------------------------------------------------------------


def test_revoked_token_raises() -> None:
    """verify_token should raise TokenRevokedError when is_revoked returns True."""
    revoked_jtis: set[str] = set()
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


# ---------------------------------------------------------------------------
# decode_unverified
# ---------------------------------------------------------------------------


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
    parts = token.split(".")
    tampered = f"{parts[0]}.{parts[1]}.invalid-signature"

    header, payload = decode_unverified(tampered)
    assert payload["sub"] == "user1"


def test_decode_unverified_malformed_raises() -> None:
    """decode_unverified should raise InvalidTokenError for malformed tokens."""
    with pytest.raises(InvalidTokenError):
        decode_unverified("not-a-token")


# ---------------------------------------------------------------------------
# decode_header
# ---------------------------------------------------------------------------


def test_decode_header_returns_header() -> None:
    """decode_header should return the token header without verification."""
    token = create_token({"sub": "user1"}, "secret", algorithm="HS512")

    header = decode_header(token)

    assert header["alg"] == "HS512"
    assert header["typ"] == "JWT"


def test_decode_header_does_not_check_signature() -> None:
    """decode_header should succeed even with a tampered signature."""
    token = create_token({"sub": "user1"}, "secret")
    parts = token.split(".")
    tampered = f"{parts[0]}.{parts[1]}.XXXX"

    header = decode_header(tampered)
    assert header["alg"] == "HS256"


def test_decode_header_malformed_raises() -> None:
    """decode_header should raise InvalidTokenError for malformed tokens."""
    with pytest.raises(InvalidTokenError):
        decode_header("nope")


def test_decode_header_with_kid() -> None:
    """decode_header should expose the kid field when present."""
    jwks = JWKSet()
    jwks.add_hmac_key("key-1", "secret123")
    token = jwks.create_token({"sub": "u"}, "key-1")

    header = decode_header(token)
    assert header["kid"] == "key-1"


# ---------------------------------------------------------------------------
# Custom claims validation
# ---------------------------------------------------------------------------


def test_validators_pass() -> None:
    """Validators that return True should not raise."""
    token = create_token({"sub": "user1", "role": "admin"}, "secret")

    result = verify_token(
        token,
        "secret",
        validators={"role": lambda r: r == "admin"},
    )
    assert result["role"] == "admin"


def test_validators_fail_raises_claim_validation_error() -> None:
    """A failing validator should raise ClaimValidationError."""
    token = create_token({"sub": "user1", "role": "guest"}, "secret")

    with pytest.raises(ClaimValidationError, match="Validation failed for claim: role"):
        verify_token(
            token,
            "secret",
            validators={"role": lambda r: r == "admin"},
        )


def test_validators_missing_claim_raises() -> None:
    """A validator for a missing claim should raise ClaimValidationError."""
    token = create_token({"sub": "user1"}, "secret")

    with pytest.raises(ClaimValidationError, match="Missing required claim: role"):
        verify_token(
            token,
            "secret",
            validators={"role": lambda r: r == "admin"},
        )


def test_claim_validation_error_is_invalid_token_error() -> None:
    """ClaimValidationError should be a subclass of InvalidTokenError."""
    assert issubclass(ClaimValidationError, InvalidTokenError)


def test_multiple_validators() -> None:
    """Multiple validators should all be checked."""
    token = create_token({"sub": "user1", "role": "admin", "aud": "app"}, "secret")

    result = verify_token(
        token,
        "secret",
        validators={
            "role": lambda r: r == "admin",
            "aud": lambda a: a == "app",
        },
    )
    assert result["role"] == "admin"
    assert result["aud"] == "app"


# ---------------------------------------------------------------------------
# refresh_token
# ---------------------------------------------------------------------------


def test_refresh_token_extends_expiry() -> None:
    """refresh_token should produce a new token with updated exp."""
    secret = "my-secret"
    token = create_token({"sub": "user1"}, secret, expires_in=60)
    before = time.time()

    new_token = refresh_token(token, secret, extends_by=7200)
    new_payload = verify_token(new_token, secret)

    exp = new_payload["exp"]
    assert isinstance(exp, (int, float))
    assert exp >= before + 7200 - 1


def test_refresh_expired_token_raises() -> None:
    """refresh_token should reject an expired token."""
    secret = "my-secret"
    token = create_token({"sub": "user1"}, secret, expires_in=-1)

    with pytest.raises(ExpiredTokenError):
        refresh_token(token, secret)


def test_refresh_preserves_claims() -> None:
    """refresh_token should preserve original claims."""
    secret = "my-secret"
    token = create_token({"sub": "user1", "role": "admin"}, secret, expires_in=60)

    new_token = refresh_token(token, secret, extends_by=3600)
    payload = verify_token(new_token, secret)

    assert payload["sub"] == "user1"
    assert payload["role"] == "admin"


# ---------------------------------------------------------------------------
# RS256 (RSA) algorithm support
# ---------------------------------------------------------------------------


def test_rs256_create_and_verify(rsa_keys: tuple[str, str]) -> None:
    """RS256 tokens should round-trip with matching key pair."""
    private_pem, public_pem = rsa_keys

    token = create_token({"sub": "user1"}, private_pem, algorithm="RS256")
    result = verify_token(token, public_pem, algorithm="RS256")

    assert result["sub"] == "user1"


def test_rs256_wrong_key_raises(
    rsa_keys: tuple[str, str],
    rsa_keys_alt: tuple[str, str],
) -> None:
    """RS256 token verified with a different key pair should fail."""
    private_pem, _ = rsa_keys
    _, wrong_public = rsa_keys_alt

    token = create_token({"sub": "user1"}, private_pem, algorithm="RS256")

    with pytest.raises(InvalidTokenError):
        verify_token(token, wrong_public, algorithm="RS256")


def test_rs256_with_expiry(rsa_keys: tuple[str, str]) -> None:
    """RS256 tokens should support expiration."""
    private_pem, public_pem = rsa_keys

    token = create_token({"sub": "user1"}, private_pem, algorithm="RS256", expires_in=3600)
    result = verify_token(token, public_pem, algorithm="RS256")

    assert result["sub"] == "user1"
    assert "exp" in result


def test_rs256_expired_token_raises(rsa_keys: tuple[str, str]) -> None:
    """RS256 token with past expiry should raise ExpiredTokenError."""
    private_pem, public_pem = rsa_keys

    token = create_token({"sub": "user1"}, private_pem, algorithm="RS256", expires_in=-1)

    with pytest.raises(ExpiredTokenError):
        verify_token(token, public_pem, algorithm="RS256")


def test_rs256_header_algorithm(rsa_keys: tuple[str, str]) -> None:
    """RS256 token header should indicate the RS256 algorithm."""
    private_pem, _ = rsa_keys

    token = create_token({"sub": "user1"}, private_pem, algorithm="RS256")
    header = decode_header(token)

    assert header["alg"] == "RS256"


def test_rs256_with_jti(rsa_keys: tuple[str, str]) -> None:
    """RS256 tokens should support include_jti."""
    private_pem, public_pem = rsa_keys

    token = create_token({"sub": "user1"}, private_pem, algorithm="RS256", include_jti=True)
    result = verify_token(token, public_pem, algorithm="RS256")

    assert "jti" in result
    uuid.UUID(str(result["jti"]), version=4)


# ---------------------------------------------------------------------------
# JWKSet
# ---------------------------------------------------------------------------


def test_jwkset_hmac_roundtrip() -> None:
    """JWKSet should create and verify HMAC tokens."""
    jwks = JWKSet()
    jwks.add_hmac_key("hmac-1", "my-secret")

    token = jwks.create_token({"sub": "user1"}, "hmac-1")
    result = jwks.verify_token(token)

    assert result["sub"] == "user1"


def test_jwkset_rsa_roundtrip(rsa_keys: tuple[str, str]) -> None:
    """JWKSet should create and verify RSA tokens."""
    private_pem, public_pem = rsa_keys

    jwks = JWKSet()
    jwks.add_rsa_key("rsa-1", private_pem=private_pem, public_pem=public_pem)

    token = jwks.create_token({"sub": "user1"}, "rsa-1")
    result = jwks.verify_token(token)

    assert result["sub"] == "user1"


def test_jwkset_multiple_keys(rsa_keys: tuple[str, str]) -> None:
    """JWKSet should support multiple keys and select by kid."""
    private_pem, public_pem = rsa_keys

    jwks = JWKSet()
    jwks.add_hmac_key("hmac-1", "secret-a")
    jwks.add_hmac_key("hmac-2", "secret-b")
    jwks.add_rsa_key("rsa-1", private_pem=private_pem, public_pem=public_pem)

    token_a = jwks.create_token({"src": "a"}, "hmac-1")
    token_b = jwks.create_token({"src": "b"}, "hmac-2")
    token_r = jwks.create_token({"src": "r"}, "rsa-1")

    assert jwks.verify_token(token_a)["src"] == "a"
    assert jwks.verify_token(token_b)["src"] == "b"
    assert jwks.verify_token(token_r)["src"] == "r"


def test_jwkset_unknown_kid_raises() -> None:
    """JWKSet should raise InvalidTokenError for unknown key IDs."""
    jwks = JWKSet()
    jwks.add_hmac_key("key-1", "secret")

    with pytest.raises(InvalidTokenError, match="Unknown key ID"):
        jwks.create_token({"sub": "u"}, "nonexistent")


def test_jwkset_verify_unknown_kid_raises() -> None:
    """JWKSet should raise InvalidTokenError if token kid is not in set."""
    jwks_a = JWKSet()
    jwks_a.add_hmac_key("key-a", "secret-a")

    jwks_b = JWKSet()
    jwks_b.add_hmac_key("key-b", "secret-b")

    token = jwks_a.create_token({"sub": "u"}, "key-a")

    with pytest.raises(InvalidTokenError, match="Unknown key ID"):
        jwks_b.verify_token(token)


def test_jwkset_key_ids() -> None:
    """key_ids should return all registered identifiers."""
    jwks = JWKSet()
    jwks.add_hmac_key("a", "s1")
    jwks.add_hmac_key("b", "s2")

    assert sorted(jwks.key_ids) == ["a", "b"]


def test_jwkset_with_expiry() -> None:
    """JWKSet tokens should support expiration."""
    jwks = JWKSet()
    jwks.add_hmac_key("k1", "secret")

    token = jwks.create_token({"sub": "u"}, "k1", expires_in=3600)
    result = jwks.verify_token(token)
    assert "exp" in result


def test_jwkset_expired_raises() -> None:
    """JWKSet should raise ExpiredTokenError for expired tokens."""
    jwks = JWKSet()
    jwks.add_hmac_key("k1", "secret")

    token = jwks.create_token({"sub": "u"}, "k1", expires_in=-1)

    with pytest.raises(ExpiredTokenError):
        jwks.verify_token(token)


def test_jwkset_validators() -> None:
    """JWKSet verify_token should support custom validators."""
    jwks = JWKSet()
    jwks.add_hmac_key("k1", "secret")

    token = jwks.create_token({"sub": "u", "role": "admin"}, "k1")

    result = jwks.verify_token(
        token,
        validators={"role": lambda r: r == "admin"},
    )
    assert result["role"] == "admin"


def test_jwkset_validators_fail_raises() -> None:
    """JWKSet verify_token should raise ClaimValidationError on validator failure."""
    jwks = JWKSet()
    jwks.add_hmac_key("k1", "secret")

    token = jwks.create_token({"sub": "u", "role": "guest"}, "k1")

    with pytest.raises(ClaimValidationError):
        jwks.verify_token(
            token,
            validators={"role": lambda r: r == "admin"},
        )


def test_jwkset_revocation() -> None:
    """JWKSet verify_token should support is_revoked callback."""
    jwks = JWKSet()
    jwks.add_hmac_key("k1", "secret")

    token = jwks.create_token({"sub": "u"}, "k1", include_jti=True)
    jti = str(decode_token(token)["jti"])

    with pytest.raises(TokenRevokedError):
        jwks.verify_token(token, is_revoked=lambda j: j == jti)


def test_jwkset_add_rsa_no_keys_raises() -> None:
    """add_rsa_key with neither private nor public key should raise ValueError."""
    jwks = JWKSet()

    with pytest.raises(ValueError, match="At least one"):
        jwks.add_rsa_key("k1")


def test_jwkset_add_hmac_bad_algorithm_raises() -> None:
    """add_hmac_key with unsupported algorithm should raise ValueError."""
    jwks = JWKSet()

    with pytest.raises(ValueError, match="Unsupported HMAC algorithm"):
        jwks.add_hmac_key("k1", "secret", algorithm="RS256")


def test_jwkset_add_rsa_bad_algorithm_raises() -> None:
    """add_rsa_key with unsupported algorithm should raise ValueError."""
    jwks = JWKSet()

    with pytest.raises(ValueError, match="Unsupported RSA algorithm"):
        jwks.add_rsa_key("k1", private_pem="fake", algorithm="HS256")


def test_jwkset_rsa_public_only_verify(rsa_keys: tuple[str, str]) -> None:
    """JWKSet with only a public RSA key should verify tokens signed elsewhere."""
    private_pem, public_pem = rsa_keys

    # Sign with standalone function
    token = create_token({"sub": "user1"}, private_pem, algorithm="RS256")

    # Manually inject kid into header for JWKSet lookup
    # Instead, use a signing JWKSet and a separate verifying JWKSet
    jwks_sign = JWKSet()
    jwks_sign.add_rsa_key("rsa-1", private_pem=private_pem, public_pem=public_pem)
    token = jwks_sign.create_token({"sub": "user1"}, "rsa-1")

    jwks_verify = JWKSet()
    jwks_verify.add_rsa_key("rsa-1", public_pem=public_pem)
    result = jwks_verify.verify_token(token)

    assert result["sub"] == "user1"


def test_jwkset_include_jti() -> None:
    """JWKSet create_token should support include_jti."""
    jwks = JWKSet()
    jwks.add_hmac_key("k1", "secret")

    token = jwks.create_token({"sub": "u"}, "k1", include_jti=True)
    payload = decode_token(token)

    assert "jti" in payload
    uuid.UUID(str(payload["jti"]), version=4)
