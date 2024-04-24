"""Minimal JWT creation and validation with HMAC and RSA signing."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Callable

__all__ = [
    "create_token",
    "verify_token",
    "decode_token",
    "decode_unverified",
    "decode_header",
    "refresh_token",
    "JWKSet",
    "ExpiredTokenError",
    "InvalidTokenError",
    "TokenRevokedError",
    "ClaimValidationError",
]

_HMAC_ALGORITHMS: dict[str, str] = {
    "HS256": "sha256",
    "HS384": "sha384",
    "HS512": "sha512",
}

_RSA_ALGORITHMS: dict[str, str] = {
    "RS256": "sha256",
}

_ALL_ALGORITHMS = {*_HMAC_ALGORITHMS, *_RSA_ALGORITHMS}


class ExpiredTokenError(Exception):
    """Raised when a token's exp claim is in the past."""


class InvalidTokenError(Exception):
    """Raised when a token's signature is invalid or the token is malformed."""


class TokenRevokedError(Exception):
    """Raised when a token has been revoked."""


class ClaimValidationError(InvalidTokenError):
    """Raised when a custom claim validator fails."""


def _b64url_encode(data: bytes) -> str:
    """Base64url-encode bytes, stripping padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url-decode a string, restoring padding."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _int_to_bytes(n: int) -> bytes:
    """Convert a positive integer to big-endian bytes."""
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder="big")


def _bytes_to_int(b: bytes) -> int:
    """Convert big-endian bytes to an integer."""
    return int.from_bytes(b, byteorder="big")


def _pkcs1v15_sign(message: bytes, private_key_der: bytes, hash_name: str) -> bytes:
    """Create an RSA PKCS#1 v1.5 signature using raw DER private key bytes.

    Parses the RSA private key from DER format and performs modular
    exponentiation for signing.
    """
    n, d = _parse_rsa_private_key_der(private_key_der)
    h = hashlib.new(hash_name, message).digest()
    digest_info = _pkcs1v15_digest_info(hash_name, h)
    k = (n.bit_length() + 7) // 8
    pad_len = k - len(digest_info) - 3
    if pad_len < 8:
        raise InvalidTokenError("RSA key too short for signing")
    em = b"\x00\x01" + (b"\xff" * pad_len) + b"\x00" + digest_info
    m_int = _bytes_to_int(em)
    s_int = pow(m_int, d, n)
    return s_int.to_bytes(k, byteorder="big")


def _pkcs1v15_verify(message: bytes, signature: bytes, public_key_der: bytes, hash_name: str) -> bool:
    """Verify an RSA PKCS#1 v1.5 signature using raw DER public key bytes."""
    n, e = _parse_rsa_public_key_der(public_key_der)
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s_int = _bytes_to_int(signature)
    if s_int >= n:
        return False
    m_int = pow(s_int, e, n)
    em = m_int.to_bytes(k, byteorder="big")
    h = hashlib.new(hash_name, message).digest()
    expected = b"\x00\x01" + (b"\xff" * (k - len(_pkcs1v15_digest_info(hash_name, h)) - 3)) + b"\x00" + _pkcs1v15_digest_info(hash_name, h)
    return hmac.compare_digest(em, expected)


_HASH_OID_PREFIX: dict[str, bytes] = {
    "sha256": bytes([
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20,
    ]),
}


def _pkcs1v15_digest_info(hash_name: str, digest: bytes) -> bytes:
    """Build the PKCS#1 v1.5 DigestInfo structure."""
    prefix = _HASH_OID_PREFIX.get(hash_name)
    if prefix is None:
        raise ValueError(f"Unsupported hash for PKCS#1 v1.5: {hash_name}")
    return prefix + digest


def _parse_asn1_length(data: bytes, offset: int) -> tuple[int, int]:
    """Parse an ASN.1 length field, returning (length, new_offset)."""
    if data[offset] < 0x80:
        return data[offset], offset + 1
    num_bytes = data[offset] & 0x7F
    length = 0
    for i in range(num_bytes):
        length = (length << 8) | data[offset + 1 + i]
    return length, offset + 1 + num_bytes


def _parse_asn1_integer(data: bytes, offset: int) -> tuple[int, int]:
    """Parse an ASN.1 INTEGER, returning (value, new_offset)."""
    if data[offset] != 0x02:
        raise InvalidTokenError("Expected ASN.1 INTEGER tag")
    length, offset = _parse_asn1_length(data, offset + 1)
    value = _bytes_to_int(data[offset:offset + length])
    return value, offset + length


def _parse_rsa_private_key_der(der: bytes) -> tuple[int, int]:
    """Parse an RSA private key in PKCS#8 or PKCS#1 DER format.

    Returns (n, d).
    """
    offset = 0
    # Outer SEQUENCE
    if der[offset] != 0x30:
        raise InvalidTokenError("Invalid DER: expected SEQUENCE")
    _, offset = _parse_asn1_length(der, offset + 1)

    # Both PKCS#1 and PKCS#8 start with version INTEGER(0)
    if der[offset] != 0x02:
        raise InvalidTokenError("Expected version INTEGER")
    version, offset = _parse_asn1_integer(der, offset)
    if version != 0:
        raise InvalidTokenError("Unexpected RSA key version")

    if der[offset] == 0x30:
        # PKCS#8: version(0) was read, next is AlgorithmIdentifier SEQUENCE
        # Skip AlgorithmIdentifier SEQUENCE
        alg_len, alg_data_offset = _parse_asn1_length(der, offset + 1)
        offset = alg_data_offset + alg_len
        # OCTET STRING containing the PKCS#1 RSAPrivateKey
        if der[offset] != 0x04:
            raise InvalidTokenError("Expected OCTET STRING in PKCS#8")
        oct_len, offset = _parse_asn1_length(der, offset + 1)
        return _parse_rsa_private_key_der(der[offset:offset + oct_len])
    elif der[offset] == 0x02:
        # PKCS#1: version(0) was read, next fields are n, e, d, ...
        n, offset = _parse_asn1_integer(der, offset)
        _e, offset = _parse_asn1_integer(der, offset)
        d, offset = _parse_asn1_integer(der, offset)
        return n, d

    raise InvalidTokenError("Unable to parse RSA private key")


def _parse_rsa_public_key_der(der: bytes) -> tuple[int, int]:
    """Parse an RSA public key in SubjectPublicKeyInfo or PKCS#1 DER format.

    Returns (n, e).
    """
    offset = 0
    if der[offset] != 0x30:
        raise InvalidTokenError("Invalid DER: expected SEQUENCE")
    _, offset = _parse_asn1_length(der, offset + 1)

    if der[offset] == 0x30:
        # SubjectPublicKeyInfo: SEQUENCE { SEQUENCE(algId), BIT STRING(key) }
        # Skip AlgorithmIdentifier
        _, alg_start = _parse_asn1_length(der, offset + 1)
        alg_len = alg_start - (offset + 1)
        # Actually recalculate properly
        inner_offset = offset + 1
        alg_len, inner_offset = _parse_asn1_length(der, inner_offset)
        inner_offset = inner_offset + alg_len
        # BIT STRING
        if der[inner_offset] != 0x03:
            raise InvalidTokenError("Expected BIT STRING in public key")
        bs_len, inner_offset = _parse_asn1_length(der, inner_offset + 1)
        # Skip the unused-bits byte
        inner_offset += 1
        # Now we have the inner PKCS#1 RSAPublicKey
        return _parse_rsa_public_key_der(der[inner_offset:inner_offset + bs_len - 1])
    elif der[offset] == 0x02:
        # PKCS#1 RSAPublicKey: SEQUENCE { INTEGER(n), INTEGER(e) }
        n, offset = _parse_asn1_integer(der, offset)
        e, offset = _parse_asn1_integer(der, offset)
        return n, e

    raise InvalidTokenError("Unable to parse RSA public key")


def _decode_pem(pem: str) -> bytes:
    """Decode a PEM-encoded key to raw DER bytes."""
    lines = pem.strip().splitlines()
    # Remove header/footer lines
    b64_lines = [line for line in lines if not line.startswith("-----")]
    return base64.b64decode("".join(b64_lines))


class JWKSet:
    """A set of JSON Web Keys for key management.

    Stores named keys (HMAC secrets or RSA PEM key pairs) and retrieves
    them by key ID (``kid``). Token headers include a ``kid`` field so
    the correct key can be selected during verification.
    """

    def __init__(self) -> None:
        self._keys: dict[str, dict[str, Any]] = {}

    def add_hmac_key(self, kid: str, secret: str, algorithm: str = "HS256") -> None:
        """Register an HMAC key.

        Args:
            kid: Key identifier included in token headers.
            secret: Shared secret for signing and verification.
            algorithm: HMAC algorithm (HS256, HS384, or HS512).

        Raises:
            ValueError: If the algorithm is not a supported HMAC algorithm.
        """
        if algorithm not in _HMAC_ALGORITHMS:
            raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")
        self._keys[kid] = {"kty": "oct", "secret": secret, "alg": algorithm}

    def add_rsa_key(
        self,
        kid: str,
        private_pem: str | None = None,
        public_pem: str | None = None,
        algorithm: str = "RS256",
    ) -> None:
        """Register an RSA key pair (or public key only for verification).

        Args:
            kid: Key identifier included in token headers.
            private_pem: PEM-encoded RSA private key for signing.
            public_pem: PEM-encoded RSA public key for verification.
            algorithm: RSA algorithm (RS256).

        Raises:
            ValueError: If the algorithm is not a supported RSA algorithm
                or neither key is provided.
        """
        if algorithm not in _RSA_ALGORITHMS:
            raise ValueError(f"Unsupported RSA algorithm: {algorithm}")
        if private_pem is None and public_pem is None:
            raise ValueError("At least one of private_pem or public_pem is required")
        self._keys[kid] = {
            "kty": "RSA",
            "private_pem": private_pem,
            "public_pem": public_pem,
            "alg": algorithm,
        }

    def get_key(self, kid: str) -> dict[str, Any]:
        """Retrieve a key entry by its identifier.

        Args:
            kid: The key identifier to look up.

        Returns:
            A dictionary with key material and metadata.

        Raises:
            InvalidTokenError: If the key ID is not found.
        """
        if kid not in self._keys:
            raise InvalidTokenError(f"Unknown key ID: {kid}")
        return self._keys[kid]

    @property
    def key_ids(self) -> list[str]:
        """Return all registered key identifiers."""
        return list(self._keys.keys())

    def create_token(
        self,
        payload: dict[str, object],
        kid: str,
        expires_in: int | float | None = None,
        include_jti: bool = False,
    ) -> str:
        """Create a signed JWT using a key from this set.

        The key's algorithm is used automatically. The ``kid`` is embedded
        in the token header for verification lookup.

        Args:
            payload: Claims to include in the token.
            kid: Key identifier to use for signing.
            expires_in: Optional expiration time in seconds from now.
            include_jti: If True, adds a ``jti`` claim with a UUID4 value.

        Returns:
            A signed JWT string.

        Raises:
            InvalidTokenError: If the key ID is not found.
            ValueError: If the key lacks signing material.
        """
        key_entry = self.get_key(kid)
        algorithm = str(key_entry["alg"])
        payload = {**payload}

        if include_jti:
            payload["jti"] = str(uuid.uuid4())

        if expires_in is not None:
            payload["exp"] = time.time() + expires_in

        header: dict[str, str] = {"alg": algorithm, "typ": "JWT", "kid": kid}
        header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{header_b64}.{payload_b64}"

        if key_entry["kty"] == "oct":
            secret: str = key_entry["secret"]
            signature = hmac.new(
                secret.encode(),
                signing_input.encode(),
                _HMAC_ALGORITHMS[algorithm],
            ).digest()
        elif key_entry["kty"] == "RSA":
            private_pem = key_entry.get("private_pem")
            if private_pem is None:
                raise ValueError("Private key required for signing")
            private_der = _decode_pem(private_pem)
            hash_name = _RSA_ALGORITHMS[algorithm]
            signature = _pkcs1v15_sign(signing_input.encode(), private_der, hash_name)
        else:
            raise ValueError(f"Unsupported key type: {key_entry['kty']}")

        return f"{signing_input}.{_b64url_encode(signature)}"

    def verify_token(
        self,
        token: str,
        validators: dict[str, Callable[[Any], bool]] | None = None,
        is_revoked: Callable[[str], bool] | None = None,
    ) -> dict[str, object]:
        """Verify a JWT using the ``kid`` in its header to find the key.

        Args:
            token: The JWT string to verify.
            validators: Optional claim validators (see :func:`verify_token`).
            is_revoked: Optional revocation checker (see :func:`verify_token`).

        Returns:
            The decoded payload as a dictionary.

        Raises:
            InvalidTokenError: If the token is malformed, has an unknown kid,
                or the signature is invalid.
            ExpiredTokenError: If the token has expired.
            TokenRevokedError: If the token has been revoked.
        """
        header = decode_header(token)
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise InvalidTokenError("Token header missing 'kid' field")

        key_entry = self.get_key(kid)
        algorithm = str(key_entry["alg"])

        parts = token.split(".")
        if len(parts) != 3:
            raise InvalidTokenError("Token must have three parts")

        header_b64, payload_b64, signature_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}"
        actual_signature = _b64url_decode(signature_b64)

        if key_entry["kty"] == "oct":
            secret_str: str = key_entry["secret"]
            expected_sig = hmac.new(
                secret_str.encode(),
                signing_input.encode(),
                _HMAC_ALGORITHMS[algorithm],
            ).digest()
            if not hmac.compare_digest(expected_sig, actual_signature):
                raise InvalidTokenError("Invalid signature")
        elif key_entry["kty"] == "RSA":
            public_pem = key_entry.get("public_pem") or key_entry.get("private_pem")
            if public_pem is None:
                raise InvalidTokenError("No public key available for verification")
            public_der = _decode_pem(public_pem)
            hash_name = _RSA_ALGORITHMS[algorithm]
            # If we have a private PEM but no public PEM, we need the public key
            # For private keys, we extract n and e differently
            if key_entry.get("public_pem") is not None:
                if not _pkcs1v15_verify(signing_input.encode(), actual_signature, public_der, hash_name):
                    raise InvalidTokenError("Invalid signature")
            else:
                # Extract public components from private key for verification
                n, _d = _parse_rsa_private_key_der(public_der)
                # Re-parse to get e as well
                priv_der = public_der
                offset = 0
                if priv_der[offset] != 0x30:
                    raise InvalidTokenError("Invalid DER")
                _, offset = _parse_asn1_length(priv_der, offset + 1)
                if priv_der[offset] == 0x02:
                    _ver, offset = _parse_asn1_integer(priv_der, offset)
                    n2, offset = _parse_asn1_integer(priv_der, offset)
                    e2, offset = _parse_asn1_integer(priv_der, offset)
                    d2, _offset = _parse_asn1_integer(priv_der, offset)
                    # Verify using public components
                    k = (n2.bit_length() + 7) // 8
                    if len(actual_signature) != k:
                        raise InvalidTokenError("Invalid signature")
                    s_int = _bytes_to_int(actual_signature)
                    m_int = pow(s_int, e2, n2)
                    em = m_int.to_bytes(k, byteorder="big")
                    h = hashlib.new(hash_name, signing_input.encode()).digest()
                    di = _pkcs1v15_digest_info(hash_name, h)
                    expected_em = b"\x00\x01" + (b"\xff" * (k - len(di) - 3)) + b"\x00" + di
                    if not hmac.compare_digest(em, expected_em):
                        raise InvalidTokenError("Invalid signature")
                else:
                    raise InvalidTokenError("Cannot extract public key from private key")
        else:
            raise InvalidTokenError(f"Unsupported key type: {key_entry['kty']}")

        payload_data: dict[str, object] = json.loads(_b64url_decode(payload_b64))

        exp = payload_data.get("exp")
        if exp is not None and isinstance(exp, (int, float)) and exp < time.time():
            raise ExpiredTokenError("Token has expired")

        if is_revoked is not None:
            jti = payload_data.get("jti")
            if isinstance(jti, str) and is_revoked(jti):
                raise TokenRevokedError("Token has been revoked")

        if validators is not None:
            for claim_name, validator_fn in validators.items():
                claim_value = payload_data.get(claim_name)
                if claim_value is None:
                    raise ClaimValidationError(
                        f"Missing required claim: {claim_name}"
                    )
                if not validator_fn(claim_value):
                    raise ClaimValidationError(
                        f"Validation failed for claim: {claim_name}"
                    )

        return payload_data


def create_token(
    payload: dict[str, object],
    secret: str | bytes,
    algorithm: str = "HS256",
    expires_in: int | float | None = None,
    include_jti: bool = False,
) -> str:
    """Create a signed JWT token.

    Args:
        payload: Claims to include in the token.
        secret: Shared secret for HMAC signing, or a PEM-encoded RSA
            private key for RSA algorithms.
        algorithm: Signing algorithm (HS256, HS384, HS512, or RS256).
        expires_in: Optional expiration time in seconds from now.
        include_jti: If True, automatically adds a ``jti`` claim with a UUID4 value.

    Returns:
        A signed JWT string.

    Raises:
        ValueError: If the algorithm is not supported.
    """
    if algorithm not in _ALL_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    header: dict[str, str] = {"alg": algorithm, "typ": "JWT"}
    payload = {**payload}

    if include_jti:
        payload["jti"] = str(uuid.uuid4())

    if expires_in is not None:
        payload["exp"] = time.time() + expires_in

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    signing_input = f"{header_b64}.{payload_b64}"

    if algorithm in _HMAC_ALGORITHMS:
        secret_bytes = secret.encode() if isinstance(secret, str) else secret
        signature = hmac.new(
            secret_bytes,
            signing_input.encode(),
            _HMAC_ALGORITHMS[algorithm],
        ).digest()
    elif algorithm in _RSA_ALGORITHMS:
        pem = secret if isinstance(secret, str) else secret.decode()
        private_der = _decode_pem(pem)
        hash_name = _RSA_ALGORITHMS[algorithm]
        signature = _pkcs1v15_sign(signing_input.encode(), private_der, hash_name)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    signature_b64 = _b64url_encode(signature)
    return f"{signing_input}.{signature_b64}"


def verify_token(
    token: str,
    secret: str | bytes,
    algorithm: str = "HS256",
    validators: dict[str, Callable[[Any], bool]] | None = None,
    is_revoked: Callable[[str], bool] | None = None,
) -> dict[str, object]:
    """Verify a JWT token's signature and expiration.

    Args:
        token: The JWT string to verify.
        secret: Shared secret for HMAC verification, or a PEM-encoded RSA
            public key for RSA algorithms.
        algorithm: Expected signing algorithm.
        validators: Optional mapping of claim names to validator functions.
            Each function receives the claim value and must return True for
            the token to be considered valid.
        is_revoked: Optional callable that receives a ``jti`` string and returns
            True if the token has been revoked.

    Returns:
        The decoded payload as a dictionary.

    Raises:
        InvalidTokenError: If the token is malformed or the signature is invalid.
        ExpiredTokenError: If the token has expired.
        TokenRevokedError: If the token has been revoked according to ``is_revoked``.
        ClaimValidationError: If any custom validator fails.
        ValueError: If the algorithm is not supported.
    """
    if algorithm not in _ALL_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidTokenError("Token must have three parts")

    header_b64, payload_b64, signature_b64 = parts

    signing_input = f"{header_b64}.{payload_b64}"
    actual_signature = _b64url_decode(signature_b64)

    if algorithm in _HMAC_ALGORITHMS:
        secret_bytes = secret.encode() if isinstance(secret, str) else secret
        expected_signature = hmac.new(
            secret_bytes,
            signing_input.encode(),
            _HMAC_ALGORITHMS[algorithm],
        ).digest()
        if not hmac.compare_digest(expected_signature, actual_signature):
            raise InvalidTokenError("Invalid signature")
    elif algorithm in _RSA_ALGORITHMS:
        pem = secret if isinstance(secret, str) else secret.decode()
        public_der = _decode_pem(pem)
        hash_name = _RSA_ALGORITHMS[algorithm]
        if not _pkcs1v15_verify(signing_input.encode(), actual_signature, public_der, hash_name):
            raise InvalidTokenError("Invalid signature")
    else:
        raise InvalidTokenError(f"Unsupported algorithm: {algorithm}")

    payload: dict[str, object] = json.loads(_b64url_decode(payload_b64))

    exp = payload.get("exp")
    if exp is not None and isinstance(exp, (int, float)) and exp < time.time():
        raise ExpiredTokenError("Token has expired")

    if is_revoked is not None:
        jti = payload.get("jti")
        if isinstance(jti, str) and is_revoked(jti):
            raise TokenRevokedError("Token has been revoked")

    if validators is not None:
        for claim_name, validator_fn in validators.items():
            claim_value = payload.get(claim_name)
            if claim_value is None:
                raise ClaimValidationError(
                    f"Missing required claim: {claim_name}"
                )
            if not validator_fn(claim_value):
                raise ClaimValidationError(
                    f"Validation failed for claim: {claim_name}"
                )

    return payload


def refresh_token(
    token: str,
    secret: str | bytes,
    extends_by: int = 3600,
    algorithm: str = "HS256",
) -> str:
    """Refresh a JWT token by re-signing with a new expiration time.

    The existing token is verified first, then a new token is created
    with the same payload but a fresh ``exp`` claim.

    Args:
        token: The JWT string to refresh.
        secret: Shared secret for HMAC signing, or PEM key for RSA.
        extends_by: New expiration time in seconds from now (default 3600).
        algorithm: Signing algorithm (HS256, HS384, HS512, or RS256).

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


def decode_header(token: str) -> dict[str, object]:
    """Decode a JWT token's header without verifying the signature.

    Useful for inspecting the algorithm or key ID before selecting
    a verification key.

    Args:
        token: The JWT string to inspect.

    Returns:
        The decoded header as a dictionary.

    Raises:
        InvalidTokenError: If the token is malformed.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidTokenError("Token must have three parts")

    try:
        header: dict[str, object] = json.loads(_b64url_decode(parts[0]))
    except (json.JSONDecodeError, Exception) as exc:
        raise InvalidTokenError("Invalid header") from exc

    return header


def decode_unverified(token: str) -> tuple[dict[str, object], dict[str, object]]:
    """Decode a JWT token's header and payload without signature validation.

    Useful for inspecting token contents during debugging. The signature
    is **not** checked, so the returned data must not be trusted for
    authorization decisions.

    Args:
        token: The JWT string to decode.

    Returns:
        A tuple of ``(header, payload)`` dictionaries.

    Raises:
        InvalidTokenError: If the token is malformed.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidTokenError("Token must have three parts")

    try:
        header: dict[str, object] = json.loads(_b64url_decode(parts[0]))
        payload: dict[str, object] = json.loads(_b64url_decode(parts[1]))
    except (json.JSONDecodeError, Exception) as exc:
        raise InvalidTokenError("Invalid token") from exc

    return header, payload
