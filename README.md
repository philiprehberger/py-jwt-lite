# philiprehberger-jwt-lite

[![Tests](https://github.com/philiprehberger/py-jwt-lite/actions/workflows/publish.yml/badge.svg)](https://github.com/philiprehberger/py-jwt-lite/actions/workflows/publish.yml)
[![PyPI version](https://img.shields.io/pypi/v/philiprehberger-jwt-lite.svg)](https://pypi.org/project/philiprehberger-jwt-lite/)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/py-jwt-lite)](https://github.com/philiprehberger/py-jwt-lite/commits/main)

Minimal JWT creation and validation with HMAC and RSA signing.

## Installation

```bash
pip install philiprehberger-jwt-lite
```

## Usage

```python
from philiprehberger_jwt_lite import create_token, verify_token

token = create_token({"sub": "user123"}, "my-secret")
payload = verify_token(token, "my-secret")
```

### Token Expiration

```python
from philiprehberger_jwt_lite import create_token, verify_token, ExpiredTokenError

token = create_token({"sub": "user123"}, "my-secret", expires_in=3600)

try:
    payload = verify_token(token, "my-secret")
except ExpiredTokenError:
    print("Token has expired")
```

### Custom Algorithm

```python
from philiprehberger_jwt_lite import create_token, verify_token

token = create_token({"sub": "user123"}, "my-secret", algorithm="HS512")
payload = verify_token(token, "my-secret", algorithm="HS512")
```

### RS256 (RSA) Signing

```python
from philiprehberger_jwt_lite import create_token, verify_token

token = create_token({"sub": "user123"}, private_pem, algorithm="RS256")
payload = verify_token(token, public_pem, algorithm="RS256")
```

### Custom Claims Validation

```python
from philiprehberger_jwt_lite import create_token, verify_token, ClaimValidationError

token = create_token({"sub": "user123", "role": "admin"}, "my-secret")

payload = verify_token(
    token,
    "my-secret",
    validators={"role": lambda r: r == "admin"},
)
```

### Token Refresh

```python
from philiprehberger_jwt_lite import create_token, refresh_token

token = create_token({"sub": "user123"}, "my-secret", expires_in=3600)
new_token = refresh_token(token, "my-secret", extends_by=7200)
```

### JTI Auto-Generation

```python
from philiprehberger_jwt_lite import create_token, decode_token

token = create_token({"sub": "user123"}, "my-secret", include_jti=True)
payload = decode_token(token)
print(payload["jti"])  # e.g. "a1b2c3d4-..."
```

### Token Revocation

```python
from philiprehberger_jwt_lite import create_token, verify_token, TokenRevokedError

revoked: set[str] = set()
token = create_token({"sub": "user123"}, "my-secret", include_jti=True)

# Later, revoke the token by its jti
# revoked.add(jti)

try:
    payload = verify_token(token, "my-secret", is_revoked=lambda jti: jti in revoked)
except TokenRevokedError:
    print("Token has been revoked")
```

### Decode Header

```python
from philiprehberger_jwt_lite import decode_header

header = decode_header(token)
print(header["alg"])  # "HS256"
```

### Decode Without Verification

```python
from philiprehberger_jwt_lite import decode_unverified

header, payload = decode_unverified(token)
print(header["alg"])  # "HS256"
```

### JWK Set Key Management

```python
from philiprehberger_jwt_lite import JWKSet

jwks = JWKSet()
jwks.add_hmac_key("hmac-1", "my-secret")
jwks.add_rsa_key("rsa-1", private_pem=priv, public_pem=pub)

token = jwks.create_token({"sub": "user123"}, "hmac-1", expires_in=3600)
payload = jwks.verify_token(token)
```

## API

| Function / Class | Description |
|------------------|-------------|
| `create_token(payload, secret, algorithm, expires_in, include_jti)` | Create a signed JWT token (HS256, HS384, HS512, RS256) |
| `verify_token(token, secret, algorithm, validators, is_revoked)` | Verify signature and expiration, run custom claim validators, return payload |
| `refresh_token(token, secret, extends_by, algorithm)` | Verify and re-sign a token with a new expiration |
| `decode_token(token)` | Decode payload without signature verification |
| `decode_header(token)` | Decode header without signature verification |
| `decode_unverified(token)` | Decode header and payload without signature validation |
| `JWKSet` | Key set for managing multiple named signing keys |
| `JWKSet.add_hmac_key(kid, secret, algorithm)` | Register an HMAC key in the set |
| `JWKSet.add_rsa_key(kid, private_pem, public_pem, algorithm)` | Register an RSA key pair in the set |
| `JWKSet.create_token(payload, kid, expires_in, include_jti)` | Create a token signed with a key from the set |
| `JWKSet.verify_token(token, validators, is_revoked)` | Verify a token using the kid in its header |
| `ExpiredTokenError` | Raised when a token's exp claim is in the past |
| `InvalidTokenError` | Raised when a token is malformed or signature is invalid |
| `ClaimValidationError` | Raised when a custom claim validator fails (subclass of InvalidTokenError) |
| `TokenRevokedError` | Raised when a token has been revoked |

## Development

```bash
pip install -e .
python -m pytest tests/ -v
```

## Support

If you find this project useful:

⭐ [Star the repo](https://github.com/philiprehberger/py-jwt-lite)

🐛 [Report issues](https://github.com/philiprehberger/py-jwt-lite/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

💡 [Suggest features](https://github.com/philiprehberger/py-jwt-lite/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)

❤️ [Sponsor development](https://github.com/sponsors/philiprehberger)

🌐 [All Open Source Projects](https://philiprehberger.com/open-source-packages)

💻 [GitHub Profile](https://github.com/philiprehberger)

🔗 [LinkedIn Profile](https://www.linkedin.com/in/philiprehberger)

## License

[MIT](LICENSE)
