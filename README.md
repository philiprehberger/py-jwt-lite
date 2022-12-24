# philiprehberger-jwt-lite

[![Tests](https://github.com/philiprehberger/py-jwt-lite/actions/workflows/publish.yml/badge.svg)](https://github.com/philiprehberger/py-jwt-lite/actions/workflows/publish.yml)
[![PyPI version](https://img.shields.io/pypi/v/philiprehberger-jwt-lite.svg)](https://pypi.org/project/philiprehberger-jwt-lite/)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/py-jwt-lite)](https://github.com/philiprehberger/py-jwt-lite/commits/main)

Minimal JWT creation and validation with zero dependencies.

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

### Custom Claims Validation

```python
from philiprehberger_jwt_lite import create_token, verify_token

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

### Decode Without Verification

```python
from philiprehberger_jwt_lite import decode_unverified

header, payload = decode_unverified(token)
print(header["alg"])  # "HS256"
```

## API

| Function / Class | Description |
|------------------|-------------|
| `create_token(payload, secret, algorithm, expires_in, include_jti)` | Create a signed JWT token |
| `verify_token(token, secret, algorithm, validators, is_revoked)` | Verify signature and expiration, run custom claim validators, return payload |
| `refresh_token(token, secret, extends_by, algorithm)` | Verify and re-sign a token with a new expiration |
| `decode_token(token)` | Decode payload without signature verification |
| `decode_unverified(token)` | Decode header and payload without signature validation |
| `ExpiredTokenError` | Raised when a token's exp claim is in the past |
| `InvalidTokenError` | Raised when a token is malformed or signature is invalid |
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
