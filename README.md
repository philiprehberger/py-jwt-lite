# philiprehberger-jwt-lite

[![Tests](https://github.com/philiprehberger/py-jwt-lite/actions/workflows/publish.yml/badge.svg)](https://github.com/philiprehberger/py-jwt-lite/actions/workflows/publish.yml)
[![PyPI version](https://img.shields.io/pypi/v/philiprehberger-jwt-lite.svg)](https://pypi.org/project/philiprehberger-jwt-lite/)
[![GitHub release](https://img.shields.io/github/v/release/philiprehberger/py-jwt-lite)](https://github.com/philiprehberger/py-jwt-lite/releases)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/py-jwt-lite)](https://github.com/philiprehberger/py-jwt-lite/commits/main)
[![License](https://img.shields.io/github/license/philiprehberger/py-jwt-lite)](LICENSE)
[![Bug Reports](https://img.shields.io/github/issues/philiprehberger/py-jwt-lite/bug)](https://github.com/philiprehberger/py-jwt-lite/issues?q=is%3Aissue+is%3Aopen+label%3Abug)
[![Feature Requests](https://img.shields.io/github/issues/philiprehberger/py-jwt-lite/enhancement)](https://github.com/philiprehberger/py-jwt-lite/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)
[![Sponsor](https://img.shields.io/badge/sponsor-GitHub%20Sponsors-ec6cb9)](https://github.com/sponsors/philiprehberger)

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

### Decode Without Verification

```python
from philiprehberger_jwt_lite import decode_token

payload = decode_token(token)
```

## API

| Function / Class | Description |
|------------------|-------------|
| `create_token(payload, secret, algorithm, expires_in)` | Create a signed JWT token |
| `verify_token(token, secret, algorithm, validators)` | Verify signature and expiration, run custom claim validators, return payload |
| `refresh_token(token, secret, extends_by, algorithm)` | Verify and re-sign a token with a new expiration |
| `decode_token(token)` | Decode payload without signature verification |
| `ExpiredTokenError` | Raised when a token's exp claim is in the past |
| `InvalidTokenError` | Raised when a token is malformed or signature is invalid |

## Development

```bash
pip install -e .
python -m pytest tests/ -v
```

## Support

If you find this package useful, consider starring the repository.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Philip%20Rehberger-blue?logo=linkedin)](https://www.linkedin.com/in/philiprehberger/)
[![More packages](https://img.shields.io/badge/More%20packages-philiprehberger-orange)](https://github.com/philiprehberger?tab=repositories)

## License

[MIT](LICENSE)
