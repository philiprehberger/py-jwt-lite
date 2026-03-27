# philiprehberger-jwt-lite

[![Tests](https://github.com/philiprehberger/py-jwt-lite/actions/workflows/publish.yml/badge.svg)](https://github.com/philiprehberger/py-jwt-lite/actions/workflows/publish.yml)
[![PyPI version](https://img.shields.io/pypi/v/philiprehberger-jwt-lite.svg)](https://pypi.org/project/philiprehberger-jwt-lite/)
[![License](https://img.shields.io/github/license/philiprehberger/py-jwt-lite)](LICENSE)
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

### Decode Without Verification

```python
from philiprehberger_jwt_lite import decode_token

payload = decode_token(token)
```

## API

| Function / Class | Description |
|------------------|-------------|
| `create_token(payload, secret, algorithm, expires_in)` | Create a signed JWT token |
| `verify_token(token, secret, algorithm)` | Verify signature and expiration, return payload |
| `decode_token(token)` | Decode payload without signature verification |
| `ExpiredTokenError` | Raised when a token's exp claim is in the past |
| `InvalidTokenError` | Raised when a token is malformed or signature is invalid |

## Development

```bash
pip install -e .
python -m pytest tests/ -v
```

## License

MIT
