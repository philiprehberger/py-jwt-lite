# Changelog

## 0.2.0 (2026-03-27)

- Add `validators` parameter to `verify_token()` for custom claims validation
- Add `refresh_token()` function to re-sign tokens with a new expiration
- Add 8 badges to README (tests, PyPI, release, last updated, license, bugs, features, sponsor)
- Add Support section to README
- Add `.github/` templates (bug report, feature request, PR template, dependabot)

## 0.1.0 (2026-03-21)

- Initial release
- JWT creation with HMAC signing (HS256, HS384, HS512)
- Token verification with signature and expiration checks
- Unverified payload decoding for inspection
- Zero dependencies — stdlib only
