"""Bearer-token authentication for gateway endpoints.

Constant-time comparison via `hmac.compare_digest` defends against timing
oracles. Errors carry no token content.
"""

from __future__ import annotations

import hmac
from typing import TYPE_CHECKING

from .errors import AuthError

if TYPE_CHECKING:
    from .profile import Profile


def verify_bearer(authorization_header: str | None, profile: Profile) -> None:
    """Verify the Authorization header against the profile's resolved bearer token.

    The header must use the `Bearer` scheme (case-insensitive). The presented
    token is compared in constant time against the profile's resolved token,
    which the loader set at startup from the env var named in the profile.

    Args:
        authorization_header: Raw value of the request `Authorization` header,
            or None if the header is absent.
        profile: The profile being accessed.

    Raises:
        AuthError: header missing, malformed, profile token not resolved, or
            token mismatch. Caller maps this to HTTP 401.
    """
    if not authorization_header:
        raise AuthError("missing authorization")

    scheme, _, presented = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not presented:
        raise AuthError("malformed authorization")

    if profile.auth.bearer_token is None:
        raise AuthError("profile token not resolved")

    expected = profile.auth.bearer_token.get_secret_value()
    if not hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8")):
        raise AuthError("invalid token")
