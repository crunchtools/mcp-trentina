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


def resolve_profile_by_token(
    authorization_header: str | None, registry: dict[str, Profile]
) -> Profile | None:
    """Resolve which profile a bearer token belongs to, or None.

    Used by the LLM proxy, which — unlike the gateway routes — carries no
    profile in its URL. The presented token is compared in constant time
    against every profile's resolved bearer token; the first match wins.

    Constant-time comparison runs for every profile so a valid token cannot be
    distinguished from an invalid one by response timing. The number of
    profiles is not secret.

    Args:
        authorization_header: Raw `Authorization` header value, or None.
        registry: Loaded profile registry (name -> Profile).

    Returns:
        The matching Profile, or None if the header is missing, malformed, or
        matches no profile.
    """
    if not authorization_header:
        return None

    scheme, _, presented = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not presented:
        return None

    presented_bytes = presented.encode("utf-8")
    match: Profile | None = None
    for profile in registry.values():
        if profile.auth.bearer_token is None:
            continue
        expected = profile.auth.bearer_token.get_secret_value().encode("utf-8")
        if hmac.compare_digest(presented_bytes, expected):
            match = profile
    return match
