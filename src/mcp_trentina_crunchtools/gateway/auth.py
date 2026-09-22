"""Bearer-token authentication for gateway endpoints.

Constant-time comparison via `hmac.compare_digest` defends against timing
oracles. Errors carry no token content.
"""

from __future__ import annotations

import hmac
from typing import TYPE_CHECKING, Any

from .errors import AuthError, OAuthChallengeError, OAuthForbiddenError

if TYPE_CHECKING:
    from .profile import Profile


def _email_verified(value: Any) -> bool:
    """Google reports ``email_verified`` as a bool or the string ``"true"``.

    Treat only an explicit affirmative as verified; a missing or falsey value
    is unverified, because an unverified email is not an identity we allowlist.
    """
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


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

    # Two distinct faults, kept distinct: an OAuth-only profile never had a
    # static token (0.15.0), while a declared one that did not resolve is a
    # misconfiguration the loader should already have refused.
    if profile.auth is None:
        raise AuthError("profile has no static bearer token")

    if profile.auth.bearer_token is None:
        raise AuthError("profile token not resolved")

    expected = profile.auth.bearer_token.get_secret_value()
    if not hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8")):
        raise AuthError("invalid token")


async def verify_oauth(
    authorization_header: str | None,
    profile: Profile,
    verifier: Any,
) -> Any:
    """Verify an OAuth bearer for an OAuth-enabled profile, and return it.

    One code path serves both modes, because both expose the same
    ``async verify_token(token) -> AccessToken | None``. In PROXY mode the
    presented token is a FastMCP-issued reference token and fastmcp's
    ``OAuthProvider.verify_token`` forwards to ``load_access_token``, which
    swaps it for the stored upstream Google token and re-validates that live
    against Google. In DELEGATED mode the token was minted by the external
    issuer itself and the verifier checks it there. Either way a revoked or
    expired session fails here, not just at issue time, and the verified
    identity's email is matched against the profile allowlist.

    Args:
        authorization_header: Raw ``Authorization`` header value, or None.
        profile: The OAuth-enabled profile being accessed.
        verifier: The thing that validates tokens for this profile — the
            gateway's proxy provider, a delegated verifier, or None if the
            gateway came up without either (a config error for an enabled
            profile).

    Returns:
        The verified access token, so the caller can audit-log the identity.

    Raises:
        OAuthChallengeError: no provider, or no usable token — caller returns
            401 with a ``WWW-Authenticate`` challenge so the client discovers
            the flow.
        OAuthForbiddenError: token valid but the email is absent, unverified,
            or not on ``profile.oauth.allowed_emails`` — caller returns 403.
    """
    if verifier is None:
        # An enabled profile with no verifier means the gateway failed to build
        # one (missing client credentials). A challenge is pointless — there is
        # no authorization server to discover — but it is the safe 401 default.
        raise OAuthChallengeError("oauth provider not configured")

    if profile.oauth is None or not profile.oauth.enabled:
        raise OAuthChallengeError("oauth not enabled for profile")

    if not authorization_header:
        raise OAuthChallengeError("missing authorization")

    scheme, _, presented = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not presented:
        raise OAuthChallengeError("malformed authorization")

    access = await verifier.verify_token(presented)
    if access is None:
        raise OAuthChallengeError("invalid or expired token")

    claims = access.claims or {}
    email = claims.get("email")
    if not email or not _email_verified(claims.get("email_verified")):
        raise OAuthForbiddenError("token has no verified email")

    if email.strip().lower() not in profile.oauth.allowed_emails:
        raise OAuthForbiddenError("email not permitted for profile")

    return access


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
        if profile.auth is None or profile.auth.bearer_token is None:
            continue
        expected = profile.auth.bearer_token.get_secret_value().encode("utf-8")
        if hmac.compare_digest(presented_bytes, expected) and match is None:
            match = profile
    return match
