"""Tests for gateway/auth.py — bearer-token verification."""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from mcp_airlock_crunchtools.gateway.auth import verify_bearer
from mcp_airlock_crunchtools.gateway.errors import AuthError
from mcp_airlock_crunchtools.gateway.profile import AuthConfig, Profile


def _profile_with_token(value: str) -> Profile:
    """Build a Profile with a pre-resolved bearer token for test convenience."""
    p = Profile(name="t", auth=AuthConfig(bearer_token_env="TEST"))
    p.auth.bearer_token = SecretStr(value)
    return p


class TestVerifyBearer:
    """Bearer-token verification covers the full set of failure paths."""

    def test_valid_token_passes(self) -> None:
        p = _profile_with_token("good-token")
        verify_bearer("Bearer good-token", p)

    def test_missing_header_rejected(self) -> None:
        p = _profile_with_token("good-token")
        with pytest.raises(AuthError, match="missing"):
            verify_bearer(None, p)
        with pytest.raises(AuthError, match="missing"):
            verify_bearer("", p)

    def test_malformed_no_scheme(self) -> None:
        p = _profile_with_token("good-token")
        with pytest.raises(AuthError, match="malformed"):
            verify_bearer("good-token", p)

    def test_malformed_wrong_scheme(self) -> None:
        p = _profile_with_token("good-token")
        with pytest.raises(AuthError, match="malformed"):
            verify_bearer("Basic abc123", p)

    def test_malformed_no_token(self) -> None:
        p = _profile_with_token("good-token")
        with pytest.raises(AuthError, match="malformed"):
            verify_bearer("Bearer ", p)

    def test_wrong_token_rejected(self) -> None:
        p = _profile_with_token("good-token")
        with pytest.raises(AuthError, match="invalid token"):
            verify_bearer("Bearer bad-token", p)

    def test_case_insensitive_scheme(self) -> None:
        p = _profile_with_token("good-token")
        verify_bearer("bearer good-token", p)
        verify_bearer("BEARER good-token", p)
        verify_bearer("BeArEr good-token", p)

    def test_unresolved_profile_token_rejected(self) -> None:
        """Loader normally guarantees this, but defense-in-depth."""
        p = Profile(name="t", auth=AuthConfig(bearer_token_env="TEST"))
        with pytest.raises(AuthError, match="not resolved"):
            verify_bearer("Bearer x", p)
