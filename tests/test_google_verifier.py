"""Delegated-mode token verification against Google (RT #1502).

The security properties under test are the audience pin, and the rule that a
rejection Google pronounced is cached while an outage is not. Everything runs
against a MockTransport; nothing here touches the network.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx2
import pytest

from mcp_trentina_crunchtools.gateway.google_verifier import (
    REJECTION_CACHE_MAX,
    REJECTION_TTL_SECONDS,
    GoogleTokeninfoVerifier,
    token_digest,
)

if TYPE_CHECKING:
    from collections.abc import Callable

AUDIENCE = "375f3fdb-c322-41bc-8dc6-c2010a095f04.apps.googleusercontent.com"
OTHER_AUDIENCE = "999999-someone-elses-app.apps.googleusercontent.com"


def _tokeninfo_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "aud": AUDIENCE,
        "sub": "114597764404176971057",
        "email": "alice@example.com",
        # Google returns this as a STRING, not a bool. Pinned deliberately.
        "email_verified": "true",
        "expires_in": 3599,
        "scope": "openid https://www.googleapis.com/auth/userinfo.email",
    }
    body.update(overrides)
    return body


class _Recorder:
    """Counts tokeninfo calls and records the paths hit."""

    def __init__(self, handler: Callable[[httpx2.Request], httpx2.Response]) -> None:
        self._handler = handler
        self.calls = 0
        self.paths: list[str] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.calls += 1
        self.paths.append(request.url.path)
        return self._handler(request)


def _verifier(
    handler: Callable[[httpx2.Request], httpx2.Response],
) -> tuple[GoogleTokeninfoVerifier, _Recorder]:
    recorder = _Recorder(handler)
    client = httpx2.AsyncClient(transport=httpx2.MockTransport(recorder))
    verifier = GoogleTokeninfoVerifier(audience=AUDIENCE, profile_name="gemini-app", client=client)
    return verifier, recorder


def _ok(**overrides: Any) -> Callable[[httpx2.Request], httpx2.Response]:
    def handler(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json=_tokeninfo_body(**overrides))

    return handler


def _status(code: int) -> Callable[[httpx2.Request], httpx2.Response]:
    def handler(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(code, json={"error": "invalid_token"})

    return handler


class TestAudiencePin:
    """The audience is the security boundary, not a formality."""

    async def test_matching_audience_verifies(self) -> None:
        verifier, _ = _verifier(_ok())
        access = await verifier.verify_token("good-token")
        assert access is not None
        assert access.claims["email"] == "alice@example.com"
        assert access.claims["aud"] == AUDIENCE

    async def test_other_apps_token_is_refused_despite_a_good_email(self) -> None:
        """A token from someone else's OAuth app carries an equally verified
        email, so the allowlist alone would let it through."""
        verifier, _ = _verifier(_ok(aud=OTHER_AUDIENCE))
        assert await verifier.verify_token("substituted") is None

    async def test_missing_audience_is_refused(self) -> None:
        verifier, _ = _verifier(_ok(aud=None))
        assert await verifier.verify_token("no-aud") is None

    def test_constructing_without_an_audience_is_refused(self) -> None:
        with pytest.raises(ValueError, match="requires an audience"):
            GoogleTokeninfoVerifier(audience="", profile_name="gemini-app")


class TestClaimHandling:
    async def test_email_verified_arrives_as_the_string_true(self) -> None:
        """Google's wire form. gateway/auth.py._email_verified accepts it."""
        verifier, _ = _verifier(_ok())
        access = await verifier.verify_token("t")
        assert access is not None
        assert access.claims["email_verified"] == "true"

    async def test_expired_token_is_refused(self) -> None:
        verifier, _ = _verifier(_ok(expires_in=0))
        assert await verifier.verify_token("stale") is None

    async def test_unparseable_expiry_is_refused(self) -> None:
        verifier, _ = _verifier(_ok(expires_in="soon"))
        assert await verifier.verify_token("weird") is None

    async def test_missing_email_is_refused(self) -> None:
        verifier, _ = _verifier(_ok(email=None))
        assert await verifier.verify_token("anon") is None

    async def test_missing_sub_is_refused(self) -> None:
        verifier, _ = _verifier(_ok(sub=None))
        assert await verifier.verify_token("nosub") is None

    async def test_userinfo_is_never_called(self) -> None:
        """tokeninfo carries everything the decision needs; a second call would
        double latency and hand the bearer to another endpoint."""
        verifier, recorder = _verifier(_ok())
        await verifier.verify_token("t")
        assert recorder.calls == 1
        assert not any("userinfo" in path for path in recorder.paths)


class TestRejectionCache:
    """Rejections are cached; outages are not."""

    async def test_rejection_is_verified_once(self) -> None:
        verifier, recorder = _verifier(_status(400))
        assert await verifier.verify_token("bad") is None
        assert await verifier.verify_token("bad") is None
        assert recorder.calls == 1

    async def test_rejection_expires(self, monkeypatch: pytest.MonkeyPatch) -> None:
        verifier, recorder = _verifier(_status(400))
        assert await verifier.verify_token("bad") is None

        import mcp_trentina_crunchtools.gateway.google_verifier as mod

        real = mod.time.monotonic
        monkeypatch.setattr(mod.time, "monotonic", lambda: real() + REJECTION_TTL_SECONDS + 1)
        assert await verifier.verify_token("bad") is None
        assert recorder.calls == 2

    async def test_google_5xx_is_not_cached(self) -> None:
        """Caching an outage would turn a Google hiccup into a lockout."""
        verifier, recorder = _verifier(_status(503))
        assert await verifier.verify_token("valid-but-unverifiable") is None
        assert await verifier.verify_token("valid-but-unverifiable") is None
        assert recorder.calls == 2

    async def test_transport_error_is_not_cached(self) -> None:
        def boom(_request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("dns is having a day")

        verifier, recorder = _verifier(boom)
        assert await verifier.verify_token("t") is None
        assert await verifier.verify_token("t") is None
        assert recorder.calls == 2

    async def test_unparseable_200_is_not_cached(self) -> None:
        """A 200 that is not JSON is Google misbehaving, not a verdict."""

        def garbage(_request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(200, content=b"<html>nope</html>")

        verifier, recorder = _verifier(garbage)
        assert await verifier.verify_token("t") is None
        assert await verifier.verify_token("t") is None
        assert recorder.calls == 2

    async def test_a_valid_token_is_never_cached(self) -> None:
        """No positive cache: revocation must take effect on the next request."""
        verifier, recorder = _verifier(_ok())
        await verifier.verify_token("good")
        await verifier.verify_token("good")
        assert recorder.calls == 2

    async def test_cache_is_bounded(self) -> None:
        verifier, _ = _verifier(_status(400))
        for i in range(REJECTION_CACHE_MAX + 25):
            await verifier.verify_token(f"bad-{i}")
        assert len(verifier._rejected) <= REJECTION_CACHE_MAX

    async def test_wrong_audience_rejection_is_cached(self) -> None:
        """Our own refusal is as final as Google's — cache it too."""
        verifier, recorder = _verifier(_ok(aud=OTHER_AUDIENCE))
        assert await verifier.verify_token("substituted") is None
        assert await verifier.verify_token("substituted") is None
        assert recorder.calls == 1


class TestTokenDigest:
    def test_digest_does_not_contain_the_token(self) -> None:
        token = "ya29.super-secret-bearer-value"
        digest = token_digest(token)
        assert token not in digest
        assert len(digest) == 64

    async def test_no_cache_key_contains_the_raw_token(self) -> None:
        verifier, _ = _verifier(_status(400))
        token = "ya29.another-secret"
        await verifier.verify_token(token)
        assert all(token not in key for key in verifier._rejected)

    async def test_token_never_appears_in_logs(self, caplog: pytest.LogCaptureFixture) -> None:
        verifier, _ = _verifier(_status(400))
        token = "ya29.must-not-be-logged"
        with caplog.at_level("DEBUG"):
            await verifier.verify_token(token)
        assert token not in caplog.text
        assert token_digest(token)[:8] in caplog.text
