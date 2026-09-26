"""Delegated-mode token verification against Google's tokeninfo endpoint.

Used when a profile names ``https://accounts.google.com`` as its issuer: the
client authenticates straight to Google and hands us the token Google minted,
so Trentina is a pure resource server and never runs an authorization server
for that profile.

Why this exists instead of fastmcp's ``GoogleTokenVerifier``
------------------------------------------------------------
That class collapses every failure — a bad token, a Google 5xx, a JSON decode
error — into ``None`` at DEBUG. A negative cache built on top of it could not
tell a rejected token from an outage, so one Google hiccup would be cached as
"this token is bad" and lock the user out for the life of the entry. Telling
those two apart is a prerequisite for caching at all, not a nicety.

It also makes a second call to the userinfo endpoint whose data we never use.
The authorization decision needs ``email`` and ``email_verified``, and
tokeninfo returns both; the extra call doubles latency and sends the bearer to
a second endpoint for nothing.

The amplifier this cache exists to bound
----------------------------------------
Proxy mode verifies a FastMCP-minted JWT signature LOCALLY first, so a garbage
bearer costs nothing. Delegated mode has no local pre-check: without a cache,
any unauthenticated request carrying any bearer string buys a TLS handshake and
an outbound call to Google. Nothing in this gateway rate-limits, and Google's
tokeninfo is quota'd — so an attacker could exhaust the quota and lock out the
real user.

Only REJECTIONS are cached, and only rejections Google itself pronounced.
Caching a rejection cannot extend the life of any valid token, so revocation
still takes effect on the very next request; that is the whole reason the
positive side is absent rather than merely unimplemented.

Nothing here is ever persisted. The keys derive from live bearer tokens, and
the token is sent in a POST body rather than the query string Google
documents, because httpx logs request URLs at INFO.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx2

logger = logging.getLogger(__name__)

TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"

REJECTION_TTL_SECONDS = 60.0
"""How long a Google-pronounced rejection is remembered.

Short on purpose. It only has to outlive a retry storm; a token Google refuses
does not become valid, but one issued seconds later legitimately might.
"""

REJECTION_CACHE_MAX = 4096
"""Bound on remembered rejections, evicted least-recently-used.

The keys are attacker-controlled, so this cache must not be allowed to grow
with traffic.
"""

MAX_CONCURRENT_VERIFICATIONS = 8
"""Ceiling on simultaneous outbound calls to Google.

A burst of distinct unseen tokens defeats the cache by construction, so the
semaphore is what stops that burst becoming an equal burst against Google.
"""

VERIFY_TIMEOUT_SECONDS = 10.0


class _UnreachableError(Exception):
    """Google could not be asked. Distinct from Google saying no."""


def token_digest(token: str) -> str:
    """Stable, non-reversible handle for a bearer token.

    Used for cache keys and log lines so a raw token never reaches either.
    """
    return hashlib.sha256(token.encode()).hexdigest()


class GoogleTokeninfoVerifier:
    """Verify a Google-minted access token and report a verified identity.

    Satisfies the ``async verify_token(token) -> AccessToken | None`` shape the
    gateway's OAuth path already expects, so it is interchangeable with
    fastmcp's proxy provider at the call site.

    ``audience`` is the expected ``aud`` — the OAuth client ID the token was
    issued to — and is required. A Google access token verifies for ANY OAuth
    client, so without this pin the profile would accept a token minted for any
    app the allowlisted human has ever authorized, carrying the same verified
    email the allowlist checks.
    """

    def __init__(
        self,
        *,
        audience: str,
        profile_name: str,
        client: httpx2.AsyncClient | None = None,
    ) -> None:
        if not audience:
            raise ValueError(
                "GoogleTokeninfoVerifier requires an audience — an unpinned "
                "audience accepts tokens minted for any other OAuth client"
            )
        self.audience = audience
        self.profile_name = profile_name
        self._client = client
        self._rejected: OrderedDict[str, float] = OrderedDict()
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_VERIFICATIONS)

    # -- rejection cache ---------------------------------------------------

    def _rejected_recently(self, digest: str) -> bool:
        deadline = self._rejected.get(digest)
        if deadline is None:
            return False
        if time.monotonic() >= deadline:
            del self._rejected[digest]
            return False
        self._rejected.move_to_end(digest)
        return True

    def _remember_rejection(self, digest: str) -> None:
        self._rejected[digest] = time.monotonic() + REJECTION_TTL_SECONDS
        self._rejected.move_to_end(digest)
        while len(self._rejected) > REJECTION_CACHE_MAX:
            self._rejected.popitem(last=False)

    def reset_cache(self) -> None:
        """Forget every remembered rejection. Test hook."""
        self._rejected.clear()

    # -- verification ------------------------------------------------------

    async def _tokeninfo(self, token: str) -> dict[str, Any] | None:
        """Ask Google about a token.

        Returns the parsed response, or None when Google says the token is not
        valid. Raises :class:`_UnreachableError` when Google could not be asked —
        the caller must not cache that as a rejection.
        """
        import httpx2

        # POST with the token in the body, never GET with it in the query.
        # Google documents the query form, but httpx logs every request URL at
        # INFO, so a GET writes live bearer tokens into the journal the moment
        # anyone raises the log level. Verified: this endpoint accepts POST and
        # returns the identical JSON.
        client = self._client
        form = {"access_token": token}
        try:
            if client is None:
                async with httpx2.AsyncClient(
                    timeout=VERIFY_TIMEOUT_SECONDS
                ) as fresh:
                    response = await fresh.post(TOKENINFO_URL, data=form)
            else:
                response = await client.post(TOKENINFO_URL, data=form)
        except httpx2.RequestError as exc:
            raise _UnreachableError(str(exc)) from exc

        if response.status_code >= 500:
            raise _UnreachableError(f"tokeninfo returned {response.status_code}")
        if response.status_code != 200:
            return None
        try:
            parsed = response.json()
        except ValueError as exc:
            # A 200 that is not JSON is Google misbehaving, not a verdict on
            # the token. Treating it as a rejection would cache a Google fault.
            raise _UnreachableError(f"tokeninfo returned unparseable body: {exc}") from exc
        if not isinstance(parsed, dict):
            raise _UnreachableError("tokeninfo returned a non-object body")
        return parsed

    async def verify_token(self, token: str) -> Any | None:
        """Return an AccessToken for a valid token, else None.

        Every ``None`` here is a refusal. The distinction the cache needs —
        Google refused it versus Google could not be reached — is resolved
        inside this method, which is why the caller does not have to care.
        """
        from fastmcp.server.auth.auth import AccessToken

        digest = token_digest(token)
        if self._rejected_recently(digest):
            return None

        async with self._semaphore:
            try:
                tokeninfo = await self._tokeninfo(token)
            except _UnreachableError as exc:
                # Deliberately NOT cached: caching an outage turns a Google
                # hiccup into a lockout lasting REJECTION_TTL_SECONDS.
                logger.warning(
                    "gateway: could not verify token with Google for "
                    "profile=%s (token sha256=%s…): %s",
                    self.profile_name, digest[:8], exc,
                )
                return None

        if tokeninfo is None:
            self._refuse(digest, "google rejected the token")
            return None

        reason = self._reject_reason(tokeninfo)
        if reason is not None:
            self._refuse(digest, reason)
            return None

        scopes = str(tokeninfo.get("scope", "")).split()
        expires_at = self._expires_at(tokeninfo)
        return AccessToken(
            token=token,
            client_id=str(tokeninfo["sub"]),
            scopes=scopes,
            expires_at=expires_at,
            subject=str(tokeninfo["sub"]),
            claims={
                "sub": tokeninfo.get("sub"),
                "aud": tokeninfo.get("aud"),
                "email": tokeninfo.get("email"),
                "email_verified": tokeninfo.get("email_verified"),
                "iss": tokeninfo.get("iss"),
            },
        )

    def _refuse(self, digest: str, reason: str) -> None:
        """Remember a Google-pronounced rejection and say why, once."""
        self._remember_rejection(digest)
        logger.info(
            "gateway: delegated token refused profile=%s expected_aud=%s "
            "token sha256=%s… reason=%s",
            self.profile_name, self.audience, digest[:8], reason,
        )

    def _reject_reason(self, tokeninfo: dict[str, Any]) -> str | None:
        """Why this tokeninfo response is not an acceptable identity.

        ``aud`` is checked first because it is the boundary: the email in a
        token from someone else's OAuth app is just as verified as the email
        in one of ours.
        """
        checks: list[tuple[bool, str]] = [
            (not tokeninfo.get("aud"), "tokeninfo carried no aud"),
            (
                bool(tokeninfo.get("aud")) and tokeninfo.get("aud") != self.audience,
                "aud does not match the profile's configured audience",
            ),
            (not tokeninfo.get("sub"), "tokeninfo carried no sub"),
            (self._expired(tokeninfo), "token has expired or carries a bad expires_in"),
            (not tokeninfo.get("email"), "tokeninfo carried no email"),
        ]
        for failed, reason in checks:
            if failed:
                return reason
        return None

    @staticmethod
    def _expired(tokeninfo: dict[str, Any]) -> bool:
        """True when expires_in says the token is spent or is unreadable."""
        expires_in = tokeninfo.get("expires_in")
        if expires_in is None:
            return False
        try:
            return int(expires_in) <= 0
        except (TypeError, ValueError):
            return True

    @staticmethod
    def _expires_at(tokeninfo: dict[str, Any]) -> int | None:
        expires_in = tokeninfo.get("expires_in")
        if expires_in is None:
            return None
        try:
            return int(time.time()) + int(expires_in)
        except (TypeError, ValueError):
            return None
