"""Config-driven LLM API reverse proxy.

Forwards requests from ``/llm/{provider}/{path}`` to the configured upstream
LLM provider, injecting the real API key.  Agents on the internal network
never hold provider credentials — Trentina is the choke point.

Adding a new provider is a YAML entry, not code::

    llm_providers:
      anthropic:
        enabled: true
        upstream: https://api.anthropic.com
        auth_header: x-api-key
        api_key_env: ANTHROPIC_API_KEY

Streaming (SSE) and non-streaming responses are forwarded transparently.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from starlette.responses import Response, StreamingResponse

from .auth import resolve_profile_by_token
from .errors import ProfileConfigError
from .proxy_utils import (
    PLAIN_TEXT,
    filter_response_headers,
    forward_request_headers,
    sanitize_proxy_path,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.requests import Request

    from .profile import Profile

logger = logging.getLogger(__name__)

_LLM_TIMEOUT = httpx.Timeout(
    connect=10.0, read=300.0, write=10.0, pool=5.0,
)

LLM_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]

_llm_client: httpx.AsyncClient | None = None


def _get_llm_client() -> httpx.AsyncClient:
    global _llm_client
    if _llm_client is None:
        _llm_client = httpx.AsyncClient(timeout=_LLM_TIMEOUT)
    return _llm_client


async def close_llm_client() -> None:
    """Close the LLM proxy httpx client. Called on application shutdown."""
    global _llm_client
    if _llm_client is not None:
        await _llm_client.aclose()
        _llm_client = None


class LlmProvider(BaseModel):
    """One LLM provider driver entry."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = Field(default=False)
    upstream: str = Field(
        ..., description="Provider base URL (https://...)",
    )
    auth_header: str = Field(
        ..., description="Header name for the API key",
    )
    auth_prefix: str = Field(
        default="", description="Prefix before the key value",
    )
    api_key_env: str = Field(
        ..., description="Env var holding the real API key",
    )
    api_key: SecretStr = Field(
        default=SecretStr(""),
        exclude=True,
        description="Resolved key (load-time)",
    )

    @field_validator("upstream")
    @classmethod
    def upstream_must_be_https(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError(
                f"upstream must start with https://: {v!r}",
            )
        return v.rstrip("/")


def load_llm_providers(
    llm_section: dict[str, Any],
) -> dict[str, LlmProvider]:
    """Parse LLM provider entries and resolve API keys.

    Accepts the ``llm_providers`` config section directly (not the full
    gateway config). Returns only enabled providers. Fails closed on a
    missing env var.
    """
    if not llm_section:
        logger.info("llm_proxy: no llm_providers — disabled")
        return {}

    providers: dict[str, LlmProvider] = {}
    for name, body in llm_section.items():
        if not isinstance(body, dict):
            raise ProfileConfigError(
                f"llm_providers.{name}: must be a mapping",
            )
        provider = LlmProvider(**body)
        if not provider.enabled:
            continue
        key = os.environ.get(provider.api_key_env, "")
        if not key:
            raise ProfileConfigError(
                f"llm_providers.{name}: env var "
                f"{provider.api_key_env} not set or empty",
            )
        provider.api_key = SecretStr(key)
        providers[name] = provider

    if providers:
        names = ", ".join(sorted(providers))
        logger.info(
            "llm_proxy: loaded %d provider(s): %s",
            len(providers), names,
        )
    return providers


def validate_profile_llm_keys(
    providers: dict[str, LlmProvider],
    profiles: dict[str, Profile],
) -> None:
    """Fail closed if any profile references an unconfigured LLM provider.

    A profile's ``llm_keys`` may only name providers that exist in the enabled
    ``llm_providers`` set — a dangling reference is an operator error we refuse
    to serve past.
    """
    for name, profile in profiles.items():
        for provider_name in profile.llm_keys:
            if provider_name not in providers:
                raise ProfileConfigError(
                    f"Profile {name!r} llm_keys references provider "
                    f"{provider_name!r}, which is not a configured/enabled "
                    "llm_providers entry"
                )


def register_llm_routes(
    mcp_server: Any,
    providers: dict[str, LlmProvider],
    profiles: dict[str, Profile],
) -> None:
    """Wire ``/llm/{provider}/{path:path}`` onto the FastMCP server.

    The endpoint authenticates each request against the caller's gateway
    bearer token (via ``profiles``) and injects that profile's provider key.
    """
    if not providers:
        return

    validate_profile_llm_keys(providers, profiles)

    async def llm_proxy_endpoint(request: Request) -> Response:
        return await _proxy_llm(request, providers, profiles)

    mcp_server.custom_route(
        "/llm/{provider}/{path:path}", methods=LLM_HTTP_METHODS,
    )(llm_proxy_endpoint)

    logger.info(
        "llm_proxy: registered /llm/{provider}/{path} "
        "for %d provider(s)", len(providers),
    )


async def _proxy_llm(
    request: Request,
    providers: dict[str, LlmProvider],
    profiles: dict[str, Profile],
) -> Response:
    """Forward one LLM request to the upstream provider.

    Authenticates against the caller's gateway bearer token, resolves the
    calling profile, and injects that profile's provider key. The caller's
    ``Authorization`` header is stripped before forwarding — ``forward_request_headers``
    keeps it (the Matrix proxy relies on that), so the token must be dropped here.
    """
    provider_name = request.path_params.get("provider", "")
    raw_path = request.path_params.get("path", "")

    provider = providers.get(provider_name)
    if provider is None:
        return Response(
            content="LLM provider not found or disabled",
            status_code=404, media_type=PLAIN_TEXT,
        )

    profile = resolve_profile_by_token(
        request.headers.get("authorization"), profiles
    )
    if profile is None:
        return Response(
            content="Unauthorized",
            status_code=401, media_type=PLAIN_TEXT,
        )

    override = profile.llm_keys.get(provider_name)
    if override is None:
        logger.info(
            "llm_proxy: profile=%s has no key for provider=%s",
            profile.name, provider_name,
        )
        return Response(
            content="No API key configured for this provider",
            status_code=502, media_type=PLAIN_TEXT,
        )

    path = sanitize_proxy_path(raw_path)
    if path is None:
        return Response(
            content="Path traversal rejected",
            status_code=400, media_type=PLAIN_TEXT,
        )

    logger.info(
        "llm_proxy: profile=%s provider=%s path=%s",
        profile.name, provider_name, path,
    )

    upstream_url = f"{provider.upstream}/{path}"
    if request.url.query:
        upstream_url = f"{upstream_url}?{request.url.query}"

    fwd_headers = forward_request_headers(list(request.headers.items()))
    for header_name in [h for h in fwd_headers if h.lower() == "authorization"]:
        del fwd_headers[header_name]
    key_value = override.api_key.get_secret_value()
    fwd_headers[provider.auth_header] = (
        f"{provider.auth_prefix}{key_value}"
    )

    return await _forward_upstream(
        request, upstream_url, fwd_headers, provider_name,
    )


async def _forward_upstream(
    request: Request,
    upstream_url: str,
    fwd_headers: dict[str, str],
    provider_name: str,
) -> Response:
    """Send the (already-authorized, key-injected) request to the provider."""
    has_body = request.method in ("POST", "PUT", "PATCH")
    client = _get_llm_client()

    try:
        resp = await client.send(
            client.build_request(
                request.method, upstream_url,
                headers=fwd_headers,
                content=request.stream() if has_body else None,
            ),
            stream=True,
        )
    except httpx.TimeoutException:
        return Response(
            content="LLM upstream timeout",
            status_code=504, media_type=PLAIN_TEXT,
        )
    except httpx.ConnectError as exc:
        logger.warning(
            "llm_proxy: connect error provider=%s: %s",
            provider_name, exc,
        )
        return Response(
            content="LLM upstream unreachable",
            status_code=502, media_type=PLAIN_TEXT,
        )

    return _streaming_response(resp)


def _streaming_response(resp: httpx.Response) -> StreamingResponse:
    resp_headers = filter_response_headers(list(resp.headers.items()))

    async def stream_body() -> AsyncIterator[bytes]:
        try:
            async for chunk in resp.aiter_bytes():
                yield chunk
        finally:
            await resp.aclose()

    ct = resp.headers.get("content-type", "application/json")
    return StreamingResponse(
        stream_body(), status_code=resp.status_code,
        headers=resp_headers, media_type=ct,
    )
