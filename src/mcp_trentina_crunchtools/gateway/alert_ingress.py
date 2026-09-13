"""Alert webhook ingress for agent profiles.

Receives POST requests at ``/alert/{token}``, validates the token
against profile ``alert_ingress`` configurations (constant-time),
and forwards the JSON payload to the profile's ``forward_url``.

The token embedded in the URL is the sole authentication — no
headers required.  Designed for monitoring systems (Nagios, Zabbix)
that need to page an agent (Hermes/Kagetora) through Trentina.

Before forwarding, the payload runs through the same three-layer
defense used elsewhere: string leaves in the JSON are sanitized
(Layer 1), the sanitized content is classified (Layer 2), and — when
a Gemini API key is configured — the Q-Agent reviews it (Layer 3).
This closes the injection vector in Hermes's own webhook adapter,
which interpolates payload values into a live agent prompt with no
sanitization of its own. Flagged payloads are forwarded anyway (with
a ``_trentina_warning`` field attached) rather than blocked — this is
a paging pipeline, and silently dropping a real incident on a
classifier false positive is worse than forwarding a flagged one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx
from starlette.responses import Response

from ..defense import advise, defend_json
from ..sanitize.pipeline import risk_level_for_count

if TYPE_CHECKING:
    from starlette.requests import Request

    from .profile import Profile

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0)
_alert_client: httpx.AsyncClient | None = None


@dataclass
class _SanitizeCounts:
    """Aggregate L1 detection counts across every string leaf in a JSON payload."""

    detections: int = field(default=0)
    suspicious: int = field(default=0)


def _get_alert_client() -> httpx.AsyncClient:
    global _alert_client
    if _alert_client is None:
        _alert_client = httpx.AsyncClient(timeout=_TIMEOUT)
    return _alert_client


async def close_alert_client() -> None:
    """Shut down the httpx client.  Called on application shutdown."""
    global _alert_client
    if _alert_client is not None:
        await _alert_client.aclose()
        _alert_client = None


def _resolve_profile_by_alert_token(
    token: str, profiles: dict[str, Profile],
) -> Profile | None:
    token_bytes = token.encode("utf-8")
    match: Profile | None = None
    for profile in profiles.values():
        if profile.alert_ingress is None or profile.alert_ingress.token is None:
            continue
        expected = profile.alert_ingress.token.get_secret_value().encode("utf-8")
        if hmac.compare_digest(token_bytes, expected) and match is None:
            match = profile
    return match


def register_alert_routes(
    mcp_server: Any, profiles: dict[str, Profile],
) -> None:
    """Wire ``POST /alert/{token}`` onto the FastMCP server."""
    alert_profiles = [
        name for name, p in profiles.items() if p.alert_ingress is not None
    ]
    if not alert_profiles:
        logger.info("alert_ingress: no profiles configured, skipping")
        return

    async def alert_endpoint(request: Request) -> Response:
        return await _handle_alert(request, profiles)

    mcp_server.custom_route("/alert/{token}", methods=["POST"])(alert_endpoint)

    logger.info(
        "alert_ingress: registered /alert/{token} for %d profile(s): %s",
        len(alert_profiles), ", ".join(alert_profiles),
    )


async def _handle_alert(
    request: Request, profiles: dict[str, Profile],
) -> Response:
    token = request.path_params.get("token", "")
    if not token:
        return Response(
            content="missing token", status_code=400, media_type="text/plain",
        )

    profile = _resolve_profile_by_alert_token(token, profiles)
    if profile is None:
        return Response(
            content="unauthorized", status_code=401, media_type="text/plain",
        )

    assert profile.alert_ingress is not None
    forward_url = profile.alert_ingress.forward_url

    try:
        body = await request.body()
    except Exception:
        return Response(
            content="bad request body", status_code=400, media_type="text/plain",
        )

    forward_body, risk_level, flagged, counts = await _sanitize_and_classify(
        body, profile
    )

    client_host = request.client.host if request.client is not None else "unknown"
    log_fn = logger.warning if flagged else logger.info
    log_fn(
        "alert_ingress: profile=%s source_ip=%s risk=%s l1_detections=%d payload=%s",
        profile.name, client_host, risk_level, counts.detections, forward_body[:4000],
    )

    fwd_headers: dict[str, str] = {"Content-Type": "application/json"}
    if profile.alert_ingress.forward_secret is not None:
        secret = profile.alert_ingress.forward_secret.get_secret_value()
        sig = hmac.new(
            secret.encode("utf-8"), forward_body, hashlib.sha256,
        ).hexdigest()
        fwd_headers["X-Hub-Signature-256"] = f"sha256={sig}"

    client = _get_alert_client()
    try:
        resp = await client.post(
            forward_url,
            content=forward_body,
            headers=fwd_headers,
        )
    except httpx.TimeoutException:
        logger.warning("alert_ingress: timeout forwarding to %s", forward_url)
        return Response(
            content="forward timeout", status_code=504, media_type="text/plain",
        )
    except httpx.ConnectError as exc:
        logger.warning("alert_ingress: connect error to %s: %s", forward_url, exc)
        return Response(
            content="forward unreachable", status_code=502, media_type="text/plain",
        )

    logger.info(
        "alert_ingress: forwarded to %s for profile %s (status=%d)",
        forward_url, profile.name, resp.status_code,
    )

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type=resp.headers.get("content-type", "application/json"),
    )


async def _sanitize_and_classify(
    body: bytes, profile: Profile,
) -> tuple[bytes, str, bool, _SanitizeCounts]:
    """Run the three-layer defense over an alert payload.

    Returns the bytes to forward — the payload's content intact, with a
    ``_trentina_warning`` field attached when flagged (JSON payloads only;
    plain text has nowhere to carry an annotation, so its warning lives in
    the log line and the D-Bus event) — plus the L1 risk level, whether any
    layer flagged, and the raw L1 detection counts. Content is never
    modified on the way through: L1 detects, the sidecar warns, and the
    enforcement mode (not this function) decides disposition.

    Two things changed when this moved onto the shared pipeline, both
    deliberate:

    1. It now honours ``profile.defense``. This was the only place in the
       codebase where the pipeline actually ran, and it was the one place that
       ignored the per-profile toggles DefenseConfig exists to hold.

    2. A truncated L2 scan now flags. Previously the classifier was handed the
       whole payload, and a payload past CLASSIFIER_MAX_TOKENS was scanned only
       in part while ``ClassifierResult.truncated`` was discarded — so an
       oversized alert forwarded looking clean. "We could not finish reading
       this" is not the same as "this is fine", and it should never again be
       reported as though it were.
    """
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = None

    defense = profile.defense
    source = f"alert:{profile.name}"

    if payload is not None:
        # L1 per leaf so the JSON survives; L2/L3 read the joined document, so
        # an instruction split across two fields is still visible.
        verdict = await defend_json(
            payload, source=source, source_type="alert", defense=defense,
        )
        counts = _SanitizeCounts(
            detections=verdict.verdict.pipeline.stats.total_detections(),
            suspicious=verdict.verdict.pipeline.stats.suspicious_detections(),
        )
        sanitized_payload: Any = verdict.payload
        joined_text = verdict.joined_text
        final = verdict.verdict
    else:
        text = body.decode("utf-8", errors="replace")
        first = await advise(
            text, source=source, source_type="alert", defense=defense, is_html=False,
        )
        counts = _SanitizeCounts(
            detections=first.pipeline.stats.total_detections(),
            suspicious=first.pipeline.stats.suspicious_detections(),
        )
        final = first
        sanitized_payload = None
        joined_text = first.content

    risk_level = risk_level_for_count(counts.suspicious)
    classification = final.classification
    l2_truncated = bool(classification is not None and classification.truncated)

    flagged = risk_level != "low" or final.flagged or l2_truncated

    if flagged and isinstance(sanitized_payload, dict):
        sanitized_payload["_trentina_warning"] = {
            "risk_level": risk_level,
            "l1_detections": counts.detections,
            "l2_label": classification.label if classification is not None else None,
            "l2_score": classification.score if classification is not None else None,
            "l2_truncated": l2_truncated,
            "l3_injection_detected": (
                final.l3_assessment.get("injection_detected")
                if final.l3_assessment is not None
                else None
            ),
        }

    forward_body = (
        json.dumps(sanitized_payload).encode("utf-8")
        if sanitized_payload is not None
        else joined_text.encode("utf-8")
    )

    return forward_body, risk_level, flagged, counts
