"""The consent page's two rough edges, and the rule that they fail soft.

A double-submitted consent form used to render a bare `<h1>Error</h1>` with a
400 — a dead end, to a user whose login had in fact already succeeded. These
tests pin the replacement page, the client-side guard that stops the common
case, and the property that matters more than either: when the markup is not
what we expected, the original bytes go out untouched. A cosmetic repair must
never be able to break a login.
"""

from __future__ import annotations

from typing import Any

from mcp_trentina_crunchtools.gateway.consent_ui import ConsentUsability

_CONSENT_PAGE = (
    "<html><body><form id='consentForm' method='POST' action=''>"
    "<button type='submit' name='action' value='approve'>Allow Access</button>"
    "</form></body></html>"
)

_SPENT_PAGE = "<h1>Error</h1><p>Invalid or expired consent token</p>"

_CSRF_MISMATCH_PAGE = (
    "<h1>Error</h1><p>Authorization session mismatch. Please try authenticating again.</p>"
)


def _app(status: int, body: str, content_type: str = "text/html") -> Any:
    async def inner(_scope: Any, _receive: Any, send: Any) -> None:
        payload = body.encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", content_type.encode()),
                    (b"content-length", str(len(payload)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload})

    return inner


async def _drive(app: Any, method: str) -> tuple[int, str, dict[bytes, bytes]]:
    status = 0
    headers: dict[bytes, bytes] = {}
    chunks: list[bytes] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]
            headers.update({k.lower(): v for k, v in message.get("headers", [])})
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    await app({"type": "http", "method": method}, receive, send)
    return status, b"".join(chunks).decode(), headers


class TestSpentToken:
    async def test_double_submit_gets_an_explanation_not_a_dead_end(self) -> None:
        wrapped = ConsentUsability(_app(400, _SPENT_PAGE))

        status, body, _ = await _drive(wrapped, "POST")

        assert status == 400
        assert "Invalid or expired consent token" not in body
        assert "already handled" in body
        # The two things a stranded user needs to know.
        assert "close this tab" in body
        assert "start the sign-in again" in body

    async def test_content_length_matches_the_replacement(self) -> None:
        """A stale content-length truncates the page in the browser."""
        wrapped = ConsentUsability(_app(400, _SPENT_PAGE))

        _, body, headers = await _drive(wrapped, "POST")

        assert int(headers[b"content-length"]) == len(body.encode())

    async def test_the_csrf_mismatch_page_is_left_alone(self) -> None:
        """A 403 session mismatch is a possible forgery, not a double-click.
        Reassuring that user with 'nothing is wrong' would be a lie."""
        wrapped = ConsentUsability(_app(403, _CSRF_MISMATCH_PAGE))

        status, body, _ = await _drive(wrapped, "POST")

        assert status == 403
        assert body == _CSRF_MISMATCH_PAGE

    async def test_a_different_400_is_left_alone(self) -> None:
        wrapped = ConsentUsability(_app(400, "<h1>Error</h1><p>Invalid or expired transaction</p>"))

        _, body, _ = await _drive(wrapped, "POST")

        assert "Invalid or expired transaction" in body


class TestSubmitGuard:
    async def test_the_form_is_given_a_double_submit_guard(self) -> None:
        wrapped = ConsentUsability(_app(200, _CONSENT_PAGE))

        status, body, _ = await _drive(wrapped, "GET")

        assert status == 200
        assert "consentForm" in body
        assert "disabled = true" in body
        # The original markup survives; the guard is added, not substituted.
        assert "Allow Access" in body

    async def test_the_guard_runs_after_the_submit_is_dispatched(self) -> None:
        """Disabling the buttons synchronously would cancel the very submit
        that triggered it, and the approve/deny value would never be sent."""
        wrapped = ConsentUsability(_app(200, _CONSENT_PAGE))

        _, body, _ = await _drive(wrapped, "GET")

        assert "setTimeout" in body

    async def test_a_page_without_a_form_is_left_alone(self) -> None:
        wrapped = ConsentUsability(_app(200, "<html><body>nothing here</body></html>"))

        _, body, _ = await _drive(wrapped, "GET")

        assert body == "<html><body>nothing here</body></html>"

    async def test_a_redirect_is_left_alone(self) -> None:
        """The success path is a 302 to the upstream authorize URL."""
        wrapped = ConsentUsability(_app(302, ""))

        status, body, _ = await _drive(wrapped, "POST")

        assert status == 302
        assert body == ""


class TestFailSoft:
    async def test_undecodable_bytes_pass_through_untouched(self) -> None:
        async def inner(_scope: Any, _receive: Any, send: Any) -> None:
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"image/png")],
                }
            )
            await send({"type": "http.response.body", "body": b"\x89PNG\xff\xfe"})

        captured: list[bytes] = []

        async def send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.body":
                captured.append(message.get("body", b""))

        async def receive() -> dict[str, Any]:
            return {"type": "http.request", "body": b"", "more_body": False}

        await ConsentUsability(inner)({"type": "http", "method": "GET"}, receive, send)

        assert captured == [b"\x89PNG\xff\xfe"]

    async def test_a_non_http_scope_is_delegated_unchanged(self) -> None:
        seen: list[str] = []

        async def inner(scope: Any, _receive: Any, _send: Any) -> None:
            seen.append(scope["type"])

        await ConsentUsability(inner)({"type": "lifespan"}, None, None)

        assert seen == ["lifespan"]
