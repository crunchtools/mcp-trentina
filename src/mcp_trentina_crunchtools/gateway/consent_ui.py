"""Two usability repairs to FastMCP's consent page, applied on the way out.

Submitting the consent form twice produced a hard dead end:

    21:17:00  POST /consent?txn_id=...  302   <- approval succeeded
    21:17:03  POST /consent?txn_id=...  400   <- same token, "Invalid or
                                                  expired consent token"

The single-use CSRF token is correct — it is the replay and cross-site-forgery
defence and it stays exactly as it is. What was wrong is what the second
submit *showed*: a bare `<h1>Error</h1>` with no statement of what happened
and no way forward, to a user whose login had in fact already succeeded. A
double-click, or a back-then-resubmit, was enough to reach it. See #156.

So: stop the common case client-side by disabling the buttons on first submit,
and when a spent token does arrive, say what happened.

Both are done by patching the rendered response rather than by overriding
`_submit_consent`. Two reasons. The handler is a `ConsentMixin` method wound
through cookie state, legacy-token fallbacks and the double-submit check;
reimplementing it here would be a second copy to keep in step on every fastmcp
upgrade. And the alternative repair the issue offers — redirecting a spent
token to the upstream authorize URL — would have to run BEFORE the CSRF check
in order to help, which is a change to the security logic in exchange for
saving one click. The explanatory page was the other option named, it costs
nothing, and it leaves the defence untouched.

Every patch here fails soft. If the markup a hook looks for is not found, the
original bytes go out unchanged: a cosmetic repair must never be able to break
a login.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

#: Disables both buttons as soon as the form is submitted, and lets the submit
#: proceed. `submitter` carries which button was pressed, so the form still
#: posts approve-vs-deny correctly; disabling the controls only stops a SECOND
#: post. Inert if scripting is off — the server-side page below is what covers
#: that case, which is why this is the convenience and not the fix.
_SUBMIT_GUARD = """
<script>
(function () {
  var form = document.getElementById('consentForm');
  if (!form) { return; }
  form.addEventListener('submit', function () {
    setTimeout(function () {
      var buttons = form.querySelectorAll('button[type="submit"]');
      for (var i = 0; i < buttons.length; i++) { buttons[i].disabled = true; }
    }, 0);
  });
})();
</script>
"""

#: What the SDK renders for a spent or bogus CSRF token. Matched as a
#: substring so a surrounding markup change does not silently stop the
#: replacement; if the SENTENCE changes, the patch stops applying and the
#: original page is served, which is the safe direction.
_SPENT_CONSENT_MARKER = "Invalid or expired consent token"

_ALREADY_APPROVED_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Already approved</title>
<style>
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
         line-height: 1.5; margin: 0; padding: 3rem 1.5rem;
         background: #f6f7f9; color: #1c1e21; }
  main { max-width: 34rem; margin: 0 auto; background: #fff; padding: 2rem;
         border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  h1 { font-size: 1.35rem; margin: 0 0 1rem; }
  p { margin: 0 0 1rem; }
  ul { margin: 0; padding-left: 1.25rem; }
  li { margin-bottom: .4rem; }
  .muted { color: #606770; font-size: .9rem; margin-top: 1.5rem; }
</style>
</head>
<body>
<main>
  <h1>This request was already handled</h1>
  <p>
    The approval form was submitted more than once — usually a double-click or
    a page refresh. Each consent form can only be submitted once, so this
    second submission was not accepted.
  </p>
  <p>Nothing is wrong, and nothing was approved twice. What to do next:</p>
  <ul>
    <li>
      If your application is already signed in, you are done — close this tab.
    </li>
    <li>
      If it is not, start the sign-in again from the application. A fresh
      request will bring you back here.
    </li>
  </ul>
  <p class="muted">
    Do not use the browser's back button to resubmit this form; it will land
    on this page again.
  </p>
</main>
</body>
</html>
"""


def _patch_html(body: bytes, method: str, status: int) -> bytes | None:
    """Return replacement bytes for one consent response, or None to pass through."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None

    if method == "POST" and status == 400 and _SPENT_CONSENT_MARKER in text:
        return _ALREADY_APPROVED_PAGE.encode()

    if method == "GET" and status == 200 and "</form>" in text:
        return text.replace("</form>", "</form>" + _SUBMIT_GUARD, 1).encode()

    return None


class ConsentUsability:
    """ASGI wrapper that rewrites the consent page's two rough edges.

    Buffers the response. Safe here for the same reason the metadata patch
    buffers: a consent page is a few kilobytes of HTML and nothing on this
    route streams.
    """

    __slots__ = ("_inner",)

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self._inner(scope, receive, send)
            return

        method = scope.get("method", "")
        start_message: dict[str, Any] | None = None
        chunks: list[bytes] = []

        async def capture(message: dict[str, Any]) -> None:
            nonlocal start_message
            if message["type"] == "http.response.start":
                start_message = message
                return
            if message["type"] != "http.response.body":
                await send(message)
                return
            chunks.append(message.get("body", b""))
            if message.get("more_body"):
                return
            await self._flush(start_message, b"".join(chunks), method, send)

        await self._inner(scope, receive, capture)

    async def _flush(
        self, start: dict[str, Any] | None, body: bytes, method: str, send: Any
    ) -> None:
        if start is None:
            return

        try:
            replacement = _patch_html(body, method, int(start.get("status", 0)))
        except Exception:
            logger.warning(
                "consent: could not patch page — serving the original",
                exc_info=True,
            )
            await self._passthrough(start, body, send)
            return

        if replacement is None:
            await self._passthrough(start, body, send)
            return

        headers = [
            (name, value)
            for name, value in start.get("headers", [])
            if name.lower() != b"content-length"
        ]
        headers.append((b"content-length", str(len(replacement)).encode()))
        await send({**start, "headers": headers})
        await send({"type": "http.response.body", "body": replacement})

    @staticmethod
    async def _passthrough(start: dict[str, Any], body: bytes, send: Any) -> None:
        """Emit the response exactly as the handler produced it."""
        await send(start)
        await send({"type": "http.response.body", "body": body})
