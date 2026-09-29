"""What a log line may carry (#262).

The gateway's log is readable by several agents through other backends'
journal and container-log tools, so a string a caller chose that reaches it
verbatim is a message board between agents, and one that outlives the
session. The rule: never log a string a caller chose — an agent, an OAuth or
HTTP client, a backend, a fetched page, a Matrix sender — nor an exception
whose message may carry one.

What may be logged: a profile name (server-configured), a tool name once it
resolved to a configured tool, ``exc_kind(exc)``, and for anything else
``redact_source(s)``, a fingerprint an operator correlates with the audit
database, which no tool can reach. ``tests/test_log_hygiene.py`` drives every
tool path with a canary at DEBUG and fails if the canary reaches a record,
and fails any ``logger.exception``, ``exc_info`` or bare exception argument
not marked ``# logsafe: ours`` with the reason its text is the server's own.

Third-party loggers that format request data themselves (uvicorn's access
log, httpx, httpcore) are held to the same rule by ``install()``.
"""

from __future__ import annotations

import hashlib
import logging
import traceback
from urllib.parse import urlsplit

#: HTTP methods written as they are; anything else is a caller's token.
_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"})

#: First path segments that are routes of ours, kept readable in the access log.
_ROUTES = frozenset(
    {
        "gateway",
        "mcp",
        "health",
        "alert",
        "matrix",
        "llm",
        "_matrix",
        "authorize",
        "token",
        "register",
        "consent",
        "auth",
        ".well-known",
        "sse",
        "messages",
    }
)


def redact_source(s: object) -> str:
    """A fingerprint of ``s``: correlatable with the audit DB, unreadable in the log."""
    text = s if isinstance(s, str) else str(s)
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    return f"sha256:{digest[:12]} len={len(text)}"


def exc_kind(exc: BaseException) -> str:
    """The exception's class, never its message: messages embed URLs, paths
    and backend text. An HTTP status, when the exception carries one, is ours
    to log too."""
    status = getattr(exc, "status_code", None)
    return (
        f"{type(exc).__name__} status={status}" if isinstance(status, int) else type(exc).__name__
    )


def exc_where(exc: BaseException) -> str:
    """Where it was raised, as ``file:line in func`` frames: the traceback's
    code locations without the message a traceback would print."""
    frames = traceback.extract_tb(exc.__traceback__)[-4:]
    return " < ".join(
        f"{f.filename.rsplit('/', 1)[-1]}:{f.lineno} in {f.name}" for f in reversed(frames)
    )


def safe_address(host: object) -> str:
    """A peer address, fingerprinted. Even a real one is partly chosen: a
    client with an IPv6 /64 picks the low 64 bits per connection, and behind
    a trusted proxy uvicorn takes the host from ``X-Forwarded-For``. Equal
    fingerprints still group one client's lines."""
    text = str(host)
    return "unix" if text in {"", "None"} else redact_source(text)


def safe_url(url: object) -> str:
    """An operator-configured URL as ``scheme://host[:port]`` only. Backend
    URLs are ours, not a caller's, but some carry a credential in the path or
    query (a token-in-URL MCP server), and the journal is agent-readable."""
    try:
        parts = urlsplit(str(url))
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        return redact_source(url)
    return f"{parts.scheme}://{host}{port}" if host else redact_source(url)


def safe_path(path: object) -> str:
    """A request path reduced to our route and a fingerprint of the rest."""
    text = str(path)
    first = text.lstrip("/").split("/", 1)[0].split("?", 1)[0]
    if text in {"/", "/health"}:
        return text
    head = f"/{first}" if first in _ROUTES else "/?"
    return f"{head}/… {redact_source(text)}"


class _AccessLogFilter(logging.Filter):
    """uvicorn.access: ``(client, method, path, http_version, status)``."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) == 5:
            client, method, path, version, status = args
            host, _, port = str(client).rpartition(":")
            record.args = (
                f"{safe_address(host)}:{port}" if host else safe_address(client),
                method if method in _METHODS else redact_source(method),
                safe_path(path),
                version,
                status,
            )
        return True


class _HttpxFilter(logging.Filter):
    """httpx: ``HTTP Request: %s %s "%s %d %s"``, method then URL. A fetched
    URL is the agent's."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 2:
            method = args[0] if args[0] in _METHODS else redact_source(args[0])
            record.args = (method, redact_source(args[1]), *args[2:])
        return True


def _clamp(name: str, floor: int, level: int) -> None:
    logging.getLogger(name).setLevel(max(floor, level))


def install(level: int) -> None:
    """Hold the third-party loggers to the rule at any ``TRENTINA_LOG_LEVEL``.

    httpcore's DEBUG names every host it connects to; the MCP SDK's and
    FastMCP's DEBUG echo whole JSON-RPC messages, arguments included. They
    stay at INFO or above however low the level goes: lowering it must not
    reopen the channel.
    """
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, _AccessLogFilter) for f in access.filters):
        access.addFilter(_AccessLogFilter())
    for name in ("httpx", "httpx2"):
        client_log = logging.getLogger(name)
        if not any(isinstance(f, _HttpxFilter) for f in client_log.filters):
            client_log.addFilter(_HttpxFilter())
    _clamp("httpcore", logging.WARNING, level)
    for name in ("mcp", "fastmcp", "sse_starlette", "hpack", "h2"):
        _clamp(name, logging.INFO, level)
