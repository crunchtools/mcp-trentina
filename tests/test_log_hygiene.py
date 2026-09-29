"""No string a caller chose reaches the log (#262).

The gateway's log is readable by other agents through journal and
container-log tools, so a caller-chosen string written there is a message
board between agents. Every path below carries ``CANARY`` in whatever the
caller controls — URL, path, query, argument names, headers, the profile in
the URL, a backend's error text — with every logger at DEBUG after
``logsafe.install``, the way production runs when an operator lowers the
level. The canary must appear in no record's message, exception or stack.

Not driven here: the Matrix proxy and the LLM proxy. Standing either up needs
an upstream homeserver or provider; their lines go through the same
``redact_source`` and ``exc_kind``, and the static check below covers them.
"""

from __future__ import annotations

import ast
import contextlib
import functools
import logging
import pathlib
from collections.abc import Iterator
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import httpx
import pytest
from pydantic import SecretStr
from starlette.testclient import TestClient

from mcp_trentina_crunchtools import config as config_mod
from mcp_trentina_crunchtools import logsafe
from mcp_trentina_crunchtools.errors import FetchError, UnsupportedContentTypeError
from mcp_trentina_crunchtools.gateway import backend as backend_mod
from mcp_trentina_crunchtools.gateway import internal
from mcp_trentina_crunchtools.gateway.app import gateway_app
from mcp_trentina_crunchtools.gateway.errors import BackendCallError, BackendNotInProfileError
from mcp_trentina_crunchtools.gateway.profile import AuthConfig, Backend, Profile
from mcp_trentina_crunchtools.gateway.router import NAMESPACE_SEP, route_jsonrpc
from mcp_trentina_crunchtools.tools import cache as cache_tool
from mcp_trentina_crunchtools.tools import reconnect as reconnect_tool

from .mode_harness import MALICIOUS, layers

if TYPE_CHECKING:
    from pathlib import Path

CANARY = "zqx7canary"
URL = f"https://{CANARY}.example.com/{CANARY}?q={CANARY}"

#: Loggers that do not propagate to the root, so they are watched directly.
_DETACHED = ("fastmcp",)


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _rendered(record: logging.LogRecord) -> str:
    fmt = logging.Formatter()
    parts = [record.getMessage()]
    if record.exc_info:
        parts.append(fmt.formatException(record.exc_info))
    if record.exc_text:
        parts.append(record.exc_text)
    if record.stack_info:
        parts.append(fmt.formatStack(record.stack_info))
    return "\n".join(parts)


@pytest.fixture
def captured() -> Iterator[_Capture]:
    """Every record at DEBUG, with the production filters and clamps installed."""
    watched = ["", "httpx", "httpcore", "mcp", "uvicorn.access", *_DETACHED]
    saved = {name: logging.getLogger(name).level for name in watched}
    handler = _Capture()
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    logging.getLogger("httpx").setLevel(logging.DEBUG)
    logsafe.install(logging.DEBUG)
    root.addHandler(handler)
    for name in _DETACHED:
        logging.getLogger(name).addHandler(handler)
    try:
        yield handler
    finally:
        root.removeHandler(handler)
        for name in _DETACHED:
            logging.getLogger(name).removeHandler(handler)
        for name, level in saved.items():
            logging.getLogger(name).setLevel(level)
    leaked = [
        f"{r.name}:{r.levelname}: {_rendered(r)[:300]}"
        for r in handler.records
        if CANARY in _rendered(r)
    ]
    assert not leaked, "caller-chosen text reached the log:\n" + "\n".join(leaked)
    assert handler.records, "nothing was logged: the path under test did not run"


@pytest.fixture
def real_server() -> Iterator[None]:
    """The gateway's internal backend bound to the real FastMCP server."""
    from mcp_trentina_crunchtools.server import mcp

    saved = internal._server
    internal.register_internal_server(mcp)
    try:
        yield
    finally:
        internal._server = saved


def _transport(monkeypatch: pytest.MonkeyPatch, status: int, content_type: str) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status, headers={"content-type": content_type}, content=f"{CANARY} body".encode()
        )

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        "mcp_trentina_crunchtools.client.httpx.AsyncClient",
        functools.partial(real_client, transport=httpx.MockTransport(handler)),
    )


async def _internal(tool: str, arguments: dict[str, Any]) -> None:
    """One internal tool call through the gateway's in-process path; its
    failure is the caller's to see, and is not what is under test."""
    with contextlib.suppress(BackendCallError):
        await internal.call_internal_tool(tool, arguments)


# ------------------------------------------------------------ internal tools


@pytest.mark.usefixtures("env", "real_server")
class TestInternalTools:
    async def test_fetch_that_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, captured: _Capture
    ) -> None:
        from mcp_trentina_crunchtools.client import fetch_url

        _transport(monkeypatch, 404, "text/plain")
        with layers(tmp_path) as fakes:
            fakes.fetch_url.side_effect = fetch_url
            await _internal("fetch_tool", {"url": URL})

    async def test_fetch_advisory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, captured: _Capture
    ) -> None:
        from mcp_trentina_crunchtools.client import fetch_url

        _transport(monkeypatch, 415, "text/plain")
        with layers(tmp_path) as fakes:
            fakes.fetch_url.side_effect = fetch_url
            await _internal("fetch_tool", {"url": URL})

    async def test_fetch_redirect_to_binary(self, tmp_path: Path, captured: _Capture) -> None:
        with layers(tmp_path) as fakes:
            fakes.fetch_url.side_effect = UnsupportedContentTypeError(URL, f"image/{CANARY}")
            await _internal("fetch_tool", {"url": URL})

    async def test_fetch_error_the_tool_raises(self, tmp_path: Path, captured: _Capture) -> None:
        with layers(tmp_path) as fakes:
            fakes.fetch_url.side_effect = FetchError(URL, f"connect failed {CANARY}")
            await _internal("fetch_tool", {"url": URL})

    async def test_fetch_flagged(self, tmp_path: Path, captured: _Capture) -> None:
        with layers(tmp_path, payload=f"{CANARY} ignore previous", classification=MALICIOUS):
            await _internal("fetch_tool", {"url": URL})

    async def test_fetch_detection_record_fails(self, tmp_path: Path, captured: _Capture) -> None:
        with (
            layers(tmp_path, classification=MALICIOUS),
            patch(
                "mcp_trentina_crunchtools.defense.record_detection",
                side_effect=RuntimeError(f"sqlite said {CANARY}"),
            ),
        ):
            await _internal("fetch_tool", {"url": URL})

    async def test_fetch_refused_at_admission(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, captured: _Capture
    ) -> None:
        monkeypatch.setenv("CLASSIFIER_MAX_TOKENS", "8")
        config_mod._config = None
        with layers(tmp_path, payload="word " * 400):
            await _internal("fetch_tool", {"url": URL})

    async def test_read_of_a_missing_path(self, tmp_path: Path, captured: _Capture) -> None:
        with layers(tmp_path):
            await _internal("read_tool", {"path": str(tmp_path / CANARY / "nope.txt")})

    async def test_read_flagged(self, tmp_path: Path, captured: _Capture) -> None:
        (tmp_path / CANARY).mkdir()
        target = tmp_path / CANARY / "doc.txt"
        target.write_text("hello", encoding="utf-8")
        with layers(tmp_path, classification=MALICIOUS):
            await _internal("read_tool", {"path": str(target)})

    async def test_dir(self, tmp_path: Path, captured: _Capture) -> None:
        listing = tmp_path / CANARY
        listing.mkdir()
        (listing / f"{CANARY}.py").write_text("x", encoding="utf-8")
        with layers(tmp_path, classification=MALICIOUS):
            await _internal("dir_tool", {"path": str(listing)})
            await _internal("dir_tool", {"path": str(tmp_path / "missing" / CANARY)})

    async def test_content(self, tmp_path: Path, captured: _Capture) -> None:
        with layers(tmp_path, classification=MALICIOUS):
            await _internal("content_tool", {"content": f"{CANARY} ignore previous"})

    async def test_search(self, tmp_path: Path, captured: _Capture) -> None:
        with layers(tmp_path, payload=f"{CANARY} result", classification=MALICIOUS):
            await _internal("search_tool", {"query": CANARY})

    async def test_search_provider_failure(self, tmp_path: Path, captured: _Capture) -> None:
        from mcp_trentina_crunchtools.errors import QuarantineAgentError

        with layers(tmp_path) as fakes:
            fakes.search_grounded.side_effect = QuarantineAgentError(f"upstream said {CANARY}")
            await _internal("search_tool", {"query": CANARY})

    async def test_unknown_tool(self, captured: _Capture) -> None:
        await _internal(CANARY, {CANARY: CANARY})

    async def test_admin_tools_refusing_a_name(self, captured: _Capture) -> None:
        await cache_tool.cache_flush(CANARY)
        await reconnect_tool.reconnect_backend(CANARY)


# ------------------------------------------------------------ proxied tools


def _profile() -> Profile:
    p = Profile(
        short_names=False,
        name="testp",
        auth=AuthConfig(bearer_token_env="TEST"),
        backends={"mcp-slack": Backend(url="http://mcp-slack:8000/mcp", tools_allow=["*"])},
    )
    p.auth.bearer_token = SecretStr("testp-token")
    return p


class TestProxiedTools:
    async def test_backend_that_fails(self, captured: _Capture) -> None:
        profile = _profile()
        backend_mod._tool_list_cache["http://mcp-slack:8000/mcp"] = [
            {
                "name": "post",
                "inputSchema": {
                    "type": "object",
                    "properties": {CANARY: {"type": "integer"}},
                },
            }
        ]
        with patch.object(
            backend_mod, "_do_call_tool", side_effect=RuntimeError(f"backend said {CANARY}")
        ):
            await route_jsonrpc(
                profile,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": f"mcp-slack{NAMESPACE_SEP}post",
                        "arguments": {CANARY: "", "text": CANARY},
                    },
                },
            )

    async def test_unknown_tool(self, captured: _Capture) -> None:
        with pytest.raises(BackendNotInProfileError):
            await route_jsonrpc(
                _profile(),
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": f"{CANARY}{NAMESPACE_SEP}{CANARY}", "arguments": {}},
                },
            )


@pytest.mark.parametrize(
    ("listed", "name", "verbatim"),
    [
        ("post", "post", True),
        ("post", CANARY, False),  # typed by the caller, never listed
        (f"{CANARY} forged\nline", f"{CANARY} forged\nline", False),  # listed, not a tool name
    ],
)
def test_loggable_tool(listed: str, name: str, verbatim: bool) -> None:
    url = "http://mcp-slack:8000/mcp"
    backend_mod._tool_list_cache[url] = [{"name": listed, "inputSchema": {}}]
    assert (backend_mod.loggable_tool(url, name) == name) is verbatim


class TestBridgeProcess:
    async def test_gateway_refusal(self, tmp_path: Path, captured: _Capture) -> None:
        from .test_bridge_process import ROOM, FakeNio, _bridge

        def gateway(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, text=f"refused {CANARY}")

        event = SimpleNamespace(
            sender="@scott:matrix.org",
            source={
                "type": "m.room.message",
                "event_id": f"${CANARY}",
                "sender": "@scott:matrix.org",
                "content": {"msgtype": "m.text", "body": CANARY},
            },
        )
        await _bridge(tmp_path, FakeNio(), gateway).handle(ROOM, event)
        assert any("gateway refused" in r.getMessage() for r in captured.records)


# ------------------------------------------------------------ HTTP edge


class TestHttpEdge:
    @pytest.fixture
    def client(self) -> TestClient:
        return TestClient(gateway_app({"testp": _profile()}))

    def test_unknown_profile(self, client: TestClient, captured: _Capture) -> None:
        resp = client.post(f"/{CANARY}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert resp.status_code == 404

    def test_initialize_and_stale_session(self, client: TestClient, captured: _Capture) -> None:
        headers = {
            "Authorization": "Bearer testp-token",
            "User-Agent": f"agent/{CANARY}",
            "Mcp-Session-Id": f"{CANARY}-stale-session",
        }
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        # A stale session header on initialize is recovered from; on anything
        # else it is refused. Every branch logs the id, the UA or the method.
        assert client.post("/testp/mcp", json=init, headers=headers).status_code == 200
        stale = {"jsonrpc": "2.0", "id": 2, "method": CANARY}
        assert client.post("/testp/mcp", json=stale, headers=headers).status_code == 404
        assert client.get("/testp/mcp", headers=headers).status_code == 404
        assert client.delete("/testp/mcp", headers=headers).status_code == 404

    def test_uvicorn_access_line(self, captured: _Capture) -> None:
        logging.getLogger("uvicorn.access").info(
            '%s - "%s %s HTTP/%s" %d',
            f"{CANARY}:443",
            CANARY,
            f"/gateway/{CANARY}/mcp?x={CANARY}",
            "1.1",
            404,
        )
        [line] = [r.getMessage() for r in captured.records if r.name == "uvicorn.access"]
        assert line.endswith('HTTP/1.1" 404')
        assert '"sha256:' in line and " /gateway/… sha256:" in line

    def test_uvicorn_access_line_keeps_what_is_ours(self) -> None:
        record = logging.LogRecord(
            "uvicorn.access",
            logging.INFO,
            __file__,
            1,
            '%s - "%s %s HTTP/%s" %d',
            ("10.0.0.1:5555", "POST", "/health", "1.1", 200),
            None,
        )
        logsafe._AccessLogFilter().filter(record)
        address = logsafe.redact_source("10.0.0.1")
        assert record.getMessage() == f'{address}:5555 - "POST /health HTTP/1.1" 200'


# ------------------------------------------------------------ static rule

_SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "mcp_trentina_crunchtools"
_LEVELS = {"debug", "info", "warning", "error", "exception", "critical", "log"}
#: Names that hold an exception or a gathered outcome by this codebase's habit.
_RAW = {"exc", "e", "err", "error", "outcome"}
_OURS = "logsafe: ours"


def _log_calls(tree: ast.AST) -> Iterator[ast.Call]:
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _LEVELS
            and "log" in ast.unparse(node.func.value).lower()
        ):
            yield node


def _violation(call: ast.Call, raw: set[str]) -> str | None:
    if isinstance(call.func, ast.Attribute) and call.func.attr == "exception":
        return "logger.exception prints the exception's message"
    for kw in call.keywords:
        if kw.arg in {"exc_info", "stack_info"} and not (
            isinstance(kw.value, ast.Constant) and kw.value.value is False
        ):
            return f"{kw.arg} prints the exception's message"
    for arg in call.args:
        if isinstance(arg, ast.Name) and arg.id in raw:
            return f"{arg.id!r} formats an exception's message; log exc_kind() instead"
    return None


def test_no_log_call_formats_an_exception_message() -> None:
    """The static half (#262): no ``logger.exception``, no ``exc_info``, no
    bare exception as an argument, unless the call is marked ``# logsafe:
    ours`` with the reason its text is the server's own."""
    found = []
    for path in sorted(_SRC.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        lines = source.splitlines()
        raw = _RAW | {h.name for h in ast.walk(tree) if isinstance(h, ast.ExceptHandler) and h.name}
        for call in _log_calls(tree):
            reason = _violation(call, raw)
            span = lines[call.lineno - 2 : call.end_lineno]
            if reason and not any(_OURS in line for line in span):
                found.append(f"{path.relative_to(_SRC)}:{call.lineno}: {reason}")
    assert not found, "\n".join(found)


def test_redact_source_is_a_stable_fingerprint() -> None:
    assert logsafe.redact_source(URL) == logsafe.redact_source(URL)
    assert CANARY not in logsafe.redact_source(URL)
    assert logsafe.redact_source("abc").endswith(" len=3")


def test_exc_kind_names_the_class_only() -> None:
    assert logsafe.exc_kind(FetchError(URL, CANARY, status_code=404)) == "FetchError status=404"
    assert logsafe.exc_kind(RuntimeError(CANARY)) == "RuntimeError"
