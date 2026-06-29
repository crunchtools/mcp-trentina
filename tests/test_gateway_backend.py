"""Tests for gateway/backend.py — circuit breaker integration and timeout wiring.

Patches at the transport layer (_do_list_tools, _do_call_tool) so the real
list_backend_tools / call_backend_tool run their circuit breaker checks,
timeout wrapping, and success/failure recording.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from mcp_trentina_crunchtools.gateway.backend import (
    call_backend_tool,
    list_backend_tools,
)
from mcp_trentina_crunchtools.gateway.circuit import State, breaker
from mcp_trentina_crunchtools.gateway.errors import BackendCallError
from mcp_trentina_crunchtools.gateway.profile import Backend


def _backend(
    url: str = "http://mcp-rotv:8080/mcp",
    timeout: float = 30.0,
    list_timeout: float = 10.0,
) -> Backend:
    return Backend(url=url, timeout_seconds=timeout, list_timeout_seconds=list_timeout)


class _FakeTool:
    def __init__(self, name: str) -> None:
        self.name = name
        self.description = ""
        self.inputSchema: dict[str, Any] = {}


class _FakeToolsResult:
    def __init__(self, names: list[str] | None = None) -> None:
        self.tools = [_FakeTool(n) for n in (names or ["some_tool"])]


class _FakeCallResult:
    def __init__(self) -> None:
        self.content = [_FakeTextBlock()]
        self.isError = False
        self.structuredContent = None


class _FakeTextBlock:
    type = "text"
    text = "ok"


URL = "http://mcp-rotv:8080/mcp"


@pytest.mark.asyncio
class TestListBackendToolsCircuit:
    """list_backend_tools circuit breaker integration."""

    async def test_circuit_open_raises_without_transport(self) -> None:
        """Circuit-open backend raises BackendCallError before touching transport."""
        for _ in range(3):
            breaker.record_failure(URL)

        async def should_not_be_called(_url: str, _headers: Any) -> Any:
            raise AssertionError("transport called despite open circuit")

        with (
            patch(
                "mcp_trentina_crunchtools.gateway.backend._do_list_tools",
                side_effect=should_not_be_called,
            ),
            pytest.raises(BackendCallError, match="circuit open"),
        ):
            await list_backend_tools("rotv", _backend())

    async def test_success_records_to_circuit(self) -> None:
        """Successful list_backend_tools closes/keeps-closed the circuit."""
        breaker.record_failure(URL)
        breaker.record_failure(URL)
        assert breaker.get_state(URL) is State.CLOSED

        async def ok_transport(_url: str, _headers: Any) -> _FakeToolsResult:
            return _FakeToolsResult()

        with patch(
            "mcp_trentina_crunchtools.gateway.backend._do_list_tools",
            side_effect=ok_transport,
        ):
            tools = await list_backend_tools("rotv", _backend())

        assert len(tools) == 1
        assert breaker.get_state(URL) is State.CLOSED
        assert breaker._get(URL).consecutive_failures == 0

    async def test_failure_records_to_circuit(self) -> None:
        """Transport failure increments the circuit failure counter."""

        async def fail_transport(_url: str, _headers: Any) -> Any:
            raise ConnectionRefusedError("connection refused")

        with (
            patch(
                "mcp_trentina_crunchtools.gateway.backend._do_list_tools",
                side_effect=fail_transport,
            ),
            pytest.raises(BackendCallError),
        ):
            await list_backend_tools("rotv", _backend())

        assert breaker._get(URL).consecutive_failures == 1

    async def test_three_failures_open_circuit(self) -> None:
        """Three consecutive transport failures open the circuit."""

        async def fail_transport(_url: str, _headers: Any) -> Any:
            raise TimeoutError("timed out")

        with patch(
            "mcp_trentina_crunchtools.gateway.backend._do_list_tools",
            side_effect=fail_transport,
        ):
            for _ in range(3):
                with pytest.raises(BackendCallError):
                    await list_backend_tools("rotv", _backend())

        assert breaker.get_state(URL) is State.OPEN

    async def test_uses_list_timeout_not_call_timeout(self) -> None:
        """list_backend_tools uses list_timeout_seconds, not timeout_seconds."""
        captured_timeout: list[float] = []

        original_wait_for = __import__("asyncio").wait_for

        async def spy_wait_for(coro: Any, *, timeout: float) -> Any:
            captured_timeout.append(timeout)
            return await original_wait_for(coro, timeout=timeout)

        async def ok_transport(_url: str, _headers: Any) -> _FakeToolsResult:
            return _FakeToolsResult()

        backend = _backend(timeout=30.0, list_timeout=7.5)
        with (
            patch(
                "mcp_trentina_crunchtools.gateway.backend._do_list_tools",
                side_effect=ok_transport,
            ),
            patch(
                "mcp_trentina_crunchtools.gateway.backend.asyncio.wait_for",
                side_effect=spy_wait_for,
            ),
        ):
            await list_backend_tools("rotv", backend)

        assert captured_timeout == [7.5]


@pytest.mark.asyncio
class TestCallBackendToolCircuit:
    """call_backend_tool circuit breaker integration."""

    async def test_circuit_open_raises_without_transport(self) -> None:
        for _ in range(3):
            breaker.record_failure(URL)

        async def should_not_be_called(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("transport called despite open circuit")

        with (
            patch(
                "mcp_trentina_crunchtools.gateway.backend._do_call_tool",
                side_effect=should_not_be_called,
            ),
            pytest.raises(BackendCallError, match="circuit open"),
        ):
            await call_backend_tool("rotv", _backend(), "some_tool", {})

    async def test_success_records_to_circuit(self) -> None:
        breaker.record_failure(URL)
        breaker.record_failure(URL)

        async def ok_transport(*_args: Any, **_kwargs: Any) -> _FakeCallResult:
            return _FakeCallResult()

        with patch(
            "mcp_trentina_crunchtools.gateway.backend._do_call_tool",
            side_effect=ok_transport,
        ):
            result = await call_backend_tool("rotv", _backend(), "some_tool", {})

        assert result.is_error is False
        assert breaker._get(URL).consecutive_failures == 0

    async def test_failure_records_to_circuit(self) -> None:
        async def fail_transport(*_args: Any, **_kwargs: Any) -> Any:
            raise ConnectionRefusedError("refused")

        with (
            patch(
                "mcp_trentina_crunchtools.gateway.backend._do_call_tool",
                side_effect=fail_transport,
            ),
            pytest.raises(BackendCallError),
        ):
            await call_backend_tool("rotv", _backend(), "some_tool", {})

        assert breaker._get(URL).consecutive_failures == 1

    async def test_uses_call_timeout_not_list_timeout(self) -> None:
        """call_backend_tool uses timeout_seconds, not list_timeout_seconds."""
        captured_timeout: list[float] = []

        original_wait_for = __import__("asyncio").wait_for

        async def spy_wait_for(coro: Any, *, timeout: float) -> Any:
            captured_timeout.append(timeout)
            return await original_wait_for(coro, timeout=timeout)

        async def ok_transport(*_args: Any, **_kwargs: Any) -> _FakeCallResult:
            return _FakeCallResult()

        backend = _backend(timeout=30.0, list_timeout=7.5)
        with (
            patch(
                "mcp_trentina_crunchtools.gateway.backend._do_call_tool",
                side_effect=ok_transport,
            ),
            patch(
                "mcp_trentina_crunchtools.gateway.backend.asyncio.wait_for",
                side_effect=spy_wait_for,
            ),
        ):
            await call_backend_tool("rotv", backend, "some_tool", {})

        assert captured_timeout == [30.0]
