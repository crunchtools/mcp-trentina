"""Tests for gateway/router.py — JSON-RPC dispatch with mocked backends."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from pydantic import SecretStr

from mcp_trentina_crunchtools.database import get_gateway_call_stats
from mcp_trentina_crunchtools.gateway.backend import BackendCall
from mcp_trentina_crunchtools.gateway.errors import BackendCallError, BackendNotInProfileError
from mcp_trentina_crunchtools.gateway.profile import (
    AuthConfig,
    Backend,
    ParameterConstraint,
    Profile,
)
from mcp_trentina_crunchtools.gateway.router import (
    NAMESPACE_SEP,
    PROTOCOL_VERSION,
    route_jsonrpc,
)


def _profile() -> Profile:
    """Build a Profile with two backends and one deny pattern for testing."""
    p = Profile(
        name="testp",
        auth=AuthConfig(bearer_token_env="TEST"),
        backends={
            "mcp-slack": Backend(
                url="http://mcp-slack:8005/mcp",
                tools_allow=["*"],
                tools_deny=["slack_dangerous"],
            ),
            "mcp-atlassian": Backend(
                url="http://mcp-atlassian:8021/mcp",
                tools_allow=["*"],
            ),
        },
    )
    p.auth.bearer_token = SecretStr("x")
    return p


def _mixed_profile() -> Profile:
    """Profile mixing an http backend with an internal:// (trentina-tools) backend."""
    p = Profile(
        name="mixed",
        auth=AuthConfig(bearer_token_env="TEST"),
        backends={
            "mcp-slack": Backend(url="http://mcp-slack:8005/mcp", tools_allow=["*"]),
            "web": Backend(url="internal://web", tools_allow=["*"]),
        },
    )
    p.auth.bearer_token = SecretStr("x")
    return p


@pytest.mark.asyncio
class TestRouter:
    """JSON-RPC dispatch covers initialize, ping, tools/list, tools/call."""

    async def test_initialize_returns_server_info(self) -> None:
        resp = await route_jsonrpc(_profile(), {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert resp["id"] == 1
        assert resp["result"]["protocolVersion"] == PROTOCOL_VERSION
        assert resp["result"]["serverInfo"]["name"] == "mcp-trentina-gateway:testp"
        assert "tools" in resp["result"]["capabilities"]

    async def test_ping_returns_empty_result(self) -> None:
        resp = await route_jsonrpc(_profile(), {"jsonrpc": "2.0", "id": 7, "method": "ping"})
        assert resp == {"jsonrpc": "2.0", "id": 7, "result": {}}

    async def test_unknown_method_returns_method_not_found(self) -> None:
        resp = await route_jsonrpc(
            _profile(),
            {"jsonrpc": "2.0", "id": 2, "method": "resources/list"},
        )
        assert resp["error"]["code"] == -32601

    async def test_tools_list_aggregates_and_namespaces(self) -> None:
        async def fake_list(backend_name: str, _backend: Backend) -> list[dict[str, Any]]:
            if backend_name == "mcp-slack":
                return [
                    {"name": "slack_list_channels", "description": "", "inputSchema": {}},
                    {"name": "slack_dangerous", "description": "", "inputSchema": {}},
                ]
            return [{"name": "jira_search", "description": "", "inputSchema": {}}]

        with patch(
            "mcp_trentina_crunchtools.gateway.router.list_backend_tools",
            side_effect=fake_list,
        ):
            resp = await route_jsonrpc(
                _profile(), {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}
            )

        names = sorted(str(t["name"]) for t in resp["result"]["tools"])
        assert names == [
            f"mcp-atlassian{NAMESPACE_SEP}jira_search",
            f"mcp-slack{NAMESPACE_SEP}slack_list_channels",
        ]

    async def test_tools_list_skips_unreachable_backend(self) -> None:
        async def fake_list(backend_name: str, _backend: Backend) -> list[dict[str, Any]]:
            if backend_name == "mcp-slack":
                raise BackendCallError("simulated outage")
            return [{"name": "jira_search", "description": "", "inputSchema": {}}]

        with patch(
            "mcp_trentina_crunchtools.gateway.router.list_backend_tools",
            side_effect=fake_list,
        ):
            resp = await route_jsonrpc(
                _profile(), {"jsonrpc": "2.0", "id": 4, "method": "tools/list"}
            )
        names = [str(t["name"]) for t in resp["result"]["tools"]]
        assert names == [f"mcp-atlassian{NAMESPACE_SEP}jira_search"]

    async def test_tools_call_routes_to_correct_backend(self) -> None:
        called: dict[str, Any] = {}

        async def fake_call(
            backend_name: str,
            _backend: Backend,
            tool_name: str,
            arguments: dict[str, Any],
        ) -> BackendCall:
            called["backend"] = backend_name
            called["tool"] = tool_name
            called["args"] = arguments
            return BackendCall(
                content=[{"type": "text", "text": "ok"}],
                is_error=False,
                structured_content=None,
            )

        with patch(
            "mcp_trentina_crunchtools.gateway.router.call_backend_tool",
            side_effect=fake_call,
        ):
            resp = await route_jsonrpc(
                _profile(),
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": f"mcp-slack{NAMESPACE_SEP}slack_list_channels",
                        "arguments": {"limit": 5},
                    },
                },
            )

        assert called == {
            "backend": "mcp-slack",
            "tool": "slack_list_channels",
            "args": {"limit": 5},
        }
        assert resp["result"]["content"] == [{"type": "text", "text": "ok"}]
        assert resp["result"]["isError"] is False

    async def test_tools_call_rejects_non_namespaced_name(self) -> None:
        resp = await route_jsonrpc(
            _profile(),
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "no_namespace", "arguments": {}},
            },
        )
        assert resp["error"]["code"] == -32602

    async def test_tools_call_rejects_unknown_backend(self) -> None:
        with pytest.raises(BackendNotInProfileError):
            await route_jsonrpc(
                _profile(),
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {
                        "name": f"mcp-unknown{NAMESPACE_SEP}some_tool",
                        "arguments": {},
                    },
                },
            )

    async def test_tools_list_aggregates_http_and_internal(self) -> None:
        """Mixed-backend tools/list: http + internal both filtered and namespaced."""

        async def fake_list(_backend_name: str, _backend: Backend) -> list[dict[str, Any]]:
            return [{"name": "slack_list_channels", "description": "", "inputSchema": {}}]

        async def fake_internal_list() -> list[dict[str, Any]]:
            return [
                {"name": "safe_fetch_tool", "description": "", "inputSchema": {}},
                {"name": "quarantine_stats_tool", "description": "", "inputSchema": {}},
            ]

        with (
            patch(
                "mcp_trentina_crunchtools.gateway.router.list_backend_tools",
                side_effect=fake_list,
            ),
            patch(
                "mcp_trentina_crunchtools.gateway.router.list_internal_tools",
                side_effect=fake_internal_list,
            ),
        ):
            resp = await route_jsonrpc(
                _mixed_profile(), {"jsonrpc": "2.0", "id": 9, "method": "tools/list"}
            )

        names = sorted(str(t["name"]) for t in resp["result"]["tools"])
        assert names == [
            f"mcp-slack{NAMESPACE_SEP}slack_list_channels",
            f"web{NAMESPACE_SEP}quarantine_stats_tool",
            f"web{NAMESPACE_SEP}safe_fetch_tool",
        ]

    async def test_tools_call_routes_to_internal_backend(self) -> None:
        """A call on the internal backend dispatches to call_internal_tool, not http."""
        called: dict[str, Any] = {}

        async def fake_internal_call(
            tool_name: str, arguments: dict[str, Any]
        ) -> BackendCall:
            called["tool"] = tool_name
            called["args"] = arguments
            return BackendCall(
                content=[{"type": "text", "text": "fetched"}],
                is_error=False,
                structured_content=None,
            )

        async def fail_http(*_args: Any, **_kwargs: Any) -> BackendCall:
            raise AssertionError("http backend must not be called for internal://")

        with (
            patch(
                "mcp_trentina_crunchtools.gateway.router.call_internal_tool",
                side_effect=fake_internal_call,
            ),
            patch(
                "mcp_trentina_crunchtools.gateway.router.call_backend_tool",
                side_effect=fail_http,
            ),
        ):
            resp = await route_jsonrpc(
                _mixed_profile(),
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/call",
                    "params": {
                        "name": f"web{NAMESPACE_SEP}safe_fetch_tool",
                        "arguments": {"url": "http://example.com"},
                    },
                },
            )

        assert called == {"tool": "safe_fetch_tool", "args": {"url": "http://example.com"}}
        assert resp["result"]["content"] == [{"type": "text", "text": "fetched"}]
        assert resp["result"]["isError"] is False

    async def test_tools_call_enforces_denylist_at_call_time(self) -> None:
        """Defense in depth: a deny-listed tool name on a valid backend must
        be rejected at call time even if the consumer somehow learned the name."""
        resp = await route_jsonrpc(
            _profile(),
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {
                    "name": f"mcp-slack{NAMESPACE_SEP}slack_dangerous",
                    "arguments": {},
                },
            },
        )
        assert resp["error"]["code"] == -32602
        assert "not permitted" in resp["error"]["message"].lower()

    async def test_tools_call_records_audit_on_success(self, tmp_path: Any) -> None:
        """Successful tools/call writes an audit row to gateway_calls."""
        import mcp_trentina_crunchtools.database as db_mod

        db_mod._db = None
        db_path = str(tmp_path / "audit_test.db")

        async def fake_call(
            _bn: str, _b: Backend, _tn: str, _args: dict[str, Any],
        ) -> BackendCall:
            return BackendCall(
                content=[{"type": "text", "text": "ok"}],
                is_error=False, structured_content=None,
            )

        tool_name = f"mcp-slack{NAMESPACE_SEP}slack_list_channels"
        with (
            patch(
                "mcp_trentina_crunchtools.gateway.router.call_backend_tool",
                side_effect=fake_call,
            ),
            patch("mcp_trentina_crunchtools.database.get_config") as mock_cfg,
        ):
            mock_cfg.return_value.db_path = db_path
            mock_cfg.return_value.ensure_db_dir = lambda: None
            await route_jsonrpc(
                _profile(),
                {
                    "jsonrpc": "2.0",
                    "id": 20,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": {}},
                },
            )

        stats = get_gateway_call_stats("testp", days=1)
        assert stats["total_calls"] == 1
        assert stats["by_tool"][0]["tool"] == "slack_list_channels"
        assert stats["by_tool"][0]["ok"] == 1
        assert stats["by_tool"][0]["errors"] == 0
        db_mod._db = None

    async def test_tools_call_records_audit_on_failure(self, tmp_path: Any) -> None:
        """Failed tools/call writes an audit row with error_message."""
        import mcp_trentina_crunchtools.database as db_mod

        db_mod._db = None
        db_path = str(tmp_path / "audit_fail_test.db")

        async def fail_call(
            _bn: str, _b: Backend, _tn: str, _args: dict[str, Any],
        ) -> BackendCall:
            raise BackendCallError("backend down")

        tool_name = f"mcp-slack{NAMESPACE_SEP}slack_list_channels"
        with (
            patch(
                "mcp_trentina_crunchtools.gateway.router.call_backend_tool",
                side_effect=fail_call,
            ),
            patch("mcp_trentina_crunchtools.database.get_config") as mock_cfg,
        ):
            mock_cfg.return_value.db_path = db_path
            mock_cfg.return_value.ensure_db_dir = lambda: None
            resp = await route_jsonrpc(
                _profile(),
                {
                    "jsonrpc": "2.0",
                    "id": 21,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": {}},
                },
            )

        assert resp["error"]["code"] == -32603
        stats = get_gateway_call_stats("testp", days=1)
        assert stats["total_calls"] == 1
        assert stats["by_tool"][0]["errors"] == 1
        db_mod._db = None

    async def test_tools_call_rejects_guarded_parameter(self) -> None:
        """Parameter guard blocks a call with a forbidden argument value."""
        p = Profile(
            name="guarded",
            auth=AuthConfig(bearer_token_env="TEST"),
            backends={
                "gws": Backend(
                    url="http://gws:8011/mcp",
                    tools_allow=["*"],
                    parameter_guards={
                        "send_gmail_message": {
                            "to": ParameterConstraint(allow=["self@example.com"]),
                        }
                    },
                ),
            },
        )
        p.auth.bearer_token = SecretStr("x")
        resp = await route_jsonrpc(
            p,
            {
                "jsonrpc": "2.0",
                "id": 30,
                "method": "tools/call",
                "params": {
                    "name": f"gws{NAMESPACE_SEP}send_gmail_message",
                    "arguments": {"to": "evil@example.com"},
                },
            },
        )
        assert resp["error"]["code"] == -32602
        assert "not in allow list" in resp["error"]["message"]

    async def test_tools_call_allowed_guarded_parameter_passes(self) -> None:
        """Parameter guard allows a call with a permitted argument value."""
        called: dict[str, Any] = {}

        async def fake_call(
            _bn: str, _b: Backend, _tn: str, _args: dict[str, Any],
        ) -> BackendCall:
            called["tool"] = _tn
            return BackendCall(
                content=[{"type": "text", "text": "sent"}],
                is_error=False, structured_content=None,
            )

        p = Profile(
            name="guarded",
            auth=AuthConfig(bearer_token_env="TEST"),
            backends={
                "gws": Backend(
                    url="http://gws:8011/mcp",
                    tools_allow=["*"],
                    parameter_guards={
                        "send_gmail_message": {
                            "to": ParameterConstraint(allow=["self@example.com"]),
                        }
                    },
                ),
            },
        )
        p.auth.bearer_token = SecretStr("x")
        with patch(
            "mcp_trentina_crunchtools.gateway.router.call_backend_tool",
            side_effect=fake_call,
        ):
            resp = await route_jsonrpc(
                p,
                {
                    "jsonrpc": "2.0",
                    "id": 31,
                    "method": "tools/call",
                    "params": {
                        "name": f"gws{NAMESPACE_SEP}send_gmail_message",
                        "arguments": {"to": "self@example.com"},
                    },
                },
            )
        assert called["tool"] == "send_gmail_message"
        assert resp["result"]["content"] == [{"type": "text", "text": "sent"}]
