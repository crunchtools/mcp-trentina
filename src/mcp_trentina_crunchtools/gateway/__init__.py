"""Gateway subpackage — per-consumer MCP proxy with tool-allowlist filtering.

Phase 2 scope: Streamable HTTP transport with session persistence and
``tools/listChanged`` notifications on circuit breaker state changes.
Builds on Phase 1 (profile loader, bearer-token auth, JSON-RPC dispatch,
tool-name allowlist filter, tools/call passthrough).

See docs/gateway-design.md and .specify/specs/006-gateway-mode/ for the
full design and phase plan.
"""

from __future__ import annotations

from .app import gateway_app, register_with_fastmcp
from .auth import verify_bearer
from .backend import BackendCall, call_backend_tool, list_backend_tools
from .circuit import CircuitBreaker, breaker
from .errors import AuthError, GatewayError, ProfileConfigError
from .filter import filter_tools
from .guards import check_parameter_guards
from .internal import (
    call_internal_tool,
    internal_server_registered,
    list_internal_tools,
    register_internal_server,
)
from .loader import GatewayConfig, load_profiles
from .profile import AuthConfig, Backend, DefenseConfig, ParameterConstraint, Profile
from .router import route_jsonrpc
from .sessions import Session, SessionRegistry, session_registry

__all__ = [
    "AuthConfig",
    "AuthError",
    "Backend",
    "BackendCall",
    "CircuitBreaker",
    "DefenseConfig",
    "ParameterConstraint",
    "GatewayConfig",
    "GatewayError",
    "Profile",
    "ProfileConfigError",
    "breaker",
    "check_parameter_guards",
    "call_backend_tool",
    "call_internal_tool",
    "filter_tools",
    "gateway_app",
    "internal_server_registered",
    "list_backend_tools",
    "list_internal_tools",
    "load_profiles",
    "register_internal_server",
    "register_with_fastmcp",
    "route_jsonrpc",
    "Session",
    "SessionRegistry",
    "session_registry",
    "verify_bearer",
]
