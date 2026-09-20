"""Gateway-specific error types.

Error messages here are deliberately terse. They never disclose bearer-token
content, profile contents beyond the profile name, or backend connection
details to the consumer. Detail goes to the structured log only.
"""

from __future__ import annotations


class GatewayError(Exception):
    """Base class for gateway errors."""


class ProfileConfigError(GatewayError):
    """Raised at startup when the profiles YAML is missing or invalid.

    Gateway routes are not mounted if profile loading fails while
    TRENTINA_GATEWAY_ENABLED is true. Fails closed.
    """


class AuthError(GatewayError):
    """Raised on missing, malformed, or mismatched bearer token.

    Maps to HTTP 401 with no body detail beyond a fixed string.
    """


class ProfileNotFoundError(GatewayError):
    """Raised when a request targets a profile not in the loaded registry.

    Maps to HTTP 404.
    """


class BackendNotInProfileError(GatewayError):
    """Raised when a tool call targets a backend not present in the profile.

    Maps to JSON-RPC error -32602 (invalid params).
    """


class ScopeError(GatewayError):
    """Raised when a caller asks an admin tool for something outside its role.

    Covers three refusals, all of which are answered the same way — say no,
    name nothing: no calling profile is bound to the call, the action needs the
    operator role, or the named backend is not in the caller's own profile. The
    message never names another profile or its backends, so a refusal is not an
    existence oracle for the rest of the gateway.
    """


class BackendCallError(GatewayError):
    """Raised when a backend MCP call fails (network, timeout, malformed response).

    Maps to JSON-RPC error -32603 (internal error) and HTTP 502 to the consumer.
    """
