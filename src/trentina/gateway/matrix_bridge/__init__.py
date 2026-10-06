"""Matrix E2EE termination, gateway side (#162, spec 015).

The bridge process (``..bridge``) holds the upstream identity and hands the
gateway plaintext. This package judges every event in both directions and is
the only writer into the agent's local homeserver.
"""

from .routes import register_bridge_routes

__all__ = ["register_bridge_routes"]
