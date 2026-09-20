"""A real MCP backend, run as a subprocess by the backend integration tests.

Deliberately NOT named ``test_*`` so pytest does not collect it.

This exists because every other test in the suite patches the transport layer
and asserts against hand-built stand-ins. That leaves the one thing the gateway
actually does -- speak MCP to another process over HTTP -- completely uncovered,
which is how a production breakage got through a fully green CI run (issue
#107). This module is the other side of a real connection.

Run as: ``python -m tests.probe_backend_server <port>``
"""

from __future__ import annotations

import sys

from fastmcp import FastMCP

mcp: FastMCP = FastMCP("probe-backend")


@mcp.tool()
def echo(text: str) -> str:
    """Echo the supplied text back to the caller."""
    return f"echo:{text}"


@mcp.tool()
def structured_echo(text: str) -> dict[str, str]:
    """Return structured content, so structured_content is exercised."""
    return {"echoed": text}


@mcp.tool()
def explode() -> str:
    """Always raise, so the is_error path is exercised."""
    raise RuntimeError("boom")


def main() -> None:
    port = int(sys.argv[1])
    mcp.run(transport="http", host="127.0.0.1", port=port, path="/mcp")


if __name__ == "__main__":
    main()
