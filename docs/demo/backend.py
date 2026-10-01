"""A stand-in Google Workspace MCP backend for the README demo.

It serves the real tool definitions of google_workspace_mcp (MIT,
https://github.com/taylorwilsdon/google_workspace_mcp), captured verbatim
from the Crunchtools deployment into fixtures/workspace-tools.json, so the
"offered" side of the demo is what an agent connected straight to that
server would pay for. Calls are answered from canned data: nothing here
touches Google.

    python backend.py            # streamable HTTP on 0.0.0.0:8000/mcp
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import uvicorn
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.transport_security import TransportSecuritySettings

TOOLS = json.loads((Path(__file__).parent / "fixtures" / "workspace-tools.json").read_text())

PORT = 8000
INBOX = [
    {"id": "18f2a1", "from": "chef@example.org", "subject": "Saturday's menu"},
    {"id": "18f2a2", "from": "school@example.org", "subject": "Field trip form"},
]


async def _list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
    return types.ListToolsResult(tools=[types.Tool(**t) for t in TOOLS])


async def _call_tool(_ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
    args = dict(params.arguments or {})
    if params.name == "search_gmail_messages":
        text = json.dumps({"messages": INBOX, "query": args.get("query", "")})
    elif params.name == "draft_gmail_message":
        text = f"Draft created. Draft ID: r-4821. Subject: {args.get('subject', '')}"
    elif params.name == "send_gmail_message":
        text = f"Message sent to {args.get('to', '')}. Message ID: 18f2b9"
    else:
        text = f"{params.name}: ok"
    # The real server is fastmcp, which wraps every result as {"result": ...}
    # and declares that outputSchema; a client holds it to the schema.
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)],
        structuredContent={"result": text},
    )


server = Server("google-workspace", on_list_tools=_list_tools, on_call_tool=_call_tool)
app = server.streamable_http_app(
    host="0.0.0.0",  # noqa: S104 -- a demo container on its own network
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="warning")  # noqa: S104
