#!/usr/bin/env python3
"""What a gateway profile costs an agent in context, by part (0.38.0).

Pulls one profile's ``tools/list`` and reports where its bytes go: names,
titles, tool descriptions, parameter descriptions, the gateway's own
``trentina_*`` parameters, output schemas and the rest. With ``--call`` it
also runs tool calls and reports each result's size, minified and exact
(``trentina_preprocess: false``).

Standard library only, so it runs on the gateway host without a venv:

    ssh host01 'set -a; . /srv/.../mcp-trentina.env; \
        python3 - --profile agent1' < benchmarks/token_budget.py

The bearer token is read from ``TRENTINA_PROFILE_<PROFILE>_TOKEN`` and never
printed. Bytes are exact; tokens are a rough estimate at ``--bytes-per-token``
(default 4, the usual rule of thumb for English and JSON), for scale only.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import sys
from typing import Any
from urllib.parse import urlsplit

_ACCEPT = "application/json, text/event-stream"


def rpc(base: str, path: str, token: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
    """One JSON-RPC call. http.client follows no redirect, so the token stays put."""
    url = urlsplit(base)
    conn_type = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    conn = conn_type(url.netloc, timeout=600)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    conn.request(
        "POST",
        path,
        body=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": _ACCEPT,
        },
    )
    raw = conn.getresponse().read().decode()
    conn.close()
    if raw.lstrip().startswith("{"):
        return json.loads(raw)
    events = [ln[5:].strip() for ln in raw.splitlines() if ln.startswith("data:")]
    return json.loads(events[-1])


def _size(value: Any) -> int:
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode())


def _param_descriptions(schema: Any) -> int:
    """Bytes of every ``description`` string under a schema's properties."""
    total = 0
    if isinstance(schema, dict):
        for key, value in schema.items():
            if key == "description" and isinstance(value, str):
                total += len(value.encode())
            else:
                total += _param_descriptions(value)
    elif isinstance(schema, list):
        total += sum(_param_descriptions(v) for v in schema)
    return total


def breakdown(tools: list[dict[str, Any]]) -> dict[str, int]:
    """Bytes of the serialized list, split by the part that spends them."""
    parts = dict.fromkeys(
        (
            "names",
            "titles",
            "descriptions",
            "param_descriptions",
            "trentina_params",
            "output_schemas",
            "annotations",
        ),
        0,
    )
    for tool in tools:
        parts["names"] += len(tool.get("name", "").encode())
        parts["titles"] += len(str(tool.get("title") or "").encode())
        parts["descriptions"] += len(str(tool.get("description") or "").encode())
        props = (tool.get("inputSchema") or {}).get("properties") or {}
        gateway = {k: v for k, v in props.items() if k.startswith("trentina_")}
        parts["trentina_params"] += _size(gateway) if gateway else 0
        rest = {k: v for k, v in props.items() if not k.startswith("trentina_")}
        parts["param_descriptions"] += _param_descriptions(rest)
        parts["param_descriptions"] += _param_descriptions(
            (tool.get("inputSchema") or {}).get("$defs") or {}
        )
        if "outputSchema" in tool:
            parts["output_schemas"] += _size(tool["outputSchema"])
        if "annotations" in tool:
            parts["annotations"] += _size(tool["annotations"])
    total = _size(tools)
    parts["other_structure"] = total - sum(parts.values())
    parts["total"] = total
    return parts


def _call(base: str, path: str, token: str, spec: str, exact: bool) -> int:
    name, _, args = spec.partition("=")
    arguments = json.loads(args or "{}")
    if exact:
        arguments["trentina_preprocess"] = False
    reply = rpc(base, path, token, "tools/call", {"name": name, "arguments": arguments})
    return _size(reply.get("result", reply.get("error")))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--profile", required=True)
    parser.add_argument("--base", default="http://127.0.0.1:8019")
    parser.add_argument("--bytes-per-token", type=float, default=4.0)
    parser.add_argument(
        "--call",
        action="append",
        default=[],
        metavar='NAME={"arg":1}',
        help="a tool call to size, minified and exact; repeatable",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    ns = parser.parse_args()

    token = os.environ.get(f"TRENTINA_PROFILE_{ns.profile.upper().replace('-', '_')}_TOKEN")
    if not token:
        print(f"no token for profile {ns.profile}", file=sys.stderr)
        return 2
    path = f"/gateway/{ns.profile}/mcp"
    tools = rpc(ns.base, path, token, "tools/list", {})["result"]["tools"]
    report: dict[str, Any] = {"profile": ns.profile, "tools": len(tools), "list": breakdown(tools)}
    report["calls"] = {
        spec: {
            "minified": _call(ns.base, path, token, spec, exact=False),
            "exact": _call(ns.base, path, token, spec, exact=True),
        }
        for spec in ns.call
    }
    if ns.json:
        print(json.dumps(report, indent=1))
        return 0
    print(f"{ns.profile}: {len(tools)} tools")
    for part, size in report["list"].items():
        print(f"  {part:<20} {size:>9,} B  ~{size / ns.bytes_per_token:>8,.0f} tok")
    for name, sizes in report["calls"].items():
        print(f"  call {name}: minified {sizes['minified']:,} B, exact {sizes['exact']:,} B")
    return 0


if __name__ == "__main__":
    sys.exit(main())
