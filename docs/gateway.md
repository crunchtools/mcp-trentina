# MCP Gateway

Trentina acts as a single MCP endpoint that proxies traffic to all your backend MCP servers. Instead of each agent connecting directly to 20+ servers with separate credentials and configurations, every agent talks to Trentina. One connection, one token, one policy plane.

## Why This Matters

The typical MCP deployment has agents connecting directly to backend servers. Each connection is a separate configuration entry, a separate trust relationship, and a separate attack surface. A Claude Code `settings.json` with 15 MCP servers means 15 SSH tunnels, 15 API keys, and 15 places where tool definitions bloat the context window.

Trentina collapses all of that into one chokepoint where you can enforce policy, audit calls, compress descriptions, and apply prompt injection defense — without modifying any backend server.

## How It Works

### Endpoint

Each agent connects to a profile-specific gateway endpoint:

```
POST /gateway/<profile_name>/mcp
```

All MCP operations (`tools/list`, `tools/call`) go through this single URL. The profile name determines which backends, tools, and defense settings apply.

### Backend Routing

When an agent calls a tool, Trentina parses the namespaced tool name to determine which backend handles it:

```
github__list_issues_tool
^^^^^^  ^^^^^^^^^^^^^^^^
backend   tool name
```

The gateway connects to the backend over the container network (Podman DNS), executes the call, and returns the response. The agent never talks to the backend directly.

### Backend Types

Trentina supports two backend URL schemes:

| Scheme | Description | Example |
|--------|-------------|---------|
| `http://` | Remote MCP server on the container network | `http://mcp-slack:8005/mcp` |
| `internal://` | Trentina's own tools (web quarantine, search, scan) | `internal://web` |

Both return identical wire shapes to the agent. The `internal://web` backend is how Trentina's original quarantine tools are exposed through the gateway — they're just another backend.

### Tool Namespacing

Backend tools are namespaced with a double-underscore separator to avoid collisions:

```
slack__slack_search_messages
github__list_issues_tool
gws-personal__draft_gmail_message
web__safe_fetch_tool
```

This matches the `mcp__<server>__<tool>` convention that Claude Code and other MCP clients already use.

### Configuration

Backends are configured per-profile in `profiles.yaml`:

```yaml
profiles:
  myagent:
    auth:
      bearer_token_env: TRENTINA_PROFILE_MYAGENT_TOKEN
    backends:
      web:
        url: "internal://web"
        tools_allow: ["*"]
      slack:
        url: "http://mcp-slack:8005/mcp"
        tools_allow: ["*"]
      github:
        url: "http://mcp-github:8016/mcp"
        tools_allow: ["*"]
```

### Real-World Scale

The CrunchTools deployment proxies 21 backends through Trentina, serving three agent profiles (Josui, Kagetora, Takeda) with 440+ tools total. The gateway has processed 5,700+ calls in the last 30 days with sub-5ms routing overhead on `tools/list` responses.

## Related

- [Per-Agent Profiles](profiles.md) — how profiles control backend access
- [Tool Filtering](tool-filtering.md) — allowlists and denylists per backend
- [Defense Pipeline](defense-pipeline.md) — content inspection on tool responses
- [Internal: Gateway Design](internal/gateway-design.md) — original design document for contributors
