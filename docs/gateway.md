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

#### The legacy `/mcp` endpoint

Earlier versions served Trentina's full tool surface at a bare `/mcp` with no
bearer token, no allowlist and no audit -- a bypass of everything the gateway
enforces. It is disabled by default: `/mcp` answers `410` with directions, and
FastMCP's own MCP app is mounted at a per-boot unguessable path instead.

Setting `TRENTINA_LEGACY_MCP` to a truthy value restores the old unguarded
`/mcp` for consumers that have not migrated. It logs a warning at startup.
Treat it as a temporary migration aid: anything reaching Trentina through it
is not inspected, not allowlisted and not audited. Migrate consumers to
`/gateway/<profile>/mcp` and unset the variable.

### Sessions and restarts

`initialize` issues an `Mcp-Session-Id`. Sessions live in memory, so every
gateway restart ends all of them. A client that sends a session id the gateway
no longer holds gets a `404` whose body is a JSON-RPC error: code `-32001`, and
a message saying why (TTL expiry, eviction, teardown, or "never issued by this
gateway process") and telling it to re-initialize. An `initialize` that still
carries the stale header is accepted and gets a new session. A client that
recovers on its own therefore never needs a human after a deploy.

Claude Code re-initializes on a `404` to a POST, so a stale session is
invisible to it. If a client reports "timed out" right after a restart, the
session isn't the cause. Look at how long the first `tools/list` took: a cold
perimeter store makes that call judge every tool description (see the startup
`caches loaded` line).

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
| `http://` | Remote MCP server on the container network | `http://mcp-slack:8000/mcp` |
| `internal://` | Trentina's own tools (web quarantine, search, scan) | `internal://web` |

Both return identical wire shapes to the agent. The `internal://web` backend is how Trentina's original quarantine tools are exposed through the gateway — they're just another backend.

### Results

A proxied result reaches the agent as the backend sent it, less two kinds of
bytes the agent would pay for and not read (0.38.0):

- **The repeated copy.** FastMCP servers return every value twice: as a text
  block and as `structuredContent`. When `structuredContent` is exactly the one
  text block again, as JSON or as `{"result": ...}`, it is dropped before
  pre-processing and the scan, so what the perimeter judges is what is
  delivered. Anything else, including a structured copy that differs in one
  value, is kept and judged. Response guards run on the result as it arrived.
- **Minified text.** The text blocks go through the profile's pre-processors,
  `detect` by default, unless the call passes `trentina_preprocess: false`.
  See [Minifying and exact text](profiles.md#minifying-and-exact-text).

### Tool Names

Since 0.38.0 each tool is served under the simplest name that says what it
does (`gateway/names.py`), not `<backend>__<tool>`:

| Backend tool | Served as |
|---|---|
| `jira` / `jira_get_issue_watchers` | `get_issue_watchers` |
| `cloudflare` / `list_zones_tool` | `list_zones` |
| `memory` / `memory_store` | `memory_store` |
| `mail-work` / `send_gmail_message` | `work_send_gmail_message` |
| `mail-home` / `send_gmail_message` | `home_send_gmail_message` |

The rule: drop a trailing `_tool`; drop the leading words every tool of the
backend shares, unless one word would be all that is left; and where two
backends' tools still collide, prefix each with the backend's tag
(`name_tag`, else the backend name). Tags, not numbers: `work_` and
`home_` tell an agent which account it is about to send mail from, and
`send_gmail_message2` would not. On a 376-tool profile this took the names from 10.2 KB
to 6.3 KB, before a client adds its own prefix.

A name, once issued to a profile, is recorded and never reassigned, so adding
a backend later cannot rename a tool an agent already knows: the newcomer
takes the tag. Only the edge sees short names. Allowlists, parameter guards,
`preprocess_tools`, the verdict cache and the audit log all keep using the real
backend and tool names.

`<backend>__<tool>` still routes, with a warning, until 0.40.0.
`short_names: false` on a profile serves the old form.

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
        url: "http://mcp-slack:8000/mcp"
        tools_allow: ["*"]
      github:
        url: "http://mcp-github:8000/mcp"
        tools_allow: ["*"]
```

Changes to `profiles.yaml` take effect on the next `reload_profiles` call or
gateway restart — there is no file watcher. What one call applies depends on
the caller's `role`: an agent profile applies its own section, an operator the
whole file. See [Roles](profiles.md#roles) and
[Applying a Change](profiles.md#applying-a-change).

### Real-World Scale

The CrunchTools deployment proxies 21 backends through Trentina, serving three agent profiles (agent2, agent1, agent3) with 440+ tools total. The gateway has processed 5,700+ calls in the last 30 days with sub-5ms routing overhead on `tools/list` responses.

## Related

- [Per-Agent Profiles](profiles.md) — how profiles control backend access
- [Tool Filtering](tool-filtering.md) — allowlists and denylists per backend
- [Defense Pipeline](defense-pipeline.md) — content inspection on tool responses
- [Internal: Gateway Design](internal/gateway-design.md) — original design document for contributors
