# Trentina

<!-- mcp-name: io.github.crunchtools/trentina -->

Trentina is a secure MCP gateway that quarantines everything between your AI agents and the outside world — web content, MCP tool responses, LLM API keys, network access, and agent-to-agent communication. Named after the 1377 quarantine system from Ragusa, where incoming ships had to anchor offshore for thirty days before anyone was allowed into the city. Same idea: keep the commerce flowing without letting something dangerous through.

## Capabilities

### [MCP Gateway](docs/gateway.md)

Single chokepoint between your agents and all their MCP backends. One endpoint, one bearer token, one audit log — instead of each agent connecting directly to dozens of MCP servers. Backend tools are namespaced automatically (`slack__slack_search_messages`, `github__list_issues_tool`) so there are no collisions.

### [Per-Agent Profiles](docs/profiles.md)

Each consumer — Claude Code, Hermes, OpenClaw, or any MCP client — gets its own profile with independent tool access, defense settings, and authentication. Your human-supervised agent can have full tool access while your autonomous agent gets a locked-down subset, all through the same gateway.

### [Tool Allowlists & Denylists](docs/tool-filtering.md)

Control which tools each agent can even see. Tools not in the allowlist are stripped from `tools/list` responses before they reach the consumer — they never enter the agent's context window. Supports exact names and glob patterns (`delete*`, `*_gmail_*`). Reduces both context cost and attack surface.

### [Parameter Guards](docs/parameter-guards.md)

Per-tool argument validation at the gateway level. Restrict *what values* an agent can pass, not just which tools it can call. Example: "this agent can send email, but only to `user@example.com`." The call is rejected before it reaches the backend — no tokens spent, no side effects. Deterministic enforcement that doesn't depend on LLM behavior.

### [Three-Layer Defense Pipeline](docs/defense-pipeline.md)

Every piece of untrusted content passes through three independent detection layers. Layer 1 strips structural attacks (hidden HTML, invisible Unicode, encoded payloads, exfiltration URLs). Layer 2 runs a Prompt Guard 2 86M classifier to catch instruction overrides. Layer 3 hands sanitized content to a quarantined LLM (Gemini Flash Lite) for semantic analysis — no tools, no memory, minimal blast radius. Each layer catches what the others miss.

### [Tool Description Compression](docs/compression.md)

MCP servers ship verbose tool descriptions that waste context tokens. Trentina uses an LLM to compress every tool description as it passes through the gateway, caching results in SQLite so the model is only called once per unique description. Real-world results: 154 tools compressed from 62K to 17K characters (72% reduction), saving ~11K tokens per session. The compressed descriptions are fully functional — agents use them without issue.

### [Gateway Audit Log](docs/audit-log.md)

Every tool call through the gateway is recorded in SQLite with profile, backend, tool name, success/failure, duration, and error message. The `quarantine_stats` tool exposes this data for monitoring — tool call counts, error rates, per-backend breakdowns. Data-driven evidence for tightening allowlists and identifying problems.

### [Cumulative Detection Memory](docs/blocklist.md)

When Trentina detects prompt injection in a source, it records the source in a SQLite blocklist. Future requests for that source trigger an immediate warning — the system remembers what it's seen before. Blocklist entries include the source URL or content hash, detection timestamp, and risk level.

### [Web Content Quarantine Tools](docs/quarantine-tools.md)

Trentina's original capability: safe web fetching, file reading, and web search with prompt injection defense. `safe_fetch` fails on injection. `quarantine_fetch` warns but proceeds, extracting content through the Q-Agent. `quarantine_search` chains Gemini grounding with the full defense pipeline. `quarantine_scan` does pre-flight detection without returning content.

### [LLM Key Proxying](docs/llm-proxying.md)

Proxy LLM API calls (Gemini, OpenAI, Anthropic) through the gateway so API keys never leave the trusted boundary. Agents send model requests to Trentina, which forwards them with the real credentials. Adding a new provider is a YAML entry, not code. Streaming and non-streaming responses are forwarded transparently.

### [Matrix Reverse Proxy](docs/network-isolation.md)

Proxy Matrix Client-Server API traffic through the gateway so agents on the internal network can communicate via Matrix without direct internet access. Agents point `MATRIX_HOMESERVER` at Trentina instead of matrix.org. Long-poll `/sync` timeouts are tuned automatically.

### [Cockpit Plugin](docs/cockpit-plugin.md)

Live web dashboard for the defense pipeline, built as a Cockpit plugin with PatternFly 6. Shows layer status, blocklist entries, and pipeline events in real time through the same web console sysadmins already use to manage RHEL systems. Vanilla JavaScript, no React, no build step.

## Quick Start

```bash
# PyPI
pip install mcp-trentina-crunchtools

# uvx (zero-install)
uvx mcp-trentina-crunchtools

# Container (includes Prompt Guard 2 86M classifier)
podman run quay.io/crunchtools/mcp-trentina
```

### Minimal Configuration

```bash
# Required for Layer 3 (Q-Agent) and description compression
export GEMINI_API_KEY=your-key

# Enable gateway mode
export TRENTINA_GATEWAY_ENABLED=true
export TRENTINA_PROFILES_PATH=/path/to/profiles.yaml

# Per-profile bearer tokens
export TRENTINA_PROFILE_MYAGENT_TOKEN=your-token
```

### Claude Code

```json
{
  "mcpServers": {
    "trentina": {
      "type": "streamable-http",
      "url": "http://localhost:8019/gateway/myprofile/mcp",
      "headers": {
        "Authorization": "Bearer your-token"
      }
    }
  }
}
```

## Documentation

| Document | Description |
|----------|-------------|
| [MCP Gateway](docs/gateway.md) | Architecture, routing, namespacing |
| [Per-Agent Profiles](docs/profiles.md) | Authentication, profile schema, multi-agent setup |
| [Tool Filtering](docs/tool-filtering.md) | Allowlists, denylists, glob patterns |
| [Parameter Guards](docs/parameter-guards.md) | Per-tool argument validation |
| [Defense Pipeline](docs/defense-pipeline.md) | L1/L2/L3 layers, coverage matrix |
| [Description Compression](docs/compression.md) | LLM-powered context reduction |
| [Audit Log](docs/audit-log.md) | Call recording, stats, monitoring |
| [Blocklist](docs/blocklist.md) | Cumulative detection memory |
| [Quarantine Tools](docs/quarantine-tools.md) | Web fetch, read, search, scan |
| [LLM Key Proxying](docs/llm-proxying.md) | API key isolation via reverse proxy |
| [Matrix Reverse Proxy](docs/network-isolation.md) | Agent communication via Matrix |
| [Cockpit Plugin](docs/cockpit-plugin.md) | Live defense pipeline dashboard |
| [Internal: Gateway Design](docs/internal/gateway-design.md) | Original design document for contributors |

## Development

```bash
uv sync --all-extras
uv run ruff check src tests
uv run mypy src
uv run pytest -v
podman build -f Containerfile .
```

## License

AGPL-3.0-or-later
