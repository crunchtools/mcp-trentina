# Trentina

<!-- mcp-name: io.github.crunchtools/trentina -->

Trentina is a secure MCP gateway that inspects everything between your AI agents and the outside world — web content, MCP tool responses and tool definitions, Matrix messages, LLM completions, and monitoring alerts — through a [three-layer defense pipeline](docs/defense-pipeline.md) at every ingress, with per-profile enforcement (annotate, extract, or block) and a full audit trail. Content is never silently modified: what your agent reads is what actually arrived, plus Trentina's verdict. (E2EE Matrix rooms are ciphertext at the gateway and outside what any proxy can defend.) Named after the 1377 quarantine system from Ragusa, where incoming ships had to anchor offshore for thirty days before anyone was allowed into the city. Same idea: keep the commerce flowing without letting something dangerous through.

## Capabilities

### [MCP Gateway](docs/gateway.md)

Single chokepoint between your agents and all their MCP backends. One endpoint, one bearer token, one audit log — instead of each agent connecting directly to dozens of MCP servers. Backend tools are namespaced automatically (`slack__slack_search_messages`, `github__list_issues_tool`) so there are no collisions.

### [Authentication](docs/authentication.md)

Four ways a client can prove who it is, chosen per profile: a static bearer token, an OAuth identity Trentina issues while proxying login to Google (with dynamic client registration or a provisioned confidential client), or a token minted by an external identity provider that Trentina only verifies — for connectors that will not authenticate against a third-party authorization server.

### [Per-Agent Profiles](docs/profiles.md)

Each consumer — Claude Code, Hermes, OpenClaw, or any MCP client — gets its own profile with independent tool access, defense settings, and authentication. Your human-supervised agent can have full tool access while your autonomous agent gets a locked-down subset, all through the same gateway.

### [Tool Allowlists & Denylists](docs/tool-filtering.md)

Control which tools each agent can even see. Tools not in the allowlist are stripped from `tools/list` responses before they reach the consumer — they never enter the agent's context window. Supports exact names and glob patterns (`delete*`, `*_gmail_*`). Reduces both context cost and attack surface.

### [Parameter Guards](docs/parameter-guards.md)

Per-tool argument validation at the gateway level. Restrict *what values* an agent can pass, not just which tools it can call. Example: "this agent can send email, but only to `user@example.com`." The call is rejected before it reaches the backend — no tokens spent, no side effects. Deterministic enforcement that doesn't depend on LLM behavior.

### [Response Guards](docs/response-guards.md)

The egress half of parameter guards: the same allow/deny constraint applied to what a backend *returns*, before the result is reduced, scanned or relayed. Argument-side matching cannot cover a semantic tool — an agent asking a memory server for "my employer's roadmap" sends nothing matchable, and the restricted material arrives in the response. Deny-oriented, blocks the whole response rather than scrubbing it, and audited as policy rather than failure.

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
| [Authentication](docs/authentication.md) | Static bearer, OAuth proxy, delegated issuers |
| [Per-Agent Profiles](docs/profiles.md) | Profile schema, multi-agent setup |
| [Tool Filtering](docs/tool-filtering.md) | Allowlists, denylists, glob patterns |
| [Parameter Guards](docs/parameter-guards.md) | Per-tool argument validation |
| [Response Guards](docs/response-guards.md) | Per-tool result validation (egress) |
| [Defense Pipeline](docs/defense-pipeline.md) | L1/L2/L3 layers, coverage matrix |
| [Description Compression](docs/compression.md) | LLM-powered context reduction |
| [Audit Log](docs/audit-log.md) | Call recording, stats, monitoring |
| [Blocklist](docs/blocklist.md) | Cumulative detection memory |
| [Quarantine Tools](docs/quarantine-tools.md) | Web fetch, read, search, scan |
| [LLM Key Proxying](docs/llm-proxying.md) | API key isolation via reverse proxy |
| [Matrix Reverse Proxy](docs/network-isolation.md) | Agent communication via Matrix |
| [Cockpit Plugin](docs/cockpit-plugin.md) | Live defense pipeline dashboard |
| [Internal: Gateway Design](docs/internal/gateway-design.md) | Original design document for contributors |

## Environment Variables

Trentina reads its gateway, profile and backend configuration from a YAML file;
these variables control the process itself. Profile tokens
(`TRENTINA_PROFILE_<NAME>_TOKEN`) and provider API keys are covered in
[Per-Agent Profiles](docs/profiles.md) and [LLM Key Proxying](docs/llm-proxying.md).

| Variable | Default | Description |
|----------|---------|-------------|
| `TRENTINA_LOG_LEVEL` | `INFO` | Application log level, sent to stderr. Any standard Python level name. |
| `TRENTINA_GATEWAY_ENABLED` | unset (disabled) | Turns on the MCP gateway (profiles, auth, allowlists, audit). See [MCP Gateway](docs/gateway.md). |
| `TRENTINA_PROFILES_PATH` | `/etc/trentina/profiles.yaml` | Path to the gateway's profile YAML file. See [Per-Agent Profiles](docs/profiles.md). |
| `TRENTINA_LEGACY_MCP` | unset (disabled) | Restores the pre-gateway unguarded `/mcp` endpoint. **Bypasses auth, allowlists and audit** — migration aid only. See [MCP Gateway](docs/gateway.md). |
| `TRENTINA_MODEL_PROVIDER` | `gemini` | Global LLM provider for L3 Q-Agent and tool-description compression, overridable per-profile. See [Per-Agent Profiles](docs/profiles.md). |
| `TRENTINA_PROVIDER_FALLBACK` | unset (none) | Comma-separated provider names to fall back to if `TRENTINA_MODEL_PROVIDER` is unavailable. |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Base URL for the Ollama provider. |
| `OLLAMA_MODEL` | `qwen2.5:0.5b` | Model used when the Ollama provider is selected. See [LLM Key Proxying](docs/llm-proxying.md). |
| `QUARANTINE_MODEL` | `gemini-2.5-flash-lite` | Model used for quarantine agent (L3) extraction/detection calls. |
| `QUARANTINE_SEARCH_MODEL` | `gemini-2.5-flash` | Model used for grounded L0 search. |
| `QUARANTINE_FALLBACK` | `layer1` | Behavior when the LLM provider is unavailable during quarantine processing. |
| `QUARANTINE_MAX_CONTENT` | `100000` | Max characters of content sent to the quarantine LLM per call. See [Token Routing](docs/token-routing.md). |
| `CLASSIFIER_THRESHOLD` | `0.5` | Malicious-score threshold above which the L2 classifier flags content. |
| `CLASSIFIER_MODEL_PATH` | `/models/prompt-guard-2-86m` | Filesystem path to the ONNX classifier model. Set to `/models/prompt-guard-2-86m` by the container image. |
| `CLASSIFIER_MAX_TOKENS` | `32768` | Max tokens the L2 classifier will scan before truncating. |
| `CLASSIFIER_THREADS` | `4` | ONNX Runtime intra-op thread count for the L2 classifier. |
| `QUARANTINE_DB` | `~/.local/share/mcp-trentina/trentina.db` (container: `/data/quarantine.db`) | Path to the main SQLite database (blocklist, audit log). See [Audit Log](docs/audit-log.md) and [Blocklist](docs/blocklist.md). |
| `TRENTINA_PERIMETER_DB` | `<QUARANTINE_DB's directory>/perimeter.db` | Path to the perimeter verdict-cache database, deliberately separate from `QUARANTINE_DB`. |
| `QUARANTINE_TRUST_CONFIG` | `~/.config/mcp-env/mcp-trentina-trust.json` | Path to the trust-level configuration JSON. See [Quarantine Tools](docs/quarantine-tools.md). |

## Development

```bash
uv sync --all-extras
uv run ruff check src tests
uv run mypy src
uv run pytest -v
```

The container image is built by the GHA pipeline
([`container.yml`](.github/workflows/container.yml)), never locally. The model-export
stage needs a gated HuggingFace credential that only CI holds, and building outside
the pipeline causes drift. Push the branch and let the pipeline verify the image.

## License

AGPL-3.0-or-later
