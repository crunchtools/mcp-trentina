# Matrix Reverse Proxy

Proxy Matrix Client-Server API traffic through the gateway so agents on the internal network can communicate via Matrix without direct internet access. Agents point `MATRIX_HOMESERVER` at Trentina instead of matrix.org.

## Why This Matters

Agents that connect to Trentina for MCP tools may still have their own network access. An agent compromised by prompt injection could bypass the gateway entirely — making direct HTTP calls, exfiltrating data to arbitrary URLs, or downloading malicious payloads. The gateway controls MCP tool calls, but it doesn't control the network.

This is Simon Willison's "lethal trifecta" in action: an agent that can (1) read private data, (2) ingest untrusted content, and (3) send data out has all the ingredients for a successful exfiltration attack. Trentina already addresses #2 with the defense pipeline. Network isolation addresses #3 by eliminating the agent's ability to send data anywhere except through the gateway.

The Matrix reverse proxy is the first piece of this: agents that use Matrix for communication (e.g., agent-to-agent messaging, notifications) route that traffic through Trentina instead of connecting directly to the homeserver.

## How It Works

Trentina exposes a transparent reverse proxy at `/matrix/{path}` that forwards Matrix Client-Server API requests to the configured upstream homeserver. Matrix handles its own authentication via access tokens in request headers — the proxy doesn't inject credentials. It's a pass-through with timeout tuning for the long-poll `/sync` endpoint.

### What This Buys You

- **No direct internet for Matrix** — agents on `--network=none` can still use Matrix through the gateway
- **Centralized network egress** — all outbound traffic from agents flows through Trentina
- **Audit trail** — Matrix traffic goes through the same infrastructure as MCP calls
- **Timeout handling** — the proxy handles Matrix's long-poll `/sync` endpoint with appropriate read timeouts (120s)

## Configuration

Matrix proxying is configured in the top-level `matrix` section of `profiles.yaml`:

```yaml
matrix:
  enabled: true
  upstream: https://matrix-client.matrix.org
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Whether the Matrix proxy is active |
| `upstream` | `https://matrix-client.matrix.org` | Matrix homeserver to forward to |

The upstream must use HTTPS.

### Agent Configuration

Point the agent's Matrix client at Trentina instead of the homeserver:

```bash
# Instead of:
MATRIX_HOMESERVER=https://matrix.org

# Use:
MATRIX_HOMESERVER=http://trentina:8019/matrix
```

All Matrix Client-Server API operations (`/sync`, `/rooms`, `/send`, etc.) are forwarded transparently.

### Architecture

```
┌─────────────────────┐    /matrix/*    ┌─────────────────────┐    HTTPS     ┌──────────┐
│  Agent (no network)  │ ──────────────► │  Trentina Gateway   │ ──────────► │  Matrix  │
│                      │                │                     │             │ Homeserver│
│  MATRIX_HOMESERVER   │ ◄────────────── │  Timeout tuning     │ ◄────────── │          │
│  = trentina:8019     │                │  Transparent proxy  │             └──────────┘
└─────────────────────┘                └─────────────────────┘
                                               │
                                    ┌──────────┼──────────┐
                                    ▼          ▼          ▼
                               MCP backends  LLM APIs  Web content
```

### Full Network Isolation Pattern

For complete network isolation, combine with the [LLM key proxy](llm-proxying.md) and run the agent container with `--network=none` plus a sidecar that only reaches Trentina:

1. **MCP tools** → `http://trentina:8019/gateway/<profile>/mcp`
2. **LLM calls** → `http://trentina:8019/llm/<provider>/<path>`
3. **Matrix** → `http://trentina:8019/matrix/<path>`

The agent has no other network access. Every outbound request goes through Trentina's controlled, audited gateway.

## Related

- [LLM Key Proxying](llm-proxying.md) — isolating model API keys from agents
- [MCP Gateway](gateway.md) — the gateway architecture this extends
- [Defense Pipeline](defense-pipeline.md) — content inspection applied to all proxied responses
