# Per-Agent Profiles

Every agent that connects to Trentina gets its own profile. A profile defines which backends the agent can access, which tools it can see, what defense layers run on responses, and how it authenticates. Different agents get different levels of trust through the same gateway.

## Why This Matters

You don't give a human-supervised IDE agent the same permissions as an autonomous agent running unattended. The IDE agent might need full Gmail access — it has a human watching every tool call. The autonomous agent should probably only read email and draft responses, never send. Without per-agent profiles, you're stuck choosing between "too open" and "too restrictive" for everyone.

## Profile Schema

Profiles are defined in YAML, typically at `/etc/trentina/profiles.yaml` or wherever `TRENTINA_PROFILES_PATH` points:

```yaml
profiles:
  josui:
    auth:
      bearer_token_env: TRENTINA_PROFILE_JOSUI_TOKEN
    backends:
      web:
        url: "internal://web"
        tools_allow: ["*"]
      slack:
        url: "http://mcp-slack:8005/mcp"
        tools_allow: ["*"]
      gws-personal:
        url: "http://gws-personal:8011/mcp"
        tools_allow: ["*"]
        tools_deny: ["delete*"]
        compress_descriptions: true
    defense:
      sanitize: true
      classify: true
      classify_threshold: 0.5
      quarantine: true

  kagetora:
    auth:
      bearer_token_env: TRENTINA_PROFILE_KAGETORA_TOKEN
    backends:
      web:
        url: "internal://web"
        tools_allow: ["*"]
      gws-personal:
        url: "http://gws-personal:8011/mcp"
        tools_allow:
          - search_gmail_messages
          - get_gmail_message_content
          - draft_gmail_message
        compress_descriptions: true
    defense:
      sanitize: true
      classify: true
      classify_threshold: 0.3
      quarantine: false
```

## Authentication

Each profile authenticates via bearer token. The token value is read from an environment variable — never from the YAML file:

```bash
# Token env vars (set in your env file, not profiles.yaml)
TRENTINA_PROFILE_JOSUI_TOKEN=your-secret-token
TRENTINA_PROFILE_KAGETORA_TOKEN=another-secret-token
```

The agent sends the token in the `Authorization` header:

```
Authorization: Bearer your-secret-token
```

Trentina matches the token to a profile. No token or wrong token = 401.

## Multi-Agent Deployment

A typical deployment serves multiple agents with different trust levels:

| Profile | Agent Type | Tool Count | Defense | Use Case |
|---------|-----------|------------|---------|----------|
| josui | Claude Code (human-supervised) | 440+ | L1+L2+L3 | Full access, human in the loop |
| kagetora | Hermes (autonomous) | ~210 | L1+L2 only | Tightened allowlists, no L3 (token cost) |
| takeda | OpenClaw (chat agent) | ~440 | L1+L2+L3 | Full access, different auth context |

All three connect to the same Trentina instance on the same port. The profile name in the URL determines everything:

```
http://trentina:8019/gateway/josui/mcp
http://trentina:8019/gateway/kagetora/mcp
http://trentina:8019/gateway/takeda/mcp
```

## Defense Settings

Each profile configures its own defense pipeline:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `sanitize` | bool | `true` | Layer 1 — deterministic sanitization |
| `classify` | bool | `true` | Layer 2 — Prompt Guard 2 classifier |
| `classify_threshold` | float | `0.5` | L2 confidence threshold (lower = more aggressive) |
| `quarantine` | bool | `true` | Layer 3 — Q-Agent semantic analysis |

An autonomous agent might set `classify_threshold: 0.3` (flag more aggressively) and `quarantine: false` (skip L3 to save tokens). A human-supervised agent can afford `quarantine: true` since L3 only fires when L2 flags something.

## Backend Headers

Some backends require their own authentication. Pass headers per-backend:

```yaml
backends:
  memory:
    url: "http://mcp-memory:8006/mcp"
    headers:
      Authorization: "Bearer ${MCP_MEMORY_API_KEY}"
```

Environment variables in header values are expanded at request time.

## Related

- [MCP Gateway](gateway.md) — how the gateway routes calls to backends
- [Tool Filtering](tool-filtering.md) — allowlist/denylist configuration
- [Parameter Guards](parameter-guards.md) — argument-level restrictions
- [Defense Pipeline](defense-pipeline.md) — L1/L2/L3 configuration details
