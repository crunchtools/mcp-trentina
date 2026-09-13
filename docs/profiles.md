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
      enforcement: annotate
      l2_threshold: 0.5
      l3_threshold: 0.7

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
      enforcement: block      # autonomous agent: flagged content is refused
      l2_threshold: 0.3       # stricter classifier gate
      l3_threshold: 0.7
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

Each profile configures its defense **policy** — never the layers' existence. All three layers run for every profile; there are deliberately no per-layer off switches (an earlier schema had them, and `quarantine: false` ran in production for months without the operator knowing). What a profile controls:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enforcement` | string | `annotate` | What a flagged response becomes: `annotate` (delivered intact + warning — the calibration mode), `block` (refused — autonomous agents), `extract` (Q-Agent rewrite — interactive agents) |
| `l2_threshold` | float | `0.5` | L2 score at/above which content is flagged, in addition to the model's own MALICIOUS label. Lower = stricter. |
| `l3_threshold` | float | `0.7` | L2 score at/above which L3 reviews the content. L3 also always fires on model-output provenance and on any suspicious L1 detection. Raise it to spend less on L3. |
| `audit` | bool | `true` | Write detection rows to SQLite |
| `provider` | string | `null` | LLM provider override (`gemini`, `openai`, `anthropic`, `ollama`) |

An autonomous agent runs `enforcement: block` with a strict `l2_threshold`; a human-supervised agent runs `extract` or `annotate`. `TRENTINA_ENFORCEMENT_OVERRIDE=annotate` is the global kill switch for the night a block threshold misfires.

The `provider` field lets each profile use a different LLM for L3 Q-Agent operations and tool description compression. When omitted, the profile uses the global `TRENTINA_MODEL_PROVIDER` environment variable. All provider API keys must be present in the environment regardless of which profiles use them.

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
