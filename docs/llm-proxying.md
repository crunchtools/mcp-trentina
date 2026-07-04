# LLM Key Proxying

Proxy LLM API calls (Gemini, OpenAI, Anthropic) through the gateway so API keys never leave the trusted boundary. Agents send model requests to Trentina, which forwards them with the real credentials. No API keys in agent configs, no key exposure through prompt injection or tool-call exfiltration.

## Why This Matters

Every agent that calls an LLM API needs an API key. That key is typically stored in an environment variable or config file accessible to the agent. If the agent is compromised — through prompt injection, a malicious MCP server, or any other vector — the attacker gets the API key.

API key theft is particularly dangerous because:

- **Keys are reusable** — unlike session tokens, API keys don't expire on use
- **Keys grant broad access** — a Gemini API key lets the attacker make arbitrary model calls, potentially running up costs or accessing fine-tuned models
- **Exfiltration is subtle** — an agent can embed a key in an outbound API call or tool response without obviously malicious behavior

## How It Works

Trentina exposes LLM API proxy endpoints at `/llm/{provider}/{path}` that mirror the upstream APIs. The agent authenticates with its **gateway bearer token** (the same token it uses for `/gateway/{profile}/mcp`). Trentina resolves which profile the token belongs to, strips the agent's `Authorization` header, injects the real API key for that profile, forwards to the upstream provider, and returns the response. Streaming (SSE) and non-streaming responses are forwarded transparently.

### Per-Profile Keys and Rate-Limit Isolation

Each profile injects **its own** provider key, declared in the profile's `llm_keys` section. This gives every consumer its own rate-limit bucket and its own token accounting on the provider's dashboard — heavy agentic traffic from one consumer can no longer exhaust another's quota (see [#53](https://github.com/crunchtools/mcp-trentina/issues/53)).

Authentication is **mandatory**:

| Condition | Result |
|-----------|--------|
| Unknown or disabled `{provider}` | `404` |
| Missing / malformed / unrecognized bearer token | `401` |
| Authenticated profile has no `llm_keys` entry for `{provider}` | `502` |
| Authenticated profile has a key for `{provider}` | Inject the profile's key, forward |

The caller's `Authorization` header is never forwarded upstream. Trentina's own Q-Agent is unaffected — it calls providers directly (not through `/llm/`) and continues to use the global `GEMINI_API_KEY`.

### What This Buys You

- **No key in agent environment** — the agent's container/process has no `GEMINI_API_KEY`, `OPENAI_API_KEY`, or `ANTHROPIC_API_KEY`
- **Key rotation without agent restart** — update the key in the gateway's env file, reload the service
- **Adding a provider is a YAML entry, not code** — no code changes to support a new LLM backend

## Configuration

LLM providers are configured in the top-level `llm_providers` section of `profiles.yaml`:

```yaml
llm_providers:
  gemini:
    enabled: true
    upstream: https://generativelanguage.googleapis.com
    auth_header: x-goog-api-key
    api_key_env: GEMINI_API_KEY

  openai:
    enabled: true
    upstream: https://api.openai.com
    auth_header: Authorization
    auth_prefix: "Bearer "
    api_key_env: OPENAI_API_KEY

  anthropic:
    enabled: true
    upstream: https://api.anthropic.com
    auth_header: x-api-key
    api_key_env: ANTHROPIC_API_KEY
```

Each provider entry specifies:

| Field | Description |
|-------|-------------|
| `enabled` | Whether this provider is active |
| `upstream` | Base URL to forward requests to |
| `auth_header` | HTTP header name for the API key |
| `auth_prefix` | Optional prefix before the key value (e.g., `"Bearer "`) |
| `api_key_env` | Environment variable holding the real API key (used by Trentina's own Q-Agent path; the LLM proxy uses per-profile keys) |

Each **profile** then declares the key it wants the proxy to inject, under `llm_keys`:

```yaml
profiles:
  kagetora:
    auth:
      bearer_token_env: AIRLOCK_PROFILE_KAGETORA_TOKEN
    llm_keys:
      gemini:
        api_key_env: KAGETORA_GEMINI_API_KEY
  takeda:
    auth:
      bearer_token_env: AIRLOCK_PROFILE_TAKEDA_TOKEN
    llm_keys:
      gemini:
        api_key_env: TAKEDA_GEMINI_API_KEY
```

The provider name under `llm_keys` must match a configured `llm_providers` entry — a dangling reference fails the server closed at startup.

### Architecture

```
┌──────────┐                    ┌────────────────┐    Real API key    ┌──────────┐
│  Agent   │ ────────────────► │   Trentina     │ ─────────────────► │  Gemini  │
│          │  /llm/gemini/...  │   Gateway      │                    │  OpenAI  │
│ No API   │ ◄──────────────── │                │ ◄───────────────── │  etc.    │
│ keys     │    LLM response   │  Key injection │    LLM response   └──────────┘
└──────────┘                   └────────────────┘
```

### Request Flow

1. Agent sends `POST /llm/gemini/v1beta/models/gemini-2.5-flash:generateContent` with `Authorization: Bearer <profile gateway token>`
2. Trentina looks up the `gemini` provider config and resolves the caller profile from the bearer token (`401` if it matches none)
3. Looks up the profile's `llm_keys.gemini` key (`502` if the profile has none)
4. Strips hop-by-hop headers **and the caller's `Authorization`**, injects `x-goog-api-key: <profile's real key>`
5. Forwards to `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent`
6. Streams the response back to the agent

### Relationship to Network Isolation

LLM key proxying works independently of the [Matrix reverse proxy](network-isolation.md), but they're complementary. With both enabled, the agent has no network access *and* no API keys — it can only interact with the outside world through Trentina's controlled gateway.

## Related

- [Matrix Reverse Proxy](network-isolation.md) — eliminating agent network access entirely
- [Per-Agent Profiles](profiles.md) — profile-level configuration
- [Audit Log](audit-log.md) — recording model API calls alongside tool calls
