# Parameter Guards

Parameter guards validate the *arguments* an agent passes to a tool, not just whether the agent can call the tool at all. They provide deterministic, gateway-level enforcement of constraints like "this agent can send email, but only to these specific recipients."

## Why This Matters

Tool allowlists control *which* tools an agent can call. But some tools are dangerous not because of what they do, but because of what values get passed to them. `send_gmail_message` is fine when sending to yourself. It's a data exfiltration vector when an injected prompt convinces the agent to send your private data to an attacker's address.

You could try to enforce this behaviorally — tell the agent "only send email to these addresses" — but behavioral enforcement depends on the LLM following instructions, which is exactly what prompt injection attacks subvert. Parameter guards enforce the constraint at the gateway, before the call reaches the backend. The LLM's opinion doesn't matter.

## How It Works

Parameter guards are configured per-backend, per-tool in the profile YAML:

```yaml
backends:
  gws-personal:
    url: "http://gws-personal:8011/mcp"
    tools_allow: ["*"]
    parameter_guards:
      send_gmail_message:
        to:
          allow: ["user@example.com"]
        cc:
          allow: ["user@example.com"]
        bcc:
          allow: ["user@example.com"]
```

When an agent calls `send_gmail_message` through this profile, Trentina checks every guarded parameter against the allow/deny patterns. If the `to` field contains any address other than `user@example.com`, the call is rejected with a JSON-RPC `-32602` error before it ever reaches the Gmail backend.

### Constraint Schema

Each guarded parameter has two fields:

| Field | Default | Description |
|-------|---------|-------------|
| `allow` | `["*"]` | Glob patterns the value must match |
| `deny` | `[]` | Glob patterns that reject the value (wins over allow) |

### Pattern Matching

Values are matched using `fnmatch.fnmatchcase()` — shell-style globs with support for `*`, `?`, and `[seq]`:

| Pattern | Matches |
|---------|---------|
| `user@example.com` | Exact match |
| `*@company.com` | Any Red Hat email address |
| `*@gmail.com` | Any Gmail address |
| `https://api.example.com/*` | Any URL under a specific domain |

### Evaluation Rules

- **Missing guard**: no `parameter_guards` entry for a tool = all values allowed
- **Missing parameter**: if a guarded parameter is absent or `None` in the arguments, it passes (nothing to validate)
- **Deny wins**: a value matching any deny pattern is rejected even if it also matches an allow pattern
- **Fail-closed**: a call that fails parameter validation never reaches the backend — no tokens spent, no side effects

## Examples

### Restrict email recipients

```yaml
parameter_guards:
  send_gmail_message:
    to:
      allow: ["*@company.com", "user@example.com"]
      deny: ["*@competitor.com"]
    cc:
      allow: ["*@company.com"]
```

### Restrict file paths

```yaml
parameter_guards:
  safe_read_tool:
    path:
      allow: ["/data/*", "/tmp/*"]
      deny: ["/etc/shadow", "/etc/passwd", "*.key"]
```

### Restrict URLs

```yaml
parameter_guards:
  safe_fetch_tool:
    url:
      allow: ["https://*"]
      deny: ["*://evil.com/*", "*://localhost*"]
```

## Pipeline Position

Parameter guards run after the tool-name allowlist check and before the backend call:

```
Parse tool name → Backend exists? → Tool in allowlist? → Parameter guards → Backend call
```

A rejected call returns immediately. The backend never sees the request. The error message is terse and does not include the rejected value (to avoid leaking guard configuration to the agent).

## Related

- [Tool Filtering](tool-filtering.md) — controlling which tools are visible
- [Per-Agent Profiles](profiles.md) — where parameter guards are configured
- [Defense Pipeline](defense-pipeline.md) — content inspection after the call succeeds
