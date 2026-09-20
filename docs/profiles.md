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

Environment variables in header values are expanded once, when the file is
loaded — so rotating one means reloading the profiles (below), not just
restarting the backend.

## Applying a Change

Editing `profiles.yaml` does not change the running gateway. The router filters
from the `Profile` objects loaded at startup, so an edited allowlist sits on
disk with no effect until it is loaded — which is the dangerous direction for
the file that decides which destructive tools an agent may call.

Apply it with the `reload_profiles` admin tool:

```
reload_profiles_tool()
```

It validates the whole file first and installs nothing unless all of it parses
and every referenced env var resolves, so a bad edit leaves the gateway exactly
as it was and returns the error. A good one swaps the profiles in place and
returns a per-profile diff of what moved, then notifies connected sessions so
clients refresh their tool list.

A reload is cheap where a restart is not. A restart re-judges every tool
description through the full defense pipeline before the first `tools/list` can
answer — on a large deployment, tens of minutes during which clients time out
on connect. A reload keeps the verdict cache, the compression cache and every
backend's tool list, so a profile-only edit re-judges nothing. Changing a
profile's `defense` thresholds is the exception: the verdicts were reached under
the old thresholds, so that profile's descriptions are judged again.

### In a container, mount the DIRECTORY, not the file

If the gateway runs in a container, bind-mount the directory holding
`profiles.yaml`:

```
-v /srv/trentina/gateway-config:/config:ro,Z      # correct
-v /srv/trentina/config/profiles.yaml:/config/profiles.yaml:ro,Z   # WRONG
```

A single-file bind mount pins the container to that file's **inode** at
container start. `sed -i`, `vim`, and anything else that writes a temp file and
renames it into place leave the original inode untouched and give the host path
a new one — so the host has your edit and the container still reads the old
bytes, for the life of the container. The reload then correctly reports
`reloaded: true` with no changes, which reads exactly like "my edit was a
no-op". Verified on the CrunchTools deployment 2026-09-20: host inode 93033554,
container still serving 93033552.

Mounting the directory makes the container resolve the path on each open, so an
edit by any editor is seen. If you must keep a file mount, every edit has to
preserve the inode (`cp new profiles.yaml`, not `mv`), which is one careless
`vim` away from silence.

Some sections cannot reload, because their routes bind at startup: the
`llm_providers` and `matrix` sections, and adding an `alert_ingress` or
`matrix_ingress` where no such route was registered at boot. The reload result
names any of these it finds in `not_applied` rather than reporting success over
an edit that went nowhere.

## Related

- [MCP Gateway](gateway.md) — how the gateway routes calls to backends
- [Tool Filtering](tool-filtering.md) — allowlist/denylist configuration
- [Parameter Guards](parameter-guards.md) — argument-level restrictions
- [Defense Pipeline](defense-pipeline.md) — L1/L2/L3 configuration details
