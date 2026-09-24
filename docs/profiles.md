# Per-Agent Profiles

Every agent that connects to Trentina gets its own profile. A profile defines which backends the agent can access, which tools it can see, what defense layers run on responses, and how it authenticates. Different agents get different levels of trust through the same gateway.

## Why This Matters

You don't give a human-supervised IDE agent the same permissions as an autonomous agent running unattended. The IDE agent might need full Gmail access — it has a human watching every tool call. The autonomous agent should probably only read email and draft responses, never send. Without per-agent profiles, you're stuck choosing between "too open" and "too restrictive" for everyone.

## Profile Schema

Profiles are defined in YAML, typically at `/etc/trentina/profiles.yaml` or wherever `TRENTINA_PROFILES_PATH` points:

```yaml
profiles:
  agent2:
    role: operator          # default: agent (see Roles)
    auth:
      bearer_token_env: TRENTINA_PROFILE_AGENT2_TOKEN
    backends:
      web:
        url: "internal://web"
        tools_allow: ["*"]
      slack:
        url: "http://mcp-slack:8000/mcp"
        tools_allow: ["*"]
      gws-personal:
        url: "http://gws-personal:8000/mcp"
        tools_allow: ["*"]
        tools_deny: ["delete*"]
        compress_descriptions: true
    defense:
      enforcement: warn
      l2_threshold: 0.5

  agent1:
    auth:
      bearer_token_env: TRENTINA_PROFILE_AGENT1_TOKEN
    backends:
      web:
        url: "internal://web"
        tools_allow: ["block_*", "clean_*"]   # no warn_* — see Content modes
      gws-personal:
        url: "http://gws-personal:8000/mcp"
        tools_allow:
          - search_gmail_messages
          - get_gmail_message_content
          - draft_gmail_message
        compress_descriptions: true
    defense:
      enforcement: block      # autonomous agent: flagged content is refused
      l2_threshold: 0.3       # stricter classifier gate
```

## Content modes

The `web` backend offers every content family in three modes — `block_*`,
`warn_*`, `clean_*` — and `tools_allow` decides which a profile gets. All
three run all three layers; they differ only in what is delivered (see
[Content Tools](quarantine-tools.md)).

`warn_*` hands over flagged content verbatim with a caution attached. That is
a **security-researcher grant**: a human reading a CVE advisory needs it; an
assistant, a coding agent or a swarm almost never does, and an injection that
can talk an agent past its own warning is the attack it exists to survive.
Offer it by name to the seat that needs it — `tools_allow: ["block_*",
"clean_*"]` for everyone else.

## Roles

One gateway process serves every profile out of one config file, one database
and one set of caches. `role` decides how much of that a profile reaches
through the gateway's own admin tools — `cache_flush`, `reconnect_backend`,
`quarantine_stats` and `reload_profiles`:

| | `role: agent` (default) | `role: operator` |
|---|---|---|
| `quarantine_stats` | its own audit rows and detections, and the defense settings it runs under | the whole gateway, plus compression savings |
| `cache_flush` | its own backends and its own aggregate | every cache |
| `reconnect_backend` | a backend in its own profile, with the tool count it would see | the name wherever it is configured, and who shares it |
| `reload_profiles` | validates the whole file, applies its own section | applies the whole file and the gateway-wide settings |

Omit `role` and the profile is an agent. Give it to the seat a human drives,
not to an autonomous agent.

An agent profile is not told what it cannot act on. Another profile's backend
names, allowlist deltas, guarded parameter names, call volumes and blocked URLs
are the shape of its permissions, and a routine flush or reload is not an
occasion to hand that over — so the refusals name nothing either, and a backend
in someone else's profile is refused exactly like one that does not exist.

Two things a role does not change. Evicting a cache or resetting a circuit is
keyed by backend URL, so doing it to a backend you do hold is felt by every
profile that shares it — that is correctness, not disclosure, and it costs a
re-probe. And a profile can never apply its **own** role change: an agent
reload that finds its `role` moved on disk refuses and changes nothing, so a
promotion costs an operator reload or a restart.

Because every profile model is `extra="forbid"`, a `role:` key against a
gateway older than this feature is a hard load error. Upgrade the gateway
first — everything defaults to `agent` — then add the key.

## Authentication

Each profile authenticates via bearer token. The token value is read from an environment variable — never from the YAML file:

```bash
# Token env vars (set in your env file, not profiles.yaml)
TRENTINA_PROFILE_AGENT2_TOKEN=your-secret-token
TRENTINA_PROFILE_AGENT1_TOKEN=another-secret-token
```

The agent sends the token in the `Authorization` header:

```
Authorization: Bearer your-secret-token
```

Trentina matches the token to a profile. No token or wrong token = 401.

### Beyond a static token

A profile can also accept an OAuth identity — either one Trentina issues
itself while proxying login to Google, or one minted by an external identity
provider that Trentina merely verifies. Which you want depends on what the
client can do, and the choice is per profile.

All four mechanisms, the `oauth` keys each one needs, and the security rules that
go with them are in **[Authentication](authentication.md)**.

## Multi-Agent Deployment

A typical deployment serves multiple agents with different trust levels:

| Profile | Agent Type | Tool Count | Defense | Use Case |
|---------|-----------|------------|---------|----------|
| agent2 | Claude Code (human-supervised) | 440+ | L1+L2+L3 | Full access, human in the loop |
| agent1 | Hermes (autonomous) | ~210 | L1+L2 only | Tightened allowlists, no L3 (token cost) |
| agent3 | OpenClaw (chat agent) | ~440 | L1+L2+L3 | Full access, different auth context |

All three connect to the same Trentina instance on the same port. The profile name in the URL determines everything:

```
http://trentina:8019/gateway/agent2/mcp
http://trentina:8019/gateway/agent1/mcp
http://trentina:8019/gateway/agent3/mcp
```

## Defense Settings

Each profile configures its defense **policy** — never the layers' existence. All three layers run for every profile; there are deliberately no per-layer off switches (an earlier schema had them, and `quarantine: false` ran in production for months without the operator knowing). What a profile controls:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enforcement` | string | `warn` | What a flagged response becomes: `warn` (delivered intact + warning — the calibration mode) or `block` (refused — autonomous agents). `clean` is refused at load: the clean_* TOOLS work, the enforcement mode never has |
| `l2_threshold` | float | `0.5` | L2 score at/above which content is flagged, in addition to the model's own MALICIOUS label. Lower = stricter. |
| `audit` | bool | `true` | Write detection rows to SQLite |
| `provider` | string | `null` | LLM provider override (`gemini`, `openai`, `anthropic`, `ollama`) |

An autonomous agent runs `enforcement: block` with a strict `l2_threshold`; a human-supervised agent runs `warn`. `TRENTINA_ENFORCEMENT_OVERRIDE=warn` is the global kill switch for the night a block threshold misfires.

`annotate` and `extract` are the pre-0.25.0 spellings. They still load, with a warning naming the release that removed in 0.29.0. `annotate` becomes `warn`; `extract` becomes `block`, which is what it already did — it shipped unimplemented and always failed closed.

The `provider` field lets each profile use a different LLM for L3 Q-Agent operations and tool description compression. When omitted, the profile uses the global `TRENTINA_MODEL_PROVIDER` environment variable. All provider API keys must be present in the environment regardless of which profiles use them.

## Backend Headers

Some backends require their own authentication. Pass headers per-backend:

```yaml
backends:
  memory:
    url: "http://mcp-memory:8000/mcp"
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
reports what moved, then notifies connected sessions so clients refresh their
tool list.

A reload is cheap where a restart is not. A restart re-judges every tool
description through the full defense pipeline before the first `tools/list` can
answer — on a large deployment, tens of minutes during which clients time out
on connect. A reload keeps the verdict cache, the compression cache and every
backend's tool list, so a profile-only edit re-judges nothing. Changing a
profile's `defense` thresholds is the exception: the verdicts were reached under
the old thresholds, so that profile's descriptions are judged again.

### A reload is scoped to the caller's role

An **operator** reload is the whole file: every profile, the gateway-wide
settings, and a diff of everything that moved.

An **agent** reload validates the whole file — a bad edit anywhere still
refuses, because half a file is not a config — and then applies exactly one
entry, its own:

```
"reloaded": true
"scope": "beta"
"applied": ["beta"]
"changes": {"beta": {...}}
"note": "agent scope — only this profile's section was applied; other
         profiles and gateway-wide settings need an operator-scope reload"
```

That note is fixed text. It does not say whether anyone else moved, or how
many did, because either would be a fact about profiles the caller does not
hold. Edits to other profiles stay on disk until an operator reload or a
restart applies them, which is the cost of the insulation and worth knowing
before you edit someone else's section and walk away.

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
