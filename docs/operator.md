# The Operator Profile

Trentina is meant to be run by an agent. It gets installed, configured, tuned
and kept healthy by an **Operator agent**, and humans set policy rather than
editing YAML. The operator profile (`role: operator`) is that agent's seat.
It is the one identity that owns the gateway.

Every other agent is a **tenant** (`role: agent`, the default). A tenant sees
its own tools, its own audit rows and its own section of the config, and
nothing about its neighbours. The operator sees the whole gateway, and the
gateway's own model work runs as the operator.

## What the seat is for

The operator holds two things.

**Administration.** The admin tools act on the whole gateway only from this
seat:

| Tool | As the operator |
|---|---|
| `quarantine_stats` | Every profile's calls and detections, plus compression savings |
| `cache_flush` | Every cache, by exact name |
| `reconnect_backend` | Any backend, wherever it is configured, and which profiles share it |
| `reload_profiles` | Applies the whole `profiles.yaml`, gateway-wide settings included |

These are what an Operator agent's loop needs. It edits `profiles.yaml`,
applies the edit with `reload_profiles`, and reads back what applied and what
needs a restart. It watches `quarantine_stats` for false positives and
calibration drift, and heals a backend with `reconnect_backend` after a
redeploy. None of this needs a shell. See [Roles](profiles.md#roles) for how
each tool narrows for a tenant.

**Service identity.** Some model calls belong to no tenant. Compressing a
shared tool description, and judging it at the perimeter before any profile
sees it, is done once for everyone. That work runs **as the operator**, on the
operator's `defense.provider`, `defense.model` and `llm_keys`, and it bills
the operator's key.

| Work | Runs as | Bills |
|---|---|---|
| L3 on a tool **response** | The calling tenant | The tenant's `llm_keys` |
| L3 on a tool **description** (perimeter, `tools/list`) | The operator | The operator's `llm_keys` |
| Description [compression](compression.md) | The operator | The operator's `llm_keys` |
| Any future gateway-initiated model call | The operator | The operator's `llm_keys` |

Thresholds are not part of the service identity. A shared description is
judged by the operator's model, but each tenant's own `l2_threshold` and
enforcement mode still decide what that tenant is shown. Verdicts are cached
per (thresholds, judging model, content), so a verdict reached by one model is
never served to a profile judged by another.

Before 0.36 there was no declared owner: compression used the first profile's
provider in file order, and the perimeter fell through to the env-global key.
Now, with **no operator declared**, both use the env-global provider, model and
key, and the gateway says so at startup:

```
service identity: no operator profile declared — centralized model calls (...) use the env-global key, ...
```

With an operator, the same line names it:

```
service identity: centralized model calls run as operator profile=ops provider=gemini model=...
```

## Declaring one

```yaml
profiles:
  ops:
    role: operator
    auth:
      bearer_token_env: TRENTINA_PROFILE_OPS_TOKEN
    llm_keys:
      gemini:
        api_key_env: TRENTINA_OPS_GEMINI_API_KEY
    backends:
      web:
        url: "internal://web"
        tools_allow: ["*"]
    # defense.provider / defense.model choose the service identity's model;
    # omitted, the env defaults (TRENTINA_MODEL_PROVIDER, QUARANTINE_MODEL).

  hermes:
    auth:
      bearer_token_env: TRENTINA_PROFILE_HERMES_TOKEN
    llm_keys:
      gemini:
        api_key_env: HERMES_GEMINI_API_KEY
    backends:
      web:
        url: "internal://web"
        tools_allow: ["fetch_tool", "search_tool"]
```

## Rules the loader enforces

- **At most one operator.** Two would make "whose identity" depend on file
  order again, so a second one refuses the whole file. On a reload the running
  config stays in force.
- **The operator pays for its own work.** It must hold `llm_keys` for the
  provider its service identity resolves to (Ollama excepted, which is
  keyless). Without that key, every description would come back
  `l3_unavailable`, and under `block` every tool would be quietly withheld from
  every profile. Failing at load is the better outcome.
- **No self-promotion.** A tenant's reload that finds its own `role` changed
  on disk refuses and applies nothing. A promotion takes effect only through an
  operator reload or a restart.

## Changing the operator

Moving the seat, or changing the operator's `defense.model`, moves every
centralized call to the new identity at the next reload. Descriptions are then
judged again under the new model: that's the verdict cache doing its job, not a
bug. Verdicts reached by the env-default model keep their cache keys, so an
operator that runs the default model inherits everything judged before
operators existed.
