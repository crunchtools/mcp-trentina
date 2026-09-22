# Gateway Audit Log

Every tool call through the Trentina gateway is recorded in SQLite — including calls the gateway itself refuses. The audit log captures who called what, **what outcome it reached**, how long it took, and what the defense pipeline found. This data drives allowlist tuning, error diagnosis, and usage monitoring.

## Why This Matters

Without observability, you're flying blind. Which tools are your agents actually using? Which backends are producing errors? How often does the defense pipeline flag content? The audit log answers these questions with data, not guesses.

## What Gets Recorded

Each gateway call writes one row to the `gateway_calls` table:

| Column | Type | Example |
|--------|------|---------|
| `timestamp` | datetime | `2026-06-23T10:42:11Z` |
| `profile` | text | `josui` |
| `backend` | text | `github` |
| `tool` | text | `list_issues_tool` |
| `success` | boolean | `true` (derived from `outcome`) |
| `duration_ms` | integer | `234` |
| `error_message` | text | `null` (or error message) |
| `outcome` | text | `ok`, `blocked_defense`, … (see below) |

### Outcomes

`success` alone cannot describe what happened, and reading it as a health
signal actively misleads. `safe_fetch` and `safe_read` **fail closed**: when
the defense blocks content the tool raises, which under a boolean is
indistinguishable from the backend being down. An operator reading
`2 ok / 34 errors` concludes the tool is broken when the truth may be that it
blocked 34 hostile pages.

| Outcome | Group | Meaning |
|---|---|---|
| `ok` | ok | Backend returned content and did not flag an error. |
| `blocked_defense` | blocked | L1/L2/L3 refused the content. Working as designed. |
| `denied_allowlist` | blocked | Tool not permitted for this profile. |
| `denied_guard` | blocked | A parameter guard rejected the arguments. |
| `denied_response_guard` | blocked | A response guard rejected the backend's result. |
| `tool_error` | failed | Backend completed but reported `isError`. |
| `backend_error` | failed | Upstream failed: network, timeout, auth, 4xx/5xx. |
| `gateway_error` | failed | Our own bug. The only outcome that should page anyone. |
| *(NULL)* | unknown | Row predates the taxonomy. Never back-fitted. |

**Only the `failed` group is a health signal.** The `blocked` group is a
security metric — a rising `blocked_defense` rate means the defense is
catching more, not that anything is broken.

`success` is derived (`outcome == "ok"`) rather than stored independently, so
the legacy boolean can never disagree with the taxonomy.

## Accessing Audit Data

The `quarantine_stats` tool exposes audit data through the gateway itself:

```json
{
  "gateway_audit": {
    "total_calls": 5743,
    "days": 30,
    "by_tool": [
      {"backend": "ashigaru", "tool": "status", "calls": 1559,
       "ok": 1553, "blocked": 0, "failed": 6, "outcomes": {"ok": 1553, "backend_error": 6}},
      {"backend": "web", "tool": "safe_read_tool", "calls": 36,
       "ok": 2, "blocked": 34, "failed": 0, "outcomes": {"ok": 2, "blocked_defense": 34}}
    ],
    "totals": {"ok": 1555, "blocked": 34, "failed": 6, "unknown": 0}
  }
}
```

The top-N breakdown shows which tools get the most use and which have the highest error rates — direct evidence for where to focus allowlist tuning or backend debugging.

## Use Cases

### Allowlist Tuning

After running with `tools_allow: ["*"]` for a week, check the audit log to see which tools are actually used. Build an explicit allowlist from the data:

```
Top 10 tools for kagetora (last 7 days):
1. ashigaru__status (1559 calls)
2. github__get_pull_request_checks_tool (195 calls)
3. web__quarantine_fetch_tool (157 calls)
...
```

### Error Diagnosis

Read the **`failed`** column, never `calls - ok`. A high `failed` rate points
at connectivity, auth, or backend bugs:

```
web__quarantine_fetch_tool: 157 calls, 133 ok,  0 blocked, 24 failed
web__safe_read_tool:         36 calls,   2 ok, 34 blocked,  0 failed
```

The second row is a healthy tool doing its job. Under the old single-`errors`
column it read as 34 errors and a 94% failure rate, which is how a working
defense got mistaken for a broken one.

### Denial Monitoring

`denied_allowlist`, `denied_guard` and `denied_response_guard` rows record
calls the gateway refused. A consumer repeatedly probing tools outside its
allowlist is a signal worth alerting on — it can indicate a misconfigured
client or a hijacked agent. These were previously not recorded at all.

`denied_response_guard` is the one denial that still costs an upstream call:
the backend answered and the answer was withheld here. A rising rate on it
means an agent keeps asking for material its profile forbids — see
[Response Guards](response-guards.md).

### Usage Patterns

Track which agents use which capabilities, how tool usage changes over time, and whether new backends are getting adopted.

## Storage

The audit table lives in the same SQLite database as the blocklist and compression cache (`trentina.db`). The table is append-only in normal operation — rows are never updated, and nothing in the request path deletes them.

Operators can reset the audit history with `reset_gateway_calls()`. It is deliberately **not** exposed as an MCP tool: erasing the audit trail is not a capability any consumer profile should hold. Database path is configurable:

```bash
QUARANTINE_DB=/data/quarantine.db  # default on container
```

## Related

- [MCP Gateway](gateway.md) — where audit recording happens
- [Blocklist](blocklist.md) — detection events that trigger blocklist entries
- [Per-Agent Profiles](profiles.md) — per-profile audit scoping
